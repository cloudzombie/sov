//! The node engine: the loop that turns pooled transactions into mined blocks.
//!
//! A [`Node`] owns a [`Blockchain`] and a [`Mempool`]. [`Node::produce`] is one
//! full Nakamoto block step:
//!
//! 1. select an executable batch from the mempool (contiguous nonces);
//! 2. mine a block over it (`produce_block` grinds the header's proof of work;
//!    the coinbase pays this node's configured miner account); and
//! 3. import it through the same validated path as any peer block, then drop
//!    the included and now-stale transactions from the pool.
//!
//! Finality is confirmation depth in the heaviest-work chain — no approvals,
//! no votes. This is deterministic and synchronous — wall-clock scheduling and
//! networked multi-node operation layer on top — which keeps the core
//! production logic fully testable.

use std::time::{SystemTime, UNIX_EPOCH};

use sov_chain::{Blockchain, ChainError, MiningCandidate};
use sov_mempool::{Admitted, Mempool, MempoolError};
use sov_primitives::{AccountId, Hash};
use sov_types::{Action, Block, Receipt, SignedTransaction};

use crate::timing::{TxTiming, TxTimingIndex};

/// A running SOV node.
pub struct Node {
    chain: Blockchain,
    mempool: Mempool,
    max_block_txs: usize,
    /// NODE-LOCAL transaction timing (see [`crate::timing`]): how long each
    /// mined transaction waited, as THIS node observed it.
    ///
    /// It is written only by [`Node::record_block_timing`] and read only by
    /// [`Node::tx_timing`] — there is no path from it into block validation,
    /// execution, selection, or fork choice, so it cannot influence any
    /// committed root. Bounded by construction; persisted outside the block log.
    timing: TxTimingIndex,
}

/// The outcome of mining one block.
pub struct Produced {
    /// The committed block.
    pub block: Block,
    /// Receipts from executing its transactions.
    pub receipts: Vec<Receipt>,
}

impl Node {
    /// Create a node over `chain`, with a mempool of `mempool_capacity` and at
    /// most `max_block_txs` transactions per block.
    pub fn new(chain: Blockchain, mempool_capacity: usize, max_block_txs: usize) -> Self {
        let mut node = Node {
            chain,
            mempool: Mempool::new(mempool_capacity),
            max_block_txs,
            timing: TxTimingIndex::new(),
        };
        node.refresh_mempool_domain();
        node
    }

    /// Override the node-local timing index's retention bounds (blocks of depth,
    /// hard row ceiling) — the operator-configurable form of
    /// [`crate::timing::DEFAULT_RETENTION_BLOCKS`] /
    /// [`crate::timing::DEFAULT_MAX_ENTRIES`]. Discards any rows already held,
    /// so it is a startup knob, applied before the index is loaded from disk.
    pub fn set_tx_timing_limits(&mut self, retention_blocks: u64, max_entries: usize) {
        self.timing = TxTimingIndex::with_limits(retention_blocks, max_entries);
    }

    /// Refresh the mempool's `tx-domain` verification mode to the one resolved at
    /// the next height, so admission verifies signatures exactly as block
    /// execution will. `Legacy` while the miner-signaled `tx-domain` fork is
    /// dormant (byte-identical to pre-fork admission); `Grace(domain)` for the
    /// grace window at/after activation (legacy OR chain-bound admitted, so
    /// in-flight legacy transactions still confirm); `Bound(domain)` once the
    /// window closes, at which point a legacy or cross-network signature is
    /// refused at the door. Called after every tip change so the pool tracks the
    /// rollout.
    ///
    /// The same tip-change hook also tells the pool the node's current height,
    /// so every admission is stamped with WHERE in the chain this node was when
    /// it saw the transaction — the height half of the one admission
    /// observation that [`Mempool::first_seen`](sov_mempool::Mempool::first_seen)
    /// reports. That is node-local bookkeeping; the pool reads it for nothing
    /// else.
    fn refresh_mempool_domain(&mut self) {
        let mode = self.chain.resolved_tx_domain_mode(self.chain.height() + 1);
        self.mempool.set_mode(mode);
        self.mempool.set_chain_height(self.chain.height());
    }

    /// Name the account this node's mined blocks credit the coinbase to — the
    /// operator's miner identity (see [`Blockchain::set_coinbase`]).
    pub fn set_coinbase(&mut self, account: AccountId) {
        self.chain.set_coinbase(account);
    }

    /// Install trusted weak-subjectivity checkpoints (`(height, block hash)`) so a
    /// forged long-range history is rejected on import. See
    /// [`Blockchain::set_checkpoints`](sov_chain::Blockchain::set_checkpoints).
    pub fn set_checkpoints(&mut self, checkpoints: impl IntoIterator<Item = (u64, Hash)>) {
        self.chain.set_checkpoints(checkpoints);
    }

    /// Add trusted checkpoints, keeping any already installed (baked defaults + operator
    /// config coexist).
    pub fn add_checkpoints(&mut self, checkpoints: impl IntoIterator<Item = (u64, Hash)>) {
        self.chain.add_checkpoints(checkpoints);
    }

    /// The underlying chain.
    pub fn chain(&self) -> &Blockchain {
        &self.chain
    }

    /// The underlying chain, mutably.
    ///
    /// Narrow by intent: sync needs to feed verified checkpoint-linkage headers
    /// in (`extend_checkpoint_linkage`), which is chain state rather than block
    /// import. Block import keeps going through the node's own methods.
    pub fn chain_mut(&mut self) -> &mut Blockchain {
        &mut self.chain
    }

    /// Number of READY (mineable) pooled transactions. Queued future-nonce
    /// entries are reported by [`mempool_queued_len`](Self::mempool_queued_len).
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// Number of QUEUED (future-nonce, not yet mineable) pooled transactions.
    pub fn mempool_queued_len(&self) -> usize {
        self.mempool.queued_len()
    }

    /// The per-block transaction capacity this node builds templates with — the
    /// packing unit `sov_getMempoolHistogram` clients project blocks by.
    pub fn max_block_txs(&self) -> usize {
        self.max_block_txs
    }

    /// The byte budget of the next block — the consensus elastic block-size cap
    /// for a block extending the current head. Together with
    /// [`max_block_txs`](Self::max_block_txs) it is the pair of limits a
    /// projected block is packed against.
    pub fn max_block_bytes(&self) -> usize {
        self.chain.next_block_size_limit()
    }

    /// Effective-tip histogram of the ready mempool, highest bucket first,
    /// bounded at `max_buckets`. See [`Mempool::tip_histogram`].
    pub fn mempool_tip_histogram(&self, max_buckets: usize) -> Vec<sov_mempool::TipBucket> {
        self.mempool.tip_histogram(max_buckets)
    }

    /// The mempool ADMISSION floor in grains — what a new transaction must beat
    /// to displace a slot in a full pool, `0` while the pool has room. See
    /// [`Mempool::pool_floor_grains`].
    pub fn mempool_pool_floor_grains(&self) -> u128 {
        self.mempool.pool_floor_grains()
    }

    /// A bounded snapshot of the mempool's CONTENTS with per-entry arrival
    /// timing — the per-transaction view `sov_getMempoolTxs` serves. Read-only,
    /// node-local, non-consensus. See [`Mempool::entries`].
    ///
    /// [`Mempool::entries`]: sov_mempool::Mempool::entries
    pub fn mempool_entries(&self, limit: usize) -> Vec<sov_mempool::MempoolEntry> {
        self.mempool.entries(limit)
    }

    /// This node's recorded timing for transaction `id`, or `None` when it holds
    /// no row — the transaction was never mined on this node's active chain, or
    /// its row has aged out of the retention window. See [`crate::timing`].
    ///
    /// Read-only, node-local, non-consensus.
    pub fn tx_timing(&self, id: &Hash) -> Option<TxTiming> {
        self.timing.get(id)
    }

    /// How many timing rows this node retains, and the bounds it retains them
    /// under: `(rows, retention_blocks, max_entries)`. For operator visibility
    /// into a structure whose whole point is that it stays bounded.
    pub fn tx_timing_stats(&self) -> (usize, u64, usize) {
        (
            self.timing.len(),
            self.timing.retention_blocks(),
            self.timing.max_entries(),
        )
    }

    /// The timing index's persisted form — written to `data_dir/txtiming.dat`
    /// beside `mempool.dat`, so an operator's view of transaction latency
    /// survives a restart. See [`TxTimingIndex::snapshot`].
    pub fn tx_timing_snapshot(&self) -> Vec<(Hash, TxTiming)> {
        self.timing.snapshot()
    }

    /// Reload a persisted timing index, re-applying this node's CONFIGURED
    /// bounds. A missing or unreadable file simply means an empty index: it is
    /// non-consensus metadata, so losing it must never keep a node from booting.
    pub fn restore_tx_timing(&mut self, rows: Vec<(Hash, TxTiming)>) {
        self.timing.restore(rows);
    }

    /// Record node-local timing for every transaction in `block`, which must
    /// already be committed on the ACTIVE chain.
    ///
    /// **Call order matters.** This reads each transaction's admission stamp out
    /// of the mempool, so it has to run BEFORE the block-connect path prunes
    /// those entries — once they are gone, the observation is gone with them and
    /// every row would be recorded as unobserved. Both connect paths
    /// ([`commit_mined`](Self::commit_mined) and
    /// [`import_block`](Self::import_block)) call it as their first step after a
    /// successful import, ahead of any pool mutation.
    ///
    /// A transaction this node never pooled — the normal case for a block synced
    /// from a peer — is recorded as UNOBSERVED: the inclusion facts are kept, the
    /// wait is `None`, and the block's own timestamp is never substituted for the
    /// arrival this node did not witness.
    ///
    /// A block that did not join the active chain (a self-mined block that lost
    /// the race, or a peer block filed on a lighter side branch) records nothing:
    /// there is no honest `included_height` for a block nobody is building on.
    fn record_block_timing(&mut self, block: &Block) {
        let height = block.header.height.get();
        // Only the active chain gets rows. Comparing by hash (not just height)
        // is what distinguishes "this block is the one at that height" from
        // "some other block occupies that height now".
        if self.chain.block_by_height(height).map(|b| b.hash()) != Some(block.hash()) {
            return;
        }
        let timestamp_ms = block.header.timestamp_ms;
        let ids: Vec<Hash> = block.transactions.iter().map(|stx| stx.id()).collect();
        // One batched lookup, not one per transaction: the queued region is
        // keyed by `(signer, nonce)`, so a per-id query re-hashes the whole
        // parked region every time — quadratic for a full block against a full
        // queue, on the block-connect hot path.
        let seen = self.mempool.first_seen_batch(&ids);
        for (id, seen) in ids.into_iter().zip(seen) {
            let timing = match seen {
                Some(seen) => TxTiming::observed(seen.at_ms, seen.at_height, height, timestamp_ms),
                None => TxTiming::unobserved(height, timestamp_ms),
            };
            self.timing.record(id, timing);
        }
    }

    /// Repair the timing index after a REORG, so no row is left claiming a
    /// transaction sits in a block that is no longer on the active chain.
    ///
    /// `reverted` is the set of transactions the reorg orphaned off the old
    /// active chain (`Imported::reverted_txs`). Their rows are WITHDRAWN first —
    /// a withdrawn row is honest (the RPC reports "no timing for this
    /// transaction"), a stale one is not. Then every active block from the
    /// lowest withdrawn height up to the new tip is re-recorded, which RE-POINTS
    /// any transaction that appears on both branches to its real new height and
    /// fills in the new branch's intermediate blocks (which were only ever
    /// imported as side-branch blocks, so they were never recorded).
    ///
    /// Bounded by the reorg's depth, and a no-op when nothing was orphaned.
    /// Called before the mempool prunes, so re-recorded transactions still find
    /// their admission stamps.
    fn repair_timing_after_reorg(&mut self, reverted: &[SignedTransaction]) {
        if reverted.is_empty() {
            return;
        }
        let mut from = None;
        for stx in reverted {
            if let Some(old) = self.timing.remove(&stx.id()) {
                from = Some(from.map_or(old.included_height, |f: u64| f.min(old.included_height)));
            }
        }
        let Some(from) = from else { return };
        // `from` can never predate the retention window, because a row outside it
        // has already been evicted and so could not have been withdrawn above —
        // the walk is bounded by the window even for an absurdly deep reorg.
        for height in from..=self.chain.height() {
            let Some(block) = self.chain.block_by_height(height).cloned() else {
                continue;
            };
            self.record_block_timing(&block);
        }
    }

    /// Ages (ms) of the oldest ready and oldest queued mempool entries —
    /// `(pending, queued)`, `None` for an empty region.
    pub fn mempool_oldest_ages_ms(&self) -> (Option<u64>, Option<u64>) {
        (
            self.mempool.oldest_pending_age_ms(),
            self.mempool.oldest_queued_age_ms(),
        )
    }

    /// The live next-block auction floor in grains: the marginal (lowest)
    /// effective tip in a full forming template, or 0 while the next block still
    /// has free room. A new transaction tipping MORE than this displaces the
    /// template's cheapest slot — the real "fee to get in".
    pub fn next_block_floor_grains(&self) -> u128 {
        self.mempool
            .nth_highest_tip(self.max_block_txs)
            .unwrap_or(0)
    }

    /// The mempool's configured bounds:
    /// `(capacity, max_per_sender, queued_capacity, max_queued_per_sender)`.
    pub fn mempool_limits(&self) -> (usize, usize, usize, usize) {
        (
            self.mempool.capacity(),
            self.mempool.max_per_sender(),
            self.mempool.queued_capacity(),
            self.mempool.max_queued_per_sender(),
        )
    }

    /// The next nonce a new transaction from `signer` should use: the account's
    /// committed on-chain nonce plus any transactions it already has pending in the
    /// pool. A wallet building back-to-back sends must use THIS (not the bare
    /// on-chain nonce) so a second send queues behind the first instead of colliding
    /// with its slot. Read-only; no consensus rule changes.
    pub fn next_nonce(&self, signer: &AccountId) -> u64 {
        let on_chain = self.chain.ledger().account(signer).nonce;
        self.mempool.next_nonce(signer, on_chain)
    }

    /// Submit a transaction to the pool, validating it against current state.
    /// Returns whether it was admitted [`Admitted::Ready`] (mineable now) or
    /// parked [`Admitted::Queued`] (future nonce; promoted when the gap fills).
    pub fn submit(&mut self, stx: SignedTransaction) -> Result<Admitted, NodeError> {
        // Mirror the runtime's authorization at admission: a validly *signed*
        // transaction that names an account whose key it does not control is
        // rejected here, not admitted and then failed in execution — which would
        // stall production on a tx that can never be included or pruned.
        let account = self.chain.ledger().account(&stx.transaction.signer);
        let authorized = if let Some(policy) =
            self.chain.ledger().multisig_of(&stx.transaction.signer)
        {
            // Multisig account (mirror the runtime): only a MultisigExec relayed by
            // a policy member; the threshold check happens in execution.
            policy.signers.contains(&stx.transaction.public_key)
                && matches!(stx.transaction.action, Action::MultisigExec { .. })
        } else {
            match &account.key {
                Some(key) => *key == stx.transaction.public_key,
                None => {
                    // Mirror the runtime's self-certifying rule exactly: a keyless
                    // IMPLICIT account (id = hash of its key) is controlled by the key
                    // whose hash IS its id — for ANY action, no activation. A keyless
                    // human-named account may only be claimed first via `RotateKey`.
                    if stx.transaction.signer.is_implicit() {
                        stx.transaction.public_key.implicit_account_id() == stx.transaction.signer
                    } else {
                        matches!(stx.transaction.action, Action::RotateKey { .. })
                    }
                }
            }
        };
        if !authorized {
            return Err(NodeError::Unauthorized {
                account: stx.transaction.signer.to_string(),
            });
        }
        self.mempool
            .insert(stx, account.nonce, account.balance)
            .map_err(NodeError::Mempool)
    }

    /// A snapshot of the pending pool — persisted to disk so it survives a restart.
    pub fn mempool_snapshot(&self) -> Vec<SignedTransaction> {
        self.mempool.snapshot()
    }

    /// Re-admit a persisted pool against current state on startup, dropping any tx that no
    /// longer validates (stale nonce, now unaffordable).
    pub fn restore_mempool(&mut self, txs: Vec<SignedTransaction>) {
        let ledger = self.chain.ledger();
        self.mempool.restore(
            txs,
            |a| ledger.account(a).nonce,
            |a| ledger.account(a).balance,
        );
    }

    /// Produce (mine), import, and (self-)finalize the next block at
    /// `timestamp_ms`: select an executable mempool batch, grind the block's
    /// proof of work via `produce_block`, and commit it through the same
    /// validated import path as any peer block. The block's coinbase pays this
    /// node's configured miner account.
    pub fn produce(&mut self, timestamp_ms: u64) -> Result<Produced, NodeError> {
        // Convenience: build + grind in-process, then commit. A mining daemon
        // should instead grind OFF the node lock — `build_candidate` (brief lock)
        // → `Candidate::into_sealed_block` (unlocked, the expensive PoW) →
        // `commit_mined` (brief lock) — so RPC stays responsive while it mines.
        let block = self
            .build_candidate(timestamp_ms)?
            .0
            .into_sealed_block()
            .map_err(NodeError::Chain)?;
        self.commit_mined(block)
    }

    /// Build an **unsealed** candidate block over an executable mempool batch.
    /// The caller grinds it via `Candidate::into_sealed_block` (off any lock —
    /// it touches no node state) and commits the result with
    /// [`commit_mined`](Self::commit_mined). This is the path the mining daemon
    /// uses to keep its JSON-RPC responsive while mining.
    pub fn build_candidate(
        &self,
        timestamp_ms: u64,
    ) -> Result<(MiningCandidate, Vec<(SignedTransaction, String)>), NodeError> {
        let batch = {
            let ledger = self.chain.ledger();
            self.mempool
                .select(|a| ledger.account(a).nonce, self.max_block_txs)
        };
        self.chain
            .build_candidate(batch, timestamp_ms)
            .map_err(NodeError::Chain)
    }

    /// Like [`build_candidate`](Self::build_candidate), but credits the coinbase to an
    /// EXPLICIT `coinbase` account rather than this node's configured miner identity —
    /// the work-distribution path (`sov_getBlockTemplate`), so a pool/out-of-process
    /// miner can direct the coinbase to its own account. Selects the same executable
    /// mempool batch; the sealed result is committed through the normal validated path.
    pub fn build_candidate_for(
        &self,
        timestamp_ms: u64,
        coinbase: AccountId,
    ) -> Result<(MiningCandidate, Vec<(SignedTransaction, String)>), NodeError> {
        let batch = {
            let ledger = self.chain.ledger();
            self.mempool
                .select(|a| ledger.account(a).nonce, self.max_block_txs)
        };
        self.chain
            .build_candidate_for(batch, timestamp_ms, coinbase)
            .map_err(NodeError::Chain)
    }

    /// Drop a transaction from the mempool by id. Used to EVICT a transaction the
    /// block-builder found unminable (it failed execution against current state, so
    /// it would be silently excluded from every block) — together with the reason
    /// logged by the caller, this stops a permanently-failing tx from clogging the
    /// mempool and producing empty blocks.
    pub fn drop_tx(&mut self, id: &Hash) {
        self.mempool.remove(id);
    }

    /// The current (confirmed) nonce of `account` — used to tell a FRONT-OF-LINE
    /// unminable tx (its turn has come; it permanently fails) from one merely
    /// blocked behind it (a nonce gap), so only the former is evicted.
    pub fn account_nonce(&self, account: &AccountId) -> u64 {
        self.chain.ledger().account(account).nonce
    }

    /// Commit a freshly-sealed block: import it through the same validated path as
    /// any peer block, then drop now-included and stale transactions from the
    /// mempool. If a peer block advanced the head during the grind, import's
    /// heaviest-work fork choice files this block on a side branch instead —
    /// exactly how a mining race between two nodes resolves in Bitcoin.
    pub fn commit_mined(&mut self, block: Block) -> Result<Produced, NodeError> {
        // `import_block_tracked` is the same import as `import_block` (which is a
        // thin wrapper over it); taking the tracked form here changes no mempool
        // behavior — the orphaned set is consumed ONLY to keep the node-local
        // timing index honest across a reorg.
        let imported = self
            .chain
            .import_block_tracked(block.clone())
            .map_err(NodeError::Chain)?;
        let receipts = imported.receipts;
        // Timing FIRST: the mempool still holds this block's transactions, so
        // their admission stamps are still readable. See `record_block_timing`.
        self.repair_timing_after_reorg(&imported.reverted_txs);
        self.record_block_timing(&block);
        for stx in &block.transactions {
            self.mempool.remove(&stx.id());
        }
        {
            let ledger = self.chain.ledger();
            self.mempool
                .prune(|a| ledger.account(a).nonce, |a| ledger.account(a).balance);
            // Drain any tx stranded behind a nonce hole (a reorg can leave one when a
            // reverted low-nonce tx fails re-admission while higher nonces stay pooled),
            // so `next_nonce` and mining recover instead of the account wedging.
            self.mempool
                .evict_stranded(|a| ledger.account(a).nonce, sov_mempool::STRANDED_TTL_MS);
        }
        self.refresh_mempool_domain();
        Ok(Produced { block, receipts })
    }

    /// Import a block received from a peer: validate and apply it (re-executed and
    /// re-checked against a state clone, exactly like a self-produced block), then
    /// drop now-included and stale transactions from the mempool. Finality is the
    /// block's confirmation depth as the chain grows past it.
    pub fn import_block(&mut self, block: Block) -> Result<Vec<Receipt>, NodeError> {
        // Node-acceptance rule: reject a block dated too far in the future
        // (Bitcoin's 2-hour rule). This pairs with the in-consensus
        // median-time-past lower bound to box a block's timestamp into a sane
        // window. It uses the wall clock, so it lives HERE, outside the
        // deterministic chain state transition — replay (which re-imports via the
        // chain directly) is unaffected and stays bit-for-bit reproducible.
        const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        if block.header.timestamp_ms > now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(NodeError::TimestampTooFarInFuture {
                got: block.header.timestamp_ms,
                now: now_ms,
            });
        }

        let imported = self
            .chain
            .import_block_tracked(block.clone())
            .map_err(NodeError::Chain)?;
        // Timing FIRST, before any pool mutation: the mempool still holds this
        // block's transactions, so their admission stamps are still readable.
        // See `record_block_timing`.
        self.repair_timing_after_reorg(&imported.reverted_txs);
        self.record_block_timing(&block);
        // Tip advanced — refresh the pool's signing domain before re-admitting any
        // reverted transactions, so admission checks them under the new tip's rules.
        self.refresh_mempool_domain();
        // Drop transactions this block committed.
        for stx in &block.transactions {
            self.mempool.remove(&stx.id());
        }
        // If this import caused a reorg, return the orphaned blocks' transactions
        // to the mempool so they are re-mined rather than silently dropped
        // (Bitcoin's behavior). `insert` re-validates each: any that the new
        // active chain already applied are rejected as stale, and the rest become
        // pending again. The reorg's new ledger is already in place.
        for stx in imported.reverted_txs {
            let acct = self.chain.ledger().account(&stx.transaction.signer);
            let (nonce, balance) = (acct.nonce, acct.balance);
            let _ = self.mempool.insert(stx, nonce, balance);
        }
        let ledger = self.chain.ledger();
        self.mempool
            .prune(|a| ledger.account(a).nonce, |a| ledger.account(a).balance);
        // Reorg is the ONLY path that can strand a tx behind a nonce hole, and this
        // import tick is the only mempool-maintenance a NON-mining node ever runs
        // (relay seeds and connect-only Stations never call commit_mined), so the
        // stranded-entry backstop must live here too, not only on the produce path.
        self.mempool
            .evict_stranded(|a| ledger.account(a).nonce, sov_mempool::STRANDED_TTL_MS);
        Ok(imported.receipts)
    }
}

/// Errors from node operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// A transaction was rejected by the mempool.
    #[error("mempool rejected transaction: {0}")]
    Mempool(MempoolError),
    /// Block production or import failed.
    #[error("chain error: {0}")]
    Chain(ChainError),
    /// The transaction's key does not control the account it names as signer.
    #[error("unauthorized: {account} cannot be acted on by this key")]
    Unauthorized {
        /// The named signer account.
        account: String,
    },
    /// A received block's timestamp is too far ahead of the node's clock.
    #[error("block timestamp {got} is too far in the future (node clock {now})")]
    TimestampTooFarInFuture {
        /// The block's timestamp (Unix ms).
        got: u64,
        /// The node's wall-clock time (Unix ms) at acceptance.
        now: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_chain::{GenesisAccount, GenesisConfig};
    use sov_crypto::Keypair;
    use sov_primitives::Balance;
    use sov_types::{Action, Transaction};

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn devnet_node() -> Node {
        let config = GenesisConfig {
            chain_id: "sov-devnet".into(),
            timestamp_ms: 0,
            accounts: vec![
                GenesisAccount {
                    account: id("val01.node.sov"),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::ZERO,
                },
                GenesisAccount {
                    account: id("usa.reserve.sov"),
                    key: Keypair::from_seed([2; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
            ],
            mining: sov_mining::MiningPolicy::test(),
            vesting: vec![],
        };
        let chain = Blockchain::new(&config).unwrap();
        let mut node = Node::new(chain, 1024, 256);
        node.set_coinbase(id("val01.node.sov"));
        node
    }

    fn usa_transfer(to: &str, sov: u128, nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed([2; 32]);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: id(to),
                amount: Balance::from_sov(sov).unwrap(),
            },
        };
        SignedTransaction::sign(tx, &kp).unwrap()
    }

    #[test]
    fn next_nonce_composes_on_chain_and_pending_end_to_end() {
        // End-to-end for sov_getNextNonce: the value a wallet must sign with is the
        // committed on-chain nonce PLUS what the account has pending here. Queuing a
        // second send at that nonce is admitted (not NonceTaken); once mined, the
        // value tracks the advanced on-chain nonce.
        let mut node = devnet_node();
        let usa = id("usa.reserve.sov");
        assert_eq!(node.next_nonce(&usa), 0, "empty: on-chain nonce");

        node.submit(usa_transfer("ecb.reserve.sov", 1, 0)).unwrap();
        assert_eq!(node.next_nonce(&usa), 1, "one pending → queue at N+1");

        // The queued send at the advised nonce is accepted (would collide at 0).
        node.submit(usa_transfer("ecb.reserve.sov", 1, 1)).unwrap();
        assert_eq!(node.next_nonce(&usa), 2);

        // Mine them; the on-chain nonce advances and next_nonce follows it.
        node.produce(1_000).unwrap();
        assert_eq!(node.chain().ledger().account(&usa).nonce, 2);
        assert_eq!(
            node.next_nonce(&usa),
            2,
            "pool drained → pure on-chain nonce"
        );
    }

    #[test]
    fn future_nonce_queues_never_mines_early_and_promotes_end_to_end() {
        // Bitcoin-like waiting at the node level: a future-nonce submission is
        // accepted (Queued), a produced block NEVER includes it while its gap is
        // open, and once the gap-filler arrives the whole run mines in order.
        let mut node = devnet_node();
        let usa = id("usa.reserve.sov");

        // Nonce 1 first (nonce 0 still missing) → parked, not mineable.
        assert!(matches!(
            node.submit(usa_transfer("ecb.reserve.sov", 5, 1)),
            Ok(Admitted::Queued)
        ));
        assert_eq!(node.mempool_len(), 0);
        assert_eq!(node.mempool_queued_len(), 1);

        // A block produced NOW is empty — the queued tx is never proposed.
        let empty = node.produce(1_000).unwrap();
        assert!(empty.block.transactions.is_empty());
        assert_eq!(node.mempool_queued_len(), 1, "still parked after the block");

        // The gap-filler lands → both become ready and mine in nonce order.
        assert!(matches!(
            node.submit(usa_transfer("ecb.reserve.sov", 5, 0)),
            Ok(Admitted::Ready)
        ));
        assert_eq!(node.mempool_len(), 2);
        assert_eq!(node.mempool_queued_len(), 0);
        let produced = node.produce(2_000).unwrap();
        assert_eq!(produced.block.transactions.len(), 2);
        assert_eq!(produced.block.transactions[0].transaction.nonce, 0);
        assert_eq!(produced.block.transactions[1].transaction.nonce, 1);
        assert_eq!(node.chain().ledger().account(&usa).nonce, 2);
        assert_eq!(node.mempool_len(), 0);
    }

    #[test]
    fn next_block_floor_is_zero_with_room_and_marginal_when_full() {
        // With max_block_txs = 2 and tips 7/4/2 pooled from three senders, the
        // forming template holds {7, 4} → the floor is the marginal tip 4; with
        // fewer ready txs than capacity the floor is 0 (free room).
        let config = GenesisConfig {
            chain_id: "sov-devnet".into(),
            timestamp_ms: 0,
            accounts: vec![
                GenesisAccount {
                    account: id("val01.node.sov"),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::ZERO,
                },
                GenesisAccount {
                    account: id("usa.reserve.sov"),
                    key: Keypair::from_seed([2; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
                GenesisAccount {
                    account: id("ecb.reserve.sov"),
                    key: Keypair::from_seed([3; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
                GenesisAccount {
                    account: id("boj.reserve.sov"),
                    key: Keypair::from_seed([4; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
            ],
            mining: sov_mining::MiningPolicy::test(),
            vesting: vec![],
        };
        let mut node = Node::new(Blockchain::new(&config).unwrap(), 1024, 2);
        node.set_coinbase(id("val01.node.sov"));
        let tip_tx = |seed: [u8; 32], from: &str, tip: u128| {
            let kp = Keypair::from_seed(seed);
            let t = sov_types::Transaction {
                signer: id(from),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Tipped {
                    tip: Balance::from_grains(tip),
                    inner: Box::new(Action::Transfer {
                        to: id("val01.node.sov"),
                        amount: Balance::from_sov(1).unwrap(),
                    }),
                },
            };
            SignedTransaction::sign(t, &kp).unwrap()
        };
        assert_eq!(node.next_block_floor_grains(), 0, "empty pool → no floor");
        node.submit(tip_tx([2; 32], "usa.reserve.sov", 7)).unwrap();
        assert_eq!(node.next_block_floor_grains(), 0, "free room → no floor");
        node.submit(tip_tx([3; 32], "ecb.reserve.sov", 4)).unwrap();
        assert_eq!(
            node.next_block_floor_grains(),
            4,
            "template full: marginal tip"
        );
        node.submit(tip_tx([4; 32], "boj.reserve.sov", 2)).unwrap();
        assert_eq!(node.next_block_floor_grains(), 4, "2 waits below the floor");
    }

    #[test]
    fn rejects_unauthorized_tx_at_submit_and_keeps_producing() {
        let mut node = devnet_node();
        // An attacker signs a tx that names usa.reserve.sov as signer but commits
        // the attacker's own key, at usa's current nonce: a valid signature, wrong
        // key. It must be rejected at submit, not admitted and then stall production.
        let attacker = Keypair::from_seed([9; 32]);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: attacker.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &attacker).unwrap();
        assert!(matches!(
            node.submit(stx),
            Err(NodeError::Unauthorized { .. })
        ));
        assert_eq!(
            node.mempool_len(),
            0,
            "unauthorized tx never entered the pool"
        );

        // A legitimate transfer still flows and a block is produced — no stall.
        node.submit(usa_transfer("ecb.reserve.sov", 100, 0))
            .unwrap();
        let produced = node.produce(1_000).unwrap();
        assert_eq!(produced.block.header.height.get(), 1);
        assert_eq!(node.chain().height(), 1);
    }

    #[test]
    fn keyless_implicit_account_is_admitted_at_submit_without_activation() {
        // A funded, KEYLESS implicit account (e.g. a freshly-mined coinbase id)
        // must be able to submit a normal action directly — the submit pre-check
        // self-certifies it by the key whose hash IS the id (no RotateKey first),
        // mirroring the runtime. Regression for "my key can't shield its funds".
        let mut node = devnet_node();
        let owner = Keypair::from_seed([55; 32]);
        let implicit = owner.public_key().implicit_account_id();
        // Fund the implicit account by paying it (as a coinbase/transfer would) —
        // it is now funded but KEYLESS on-chain.
        node.submit(usa_transfer(implicit.as_str(), 5, 0)).unwrap();
        node.produce(1_000).unwrap();
        assert!(
            node.chain().ledger().account(&implicit).key.is_none(),
            "implicit account is funded but keyless"
        );
        // The owner submits a plain transfer FROM its keyless implicit account.
        let tx = Transaction {
            signer: implicit.clone(),
            public_key: owner.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &owner).unwrap();
        node.submit(stx)
            .expect("keyless implicit self-certifies at submit");
        assert_eq!(node.mempool_len(), 1);

        // A stranger's key for the same implicit id is still rejected.
        let thief = Keypair::from_seed([66; 32]);
        let bad = Transaction {
            signer: implicit,
            public_key: thief.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let bad = SignedTransaction::sign(bad, &thief).unwrap();
        assert!(matches!(
            node.submit(bad),
            Err(NodeError::Unauthorized { .. })
        ));
    }

    #[test]
    fn build_candidate_reports_a_tx_that_cannot_afford_the_fee_so_it_can_be_evicted() {
        // The real "tx stuck while blocks are empty" case: with fees ON, a sender whose
        // balance is below the intrinsic FEE produces a tx that is authorized (so it is
        // admitted) but can never execute — `CannotAffordFee`. It must be kept OUT of the
        // block AND reported with a reason, so the producer evicts it instead of silently
        // re-trying it every block. (An *insufficient-balance* transfer, by contrast, is
        // included as a failed receipt — fee + nonce consumed — so it does NOT clog.)
        let poor_kp = Keypair::from_seed([7; 32]);
        let mut mining = sov_mining::MiningPolicy::test();
        mining.gas_price = Balance::from_grains(1); // fees ON ⇒ a transfer costs ~21,000 grains
        let config = GenesisConfig {
            chain_id: "sov-devnet".into(),
            timestamp_ms: 0,
            accounts: vec![
                GenesisAccount {
                    account: id("val01.node.sov"),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::ZERO,
                },
                GenesisAccount {
                    account: id("poor.sov"),
                    key: poor_kp.public_key(),
                    balance: Balance::from_grains(100), // far below the fee
                },
            ],
            mining,
            vesting: vec![],
        };
        let chain = Blockchain::new(&config).unwrap();
        let mut node = Node::new(chain, 1024, 256);
        node.set_coinbase(id("val01.node.sov"));

        let tx = SignedTransaction::sign(
            Transaction {
                signer: id("poor.sov"),
                public_key: poor_kp.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: id("val01.node.sov"),
                    amount: Balance::from_grains(1),
                },
            },
            &poor_kp,
        )
        .unwrap();
        let tx_id = tx.id();
        node.submit(tx)
            .expect("admitted: authorized + correct nonce");
        assert_eq!(node.mempool_len(), 1);

        let (candidate, excluded) = node.build_candidate(1).expect("build candidate");
        assert!(
            candidate.block().transactions.is_empty(),
            "the unminable tx is kept out of the block"
        );
        assert_eq!(excluded.len(), 1, "it is reported as excluded");
        assert_eq!(excluded[0].0.id(), tx_id);
        assert!(!excluded[0].1.is_empty(), "with a non-empty reason");

        // FRONT-OF-LINE (its nonce is the account's current nonce) ⇒ the producer evicts
        // it; a tx merely blocked behind a gap would not be.
        assert_eq!(node.account_nonce(&id("poor.sov")), 0);
        node.drop_tx(&tx_id);
        assert_eq!(
            node.mempool_len(),
            0,
            "evicted → no longer clogs the mempool"
        );
    }

    #[test]
    fn produces_and_commits_block_with_txs() {
        let mut node = devnet_node();
        node.submit(usa_transfer("ecb.reserve.sov", 100, 0))
            .unwrap();
        assert_eq!(node.mempool_len(), 1);

        let produced = node.produce(1_000).unwrap();
        assert_eq!(produced.block.header.height.get(), 1);
        assert_eq!(produced.receipts.len(), 1);
        assert!(produced.receipts[0].succeeded());
        assert_eq!(node.mempool_len(), 0); // included tx removed
        assert_eq!(
            node.chain()
                .ledger()
                .account(&id("ecb.reserve.sov"))
                .balance,
            Balance::from_sov(100).unwrap()
        );
    }

    #[test]
    fn multiple_blocks_advance_state_and_height() {
        let mut node = devnet_node();
        for nonce in 0..3u64 {
            node.submit(usa_transfer("ecb.reserve.sov", 10, nonce))
                .unwrap();
            let produced = node.produce(1_000 + nonce * 1_000).unwrap();
            assert_eq!(produced.block.header.height.get(), nonce + 1);
        }
        assert_eq!(node.chain().height(), 3);
        assert_eq!(
            node.chain()
                .ledger()
                .account(&id("usa.reserve.sov"))
                .balance,
            Balance::from_sov(970).unwrap()
        );
        assert_eq!(
            node.chain()
                .ledger()
                .account(&id("ecb.reserve.sov"))
                .balance,
            Balance::from_sov(30).unwrap()
        );
    }

    #[test]
    fn empty_blocks_still_produce_and_commit() {
        let mut node = devnet_node();
        let produced = node.produce(1_000).unwrap();
        assert!(produced.block.transactions.is_empty());
        assert_eq!(node.chain().height(), 1);
    }

    #[test]
    fn finality_is_confirmation_depth() {
        // Nakamoto finality at the node level: a mined block becomes final only
        // once FINALITY_DEPTH blocks of work are piled on top of it.
        let mut node = devnet_node();
        let first = node.produce(1_000).unwrap().block.hash();
        assert_eq!(node.chain().confirmations(&first), Some(1));
        assert!(!node.chain().is_final(&first));

        for i in 1..sov_chain::FINALITY_DEPTH {
            node.produce(1_000 + i * 1_000).unwrap();
        }
        assert_eq!(
            node.chain().confirmations(&first),
            Some(sov_chain::FINALITY_DEPTH)
        );
        assert!(node.chain().is_final(&first));
    }

    #[test]
    fn stale_transaction_is_rejected_on_submit() {
        let mut node = devnet_node();
        node.submit(usa_transfer("ecb.reserve.sov", 10, 0)).unwrap();
        node.produce(1_000).unwrap(); // usa nonce now 1
                                      // Re-submitting the nonce-0 transfer is stale.
        let err = node
            .submit(usa_transfer("ecb.reserve.sov", 10, 0))
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::Mempool(MempoolError::Stale { current: 1, got: 0 })
        ));
    }

    #[test]
    fn timing_pairs_a_real_admission_with_a_real_inclusion() {
        // The core pairing: a transaction admitted at a known time and height,
        // mined into a later block at a known time and height, must report the
        // exact difference in BOTH units — and nothing else may be inferred.
        let mut node = devnet_node();
        let stx = usa_transfer("ecb.reserve.sov", 10, 0);
        let tx_id = stx.id();

        // Advance the chain so admission does not happen at height 0 — a
        // `waited_blocks` that is right only because both heights are zero
        // proves nothing.
        node.produce(1_000).unwrap();
        node.produce(2_000).unwrap();
        assert_eq!(node.chain().height(), 2, "admitted against height 2");

        node.submit(stx).unwrap();
        let seen = node
            .mempool
            .first_seen(&tx_id)
            .expect("the pool holds an admission observation for it");
        assert_eq!(seen.at_height, 2, "stamped with the height it was seen at");

        // Mine it at a block timestamp we control.
        let included_ms = seen.at_ms + 90_000;
        let produced = node.produce(included_ms).unwrap();
        assert_eq!(produced.block.header.height.get(), 3);
        assert!(produced.block.transactions.iter().any(|t| t.id() == tx_id));

        let timing = node.tx_timing(&tx_id).expect("row recorded at inclusion");
        assert!(timing.is_observed());
        assert_eq!(timing.first_seen_ms, Some(seen.at_ms));
        assert_eq!(timing.first_seen_height, Some(2));
        assert_eq!(timing.included_height, 3);
        assert_eq!(timing.included_timestamp_ms, included_ms);
        assert_eq!(timing.waited_ms(), Some(90_000), "the exact ms difference");
        assert_eq!(timing.waited_blocks(), Some(1), "height 3 minus height 2");
    }

    #[test]
    fn timing_counts_every_block_a_tx_waited_through_not_just_the_last_one() {
        // A wait of more than one block: with room for a single transaction per
        // block, the loser of the first round waits through it and is mined in
        // the next — `waited_blocks` must count BOTH blocks, measured from the
        // height it was admitted at, not from the block before inclusion.
        let config = GenesisConfig {
            chain_id: "sov-devnet".into(),
            timestamp_ms: 0,
            accounts: vec![
                GenesisAccount {
                    account: id("val01.node.sov"),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::ZERO,
                },
                GenesisAccount {
                    account: id("usa.reserve.sov"),
                    key: Keypair::from_seed([2; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
                GenesisAccount {
                    account: id("ecb.reserve.sov"),
                    key: Keypair::from_seed([3; 32]).public_key(),
                    balance: Balance::from_sov(1_000).unwrap(),
                },
            ],
            mining: sov_mining::MiningPolicy::test(),
            vesting: vec![],
        };
        let mut node = Node::new(Blockchain::new(&config).unwrap(), 1024, 1);
        node.set_coinbase(id("val01.node.sov"));

        let from_ecb = {
            let kp = Keypair::from_seed([3; 32]);
            let tx = Transaction {
                signer: id("ecb.reserve.sov"),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: id("val01.node.sov"),
                    amount: Balance::from_sov(1).unwrap(),
                },
            };
            SignedTransaction::sign(tx, &kp).unwrap()
        };
        // Both admitted at height 0, one block apart in inclusion.
        node.submit(usa_transfer("val01.node.sov", 1, 0)).unwrap();
        node.submit(from_ecb).unwrap();

        let first = node.produce(1_000).unwrap().block;
        assert_eq!(first.transactions.len(), 1, "one slot per block");
        let second = node.produce(2_000).unwrap().block;
        assert_eq!(second.transactions.len(), 1);

        let early = node.tx_timing(&first.transactions[0].id()).unwrap();
        let late = node.tx_timing(&second.transactions[0].id()).unwrap();
        assert_eq!(early.first_seen_height, Some(0));
        assert_eq!(late.first_seen_height, Some(0));
        assert_eq!(early.waited_blocks(), Some(1), "mined in the next block");
        assert_eq!(late.waited_blocks(), Some(2), "waited one block out");
        // The block timestamps here are synthetic (1_000/2_000 ms) and precede
        // the real admission clock, so both ms-waits saturate to zero — the
        // clamp working as designed rather than wrapping to ~2^64. The ms
        // pairing itself is pinned by
        // `timing_pairs_a_real_admission_with_a_real_inclusion`.
        assert_eq!(early.included_timestamp_ms, 1_000);
        assert_eq!(late.included_timestamp_ms, 2_000);
        assert_eq!(early.waited_ms(), Some(0));
        assert_eq!(late.waited_ms(), Some(0));
    }

    #[test]
    fn a_tx_this_node_never_pooled_reports_an_unknown_wait_not_a_fabricated_one() {
        // THE HONESTY RULE. A block synced from a peer carries transactions this
        // node never saw waiting. It must record the inclusion facts and refuse
        // to invent an arrival — no block time, no zero, no estimate.
        let mut producer = devnet_node();
        producer
            .submit(usa_transfer("ecb.reserve.sov", 10, 0))
            .unwrap();
        let block = producer.produce(1_000).unwrap().block;
        let tx_id = block.transactions[0].id();

        // A second node that never held the transaction imports the block.
        let mut observer = devnet_node();
        assert!(
            observer.mempool.first_seen(&tx_id).is_none(),
            "precondition: this node never saw it"
        );
        observer.import_block(block.clone()).unwrap();

        let timing = observer
            .tx_timing(&tx_id)
            .expect("inclusion is still recorded");
        assert!(!timing.is_observed(), "observed is false, not 'instant'");
        assert_eq!(timing.first_seen_ms, None);
        assert_eq!(timing.first_seen_height, None);
        assert_eq!(timing.waited_ms(), None);
        assert_eq!(timing.waited_blocks(), None);
        // The inclusion half is fact, and is kept.
        assert_eq!(timing.included_height, 1);
        assert_eq!(timing.included_timestamp_ms, block.header.timestamp_ms);

        // And the node that DID see it wait reports a real number for the same
        // transaction — two honest nodes, legitimately different answers.
        let mine = producer
            .tx_timing(&tx_id)
            .expect("the producer observed it");
        assert!(mine.is_observed());
        assert!(mine.waited_ms().is_some());
    }

    #[test]
    fn a_reorg_withdraws_timing_rows_instead_of_leaving_a_stale_height_claim() {
        // Build a chain, then feed a heavier competing branch. The transaction
        // mined on the branch that loses must NOT keep claiming it sits in a
        // block that is no longer on the active chain.
        let mut node = devnet_node();
        node.submit(usa_transfer("ecb.reserve.sov", 10, 0)).unwrap();
        let orphaned = node.produce(1_000).unwrap().block;
        let orphan_tx = orphaned.transactions[0].id();
        assert_eq!(
            node.tx_timing(&orphan_tx).map(|t| t.included_height),
            Some(1),
            "recorded on the branch that is active right now"
        );

        // A competing, HEAVIER branch built independently from genesis.
        let mut rival = devnet_node();
        let b1 = rival.produce(1_100).unwrap().block;
        let b2 = rival.produce(1_200).unwrap().block;
        assert_ne!(b1.hash(), orphaned.hash(), "a genuinely different branch");

        node.import_block(b1).unwrap();
        node.import_block(b2).unwrap();
        assert_eq!(node.chain().height(), 2, "the heavier branch was adopted");

        // The row is WITHDRAWN. Reporting nothing is honest; reporting
        // "included at height 1" would be a claim about a block the node is no
        // longer building on.
        match node.tx_timing(&orphan_tx) {
            None => {}
            Some(t) => {
                let still_there = node
                    .chain()
                    .block_by_height(t.included_height)
                    .map(|b| b.transactions.iter().any(|s| s.id() == orphan_tx))
                    .unwrap_or(false);
                assert!(
                    still_there,
                    "a surviving row must point at a block that really contains the tx"
                );
            }
        }
    }

    #[test]
    fn a_block_that_loses_the_race_records_no_timing() {
        // A self-mined block that lands on a LIGHTER side branch is not on the
        // active chain, so there is no honest `included_height` for it and
        // nothing may be recorded.
        let mut node = devnet_node();
        // Give the node a heavier chain first, so the stale block below is
        // filed on a side branch rather than extending the head.
        let mut rival = devnet_node();
        rival
            .submit(usa_transfer("ecb.reserve.sov", 10, 0))
            .unwrap();
        let side = rival.produce(1_000).unwrap().block;
        let side_tx = side.transactions[0].id();

        node.produce(1_100).unwrap();
        node.produce(1_200).unwrap();
        // The rival's height-1 block is now on a lighter branch.
        node.import_block(side).unwrap();
        assert!(
            node.tx_timing(&side_tx).is_none(),
            "a side-branch block commits nothing, so it times nothing"
        );
    }

    #[test]
    fn the_timing_index_stays_bounded_as_blocks_accumulate() {
        // Retention is a hard property, not a hope: with a 2-block window the
        // index can never hold rows from more than the last two heights, no
        // matter how many blocks are mined.
        let mut node = devnet_node();
        node.set_tx_timing_limits(2, 1_000);
        let mut ids = Vec::new();
        for nonce in 0..6u64 {
            let stx = usa_transfer("ecb.reserve.sov", 1, nonce);
            ids.push(stx.id());
            node.submit(stx).unwrap();
            node.produce(1_000 + nonce * 1_000).unwrap();
        }
        let (rows, retention, max) = node.tx_timing_stats();
        assert_eq!((retention, max), (2, 1_000));
        assert!(rows <= 2, "bounded to the window, got {rows}");
        assert!(
            node.tx_timing(&ids[0]).is_none(),
            "the oldest row aged out first"
        );
        assert!(
            node.tx_timing(&ids[5]).is_some(),
            "the newest row is retained"
        );
    }

    #[test]
    fn the_admission_clock_has_exactly_one_source() {
        // REGRESSION GUARD. The timing feature must read the pool's EXISTING
        // admission clock, never a second one kept alongside it. If a parallel
        // clock were ever introduced, the value the timing index pairs with an
        // inclusion would drift away from the value `sov_getMempoolTxs` and
        // `sov_getMempoolInfo` report for the same transaction. Here we pin all
        // three to the same underlying stamp.
        let mut node = devnet_node();
        let stx = usa_transfer("ecb.reserve.sov", 10, 0);
        let tx_id = stx.id();
        node.submit(stx).unwrap();

        let seen = node.mempool.first_seen(&tx_id).unwrap();
        let entry = node
            .mempool_entries(16)
            .into_iter()
            .find(|e| e.id == tx_id)
            .expect("the entry is in the paged view");
        assert_eq!(
            entry.first_seen_ms, seen.at_ms,
            "`entries` and `first_seen` read the same stamp"
        );
        // ...and the aggregate `oldest_pending_age_ms` is derived from that same
        // stamp too, so no view can report an age the others disagree with.
        let (oldest, _) = node.mempool_oldest_ages_ms();
        let oldest = oldest.expect("one ready entry");
        assert!(
            oldest >= entry.age_ms && oldest - entry.age_ms <= 50,
            "aggregate age {oldest} tracks the per-entry age {}",
            entry.age_ms
        );

        // Mine it: the row the index stores is that SAME stamp, unmodified.
        let block = node.produce(seen.at_ms + 5_000).unwrap().block;
        assert!(block.transactions.iter().any(|t| t.id() == tx_id));
        assert_eq!(
            node.tx_timing(&tx_id).unwrap().first_seen_ms,
            Some(seen.at_ms),
            "the index pairs the pool's own stamp, not a re-read of any clock"
        );
    }

    #[test]
    fn rejects_a_block_dated_too_far_in_the_future() {
        // Produce a valid block, then re-date it past the 2-hour acceptance
        // window; a peer node must reject it at the acceptance layer.
        let mut producer = devnet_node();
        let mut block = producer.produce(1_000).unwrap().block;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        block.header.timestamp_ms = now_ms + 3 * 60 * 60 * 1000; // 3h ahead

        let mut peer = devnet_node();
        assert!(matches!(
            peer.import_block(block),
            Err(NodeError::TimestampTooFarInFuture { .. })
        ));
    }
}
