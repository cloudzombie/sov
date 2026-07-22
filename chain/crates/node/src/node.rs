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
use sov_mempool::{Mempool, MempoolError};
use sov_primitives::{AccountId, Hash};
use sov_types::{Action, Block, Receipt, SignedTransaction};

/// A running SOV node.
pub struct Node {
    chain: Blockchain,
    mempool: Mempool,
    max_block_txs: usize,
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
        };
        node.refresh_mempool_domain();
        node
    }

    /// Refresh the mempool's signing domain to the one resolved at the next height,
    /// so admission verifies signatures exactly as block execution will. `None`
    /// while the miner-signaled `tx-domain` fork is dormant (byte-identical to
    /// pre-fork admission); `Some(domain)` once it activates, at which point a
    /// legacy or cross-network signature is refused at the door. Called after every
    /// tip change so the pool tracks activation.
    fn refresh_mempool_domain(&mut self) {
        let domain = self.chain.resolved_tx_domain(self.chain.height() + 1);
        self.mempool.set_domain(domain);
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

    /// Number of pooled transactions.
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
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
    pub fn submit(&mut self, stx: SignedTransaction) -> Result<(), NodeError> {
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
        let receipts = self
            .chain
            .import_block(block.clone())
            .map_err(NodeError::Chain)?;
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
        assert_eq!(node.next_nonce(&usa), 2, "pool drained → pure on-chain nonce");
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
