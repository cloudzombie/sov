//! The blockchain: a validated, append-only sequence of blocks over a single
//! evolving [`Ledger`].
//!
//! The design separates *producing* a block from *importing* one, and routes
//! both through the same validation in [`Blockchain::import_block`]. A node
//! validates its own proposed blocks exactly as it validates a peer's — there is
//! no trusted path. Import re-executes every transaction against a *clone* of the
//! ledger and only commits if the recomputed `state_root` and `receipts_root`
//! match the header, so a block can never install state it didn't legitimately
//! compute.
//!
//! **Finality is Nakamoto-probabilistic:** a block is final once it is buried
//! [`FINALITY_DEPTH`] confirmations deep in the heaviest-work chain — there is
//! no finality gadget, no validator votes, and no proposer schedule; proof of
//! work is the only authority.

use std::collections::HashMap;

use sov_mining::{Difficulty, MiningPolicy, Target, Work};
use sov_primitives::{AccountId, Balance, BlockHeight, Hash};
use sov_runtime::{
    apply_coinbase, apply_transaction, apply_transactions, BlockContext, BlockExecutionError,
};
use sov_state::Ledger;
use sov_types::{receipts_root, Block, Receipt, SignedTransaction};

use crate::genesis::{GenesisConfig, GenesisError};

/// An in-memory SOV blockchain.
pub struct Blockchain {
    chain_id: String,
    ledger: Ledger,
    mining: MiningPolicy,
    /// Current proof-of-work difficulty (SHA-256d), retargeted each epoch from
    /// observed block intervals toward `mining.target_block_ms`.
    sha256d_difficulty: Difficulty,
    /// The **active** (canonical) chain, indexed by height; `blocks[0]` is
    /// genesis and `blocks.last()` is the current head. This is always the
    /// heaviest-work chain known to the node (Nakamoto fork choice); a reorg
    /// rebuilds it.
    blocks: Vec<Block>,
    /// Every block this node has accepted — *including* blocks on lighter side
    /// branches that are not (yet) part of the active chain — keyed by block
    /// hash. Each entry carries the cumulative proof of work to that block, so
    /// fork choice is a constant-time work comparison and a heavier branch can be
    /// adopted by replaying it. The source of truth for parent links and work;
    /// `blocks` is the materialized active path through it.
    index: HashMap<Hash, BlockIndexEntry>,
    /// Hash of the active head (`== blocks.last().hash()`); the heaviest tip.
    head: Hash,
    /// The genesis (height-0) ledger, snapshotted at construction. A reorg
    /// replays a competing branch from here, since the ledger keeps no per-block
    /// snapshots; this is the one state a node can always return to.
    genesis_ledger: Ledger,
    genesis_hash: Hash,
    /// Trusted weak-subjectivity checkpoints: `height -> block hash`. A block at a
    /// checkpoint height must hash exactly to the pinned value, so a node can never
    /// be fooled into following a forged long-range history that diverges from a
    /// known-good point. Empty by default.
    checkpoints: HashMap<u64, Hash>,
    /// The version-bits mask this node commits in blocks it produces (its
    /// miner-signaled governance votes). `0` = signals nothing.
    signal_mask: u32,
    /// The account this node's produced blocks credit the coinbase to — this
    /// node's miner identity, set via [`set_coinbase`](Self::set_coinbase).
    /// `None` falls back to [`default_coinbase`](Self::default_coinbase).
    coinbase_account: Option<AccountId>,
    /// The fallback coinbase recipient when no miner identity is configured:
    /// the genesis coinbase account (canonical-first funded account). A
    /// deterministic default so nodes that never call `set_coinbase` (e.g. unit
    /// tests) still produce valid blocks.
    default_coinbase: AccountId,
    /// Per-height version-bits record of every committed block — the consensus
    /// signal history the BIP-9/8 state machine evaluates. Rebuilt
    /// deterministically on replay, since the bits live in the header hash.
    signals: sov_governance::SignalLog,
    /// The `pq-sunset` deployment and its enforcement parameters, if this
    /// chain schedules one (see [`sov_mining::PqSchedule`]).
    pq_deployment: Option<PqDeploymentConfig>,
    /// Transaction receipts for the **active chain**, indexed for RPC lookup.
    /// `active_receipts[h]` holds the receipts of the active block at height `h`
    /// (in transaction order); only heights with at least one transaction appear.
    /// Rebuilt on reorg, so it always reflects the committed active chain.
    ///
    /// In-memory only and derived from execution — the receipts themselves are
    /// already authenticated by the consensus `receipts_root` in each header — so
    /// this index changes no block hash, state root, or wire encoding (the genesis
    /// KAT is unaffected). It exists purely so a node can answer "what happened to
    /// this transaction?" without re-executing history.
    active_receipts: HashMap<u64, Vec<Receipt>>,
    /// Maps a transaction id to the active height whose block contains it, so a
    /// receipt can be found by transaction id in one lookup. Rebuilt on reorg.
    tx_height: HashMap<Hash, u64>,
}

/// A block known to the node, with the metadata fork choice needs: its
/// proof-of-work targets and the cumulative work to it. Stored for every
/// accepted block (active or side-branch), keyed by block hash.
struct BlockIndexEntry {
    /// The block itself (full body, so a side branch can be replayed if it later
    /// becomes the heaviest chain).
    block: Block,
    /// The SHA-256d PoW target in force for this block, derived from its parent
    /// branch (`expected_target`). This — not chain-global state — is what the
    /// block's proof of work was checked against, so each block's work is
    /// computable on any branch.
    sha_target: Target,
    /// Cumulative proof of work from genesis through this block: `parent.chain_work
    /// + work(sha_target)`. The quantity fork choice maximizes.
    chain_work: Work,
    /// The block's height (cached; equals `block.header.height`).
    height: u64,
}

/// The validated, not-yet-stored result of checking an incoming block against
/// its parent branch: the proof-of-work targets it must use, its cumulative
/// work, and its height. Produced by [`Blockchain::validate_candidate`] and
/// consumed by the fork-choice paths in [`Blockchain::import_block`].
struct Candidate {
    sha_target: Target,
    new_work: Work,
    height: u64,
}

/// The state a reorg would install, computed by replaying a competing branch
/// from genesis ([`Blockchain::rebuild_branch`]). Adopted atomically only if the
/// whole branch validated.
struct Rebuilt {
    ledger: Ledger,
    active_blocks: Vec<Block>,
    signals: sov_governance::SignalLog,
    tip_receipts: Vec<Receipt>,
    /// Per-block receipts for every non-genesis block on the rebuilt active path,
    /// as `(height, receipts)` in ascending height order — used to rebuild the
    /// receipt index after a reorg so it matches the newly adopted chain.
    branch_receipts: Vec<(u64, Vec<Receipt>)>,
}

/// The outcome of [`Blockchain::import_block_tracked`]: the imported block's
/// receipts (when it joined the active chain) plus any transactions a reorg
/// orphaned off the old active chain, which a node should return to its mempool.
pub struct Imported {
    /// Receipts of the block when it becomes part of the active chain (extend or
    /// reorg-tip); empty when the block is merely stored on a lighter side branch.
    pub receipts: Vec<Receipt>,
    /// Transactions from blocks a reorg dropped from the active chain — to be
    /// re-queued so no transaction is silently lost. Empty unless a reorg occurred.
    pub reverted_txs: Vec<SignedTransaction>,
}

impl Imported {
    /// An import that committed nothing to the active chain and orphaned nothing.
    fn empty() -> Self {
        Imported {
            receipts: Vec::new(),
            reverted_txs: Vec::new(),
        }
    }
}

/// An **unsealed** mining candidate from [`Blockchain::build_candidate`]: the
/// fully-built block plus the proof-of-work parameters needed to seal it.
///
/// The grind in [`into_sealed_block`](MiningCandidate::into_sealed_block) is the
/// only expensive step of mining and it touches **no chain state** (it hashes
/// the candidate's own header), so a node grinds it **off the chain lock** —
/// keeping its JSON-RPC responsive while it mines — then commits the sealed
/// block via the normal validated import path.
pub struct MiningCandidate {
    /// The block being built; its `nonce` is filled in by the grind.
    block: Block,
    target: sov_mining::Target,
    pow_algo: sov_mining::PowAlgo,
    pow_key: Hash,
}

impl MiningCandidate {
    /// The (still unsealed) candidate block — e.g. to read its height for logs.
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Grind the header nonce until the proof-of-work seal meets the target,
    /// returning the sealed block. Pure CPU work over the candidate's own data —
    /// **no chain lock is required**, which is the whole point: the node mines
    /// here without blocking RPC or block import. `PowNotFound` only if the
    /// (astronomically large) nonce budget is exhausted.
    pub fn into_sealed_block(mut self) -> Result<Block, ChainError> {
        for nonce in 0..MAX_MINING_ITERS {
            self.block.header.nonce = nonce;
            let seal = Hash::from_bytes(sov_pow::pow_seal(
                self.pow_algo,
                self.pow_key.as_bytes(),
                &self.block.header.pow_preimage(),
            ));
            if self.target.is_met_by(&seal) {
                return Ok(self.block);
            }
        }
        Err(ChainError::PowNotFound)
    }

    /// Grind a BOUNDED batch of `count` nonces starting at `start`, returning the sealed
    /// block if one meets the target within the batch, else `None`. This is the
    /// continuous-mining primitive (the Monero/Zcash model): a node grinds batch after
    /// batch on a template built on the CURRENT tip, and between batches it can cheaply
    /// check for a new tip (a peer's block) or shutdown and abandon a stale template —
    /// instead of committing to one expensive grind-to-completion. Block discovery is
    /// thus a memoryless lottery at the chain's live difficulty: every miner has an equal
    /// per-hash chance each instant, so many miners SHARE blocks fairly rather than the
    /// node that got ahead lapping the others (the failure of fixed-interval mining).
    pub fn try_seal_batch(&mut self, start: u64, count: u64) -> Option<Block> {
        let end = start.saturating_add(count);
        for nonce in start..end {
            self.block.header.nonce = nonce;
            let seal = Hash::from_bytes(sov_pow::pow_seal(
                self.pow_algo,
                self.pow_key.as_bytes(),
                &self.block.header.pow_preimage(),
            ));
            if self.target.is_met_by(&seal) {
                return Some(self.block.clone());
            }
        }
        None
    }
}

/// Configuration of the miner-signaled post-quantum sunset: the BIP-9/8
/// deployment that activates it, plus the enforcement parameters derived at
/// activation.
#[derive(Clone, Debug)]
pub struct PqDeploymentConfig {
    /// The signaling deployment (bit, windows, threshold, BIP-8 LOT flag).
    pub deployment: sov_governance::Deployment,
    /// Blocks between activation (rotation window opens) and the full sunset.
    pub sunset_delay_blocks: u64,
    /// Balance threshold (grains) above which legacy accounts must rotate
    /// during the window.
    pub threshold_grains: u128,
}

/// A miner's activity, derived from committed block headers: every block's
/// `proposer` is the account its coinbase paid — the miner that found its proof
/// of work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerStats {
    /// The miner's account.
    pub account: AccountId,
    /// Height of the first block it mined — i.e. when it came online.
    pub first_seen_height: u64,
    /// Wall-clock timestamp (Unix ms) of that first block.
    pub first_seen_timestamp_ms: u64,
    /// Number of blocks it has mined (coinbases earned).
    pub blocks_mined: u64,
    /// The most recent height it mined at.
    pub last_seen_height: u64,
}

/// Difficulty retarget WINDOW, in blocks: the trailing span the **per-block** retarget
/// averages over. This is the Monero/Zcash model (Monero's LWMA uses ~60, Zcash's
/// DigiShield ~17), NOT Bitcoin's 2016-block epoch. A short, per-block window lets
/// difficulty track the LIVE hashrate within a handful of blocks, so the network
/// self-regulates to `target_block_ms` for ANY number of miners joining or leaving at
/// once — the property a continuous-grind chain needs to support many miners and a fair
/// reward lottery. (Bitcoin's 2016-epoch can't follow a fast-changing miner set, which
/// is why the old "sleep then mine" daemon had to throttle by hand and could not share
/// blocks fairly between miners.) Genesis (height 0) and the first `DIFFICULTY_WINDOW`
/// blocks carry the genesis difficulty, so the frozen genesis hash is unchanged.
const DIFFICULTY_WINDOW: u64 = 17;

/// Snap a difficulty target to the value representable in Bitcoin's compact
/// "nBits" form — the canonical on-chain target. Difficulty arithmetic produces
/// a full-precision 256-bit target, but the header carries only the 3-byte
/// compact mantissa; rounding the consensus target to that grid up front means
/// the value a miner seals against, the value an importer checks, and
/// `from_compact(header.bits)` are all bit-identical. (`to_compact` never yields
/// a negative/overflowing encoding, so the decode always succeeds.)
fn canonical_target(target: Target) -> Target {
    Target::from_compact(target.to_compact())
        .expect("to_compact always yields a decodable, in-range target")
}

/// Confirmation depth at which a block is reported **final**: buried this many
/// blocks deep in the active (heaviest-work) chain. Six confirmations is
/// Bitcoin's long-standing settlement convention — deep enough that displacing
/// the block requires out-mining the honest network across six consecutive
/// blocks. Finality under Nakamoto consensus is probabilistic, never absolute;
/// this constant is where the protocol draws the operational line.
pub const FINALITY_DEPTH: u64 = 6;

/// Producer-side nonce budget for sealing one block. Generous: at any sane
/// difficulty a solution is found in a vanishing fraction of this; it exists
/// only so a misconfigured (absurdly hard) target fails loudly instead of
/// spinning forever. Consensus itself imposes no nonce bound — a real miner
/// loops indefinitely across candidate blocks.
const MAX_MINING_ITERS: u64 = 1 << 32;

impl Blockchain {
    /// Create a chain from genesis configuration.
    pub fn new(config: &GenesisConfig) -> Result<Self, ChainError> {
        let genesis = config.build()?;
        let genesis_hash = genesis.block.hash();
        let ledger = genesis.ledger;
        // The genesis state itself must satisfy every protocol invariant (supply
        // within the cap, mining budget, per-asset conservation) — a chain can never
        // start from a state whose math is already broken.
        sov_verify::check_ledger(&ledger, &config.mining)?;
        // Snapshot the height-0 ledger: a reorg replays a competing branch from
        // this state (the chain keeps no per-block snapshots).
        let genesis_ledger = ledger.clone();

        // Seed the fork-choice index with genesis. Its in-force targets are the
        // configured genesis targets, and its cumulative work is the work of one
        // block at that target — a consistent base for the running sum.
        // Canonicalize to the compact grid so the seeded target matches the
        // genesis header's `bits` (set from the same configured target).
        let sha_target = canonical_target(config.mining.sha256d_target);
        let mut index = HashMap::new();
        index.insert(
            genesis_hash,
            BlockIndexEntry {
                block: genesis.block.clone(),
                sha_target,
                chain_work: Work::zero().saturating_add(Work::of_target(&sha_target)),
                height: 0,
            },
        );

        Ok(Blockchain {
            chain_id: config.chain_id.clone(),
            ledger,
            sha256d_difficulty: Difficulty::from_target(sha_target),
            mining: config.mining.clone(),
            blocks: vec![genesis.block],
            index,
            head: genesis_hash,
            genesis_ledger,
            genesis_hash,
            checkpoints: HashMap::new(),
            signal_mask: 0,
            coinbase_account: None,
            default_coinbase: genesis.coinbase,
            signals: sov_governance::SignalLog::new(),
            pq_deployment: None,
            active_receipts: HashMap::new(),
            tx_height: HashMap::new(),
        })
    }

    /// Install trusted weak-subjectivity checkpoints (`(height, block hash)`),
    /// replacing any previously set. Blocks imported at a checkpoint height must
    /// match the pinned hash. See [`checkpoints`](Self::checkpoints).
    pub fn set_checkpoints(&mut self, checkpoints: impl IntoIterator<Item = (u64, Hash)>) {
        self.checkpoints = checkpoints.into_iter().collect();
    }

    /// The network identifier.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The current head block.
    pub fn head(&self) -> &Block {
        self.blocks.last().expect("chain always has genesis")
    }

    /// The head's height.
    pub fn height(&self) -> u64 {
        self.head().header.height.get()
    }

    /// Read-only access to the current world state.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Current SHA-256d mining difficulty (retargeted each epoch).
    pub fn sha256d_difficulty(&self) -> Difficulty {
        self.sha256d_difficulty
    }

    /// Set the version-bits mask this node commits in blocks it produces — its
    /// miner-signaled governance votes (e.g. the `pq-sunset` deployment bit).
    pub fn set_signal_mask(&mut self, mask: u32) {
        self.signal_mask = mask;
    }

    /// Name the account this node's produced blocks credit the coinbase to (the
    /// operator's miner identity). Blocks produced afterward carry it as the
    /// header `proposer` — the coinbase claim PoW authorizes. The account should
    /// hold (or later claim, via `RotateKey`) a key, or its rewards accrue
    /// unspendably.
    pub fn set_coinbase(&mut self, account: AccountId) {
        self.coinbase_account = Some(account);
    }

    /// Schedule the miner-signaled post-quantum sunset (see
    /// [`PqDeploymentConfig`]). Enforcement begins only if/when the deployment
    /// activates under the BIP-9/8 state machine over committed header bits.
    pub fn set_pq_deployment(&mut self, config: PqDeploymentConfig) {
        self.pq_deployment = Some(config);
    }

    /// The resolved post-quantum schedule in force for a block at `height`,
    /// derived deterministically from the committed signal history: the
    /// activation height is the earliest window boundary at which the
    /// deployment is `Active`; the sunset follows `sunset_delay_blocks` later.
    /// `None` until activation (or if no deployment is scheduled).
    pub fn resolved_pq(&self, height: u64) -> Option<sov_mining::PqSchedule> {
        self.resolved_pq_with(height, &self.signals)
    }

    /// As [`resolved_pq`](Self::resolved_pq), but resolved against an explicit
    /// signal history rather than the active chain's. Fork-choice replay of a
    /// competing branch evaluates the deployment over *that branch's* signals,
    /// so the post-quantum schedule a block executes under is the one its own
    /// branch voted in — not the active chain's.
    fn resolved_pq_with(
        &self,
        height: u64,
        signals: &sov_governance::SignalLog,
    ) -> Option<sov_mining::PqSchedule> {
        let cfg = self.pq_deployment.as_ref()?;
        let period = cfg.deployment.period;
        // Walk window boundaries up to (and including) the one governing
        // `height`; the first boundary whose state is Active is the activation
        // height. States change only at boundaries and Active is terminal, so
        // this is exact and monotone.
        let governing = height - (height % period);
        let mut boundary = period; // genesis window (0) is always Defined.
        while boundary <= governing {
            if sov_governance::state_at(
                &cfg.deployment,
                sov_primitives::BlockHeight::new(boundary),
                signals,
            ) == sov_governance::ThresholdState::Active
            {
                return Some(sov_mining::PqSchedule {
                    rotation_only_height: boundary,
                    sunset_height: boundary.saturating_add(cfg.sunset_delay_blocks),
                    threshold_grains: cfg.threshold_grains,
                });
            }
            boundary += period;
        }
        None
    }

    /// The mining policy a block extending `sha_target` is metered against — the
    /// chain's static policy with that branch-in-force target substituted in.
    /// Producer and importer build this identically, so the recomputed roots match.
    fn policy_with(&self, sha_target: Target) -> MiningPolicy {
        MiningPolicy {
            sha256d_target: sha_target,
            ..self.mining.clone()
        }
    }

    /// The proof-of-work target a block extending `parent` must use, derived
    /// purely from the parent's branch — so the rule holds on *any* branch, not
    /// just the active chain. Difficulty is constant within an epoch and
    /// recomputed at each [`RETARGET_INTERVAL`] boundary from that branch's
    /// actual-vs-expected timespan (Bitcoin's model). The result is canonical
    /// (snapped to the compact `nBits` grid).
    fn expected_target(&self, parent: &BlockIndexEntry) -> Target {
        let height = parent.height + 1;
        // Warmup: until a full window of history exists, carry the parent's (ultimately
        // the genesis) difficulty forward. Genesis (height 0) is therefore unaffected, so
        // the frozen genesis hash is unchanged.
        if height <= DIFFICULTY_WINDOW {
            return parent.sha_target;
        }
        // PER-BLOCK retarget (Zcash DigiShield / Monero LWMA family): set the next
        // target from the ACTUAL time the last `DIFFICULTY_WINDOW` blocks took versus the
        // time they SHOULD have taken. Faster-than-target ⇒ harder; slower ⇒ easier. The
        // trailing-window average damps single-block jitter and the retarget's 4× clamp
        // bounds any one step, so difficulty tracks the live hashrate smoothly and
        // responsively — converging to `target_block_ms` within a few blocks no matter
        // how many miners are grinding.
        let window_start = self.ancestor_at_height(parent, height - 1 - DIFFICULTY_WINDOW);
        let actual = parent
            .block
            .header
            .timestamp_ms
            .saturating_sub(window_start.block.header.timestamp_ms)
            .max(1);
        let expected = self
            .mining
            .target_block_ms
            .saturating_mul(DIFFICULTY_WINDOW)
            .max(1);
        canonical_target(
            Difficulty::from_target(parent.sha_target)
                .retarget(actual, expected)
                .to_target(),
        )
    }

    /// Walk `from`'s ancestry (via parent links in the index) down to the block at
    /// `target_height`. Used by the per-block retarget to reach the start of the
    /// difficulty window; the ancestor is always within `DIFFICULTY_WINDOW` of `from`
    /// and therefore indexed.
    fn ancestor_at_height<'a>(
        &'a self,
        from: &'a BlockIndexEntry,
        target_height: u64,
    ) -> &'a BlockIndexEntry {
        let mut entry = from;
        while entry.height > target_height {
            entry = self
                .index
                .get(&entry.block.header.prev_hash)
                .expect("ancestor within the difficulty window is always indexed");
        }
        entry
    }

    /// Recompute the active head's *next-block* difficulty and cache it in the
    /// reported [`sha256d_difficulty`](Self::sha256d_difficulty) scalar. Called
    /// after every head change (extend or reorg).
    fn sync_active_difficulty(&mut self) {
        let sha = {
            let head = self.index.get(&self.head).expect("head is always indexed");
            self.expected_target(head)
        };
        self.sha256d_difficulty = Difficulty::from_target(sha);
    }

    /// The proof-of-work **seal** of `header` under this chain's configured
    /// algorithm — the 32-byte value consensus compares against the difficulty
    /// target. SHA-256d on dev/test chains; **RandomX** on mainnet (memory-hard,
    /// ASIC-resistant), keyed by the genesis hash (a per-chain consensus
    /// constant). The same on every node, so producer and importer agree.
    fn seal(&self, header: &sov_types::BlockHeader) -> Hash {
        Hash::from_bytes(sov_pow::pow_seal(
            self.mining.pow_algo,
            self.genesis_hash.as_bytes(),
            &header.pow_preimage(),
        ))
    }

    /// The proof-of-work reward a mint would currently earn — the emission
    /// schedule evaluated at the present mined supply. A shielded miner queries
    /// this to build a coinbase bundle whose value matches exactly (the runtime
    /// rejects any other amount); `Balance::ZERO` once the mining budget is spent.
    pub fn mint_reward(&self) -> Balance {
        self.mining
            .reward_at(self.height() + 1, self.ledger.mined_emitted())
    }

    /// The consensus mining/emission policy (read-only) — emission schedule and
    /// the founder/dev tax split. Used to surface a block's coinbase (subsidy +
    /// 93/5/2 split) to explorers from the authoritative source.
    pub fn mining_policy(&self) -> &sov_mining::MiningPolicy {
        &self.mining
    }

    /// The coinbase subsidy a block at `height` mints — the real height-keyed
    /// emission (`reward_at`), pre-tax. Genesis (height 0) mints nothing.
    pub fn coinbase_reward_at(&self, height: u64) -> Balance {
        if height == 0 {
            return Balance::ZERO;
        }
        self.mining.reward_at(height, self.ledger.mined_emitted())
    }

    /// The **median-time-past** (BIP-113): the median timestamp of the most
    /// recent (up to) 11 blocks. It is far harder for a single proposer to push
    /// around than the parent's timestamp alone, so binding a new block's
    /// timestamp to exceed it neutralizes timestamp-stalling attacks on
    /// difficulty retargeting and (future) timelocks.
    pub fn median_time_past(&self) -> u64 {
        let head = self.index.get(&self.head).expect("head is always indexed");
        self.median_time_past_of(head)
    }

    /// The median-time-past of the branch ending at `tip` (the median of `tip`
    /// and up to its 10 most recent ancestors). Computed per-branch so the
    /// BIP-113 timestamp rule applies correctly to a block on any fork, not only
    /// the active chain.
    fn median_time_past_of(&self, tip: &BlockIndexEntry) -> u64 {
        const WINDOW: usize = 11;
        let mut times: Vec<u64> = Vec::with_capacity(WINDOW);
        let mut cursor = Some(tip);
        while let Some(entry) = cursor {
            times.push(entry.block.header.timestamp_ms);
            if times.len() == WINDOW || entry.height == 0 {
                break;
            }
            cursor = self.index.get(&entry.block.header.prev_hash);
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// A committed block by height.
    pub fn block_by_height(&self, height: u64) -> Option<&Block> {
        self.blocks.get(height as usize)
    }

    /// A committed block by its hash.
    pub fn block_by_hash(&self, hash: &Hash) -> Option<&Block> {
        self.blocks.iter().find(|b| &b.hash() == hash)
    }

    /// The receipt for transaction `tx_id` on the active chain, together with the
    /// height of the block that contains it; `None` if no active block does. This
    /// is how a node answers "what happened to my transaction?" — including the
    /// exact failure reason for a transaction that was included but did not apply
    /// (e.g. a de-shield that exceeded the drain limit), which is otherwise
    /// invisible from balances alone.
    pub fn receipt(&self, tx_id: &Hash) -> Option<(u64, &Receipt)> {
        let height = *self.tx_height.get(tx_id)?;
        let r = self
            .active_receipts
            .get(&height)?
            .iter()
            .find(|r| &r.tx_id == tx_id)?;
        Some((height, r))
    }

    /// All receipts of the active block at `height`, in transaction order. Returns
    /// an empty slice for a known block with no transactions, and `None` only when
    /// `height` is beyond the active chain.
    pub fn receipts_at_height(&self, height: u64) -> Option<&[Receipt]> {
        if height > self.height() {
            return None;
        }
        Some(
            self.active_receipts
                .get(&height)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        )
    }

    /// Whether this node already knows `hash`, either on the active chain or a
    /// validated side branch.
    pub fn contains_block(&self, hash: &Hash) -> bool {
        self.index.contains_key(hash)
    }

    /// Cumulative proof-of-work of the active head, the quantity Nakamoto fork
    /// choice maximizes.
    pub fn chain_work(&self) -> Work {
        self.index
            .get(&self.head)
            .expect("head is always indexed")
            .chain_work
    }

    /// Total committed blocks (including genesis).
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Always false — a chain always contains at least genesis.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Produce (mine) a candidate block extending the head with `transactions`,
    /// stamped `timestamp_ms`. The result is *not* committed; pass it to
    /// [`import_block`](Self::import_block), which validates it like any other.
    pub fn produce_block(
        &self,
        transactions: Vec<SignedTransaction>,
        timestamp_ms: u64,
    ) -> Result<Block, ChainError> {
        // Build the candidate, then grind in-process. A mining daemon should
        // instead call [`build_candidate`](Self::build_candidate) and grind
        // [`Candidate::into_sealed_block`] OFF the chain lock (see its docs) so
        // its RPC stays responsive while mining; this convenience method keeps
        // the one-shot build+grind path for tests and simple callers.
        self.build_candidate(transactions, timestamp_ms)?
            .into_sealed_block()
    }

    /// Build an **unsealed** block candidate extending the head — the coinbase
    /// plus the admissible subset of `transactions`, executed against scratch
    /// ledgers to derive the committed roots and the branch-required difficulty
    /// (`bits`) — **without** grinding the proof of work.
    ///
    /// The PoW grind is the only expensive step and it touches **no chain
    /// state**, so a node grinds the returned [`Candidate`] off the chain lock
    /// (keeping its RPC responsive while mining) and then commits the sealed
    /// block through the normal validated [`import_block`](Self::import_block)
    /// path. If a peer block advanced the head during the grind, the sealed block
    /// simply lands on a now-lighter side branch (fork choice), exactly as a
    /// race between two miners resolves in Bitcoin.
    pub fn build_candidate(
        &self,
        transactions: Vec<SignedTransaction>,
        timestamp_ms: u64,
    ) -> Result<MiningCandidate, ChainError> {
        let next_height = self.height() + 1;
        // The coinbase recipient this block credits: this node's configured
        // miner account if one is set, else the genesis default (a deterministic
        // fallback for nodes that never configure a miner identity — e.g. unit
        // tests). The header's `proposer` field IS the coinbase claim — whoever
        // does the work names who gets paid.
        let proposer = self
            .coinbase_account
            .clone()
            .unwrap_or_else(|| self.default_coinbase.clone());

        // Meter and seal against the targets in force for a block extending the
        // head — derived from the head's branch, exactly as `import_block` will
        // recompute them, so the producer and the importer agree bit-for-bit.
        let sha_target = {
            let head = self.index.get(&self.head).expect("head is always indexed");
            self.expected_target(head)
        };
        let policy = self.policy_with(sha_target);
        let prev_hash = self.head().hash();

        // Pass 1 — best-effort selection: apply against a scratch and keep only the
        // admissible transactions. A producer must not fail the whole block over one
        // bad transaction (e.g. a sender who cannot afford the fee); import
        // re-validates the result strictly. `apply_transaction` never mutates the
        // ledger on its `Err` path, so a skipped transaction leaves the scratch
        // untouched. The coinbase is applied to the probe first, mirroring final
        // execution exactly (a transaction may spend coinbase-funded balance).
        let mut probe = self.ledger.clone();
        let selection_ctx = BlockContext {
            height: next_height,
            prev_hash,
            mining: &policy,
            gas_price: policy.gas_price,
            miner: proposer.clone(),
            pq: self.resolved_pq(next_height),
        };
        apply_coinbase(&mut probe, &selection_ctx)?;
        let mut included = Vec::new();
        for stx in transactions {
            if apply_transaction(&mut probe, &stx, &selection_ctx).is_ok() {
                included.push(stx);
            }
        }

        // Pass 2 — re-execute the selected set (coinbase first, exactly as
        // import will) to derive the committed roots.
        let mut scratch = self.ledger.clone();
        let ctx = BlockContext {
            height: next_height,
            prev_hash,
            mining: &policy,
            gas_price: policy.gas_price,
            miner: proposer.clone(),
            pq: self.resolved_pq(next_height),
        };
        apply_coinbase(&mut scratch, &ctx)?;
        let receipts = apply_transactions(&mut scratch, &included, &ctx)?;

        let mut block = Block::assemble(
            BlockHeight::new(next_height),
            prev_hash,
            scratch.state_root(),
            receipts_root(&receipts),
            timestamp_ms,
            proposer,
            included,
        );
        // Commit this node's governance signals in the header (hash-bound).
        block.header.version_bits = self.signal_mask;
        // Commit the branch-required difficulty (Bitcoin's nBits). The target is
        // already canonical (`expected_target` snaps it to the compact grid), so
        // it round-trips through `bits` exactly — the importer recomputes the same
        // required value and decodes the same target.
        block.header.bits = sha_target.to_compact();

        Ok(MiningCandidate {
            block,
            target: policy.sha256d_target,
            pow_algo: self.mining.pow_algo,
            pow_key: self.genesis_hash,
        })
    }

    /// Validate `block` and fold it into the chain under **Nakamoto fork choice**:
    /// the heaviest-work chain wins. A block that extends the active head is
    /// connected directly; a block that builds a side branch heavier than the
    /// current head triggers a **reorg** (the competing branch is replayed from
    /// genesis and adopted); a valid block on a lighter branch is stored but not
    /// connected.
    ///
    /// Returns the receipts of executing `block` when it becomes part of the
    /// active chain (extend or reorg-tip), and an empty vector when the block is
    /// merely stored on a lighter side branch. Thin wrapper over
    /// [`import_block_tracked`](Self::import_block_tracked) for callers that don't
    /// need the reorg-orphaned transactions.
    pub fn import_block(&mut self, block: Block) -> Result<Vec<Receipt>, ChainError> {
        self.import_block_tracked(block).map(|i| i.receipts)
    }

    /// Like [`import_block`](Self::import_block), but also reports the
    /// transactions a **reorg orphaned** off the active chain. When a heavier
    /// branch is adopted, blocks on the old branch that are not on the new one
    /// are no longer committed; their transactions should be returned to the
    /// mempool to be re-mined (Bitcoin's behavior). `reverted_txs` is empty
    /// unless this import caused a reorg.
    pub fn import_block_tracked(&mut self, block: Block) -> Result<Imported, ChainError> {
        let block_hash = block.hash();
        if self.index.contains_key(&block_hash) {
            return Ok(Imported::empty());
        }
        // Validate the block against its *parent's* branch (height, checkpoint,
        // timestamp/BIP-113, proof of work against the branch-in-force target,
        // body consistency) and compute its cumulative work. This works for a
        // block on any branch, not just one extending the head.
        let cand = self.validate_candidate(&block)?;
        let head_work = self
            .index
            .get(&self.head)
            .expect("head is always indexed")
            .chain_work;

        if block.header.prev_hash == self.head {
            // Fast path: extends the active head. Execute against the live
            // ledger and commit. No reorg, so nothing is orphaned.
            let receipts = self.connect_to_active(&block, cand.sha_target)?;
            self.insert_entry(block, &cand);
            self.head = block_hash;
            self.sync_active_difficulty();
            self.index_block_receipts(cand.height, &receipts);
            Ok(Imported {
                receipts,
                reverted_txs: Vec::new(),
            })
        } else if cand.new_work > head_work
            || (cand.new_work == head_work && block_hash < self.head)
        {
            // Reorg: this block tips a branch at least as heavy as the active chain,
            // AND wins the deterministic tie-break. Strictly-heavier always wins;
            // at EQUAL cumulative work we adopt the branch whose tip hash is smaller.
            //
            // The tie-break is what makes two independent miners CONVERGE. Without it,
            // when both mine a competing block at the same height (equal work), each
            // node keeps its own (subjective first-seen) and they fork-war forever —
            // "the chain was lost as soon as both were mining." A smaller hash is a
            // total order EVERY node computes identically (and, since hash < target,
            // literally means more proof of work was found), so both nodes pick the
            // SAME head each round and stay on one chain. `heaviest_chain` (boot
            // reconstruction) applies the identical rule, so live and restart agree.
            // Re-validate and re-execute the whole branch from genesis; adopt it only
            // if it is valid end-to-end (so an invalid heavier branch can never
            // displace a valid lighter one).
            let rebuilt = self.rebuild_branch(&block, &cand)?;
            // Capture transactions orphaned by the reorg: those in the OLD active
            // chain whose block is not on the NEW active chain. They return to the
            // mempool so no transaction is silently dropped by a reorg.
            let new_hashes: std::collections::HashSet<Hash> =
                rebuilt.active_blocks.iter().map(|b| b.hash()).collect();
            let reverted_txs: Vec<SignedTransaction> = self
                .blocks
                .iter()
                .filter(|b| !new_hashes.contains(&b.hash()))
                .flat_map(|b| b.transactions.iter().cloned())
                .collect();
            self.insert_entry(block, &cand);
            self.ledger = rebuilt.ledger;
            self.blocks = rebuilt.active_blocks;
            self.signals = rebuilt.signals;
            self.head = block_hash;
            self.sync_active_difficulty();
            self.rebuild_receipt_index(rebuilt.branch_receipts);
            Ok(Imported {
                receipts: rebuilt.tip_receipts,
                reverted_txs,
            })
        } else {
            // A valid block on a lighter side branch: fully replay its branch and
            // check committed roots before keeping it. Proof of work alone is not
            // enough to make an invalid full block durable or gossipable.
            let _ = self.rebuild_branch(&block, &cand)?;
            self.insert_entry(block, &cand);
            Ok(Imported::empty())
        }
    }

    /// Read-only validation of an incoming block against its parent branch,
    /// returning the proof-of-work targets it must use and its cumulative work.
    /// Performs every check that does not require executing the transactions:
    /// the parent must be known, the height/link/checkpoint/timestamp rules, the
    /// BIP-113 median-time-past along the branch, the proof of work against the
    /// branch-in-force target, the transaction-root consistency, and signatures.
    fn validate_candidate(&self, block: &Block) -> Result<Candidate, ChainError> {
        // The parent must be a block we already hold (no orphan pool yet): an
        // unknown or forged parent link is rejected outright.
        let parent = self
            .index
            .get(&block.header.prev_hash)
            .ok_or(ChainError::PrevHashMismatch)?;

        let sha_target = self.expected_target(parent);
        let expected_height = parent.height + 1;
        if block.header.height.get() != expected_height {
            return Err(ChainError::HeightMismatch {
                expected: expected_height,
                got: block.header.height.get(),
            });
        }
        // Weak-subjectivity gate: a block at a pinned checkpoint height must
        // match the trusted hash exactly, so a forged long-range history is
        // rejected.
        if let Some(&expected) = self.checkpoints.get(&block.header.height.get()) {
            if block.hash() != expected {
                return Err(ChainError::CheckpointMismatch {
                    height: block.header.height.get(),
                });
            }
        }
        if block.header.timestamp_ms < parent.block.header.timestamp_ms {
            return Err(ChainError::NonMonotonicTimestamp);
        }
        // BIP-113: the timestamp must exceed the branch's median-time-past, which
        // (with the monotonic guard) stops a miner from stalling timestamps to
        // skew difficulty.
        let mtp = self.median_time_past_of(parent);
        if block.header.timestamp_ms <= mtp {
            return Err(ChainError::TimestampNotAfterMedian {
                mtp,
                got: block.header.timestamp_ms,
            });
        }
        // Difficulty commitment (Bitcoin's nBits rule): the header must declare
        // exactly the difficulty the retarget rule requires for this height. A
        // block cannot pick an easier target than its branch dictates. Because
        // `sha_target` is canonical (snapped to the compact grid), it equals
        // `from_compact(header.bits)` whenever the bits match — so the proof-of-
        // work check below is against precisely the committed, required target.
        let required_bits = sha_target.to_compact();
        if block.header.bits != required_bits {
            return Err(ChainError::BadDifficultyBits {
                expected: required_bits,
                got: block.header.bits,
            });
        }
        // Proof of work (Nakamoto consensus): the header's seal (RandomX on
        // mainnet, SHA-256d on dev) must meet the branch-in-force target. This —
        // not a validator schedule — is what authorizes a block; the `proposer`
        // field merely names the coinbase recipient. Cheap to verify, expensive
        // to produce.
        if !sha_target.is_met_by(&self.seal(&block.header)) {
            return Err(ChainError::PowInsufficient);
        }
        // Body internal consistency (independent of execution).
        if !block.tx_root_matches() {
            return Err(ChainError::TxRootMismatch);
        }
        if !block.all_signatures_valid() {
            return Err(ChainError::BadSignatures);
        }

        let new_work = parent
            .chain_work
            .saturating_add(Work::of_target(&sha_target));
        Ok(Candidate {
            sha_target,
            new_work,
            height: expected_height,
        })
    }

    /// Execute a validated block that extends the active head against the live
    /// ledger, verify its committed roots, and commit it. Returns the receipts.
    fn connect_to_active(
        &mut self,
        block: &Block,
        sha_target: Target,
    ) -> Result<Vec<Receipt>, ChainError> {
        let mut scratch = self.ledger.clone();
        let receipts = self.execute_block_on(&mut scratch, block, sha_target, &self.signals)?;
        if scratch.state_root() != block.header.state_root {
            return Err(ChainError::StateRootMismatch);
        }
        if receipts_root(&receipts) != block.header.receipts_root {
            return Err(ChainError::ReceiptsRootMismatch);
        }
        // Consensus backstop: the block must conserve value (supply only moves by
        // the coinbase counter) and leave every protocol invariant intact, or it is
        // rejected. `self.ledger` is the pre-state, `scratch` the post-state, so this
        // is free — no extra clone — and runs on every committed block, every network.
        self.verify_invariants(&self.ledger, &scratch, sha_target)?;
        self.ledger = scratch;
        self.signals
            .record(block.header.height, block.header.version_bits);
        self.blocks.push(block.clone());
        Ok(receipts)
    }

    /// **Trusted fast-replay** of a block from this node's OWN persisted, checksummed
    /// block log: append it WITHOUT re-verifying proof of work, committed roots, or
    /// invariants — all were checked when the block was first accepted, and the log is
    /// integrity-checked on read. Crucially it executes **directly on the live ledger**
    /// (no per-block clone) and skips the per-block state-root recompute/compare, so
    /// resuming a long chain takes seconds instead of minutes. Blocks must arrive in
    /// order, each extending the head (true for a sequential log). The caller verifies
    /// the final state root ONCE via [`replayed_state_matches_head`]. This is for local
    /// replay only — network blocks always go through the fully-verified `import_block`.
    pub fn extend_trusted(&mut self, block: Block) -> Result<(), ChainError> {
        if block.header.prev_hash != self.head {
            return Err(ChainError::PrevHashMismatch); // not a sequential extend
        }
        let block_hash = block.hash();
        let height = block.header.height.get();
        // Trust the committed difficulty (validated when first accepted).
        let sha_target = canonical_target(
            Target::from_compact(block.header.bits).ok_or(ChainError::BadDifficultyBits {
                expected: block.header.bits,
                got: block.header.bits,
            })?,
        );
        let parent_work = self
            .index
            .get(&self.head)
            .expect("head is always indexed")
            .chain_work;
        let new_work = parent_work.saturating_add(Work::of_target(&sha_target));

        // Execute on the live ledger with no clone: move it out, apply, move back.
        // (Borrow-safe — `self` is only read while `self.ledger` is a local.)
        let mut ledger = std::mem::take(&mut self.ledger);
        let receipts = match self.execute_block_on(&mut ledger, &block, sha_target, &self.signals) {
            Ok(r) => r,
            Err(e) => {
                self.ledger = ledger; // restore before bailing
                return Err(e);
            }
        };
        self.ledger = ledger;

        let cand = Candidate {
            sha_target,
            new_work,
            height,
        };
        self.signals
            .record(block.header.height, block.header.version_bits);
        self.blocks.push(block.clone());
        self.head = block_hash;
        self.index_block_receipts(height, &receipts);
        self.insert_entry(block, &cand);
        self.sync_active_difficulty();
        Ok(())
    }

    /// Whether a trusted fast-replay landed on the committed head state — the single
    /// integrity check that replaces the per-block root verification. If this is false
    /// the local log is inconsistent and the caller should rebuild with full
    /// verification.
    pub fn replayed_state_matches_head(&self) -> bool {
        self.ledger.state_root() == self.head().header.state_root
    }

    /// **Fast trusted replay of a persisted block log**, which may contain orphan
    /// side-branches from past reorgs (so it is NOT a single linear chain). Rather
    /// than re-running fork choice block-by-block (each reorg replays from genesis —
    /// O(reorgs × n), the source of minute-long startups), this first reconstructs
    /// the **heaviest chain** by cumulative work, then trusted-replays just that
    /// linear chain ([`extend_trusted`]). Returns `true` if the result matches the
    /// committed head state; on `false` (or `Err`) the caller rebuilds with the
    /// fully-verified path. Local log only — network blocks use `import_block`.
    pub fn replay_log_trusted(
        &mut self,
        blocks: &[Block],
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<bool, ChainError> {
        if blocks.is_empty() {
            return Ok(true);
        }
        let chain = self.heaviest_chain(blocks);
        let total = chain.len() as u64;
        progress(0, total);
        for (i, block) in chain.into_iter().enumerate() {
            self.extend_trusted(block)?;
            let done = i as u64 + 1;
            if done % 128 == 0 || done == total {
                progress(done, total);
            }
        }
        Ok(self.replayed_state_matches_head())
    }

    /// **Last-resort FULLY-VALIDATED replay** of a persisted log — used only when the
    /// trusted fast-replay's final state root does not verify. Like [`replay_log_trusted`]
    /// it first reconstructs the **heaviest chain**, then imports each block IN
    /// ACTIVE-CHAIN ORDER through the normal validated [`import_block`] path. The key
    /// point: because the blocks arrive in order, each one *fast-path extends the head*
    /// (no reorg), so this is **O(N) fully-validated** — NOT the O(reorgs × N) of
    /// importing the RAW log, where every historical fork re-triggers a from-genesis
    /// branch rebuild (the cause of a multi-minute / apparently-hung boot on a long,
    /// contested cross-machine chain). Call on a freshly constructed (genesis) chain.
    pub fn replay_log_verified(
        &mut self,
        blocks: &[Block],
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), ChainError> {
        let chain = self.heaviest_chain(blocks);
        let total = chain.len() as u64;
        progress(0, total);
        for (i, block) in chain.into_iter().enumerate() {
            self.import_block(block)?;
            let done = i as u64 + 1;
            if done % 64 == 0 || done == total {
                progress(done, total);
            }
        }
        Ok(())
    }

    /// The active-chain receipt index as a serializable list, for inclusion in a
    /// chainstate snapshot (pairs with [`resume_from_snapshot`]).
    pub fn active_receipts_snapshot(&self) -> Vec<(u64, Vec<Receipt>)> {
        self.active_receipts
            .iter()
            .map(|(h, r)| (*h, r.clone()))
            .collect()
    }

    /// **Fast-resume from a trusted local chainstate snapshot** instead of replaying
    /// every block. The snapshot is the ledger + active receipt index at some height
    /// `snapshot_height` (identified by `snapshot_head`) on the chain. This:
    ///
    /// 1. reconstructs the active chain's `blocks` / fork-choice `index` / signal
    ///    history for the snapshot-covered prefix from each block's COMMITTED bits —
    ///    NO transaction execution (the snapshot supplies that state);
    /// 2. installs the snapshot ledger + receipts and VERIFIES the loaded state root
    ///    equals the prefix tip's committed root (the backstop against a stale or
    ///    tampered snapshot);
    /// 3. trusted-replays (executing) only the blocks AFTER the snapshot up to the
    ///    heaviest tip — a bounded gap, so a snapshot that lags the tip (periodic
    ///    snapshot + unclean exit) still resumes fast instead of replaying everything.
    ///
    /// Returns `Ok(true)` on a clean, fully-verified resume; `Ok(false)` (the caller
    /// rebuilds via replay) if the snapshot is not an ancestor of the log's heaviest
    /// tip or its state root does not verify — so a stale/tampered snapshot can never
    /// boot a node onto unverified state. Startup is then bounded by state size + the
    /// post-snapshot gap, NOT by chain length — the Bitcoin/Zcash chainstate model.
    /// Call on a freshly constructed (genesis-only) chain.
    pub fn resume_from_snapshot(
        &mut self,
        ledger: Ledger,
        active_receipts: Vec<(u64, Vec<Receipt>)>,
        snapshot_head: Hash,
        snapshot_height: u64,
        log: &[Block],
    ) -> Result<bool, ChainError> {
        if self.height() != 0 {
            return Ok(false); // only meaningful as the first load on a fresh chain
        }
        let chain = self.heaviest_chain(log);
        // The snapshot must sit ON this heaviest chain. `chain` is genesis-exclusive
        // and ascending/contiguous (it is walked parent→genesis), so the block at
        // `snapshot_height` is `chain[snapshot_height - 1]`.
        if snapshot_height == 0 || snapshot_height as usize > chain.len() {
            return Ok(false);
        }
        let at = &chain[snapshot_height as usize - 1];
        if at.hash() != snapshot_head || at.header.height.get() != snapshot_height {
            return Ok(false); // snapshot is on an orphaned branch / a different chain
        }
        // Phase 1 — header-only reconstruction of the snapshot-covered prefix
        // [1..=snapshot_height]: same trust basis as `extend_trusted` (committed bits),
        // but no execution, since the snapshot already holds the resulting state.
        for block in chain.iter().take(snapshot_height as usize) {
            if block.header.prev_hash != self.head {
                return Ok(false);
            }
            let Some(target) = Target::from_compact(block.header.bits).map(canonical_target) else {
                return Ok(false);
            };
            let parent_work = self
                .index
                .get(&self.head)
                .expect("head is indexed")
                .chain_work;
            let cand = Candidate {
                sha_target: target,
                new_work: parent_work.saturating_add(Work::of_target(&target)),
                height: block.header.height.get(),
            };
            self.signals
                .record(block.header.height, block.header.version_bits);
            self.blocks.push(block.clone());
            self.head = block.hash();
            self.insert_entry(block.clone(), &cand);
        }
        // Install the snapshot state and VERIFY against the prefix tip — reject a
        // snapshot whose state root does not match before we build anything on it.
        self.ledger = ledger;
        self.rebuild_receipt_index(active_receipts);
        self.sync_active_difficulty();
        if !self.replayed_state_matches_head() {
            return Ok(false);
        }
        // Phase 2 — trusted replay (with execution) of any blocks after the snapshot
        // up to the heaviest tip. Bounded by how far the snapshot lags, not by length.
        for block in chain.into_iter().skip(snapshot_height as usize) {
            self.extend_trusted(block)?;
        }
        Ok(self.replayed_state_matches_head())
    }

    /// Reconstruct the heaviest (active) chain — genesis-exclusive, ascending height —
    /// from an unordered block set that may include orphan side-branches. Cumulative
    /// work is computed in height order (a block's parent has a lower height, so it is
    /// processed first), then we walk back from the max-work tip to genesis.
    fn heaviest_chain(&self, blocks: &[Block]) -> Vec<Block> {
        let by_hash: HashMap<Hash, &Block> = blocks.iter().map(|b| (b.hash(), b)).collect();
        let genesis_work = self
            .index
            .get(&self.genesis_hash)
            .map(|e| e.chain_work)
            .unwrap_or_else(Work::zero);
        let mut sorted: Vec<&Block> = blocks.iter().collect();
        sorted.sort_by_key(|b| b.header.height.get());
        let mut cum: HashMap<Hash, Work> = HashMap::new();
        for b in &sorted {
            let parent = b.header.prev_hash;
            let parent_work = if parent == self.genesis_hash {
                Some(genesis_work)
            } else {
                cum.get(&parent).copied()
            };
            // A block whose parent isn't genesis or a known earlier block is an
            // orphan with a missing ancestor — skip it (it cannot be the head).
            let Some(pw) = parent_work else { continue };
            let Some(target) = Target::from_compact(b.header.bits) else {
                continue;
            };
            let w = pw.saturating_add(Work::of_target(&canonical_target(target)));
            cum.insert(b.hash(), w);
        }
        // Pick the heaviest tip, breaking work ties by SMALLER TIP HASH — the exact same
        // deterministic rule live fork choice uses (`import_block_tracked`), so a node
        // reconstructs on boot the identical head it would hold live, and any two nodes
        // independently agree on the one canonical chain even when miners produced
        // equal-work competitors. (A smaller hash is a total order all nodes compute
        // identically and, since hash < target, reflects more proof of work.)
        let mut best: Option<(Hash, Work)> = None;
        for (h, w) in &cum {
            let better = match &best {
                None => true,
                Some((bh, bw)) => *w > *bw || (*w == *bw && h < bh),
            };
            if better {
                best = Some((*h, *w));
            }
        }
        let Some((tip, _)) = best else {
            return Vec::new();
        };
        // Walk back from the heaviest tip to genesis, then reverse to ascending order.
        // Hard cap the walk at the block count: an acyclic chain can visit each block at
        // most once, so exceeding that means the (corrupt) log forms a prev_hash CYCLE —
        // bail rather than loop forever (a real, valid log can't cycle, since prev_hash
        // is a cryptographic digest, but a damaged data dir must never hang a boot).
        let mut chain = Vec::new();
        let mut cur = tip;
        while cur != self.genesis_hash && chain.len() <= blocks.len() {
            let Some(b) = by_hash.get(&cur) else { break };
            chain.push((*b).clone());
            cur = b.header.prev_hash;
        }
        // A cycle (didn't terminate at genesis within the bound) yields no usable chain;
        // the caller falls back to the fully-verified import path.
        if cur != self.genesis_hash && chain.len() > blocks.len() {
            return Vec::new();
        }
        chain.reverse();
        chain
    }

    /// The consensus invariant backstop run on every committed block: value
    /// conservation across the transition (`supply_after == supply_before + Δmined`)
    /// and the per-state invariants (supply cap, mining budget, per-asset
    /// conservation). Mapped to a [`ChainError`] so a violation REJECTS the block.
    /// Defense in depth behind the state-root check: even an execution bug that
    /// produced a self-consistent-but-wrong root cannot make the math diverge,
    /// because the chain refuses to commit such a block.
    fn verify_invariants(
        &self,
        before: &Ledger,
        after: &Ledger,
        sha_target: Target,
    ) -> Result<(), ChainError> {
        sov_verify::check_transition(before, after)?;
        sov_verify::check_ledger(after, &self.policy_with(sha_target))?;
        Ok(())
    }

    /// Re-execute one block against `ledger` — the **coinbase first** (the
    /// scheduled reward mints to the header's `proposer`, the miner that found
    /// the block's proof of work), then its transactions — with the fee routing
    /// and post-quantum schedule its branch implies. Does **not** check the
    /// committed roots (callers do, against the live or replayed state).
    fn execute_block_on(
        &self,
        ledger: &mut Ledger,
        block: &Block,
        sha_target: Target,
        signals: &sov_governance::SignalLog,
    ) -> Result<Vec<Receipt>, ChainError> {
        let policy = self.policy_with(sha_target);
        let height = block.header.height.get();
        let ctx = BlockContext {
            height,
            prev_hash: block.header.prev_hash,
            mining: &policy,
            gas_price: policy.gas_price,
            miner: block.header.proposer.clone(),
            pq: self.resolved_pq_with(height, signals),
        };
        apply_coinbase(ledger, &ctx)?;
        Ok(apply_transactions(ledger, &block.transactions, &ctx)?)
    }

    /// Replay the entire branch tipped by `tip` from the genesis ledger,
    /// re-validating and re-executing every block (and checking its committed
    /// roots), to produce the would-be active state. Used on reorg: the result
    /// is adopted only if the whole branch is valid, so a heavier-but-invalid
    /// branch can never displace the current head.
    fn rebuild_branch(&self, tip: &Block, cand: &Candidate) -> Result<Rebuilt, ChainError> {
        // Collect the branch genesis..=parent(tip) by walking parent links.
        let mut ancestors: Vec<&Block> = Vec::new();
        let mut cursor = tip.header.prev_hash;
        while cursor != self.genesis_hash {
            let entry = self
                .index
                .get(&cursor)
                .ok_or(ChainError::PrevHashMismatch)?;
            ancestors.push(&entry.block);
            cursor = entry.block.header.prev_hash;
        }
        ancestors.reverse(); // now ordered height 1 .. parent(tip)

        let mut ledger = self.genesis_ledger.clone();
        let mut signals = sov_governance::SignalLog::new();
        let mut active_blocks: Vec<Block> = Vec::with_capacity(ancestors.len() + 2);
        active_blocks.push(self.blocks[0].clone()); // genesis
        let mut branch_receipts: Vec<(u64, Vec<Receipt>)> = Vec::new();

        // Replay each ancestor with the targets recorded when it was first
        // accepted (stored in its index entry), checking its committed roots AND the
        // protocol invariants (so a reorg can never adopt a branch whose math is
        // broken — the same backstop as the extend path, here per replayed block).
        for b in ancestors {
            let entry = self.index.get(&b.hash()).expect("ancestor is indexed");
            let sha_target = entry.sha_target;
            let before = ledger.clone();
            let receipts = self.execute_block_on(&mut ledger, b, sha_target, &signals)?;
            if ledger.state_root() != b.header.state_root {
                return Err(ChainError::StateRootMismatch);
            }
            if receipts_root(&receipts) != b.header.receipts_root {
                return Err(ChainError::ReceiptsRootMismatch);
            }
            self.verify_invariants(&before, &ledger, sha_target)?;
            signals.record(b.header.height, b.header.version_bits);
            branch_receipts.push((b.header.height.get(), receipts));
            active_blocks.push(b.clone());
        }

        // Finally the tip itself, with its freshly-derived target.
        let before_tip = ledger.clone();
        let tip_receipts = self.execute_block_on(&mut ledger, tip, cand.sha_target, &signals)?;
        if ledger.state_root() != tip.header.state_root {
            return Err(ChainError::StateRootMismatch);
        }
        if receipts_root(&tip_receipts) != tip.header.receipts_root {
            return Err(ChainError::ReceiptsRootMismatch);
        }
        self.verify_invariants(&before_tip, &ledger, cand.sha_target)?;
        signals.record(tip.header.height, tip.header.version_bits);
        branch_receipts.push((tip.header.height.get(), tip_receipts.clone()));
        active_blocks.push(tip.clone());

        Ok(Rebuilt {
            ledger,
            active_blocks,
            signals,
            tip_receipts,
            branch_receipts,
        })
    }

    /// Record an active block's receipts in the lookup index. Only blocks with at
    /// least one transaction are stored (a block with no transactions has no
    /// receipts to find). Called when a block extends the active head.
    fn index_block_receipts(&mut self, height: u64, receipts: &[Receipt]) {
        if receipts.is_empty() {
            return;
        }
        for r in receipts {
            self.tx_height.insert(r.tx_id, height);
        }
        self.active_receipts.insert(height, receipts.to_vec());
    }

    /// Replace the active-chain receipt index after a reorg with the receipts of
    /// the newly adopted branch, so a receipt lookup always reflects the committed
    /// active chain (a transaction orphaned by the reorg is no longer found).
    fn rebuild_receipt_index(&mut self, branch_receipts: Vec<(u64, Vec<Receipt>)>) {
        self.active_receipts.clear();
        self.tx_height.clear();
        for (height, receipts) in branch_receipts {
            self.index_block_receipts(height, &receipts);
        }
    }

    /// Record an accepted block in the fork-choice index.
    fn insert_entry(&mut self, block: Block, cand: &Candidate) {
        let hash = block.hash();
        self.index.insert(
            hash,
            BlockIndexEntry {
                block,
                sha_target: cand.sha_target,
                chain_work: cand.new_work,
                height: cand.height,
            },
        );
    }

    // --- Miner tracking ---

    /// The miner registry, derived purely from committed block headers: every
    /// account that has mined a block (each header's `proposer` is the account
    /// its coinbase paid), when it first appeared, how many blocks it has mined,
    /// and the last height it mined at. Genesis is excluded — nobody mined it.
    /// This is how the dashboard tracks miners coming online — from real chain
    /// data, nothing fabricated.
    pub fn miner_registry(&self) -> Vec<MinerStats> {
        let mut by_account: std::collections::BTreeMap<AccountId, MinerStats> =
            std::collections::BTreeMap::new();
        for block in self.blocks.iter().skip(1) {
            let height = block.header.height.get();
            let timestamp_ms = block.header.timestamp_ms;
            by_account
                .entry(block.header.proposer.clone())
                .and_modify(|s| {
                    s.blocks_mined += 1;
                    s.last_seen_height = height;
                })
                .or_insert_with(|| MinerStats {
                    account: block.header.proposer.clone(),
                    first_seen_height: height,
                    first_seen_timestamp_ms: timestamp_ms,
                    blocks_mined: 1,
                    last_seen_height: height,
                });
        }
        by_account.into_values().collect()
    }

    /// The number of **confirmations** `block_hash` has: 1 for the active head,
    /// 2 for its parent, and so on (Bitcoin's convention). `None` if the block
    /// is not on the active chain — a side-branch block has no confirmations,
    /// because the network's work is not accumulating on top of it.
    pub fn confirmations(&self, block_hash: &Hash) -> Option<u64> {
        let block = self.block_by_hash(block_hash)?;
        Some(self.height() - block.header.height.get() + 1)
    }

    /// Whether `block_hash` is **final under Nakamoto consensus**: buried at
    /// least [`FINALITY_DEPTH`] blocks deep in the active chain. Finality is
    /// probabilistic — each confirmation multiplies the work an attacker must
    /// redo to displace the block — and this depth is the long-standing
    /// Bitcoin convention for treating a payment as settled. Genesis is final
    /// by definition.
    pub fn is_final(&self, block_hash: &Hash) -> bool {
        if *block_hash == self.genesis_hash {
            return true;
        }
        self.confirmations(block_hash)
            .is_some_and(|c| c >= FINALITY_DEPTH)
    }
}

/// Errors importing a block or constructing a chain.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Genesis configuration was invalid.
    #[error("genesis error: {0}")]
    Genesis(#[from] GenesisError),
    /// The block's proof-of-work does not meet the difficulty target — it was
    /// not validly mined.
    #[error("insufficient proof of work: the header does not meet the difficulty target")]
    PowInsufficient,
    /// The header's committed difficulty (`bits`) does not equal the value the
    /// retarget rule requires for this height — a block cannot choose its own
    /// difficulty.
    #[error("difficulty bits mismatch: expected {expected:#010x}, got {got:#010x}")]
    BadDifficultyBits {
        /// The compact `bits` the retarget rule requires at this height.
        expected: u32,
        /// The compact `bits` the header actually declared.
        got: u32,
    },
    /// Mining exhausted its nonce budget without finding a solution (only
    /// reachable at a difficulty far above the configured target — a producer
    /// guard, not a consensus rule).
    #[error("no proof-of-work solution found within the nonce budget")]
    PowNotFound,
    /// The block's height did not follow the head.
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch {
        /// The height the chain expected next.
        expected: u64,
        /// The height the block carried.
        got: u64,
    },
    /// The block did not point at the current head.
    #[error("previous-hash mismatch: block does not extend the head")]
    PrevHashMismatch,
    /// The block's timestamp went backwards.
    #[error("non-monotonic timestamp")]
    NonMonotonicTimestamp,
    /// The block's timestamp did not exceed the median-time-past (BIP-113).
    #[error("timestamp {got} is not after the median-time-past {mtp}")]
    TimestampNotAfterMedian {
        /// The median of the last 11 blocks' timestamps.
        mtp: u64,
        /// The timestamp the block carried.
        got: u64,
    },
    /// The header's transaction root did not match the body.
    #[error("transaction root mismatch")]
    TxRootMismatch,
    /// A transaction signature failed to verify.
    #[error("a transaction signature is invalid")]
    BadSignatures,
    /// The recomputed state root did not match the header.
    #[error("state root mismatch")]
    StateRootMismatch,
    /// The recomputed receipts root did not match the header.
    #[error("receipts root mismatch")]
    ReceiptsRootMismatch,
    /// A transaction was rejected during execution.
    #[error("execution error: {0}")]
    Execution(#[from] BlockExecutionError),
    /// A block at a trusted weak-subjectivity checkpoint height did not match the
    /// pinned hash — a forged or divergent history.
    #[error("block at checkpoint height {height} does not match the trusted hash")]
    CheckpointMismatch {
        /// The checkpoint height that failed to match.
        height: u64,
    },
    /// A committed block would have driven the ledger into a state that violates a
    /// protocol invariant — supply conservation, the supply cap, the mining budget,
    /// or per-asset conservation. The block is REJECTED rather than committed, so
    /// the chain can never advance into a state where the math is broken. This is a
    /// consensus-level backstop, enforced on every block and every network, even if
    /// an execution bug ever produced a self-consistent-but-wrong state root.
    #[error("protocol invariant violated: {0}")]
    Invariant(#[from] sov_verify::InvariantViolation),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;
    use sov_primitives::{AccountId, Balance};
    use sov_types::{Action, Transaction};

    use crate::genesis::{GenesisAccount, VestingGrant};

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    /// A chain like [`fresh_chain`] but with vesting grants, used to exercise
    /// tokenomics end-to-end through produced blocks.
    fn chain_with_vesting(vesting: Vec<VestingGrant>) -> Blockchain {
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
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
            mining: MiningPolicy::test(),
            vesting,
        };
        Blockchain::new(&config).unwrap()
    }

    /// A signed action from usa.reserve.sov (key seed [2]).
    fn usa_action(action: Action, nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed([2; 32]);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            action,
        };
        SignedTransaction::sign(tx, &kp).unwrap()
    }

    /// A chain with one validator (key seed [1]) and a funded usa account
    /// (key seed [2], 1000 SOV).
    fn fresh_chain() -> Blockchain {
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
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
            mining: MiningPolicy::test(),
            vesting: vec![],
        };
        Blockchain::new(&config).unwrap()
    }

    // ---- Miner-signaled post-quantum sunset (the Q-day runbook) ----

    #[test]
    fn miner_signaled_pq_sunset_activates_and_enforces_end_to_end() {
        use sov_governance::{Deployment, Threshold};
        use sov_types::rotation_signing_bytes;

        // Deployment on bit 0: signaling opens at height 4, window length 4,
        // 3-of-4 threshold, generous timeout. Sunset 8 blocks after activation;
        // rotation threshold 50 SOV.
        let mut chain = fresh_chain();
        chain.set_pq_deployment(PqDeploymentConfig {
            deployment: Deployment::new(
                "pq-sunset",
                0,
                BlockHeight::new(4),
                BlockHeight::new(400),
                4,
                Threshold::new(3, 4).unwrap(),
                BlockHeight::new(0),
                true, // BIP-8 lock-in on timeout: activation is guaranteed
            )
            .unwrap(),
            sunset_delay_blocks: 8,
            threshold_grains: Balance::from_sov(50).unwrap().grains(),
        });
        // This node's blocks SIGNAL readiness (bit 0), committed in headers.
        chain.set_signal_mask(1);

        // Produce + import 11 signaling blocks. Window math (period 4):
        // [4,8) signals 4/4 -> LockedIn at boundary 8 -> Active at boundary 12.
        let mut ts = 2_000u64;
        for _ in 1..=11 {
            let block = chain.produce_block(vec![], ts).unwrap();
            assert_eq!(block.header.version_bits, 1, "blocks carry the signal");
            chain.import_block(block).unwrap();
            ts += 1_000;
        }
        // Not active through height 11...
        assert_eq!(chain.resolved_pq(11), None);
        // ...ACTIVE for the block at height 12, sunset at 20 — derived purely
        // from committed header bits, identically on every node.
        assert_eq!(
            chain.resolved_pq(12),
            Some(sov_mining::PqSchedule {
                rotation_only_height: 12,
                sunset_height: 20,
                threshold_grains: Balance::from_sov(50).unwrap().grains(),
            })
        );

        // In the window, usa (1000 SOV, legacy V1 key) cannot transfer: the
        // producer EXCLUDES the transaction...
        let blocked = usa_transfer("ecb.reserve.sov", 10, 0);
        let block = chain.produce_block(vec![blocked.clone()], ts).unwrap();
        assert!(
            block.transactions.is_empty(),
            "a producer must exclude window-blocked legacy transactions"
        );
        // ...and a block that smuggles it in is REJECTED on import (the gate
        // is consensus, not producer politeness).
        let smuggled = Block::assemble(
            block.header.height,
            block.header.prev_hash,
            block.header.state_root,
            block.header.receipts_root,
            block.header.timestamp_ms,
            block.header.proposer.clone(),
            vec![blocked],
        );
        assert!(chain.import_block(smuggled).is_err());
        chain.import_block(block).unwrap(); // the honest (empty) block lands
        ts += 1_000;

        // usa rotates to a hybrid key — the one admissible legacy action —
        // and then transacts freely inside the window.
        let hybrid = Keypair::hybrid_from_seed([60; 32]);
        let new_key = hybrid.public_key();
        let proof = hybrid.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let rotate = usa_action(Action::RotateKey { new_key, proof }, 0);
        let block = chain.produce_block(vec![rotate], ts).unwrap();
        assert_eq!(block.transactions.len(), 1, "the rotation is admitted");
        chain.import_block(block).unwrap();
        ts += 1_000;

        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: new_key,
            nonce: 1,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(10).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &hybrid).unwrap();
        let block = chain.produce_block(vec![stx], ts).unwrap();
        assert_eq!(block.transactions.len(), 1, "hybrid transactions flow");
        chain.import_block(block).unwrap();
        ts += 1_000;

        // Advance past the sunset (height 20): now EVERY legacy signature is
        // rejected — val01 (the validator, still V1-keyed) too.
        while chain.height() < 20 {
            let block = chain.produce_block(vec![], ts).unwrap();
            chain.import_block(block).unwrap();
            ts += 1_000;
        }
        let kp = Keypair::from_seed([1; 32]);
        let late = SignedTransaction::sign(
            Transaction {
                signer: id("val01.node.sov"),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::ZERO,
                },
            },
            &kp,
        )
        .unwrap();
        let block = chain.produce_block(vec![late], ts).unwrap();
        assert!(
            block.transactions.is_empty(),
            "post-sunset, legacy signatures are frozen out entirely"
        );
    }

    #[test]
    fn pq_activation_is_deterministic_and_monotone_over_all_signal_histories() {
        use sov_governance::{state_at, Deployment, SignalLog, Threshold, ThresholdState};

        // EXHAUSTIVE model check of the activation state machine: every
        // possible 8-block signal history (256 patterns) over a period-2
        // deployment with BIP-8 lock-in-on-timeout. For each history, two
        // independently-built signal logs must agree at every height
        // (determinism), the state must never regress once Active
        // (monotonicity), and with LOT=true the deployment must NEVER fail —
        // activation is guaranteed, the flag-day property the Q-day runbook
        // relies on.
        let dep = Deployment::new(
            "pq-sunset",
            0,
            BlockHeight::new(2),
            BlockHeight::new(8),
            2,
            Threshold::new(1, 2).unwrap(),
            BlockHeight::new(0),
            true,
        )
        .unwrap();

        for pattern in 0u32..256 {
            let mut a = SignalLog::new();
            let mut b = SignalLog::new();
            for h in 1u64..=8 {
                let mask = if pattern & (1 << (h - 1)) != 0 { 1 } else { 0 };
                a.record(BlockHeight::new(h), mask);
                b.record(BlockHeight::new(h), mask);
            }
            let mut was_active = false;
            for h in 0u64..=24 {
                let s1 = state_at(&dep, BlockHeight::new(h), &a);
                let s2 = state_at(&dep, BlockHeight::new(h), &b);
                assert_eq!(
                    s1, s2,
                    "determinism violated: pattern {pattern}, height {h}"
                );
                assert_ne!(
                    s1,
                    ThresholdState::Failed,
                    "LOT=true must never fail: pattern {pattern}, height {h}"
                );
                if was_active {
                    assert_eq!(
                        s1,
                        ThresholdState::Active,
                        "activation regressed: pattern {pattern}, height {h}"
                    );
                }
                if was_active || s1 == ThresholdState::Active {
                    was_active = true;
                }
            }
            // The flag-day guarantee: by well past the timeout, ACTIVE for
            // every possible history.
            assert_eq!(
                state_at(&dep, BlockHeight::new(24), &a),
                ThresholdState::Active,
                "pattern {pattern} never activated"
            );
        }
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

    /// A chain like [`fresh_chain`] but with transaction fees switched on.
    fn chain_with_fees(gas_price_grains: u128) -> Blockchain {
        let mut mining = MiningPolicy::test();
        mining.gas_price = Balance::from_grains(gas_price_grains);
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
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
            mining,
            vesting: vec![],
        };
        Blockchain::new(&config).unwrap()
    }

    #[test]
    fn coinbase_mints_the_scheduled_reward_to_the_miner_every_block() {
        // The Bitcoin issuance model end-to-end: every block's coinbase mints
        // the scheduled reward to the header's proposer (the PoW finder), the
        // emission counter and total supply rise by exactly that amount, and
        // the reward halves on schedule — all enforced by import re-execution.
        let mut mining = MiningPolicy::test();
        mining.base_reward = Balance::from_sov(50).unwrap();
        mining.halving_interval_blocks = 2; // heights 1-2 pay 50; height 3 pays 25
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
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
            mining,
            vesting: vec![],
        };
        let mut chain = Blockchain::new(&config).unwrap();
        let supply_genesis = chain.ledger().total_supply().unwrap().grains();

        // Block 1: 50 SOV to the miner (height 1, epoch 0 of the height-keyed
        // halving schedule).
        let b1 = chain.produce_block(vec![], 2_000).unwrap();
        assert_eq!(b1.header.proposer, id("val01.node.sov"));
        chain.import_block(b1).unwrap();
        assert_eq!(
            chain.ledger().account(&id("val01.node.sov")).balance,
            Balance::from_sov(50).unwrap(),
            "block 1 coinbase pays the miner the scheduled 50 SOV"
        );

        // Block 2: another 50 (height 2 closes epoch 0). Block 3 (height 3) is
        // epoch 1 — the reward HALVES to 25, Bitcoin's exact rule.
        let b2 = chain.produce_block(vec![], 3_000).unwrap();
        chain.import_block(b2).unwrap();
        assert_eq!(chain.mint_reward(), Balance::from_sov(25).unwrap());
        let b3 = chain.produce_block(vec![], 4_000).unwrap();
        chain.import_block(b3).unwrap();

        let l = chain.ledger();
        assert_eq!(
            l.account(&id("val01.node.sov")).balance,
            Balance::from_sov(125).unwrap(),
            "50 + 50 + 25: the halving schedule is enforced"
        );
        assert_eq!(l.mined_emitted(), Balance::from_sov(125).unwrap());
        assert_eq!(
            l.total_supply().unwrap().grains(),
            supply_genesis + Balance::from_sov(125).unwrap().grains(),
            "supply rose by exactly the minted coinbases"
        );
    }

    #[test]
    fn set_coinbase_routes_the_reward_to_the_operator_account() {
        // A configured coinbase account becomes the header proposer and is paid
        // the reward — the operator's miner identity, not the validator schedule.
        let mut mining = MiningPolicy::test();
        mining.base_reward = Balance::from_sov(50).unwrap();
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
            accounts: vec![
                GenesisAccount {
                    account: id("val01.node.sov"),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::ZERO,
                },
                GenesisAccount {
                    account: id("miner01.sov"),
                    key: Keypair::from_seed([7; 32]).public_key(),
                    balance: Balance::ZERO,
                },
            ],
            mining,
            vesting: vec![],
        };
        let mut chain = Blockchain::new(&config).unwrap();
        chain.set_coinbase(id("miner01.sov"));

        let block = chain.produce_block(vec![], 2_000).unwrap();
        assert_eq!(block.header.proposer, id("miner01.sov"));
        chain.import_block(block).unwrap();
        assert_eq!(
            chain.ledger().account(&id("miner01.sov")).balance,
            Balance::from_sov(50).unwrap(),
            "the operator's miner account is paid the coinbase"
        );
    }

    #[test]
    fn transaction_fees_pay_the_producer_and_are_never_burned() {
        let mut chain = chain_with_fees(100); // 100 grains per gas
        let supply_before = chain.ledger().total_supply().unwrap().grains();

        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 2_000)
            .unwrap();
        assert_eq!(block.transactions.len(), 1, "the transfer is included");
        chain.import_block(block).unwrap();

        let l = chain.ledger();
        // The recipient got the full amount; the sender paid the amount plus a fee.
        assert_eq!(
            l.account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(100).unwrap()
        );
        let fee = Balance::from_sov(1_000).unwrap().grains()
            - Balance::from_sov(100).unwrap().grains()
            - l.account(&id("usa.reserve.sov")).balance.grains();
        assert!(fee > 0, "a transaction fee was charged");

        // No burn: the whole fee is paid to the block producer (proposer == miner;
        // the test policy's tax is zero). Supply is unchanged — value only moved
        // from the sender to the producer.
        assert_eq!(
            l.account(&id("val01.node.sov")).balance.grains(),
            fee,
            "the producer earns the entire fee"
        );
        assert_eq!(
            l.total_supply().unwrap().grains(),
            supply_before,
            "supply is unchanged — nothing is burned"
        );
    }

    #[test]
    fn production_skips_a_transaction_whose_sender_cannot_afford_the_fee() {
        // An astronomical gas price makes the fee exceed the sender's whole balance.
        let mut chain = chain_with_fees(10_000_000);
        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 1, 0)], 2_000)
            .unwrap();
        assert!(
            block.transactions.is_empty(),
            "an unaffordable transaction is skipped, never stalling production"
        );
        chain.import_block(block).unwrap();
        assert_eq!(chain.height(), 1, "an (empty) block is still produced");
        assert_eq!(
            chain.ledger().account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(1_000).unwrap(),
            "a skipped sender is not charged"
        );
    }

    #[test]
    fn finality_is_confirmation_depth_in_the_active_chain() {
        // Nakamoto finality: a block is final once FINALITY_DEPTH blocks are
        // mined on top of it — no votes, no gadget. Walk a block from 1
        // confirmation to the threshold and watch it cross.
        let mut chain = fresh_chain();
        let block = chain.produce_block(vec![], 2_000).unwrap();
        let h = block.hash();
        chain.import_block(block).unwrap();

        // Fresh at the tip: 1 confirmation, not final.
        assert_eq!(chain.confirmations(&h), Some(1));
        assert!(!chain.is_final(&h));

        // Mine FINALITY_DEPTH - 1 more blocks on top.
        let mut ts = 3_000;
        for _ in 1..FINALITY_DEPTH {
            let b = chain.produce_block(vec![], ts).unwrap();
            chain.import_block(b).unwrap();
            ts += 1_000;
        }
        assert_eq!(chain.confirmations(&h), Some(FINALITY_DEPTH));
        assert!(chain.is_final(&h), "buried FINALITY_DEPTH deep => final");

        // A hash the chain does not hold has no confirmations and is never final.
        let bogus = Hash::digest(b"no such block");
        assert_eq!(chain.confirmations(&bogus), None);
        assert!(!chain.is_final(&bogus));

        // Genesis is final by definition.
        assert!(chain.is_final(&chain.block_by_height(0).unwrap().hash()));
    }

    #[test]
    fn difficulty_is_stable_within_an_epoch() {
        // Bitcoin-style epoch retargeting: difficulty does NOT change block to
        // block — it is recomputed only at epoch boundaries (every
        // RETARGET_INTERVAL blocks). So a short sequence mines at the genesis
        // difficulty throughout, regardless of timestamps. This is both the
        // correct PoW design and what keeps mining tractable for any chain
        // shorter than one epoch.
        let mut chain = fresh_chain();
        let genesis_difficulty = chain.sha256d_difficulty();
        let mut ts = 2_000;
        for _ in 0..10 {
            let block = chain.produce_block(vec![], ts).unwrap();
            chain.import_block(block).unwrap();
            ts += 1_000;
            assert_eq!(
                chain.sha256d_difficulty(),
                genesis_difficulty,
                "difficulty is constant within an epoch"
            );
        }
    }

    #[test]
    fn header_commits_the_required_difficulty_bits() {
        // Every block carries Bitcoin's compact nBits, equal to the compact form
        // of the chain's configured difficulty (canonicalization preserves the
        // compact encoding), and the value decodes canonically — the round-trip
        // producer and importer both rely on.
        let mut chain = fresh_chain();
        let expected_bits = MiningPolicy::test().sha256d_target.to_compact();
        let block = chain.produce_block(vec![], 2_000).unwrap();
        assert_eq!(block.header.bits, expected_bits);
        // Decodes to a canonical target (re-encoding it yields the same bits).
        let decoded = Target::from_compact(block.header.bits).unwrap();
        assert_eq!(decoded.to_compact(), block.header.bits);
        // Genesis commits the same difficulty (same epoch as block 1).
        let genesis = chain.block_by_height(0).unwrap();
        assert_eq!(genesis.header.bits, expected_bits);
        // And the committed work is real: the block imports (its PoW meets the
        // decoded target).
        chain.import_block(block).unwrap();
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn block_claiming_easier_difficulty_is_rejected() {
        // A miner cannot lower its own difficulty: a header whose `bits` differs
        // from the retarget-required value is rejected before any PoW check —
        // even if (as here) it still satisfies the easier claimed target.
        let mut chain = fresh_chain();
        let mut block = chain.produce_block(vec![], 2_000).unwrap();
        let honest_bits = block.header.bits;
        // Claim an easier target (a larger compact value). This invalidates the
        // header hash/seal too, but the difficulty-bits rule rejects it first.
        block.header.bits = Target::EASIEST.to_compact();
        assert_ne!(block.header.bits, honest_bits);
        assert!(matches!(
            chain.import_block(block),
            Err(ChainError::BadDifficultyBits { .. })
        ));
        // The honest chain is untouched.
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn starts_at_genesis() {
        let chain = fresh_chain();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.len(), 1);
        assert!(chain.is_final(&chain.head().hash()));
        assert_eq!(
            chain.ledger().account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(1_000).unwrap()
        );
    }

    #[test]
    fn consensus_rejects_a_block_that_breaks_value_conservation() {
        // The "unfuckable" backstop: even if execution ever produced a state whose
        // SUPPLY did not match the minted counter, the chain refuses to commit it.
        // Simulate such a post-state by crediting the shielded pool "from thin air"
        // (supply rises with no Δmined) and confirm the invariant check rejects it
        // — this is what makes a silent value divergence impossible, every network.
        let chain = fresh_chain();
        let before = chain.ledger().clone();
        let mut after = before.clone();
        after
            .add_shielded_value(Balance::from_sov(1_000).unwrap())
            .unwrap();
        let target = canonical_target(chain.mining.sha256d_target);

        let err = chain
            .verify_invariants(&before, &after, target)
            .expect_err("a supply increase with no minting must be rejected");
        assert!(
            matches!(
                err,
                ChainError::Invariant(sov_verify::InvariantViolation::ValueNotConserved { .. })
            ),
            "expected ValueNotConserved, got {err:?}"
        );

        // A genuine no-op transition (nothing minted, nothing moved) passes.
        chain
            .verify_invariants(&before, &before, target)
            .expect("a conserving transition is accepted");
    }

    #[test]
    fn receipt_index_records_success_and_failure_for_lookup() {
        // The receipt index is what lets a node answer "what happened to my
        // transaction?" — including a transaction that was INCLUDED but did not
        // apply. Here a valid transfer and an over-spend (which fails but still
        // consumes its nonce) are mined together; both must be retrievable by id
        // and by height, with the failure carrying its reason.
        let mut chain = fresh_chain();
        let good = usa_transfer("ecb.reserve.sov", 10, 0);
        // usa has 1000 SOV; spending 10_000 fails with "insufficient balance".
        let bad = usa_transfer("ecb.reserve.sov", 10_000, 1);
        let good_id = good.id();
        let bad_id = bad.id();

        let block = chain.produce_block(vec![good, bad], 2_000).unwrap();
        chain.import_block(block).unwrap();
        assert_eq!(chain.height(), 1);

        // By transaction id: the good one succeeded, the bad one failed WITH a reason.
        let (h_good, r_good) = chain.receipt(&good_id).expect("good receipt indexed");
        assert_eq!(h_good, 1);
        assert!(r_good.succeeded());
        let (h_bad, r_bad) = chain.receipt(&bad_id).expect("failed receipt indexed");
        assert_eq!(h_bad, 1);
        assert!(!r_bad.succeeded());
        match &r_bad.status {
            sov_types::ExecutionStatus::Failed { reason } => {
                assert!(!reason.is_empty(), "a failed receipt carries a reason")
            }
            _ => panic!("expected a failed status"),
        }

        // By height: both receipts, in transaction order.
        let at = chain.receipts_at_height(1).expect("height 1 has receipts");
        assert_eq!(at.len(), 2);
        assert_eq!(at[0].tx_id, good_id);
        assert_eq!(at[1].tx_id, bad_id);

        // Honest absence: unknown tx id and a height beyond the chain.
        assert!(chain.receipt(&Hash::digest(b"nope")).is_none());
        assert!(chain.receipts_at_height(0).unwrap().is_empty()); // genesis: no txs
        assert!(chain.receipts_at_height(99).is_none()); // beyond head
    }

    #[test]
    fn randomx_chain_mines_and_verifies_a_real_block() {
        // The mainnet seal (RandomX — memory-hard, ASIC-resistant) at a trivially
        // low difficulty: producing grinds a REAL RandomX proof of work, and
        // importing re-verifies it through the same memory-hard seal. Proves the
        // ASIC-resistant path end to end on commodity (M-series) CPUs.
        let mining = MiningPolicy {
            pow_algo: sov_mining::PowAlgo::RandomX,
            sha256d_target: Target::from_leading_zero_bits(4),
            ..MiningPolicy::test()
        };
        let config = GenesisConfig {
            chain_id: "sov-randomx".into(),
            timestamp_ms: 1_000,
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
            mining,
            vesting: vec![],
        };
        let mut chain = Blockchain::new(&config).unwrap();
        // produce_block grinds the header until its RandomX seal meets the target.
        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 10, 0)], 2_000)
            .unwrap();
        // import_block independently re-verifies that RandomX seal against the
        // branch-required target before committing.
        let receipts = chain.import_block(block).unwrap();
        assert_eq!(chain.height(), 1);
        assert!(receipts[0].succeeded());
        assert_eq!(
            chain.ledger().account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(10).unwrap()
        );
    }

    #[test]
    fn produce_and_import_advances_state() {
        let mut chain = fresh_chain();
        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 250, 0)], 2_000)
            .unwrap();
        let receipts = chain.import_block(block).unwrap();

        assert_eq!(chain.height(), 1);
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].succeeded());
        assert_eq!(
            chain.ledger().account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(750).unwrap()
        );
        assert_eq!(
            chain.ledger().account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(250).unwrap()
        );
        // Supply conserved across the block (the test preset's coinbase is
        // zero, so supply is exactly the 1,000-SOV genesis allocation).
        assert_eq!(
            chain.ledger().total_supply().unwrap(),
            Balance::from_sov(1_000).unwrap()
        );
    }

    #[test]
    fn tampered_state_root_is_rejected() {
        let mut chain = fresh_chain();
        let mut block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 10, 0)], 2_000)
            .unwrap();
        // Forging the committed state root and then RE-MINING a valid PoW over
        // the tampered header (so the block is not merely rejected for bad
        // work): re-execution still catches the wrong root. Tampering without
        // re-mining would already break the PoW seal — an even cheaper
        // rejection — since the header commits to the state root.
        block.header.state_root = Hash::digest(b"forged");
        let target = chain.sha256d_difficulty().to_target();
        for nonce in 0.. {
            block.header.nonce = nonce;
            if target.is_met_by(&block.header.pow_hash()) {
                break;
            }
        }
        assert!(matches!(
            chain.import_block(block),
            Err(ChainError::StateRootMismatch)
        ));
        // Chain did not advance.
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn checkpoint_mismatch_is_rejected() {
        let mut chain = fresh_chain();
        // Pin height 1 to a hash the real block cannot have.
        chain.set_checkpoints([(1u64, Hash::digest(b"not the real block"))]);
        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 1, 0)], 2_000)
            .unwrap();
        assert!(matches!(
            chain.import_block(block),
            Err(ChainError::CheckpointMismatch { height: 1 })
        ));
        assert_eq!(
            chain.height(),
            0,
            "the forged-history block was not committed"
        );
    }

    #[test]
    fn matching_checkpoint_is_accepted() {
        let mut chain = fresh_chain();
        let block = chain
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 1, 0)], 2_000)
            .unwrap();
        // Pin the checkpoint to the real block's hash, then import it.
        chain.set_checkpoints([(1u64, block.hash())]);
        chain.import_block(block).unwrap();
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn wrong_prev_hash_is_rejected() {
        let mut chain = fresh_chain();
        let mut block = chain.produce_block(vec![], 2_000).unwrap();
        block.header.prev_hash = Hash::digest(b"not the head");
        // tx_root still matches (empty), but the link is broken.
        assert!(matches!(
            chain.import_block(block),
            Err(ChainError::PrevHashMismatch)
        ));
    }

    #[test]
    fn multi_block_sequence_keeps_roots_consistent() {
        let mut chain = fresh_chain();
        for (i, nonce) in (0..5u64).enumerate() {
            let block = chain
                .produce_block(
                    vec![usa_transfer("ecb.reserve.sov", 1, nonce)],
                    2_000 + i as u64 * 1_000,
                )
                .unwrap();
            chain.import_block(block).unwrap();
        }
        assert_eq!(chain.height(), 5);
        assert_eq!(
            chain.ledger().account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(995).unwrap()
        );
        assert_eq!(
            chain.ledger().account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(5).unwrap()
        );
        // Re-importing the same head height must fail (chain only moves forward).
        let stale = chain.produce_block(vec![], 9_000).unwrap();
        let next = chain.height();
        chain.import_block(stale).unwrap();
        assert_eq!(chain.height(), next + 1);
    }

    #[test]
    fn miner_registry_tracks_when_miners_come_online() {
        // The registry derives from block headers: each block's proposer is the
        // miner its coinbase paid. Switch the configured coinbase between blocks
        // to simulate two miners taking turns.
        let mut chain = fresh_chain();

        // Blocks 1 & 2: miner01. Block 3: miner02 comes online.
        chain.set_coinbase(id("miner01.sov"));
        let b1 = chain.produce_block(vec![], 2_000).unwrap();
        chain.import_block(b1).unwrap();
        let b2 = chain.produce_block(vec![], 3_000).unwrap();
        chain.import_block(b2).unwrap();
        chain.set_coinbase(id("miner02.sov"));
        let b3 = chain.produce_block(vec![], 4_000).unwrap();
        chain.import_block(b3).unwrap();

        let reg = chain.miner_registry();
        assert_eq!(reg.len(), 2);
        let m1 = reg.iter().find(|m| m.account == id("miner01.sov")).unwrap();
        assert_eq!(m1.first_seen_height, 1);
        assert_eq!(m1.blocks_mined, 2);
        assert_eq!(m1.last_seen_height, 2);
        let m2 = reg.iter().find(|m| m.account == id("miner02.sov")).unwrap();
        assert_eq!(m2.first_seen_height, 3); // came online later
        assert_eq!(m2.blocks_mined, 1);
    }

    /// The real counter contract, compiled from chain/contracts/counter.
    const COUNTER_WASM: &[u8] = include_bytes!("../../vm/tests/counter.wasm");

    #[test]
    fn deploy_and_call_contract_through_blocks() {
        let mut chain = fresh_chain();

        // Block 1: usa.reserve.sov deploys the counter contract (becomes a contract).
        let deploy = usa_action(
            Action::Deploy {
                code: COUNTER_WASM.to_vec(),
            },
            0,
        );
        let b1 = chain.produce_block(vec![deploy], 2_000).unwrap();
        chain.import_block(b1).unwrap();
        assert!(chain.ledger().account(&id("usa.reserve.sov")).is_contract());

        // Blocks 2 & 3: call it twice; the on-chain counter increments and is
        // committed to the state root (produce + import agree on the root).
        for (i, nonce) in [(0u64, 1u64), (1, 2)] {
            let call = usa_action(
                Action::Call {
                    contract: id("usa.reserve.sov"),
                    gas_limit: 10_000_000,
                    calldata: Vec::new(),
                },
                nonce,
            );
            let block = chain.produce_block(vec![call], 3_000 + i * 1_000).unwrap();
            let receipts = chain.import_block(block).unwrap();
            assert!(receipts[0].succeeded());
        }

        // The contract's committed storage shows count == 2.
        assert_eq!(
            chain
                .ledger()
                .contract_value(&id("usa.reserve.sov"), b"count"),
            Some(&2i32.to_le_bytes()[..])
        );
    }

    #[test]
    fn genesis_vesting_locks_then_claims() {
        // usa gets a 500 SOV vesting grant unlocking at height 2.
        let vesting = vec![VestingGrant {
            account: id("usa.reserve.sov"),
            amount: Balance::from_sov(500).unwrap(),
            unlock_height: 2,
        }];
        let mut chain = chain_with_vesting(vesting);

        // At genesis the grant is locked, not liquid.
        let acct = chain.ledger().account(&id("usa.reserve.sov"));
        assert_eq!(acct.balance, Balance::from_sov(1_000).unwrap());
        assert_eq!(acct.locked, Balance::from_sov(500).unwrap());

        // Block 1 (height 1 < 2): claim is too early and fails.
        let b1 = chain
            .produce_block(vec![usa_action(Action::ClaimVesting, 0)], 2_000)
            .unwrap();
        let r1 = chain.import_block(b1).unwrap();
        assert!(!r1[0].succeeded());
        assert_eq!(
            chain.ledger().account(&id("usa.reserve.sov")).locked,
            Balance::from_sov(500).unwrap()
        );

        // Block 2 (height 2): claim releases the vested funds to the liquid balance.
        let b2 = chain
            .produce_block(vec![usa_action(Action::ClaimVesting, 1)], 3_000)
            .unwrap();
        let r2 = chain.import_block(b2).unwrap();
        assert!(r2[0].succeeded());
        let acct = chain.ledger().account(&id("usa.reserve.sov"));
        assert_eq!(acct.locked, Balance::ZERO);
        assert_eq!(acct.balance, Balance::from_sov(1_500).unwrap()); // 1000 + 500
    }

    #[test]
    fn a_block_must_postdate_the_median_time_past() {
        let mut chain = fresh_chain(); // genesis @ 1_000
        assert_eq!(chain.median_time_past(), 1_000);

        // A block past the median is accepted, and the median advances.
        let b1 = chain.produce_block(vec![], 2_000).unwrap();
        chain.import_block(b1).unwrap();
        assert_eq!(chain.median_time_past(), 2_000);

        // BIP-113: a block whose timestamp does NOT exceed the median-time-past is
        // rejected — even though it does not strictly go backwards (it equals the
        // median), so the bare monotonic rule would have let it through.
        let stalled = chain.produce_block(vec![], 2_000).unwrap();
        assert!(matches!(
            chain.import_block(stalled),
            Err(ChainError::TimestampNotAfterMedian {
                mtp: 2_000,
                got: 2_000
            })
        ));

        // One millisecond past the median is sufficient.
        let ok = chain.produce_block(vec![], 2_001).unwrap();
        chain.import_block(ok).unwrap();
    }

    #[test]
    fn heavier_branch_triggers_reorg() {
        // Two nodes share genesis. node1 builds branch A (1 block); node2 builds
        // a competing branch B (2 blocks). Feeding B to node1 must reorg it onto
        // the heavier branch — rolling back A and matching node2's state exactly.
        let mut node1 = fresh_chain();
        let mut node2 = fresh_chain();

        // Branch A on node1: a 100-SOV transfer at height 1.
        let a1 = node1
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 2_000)
            .unwrap();
        node1.import_block(a1).unwrap();
        assert_eq!(node1.height(), 1);

        // Branch B on node2: a different transfer at height 1, then a second
        // block at height 2 — strictly more cumulative work than A.
        let b1 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 250, 0)], 3_000)
            .unwrap();
        node2.import_block(b1.clone()).unwrap();
        let b2 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 1, 1)], 4_000)
            .unwrap();
        node2.import_block(b2.clone()).unwrap();
        assert_eq!(node2.height(), 2);

        // b1 is an equal-work side branch on node1: stored, but no reorg.
        node1.import_block(b1).unwrap();
        assert_eq!(node1.height(), 1, "equal-work side branch does not reorg");

        // b2 tips branch B over the active head -> reorg.
        node1.import_block(b2.clone()).unwrap();
        assert_eq!(node1.height(), 2, "node1 reorged onto the heavier branch");
        assert_eq!(node1.head().hash(), b2.hash());
        // The reorg rolled back A and replayed B: state matches node2 exactly,
        // and ecb shows branch B's 251 SOV, never branch A's 100.
        assert_eq!(node1.ledger().state_root(), node2.ledger().state_root());
        assert_eq!(
            node1.ledger().account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(251).unwrap()
        );
    }

    #[test]
    fn reorg_returns_orphaned_transactions() {
        // A reorg must not silently drop transactions: txs in blocks the reorg
        // orphans (and that the winning branch does not itself include) are
        // reported so a node can return them to its mempool (Bitcoin's behavior).
        let mut node1 = fresh_chain();
        let mut node2 = fresh_chain();

        // Branch A on node1: a transfer at height 1 (the tx that will be orphaned).
        let orphan_tx = usa_transfer("ecb.reserve.sov", 100, 0);
        let orphan_id = orphan_tx.id();
        let a1 = node1.produce_block(vec![orphan_tx], 2_000).unwrap();
        node1.import_block(a1).unwrap();

        // Branch B on node2: TWO EMPTY blocks — strictly heavier than A, and it
        // does not include usa's transfer, so the transfer is genuinely orphaned.
        let b1 = node2.produce_block(vec![], 3_000).unwrap();
        node2.import_block(b1.clone()).unwrap();
        let b2 = node2.produce_block(vec![], 4_000).unwrap();
        node2.import_block(b2.clone()).unwrap();

        // Feed B to node1: b1 is stored (equal work), b2 triggers the reorg.
        node1.import_block(b1).unwrap();
        let imported = node1.import_block_tracked(b2).unwrap();
        assert_eq!(node1.height(), 2, "reorged onto the heavier (empty) branch");
        // The orphaned transfer is reported for re-queue, and the post-reorg
        // ledger no longer reflects it (ecb is back to zero).
        assert!(
            imported.reverted_txs.iter().any(|t| t.id() == orphan_id),
            "the orphaned transfer must be surfaced for re-queue"
        );
        assert_eq!(
            node1.ledger().account(&id("ecb.reserve.sov")).balance,
            Balance::ZERO
        );
    }

    #[test]
    fn invalid_heavier_branch_cannot_displace_head() {
        // A heavier branch whose tip re-executes to the wrong state must be
        // rejected without disturbing the current head — proof of work buys the
        // right to be *considered*, not to install unverified state.
        let mut node1 = fresh_chain();
        let mut node2 = fresh_chain();

        let a1 = node1
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 2_000)
            .unwrap();
        let a1_hash = a1.hash();
        node1.import_block(a1).unwrap();

        let b1 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 250, 0)], 3_000)
            .unwrap();
        let b1_hash = b1.hash();
        node2.import_block(b1.clone()).unwrap();
        let mut b2 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 1, 1)], 4_000)
            .unwrap();
        // An equal-work competitor at height 1: kept as a side branch, or adopted by
        // the deterministic tie-break if its hash is smaller. Either way the head is the
        // VALID tie-break winner at height 1.
        node1.import_block(b1).unwrap();
        let valid_head = a1_hash.min(b1_hash);

        // Forge the heavier tip's state root, then re-mine valid PoW against the
        // exact genesis target so it clears the work check but fails replay.
        b2.header.state_root = Hash::digest(b"forged");
        let target = MiningPolicy::test().sha256d_target;
        for nonce in 0.. {
            b2.header.nonce = nonce;
            if target.is_met_by(&b2.header.pow_hash()) {
                break;
            }
        }
        assert!(matches!(
            node1.import_block(b2),
            Err(ChainError::StateRootMismatch)
        ));
        // The FORGED heavier tip did not move the head: still height 1, on the valid
        // tie-break winner (proof of work buys consideration, not unverified state).
        assert_eq!(node1.height(), 1);
        assert_eq!(node1.head().hash(), valid_head);
    }

    #[test]
    fn invalid_equal_work_side_branch_is_rejected_not_stored() {
        // A side branch must be fully executable before the node stores it. Without
        // this, a peer could make invalid full blocks durable by keeping them below
        // the active chain's cumulative work.
        let mut node1 = fresh_chain();
        let node2 = fresh_chain();

        let a1 = node1
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 2_000)
            .unwrap();
        node1.import_block(a1.clone()).unwrap();

        let mut b1 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 250, 0)], 3_000)
            .unwrap();
        b1.header.state_root = Hash::digest(b"forged side branch");
        let target = MiningPolicy::test().sha256d_target;
        for nonce in 0.. {
            b1.header.nonce = nonce;
            if target.is_met_by(&b1.header.pow_hash()) {
                break;
            }
        }
        let b1_hash = b1.hash();

        assert!(matches!(
            node1.import_block(b1),
            Err(ChainError::StateRootMismatch)
        ));
        assert_eq!(node1.height(), 1);
        assert_eq!(node1.head().hash(), a1.hash());
        assert!(
            !node1.contains_block(&b1_hash),
            "invalid side branch was not inserted into the block index"
        );
    }

    #[test]
    fn equal_work_fork_converges_on_smaller_hash() {
        // THE convergence guarantee for many simultaneous miners. When two miners
        // produce competing blocks at the same height (EQUAL cumulative work), every
        // node must deterministically pick the SAME one — the block with the smaller
        // hash (which, since hash < target, also reflects more proof of work). Without
        // this, equal-work competitors each keep their own (subjective first-seen) and
        // independent nodes diverge permanently — the "both mining and the chain was
        // lost" failure. The choice is order-independent, so a node that saw either
        // block first ends up on the same head.
        let mut node1 = fresh_chain();
        let node2 = fresh_chain();
        let a1 = node1
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 2_000)
            .unwrap();
        node1.import_block(a1.clone()).unwrap();
        // A competing, equally valid height-1 block (different timestamp ⇒ different
        // hash), built on the same genesis by an independent miner.
        let b1 = node2
            .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 0)], 3_000)
            .unwrap();
        assert_ne!(a1.hash(), b1.hash());
        let winner = a1.hash().min(b1.hash());

        node1.import_block(b1.clone()).unwrap();
        assert_eq!(node1.height(), 1);
        assert_eq!(
            node1.head().hash(),
            winner,
            "a node converges on the smaller-hash competitor at equal work"
        );

        // Order-independent: a node that imported b1 first reaches the SAME head.
        let mut node3 = fresh_chain();
        node3.import_block(b1).unwrap();
        node3.import_block(a1).unwrap();
        assert_eq!(
            node3.head().hash(),
            winner,
            "convergence is independent of which competitor arrived first"
        );
    }

    // ---- Chainstate snapshot fast-resume ----

    /// Mine `count` blocks onto `chain` (one transfer in the first, the rest empty),
    /// committing each through the normal validated import path. Timestamps are keyed
    /// to height so they stay strictly increasing across multiple calls.
    fn mine_blocks(chain: &mut Blockchain, count: u64) {
        for _ in 0..count {
            let height = chain.height();
            let txs = if height == 0 {
                vec![usa_transfer("ecb.reserve.sov", 250, 0)]
            } else {
                vec![]
            };
            let ts = 2_000 + (height + 1) * 1_000;
            let block = chain.produce_block(txs, ts).unwrap();
            chain.import_block(block).unwrap();
        }
    }

    /// The active block log (heights 1..=tip), exactly what the daemon persists and
    /// replays (genesis is not logged).
    fn active_log(chain: &Blockchain) -> Vec<Block> {
        (1..=chain.height())
            .map(|h| chain.block_by_height(h).unwrap().clone())
            .collect()
    }

    #[test]
    fn snapshot_resume_reproduces_full_replay_state() {
        // Build a chain, take a snapshot of its tip, and resume a FRESH chain from it
        // (round-tripping the ledger through its Borsh snapshot bytes, as the daemon
        // does). The resumed chain must be byte-identical: same head, state root, and
        // receipt lookups — with NO block execution beyond the snapshot.
        let mut chain = fresh_chain();
        mine_blocks(&mut chain, 6);
        let tip = chain.head().clone();
        let log = active_log(&chain);

        let ledger = Ledger::from_snapshot_bytes(&chain.ledger().to_snapshot_bytes()).unwrap();
        let receipts = chain.active_receipts_snapshot();

        let mut resumed = fresh_chain();
        let ok = resumed
            .resume_from_snapshot(ledger, receipts, tip.hash(), tip.header.height.get(), &log)
            .unwrap();
        assert!(ok, "snapshot resume verified against the committed head");
        assert_eq!(resumed.height(), chain.height());
        assert_eq!(resumed.head().hash(), chain.head().hash());
        assert_eq!(resumed.ledger().state_root(), chain.ledger().state_root());
        // The transfer's receipt is found on the resumed chain (receipt index restored).
        let tx_id = chain.block_by_height(1).unwrap().transactions[0].id();
        assert!(
            resumed.receipt(&tx_id).is_some(),
            "restored snapshot serves historical receipts"
        );
    }

    #[test]
    fn snapshot_resume_replays_the_post_snapshot_gap() {
        // A snapshot that LAGS the tip (periodic snapshot + later blocks) must still
        // resume correctly by trusted-replaying only the gap — not the whole chain.
        let mut chain = fresh_chain();
        mine_blocks(&mut chain, 4);
        // Snapshot at height 4.
        let snap_head = chain.head().hash();
        let snap_height = chain.height();
        let snap_ledger = Ledger::from_snapshot_bytes(&chain.ledger().to_snapshot_bytes()).unwrap();
        let snap_receipts = chain.active_receipts_snapshot();
        // ...then mine 5 more (the gap the resume must replay).
        mine_blocks(&mut chain, 5);
        assert_eq!(chain.height(), 9);
        let log = active_log(&chain);

        let mut resumed = fresh_chain();
        let ok = resumed
            .resume_from_snapshot(snap_ledger, snap_receipts, snap_head, snap_height, &log)
            .unwrap();
        assert!(ok);
        assert_eq!(resumed.height(), 9);
        assert_eq!(resumed.head().hash(), chain.head().hash());
        assert_eq!(resumed.ledger().state_root(), chain.ledger().state_root());
    }

    #[test]
    fn stale_snapshot_is_rejected_for_replay_fallback() {
        // A snapshot whose height exceeds the log's heaviest chain (e.g. the log was
        // truncated / the snapshot is from a longer foreign chain) is rejected, so the
        // caller falls back to a full replay rather than booting on unverified state.
        let mut chain = fresh_chain();
        mine_blocks(&mut chain, 5);
        let ledger = Ledger::from_snapshot_bytes(&chain.ledger().to_snapshot_bytes()).unwrap();
        let receipts = chain.active_receipts_snapshot();
        let snap_head = chain.head().hash();

        // Present only the first 3 blocks of the log, but claim a height-5 snapshot.
        let short_log: Vec<Block> = active_log(&chain).into_iter().take(3).collect();
        let mut resumed = fresh_chain();
        let ok = resumed
            .resume_from_snapshot(ledger, receipts, snap_head, 5, &short_log)
            .unwrap();
        assert!(!ok, "a snapshot ahead of the log's heaviest tip is rejected");
    }

    #[test]
    fn snapshot_head_not_on_heaviest_chain_is_rejected() {
        // A snapshot whose claimed head hash is not the block at that height on the
        // log's heaviest chain (wrong fork / corruption) is rejected.
        let mut chain = fresh_chain();
        mine_blocks(&mut chain, 5);
        let ledger = Ledger::from_snapshot_bytes(&chain.ledger().to_snapshot_bytes()).unwrap();
        let receipts = chain.active_receipts_snapshot();
        let log = active_log(&chain);

        let mut resumed = fresh_chain();
        let ok = resumed
            .resume_from_snapshot(ledger, receipts, Hash::digest(b"wrong head"), 5, &log)
            .unwrap();
        assert!(!ok, "a snapshot head off the heaviest chain is rejected");
    }
}
