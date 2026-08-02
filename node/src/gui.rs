//! The native `sov-station` desktop window — a real cross-platform GUI (macOS,
//! Windows, Linux) over the SAME read-only RPC the CLI uses. A background thread
//! polls a node every second and writes a [`Snapshot`]; the UI renders it live.
//! The station can also **launch and supervise a local testnet-1 node** (Start /
//! Stop), so it is a self-contained "run a node and watch it" application.
//!
//! Everything shown is real data read from a running node over JSON-RPC — the
//! GUI invents nothing; like the CLI, it only re-presents.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::collections::{HashMap, HashSet};

use eframe::egui;
use serde_json::{json, Value};
use sov_crypto::{Keypair, PublicKey};
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::{
    ChainSpec, Daemon, DaemonHandle, Keystore, KeystoreEntry, NodeConfig, P2p, P2pConfig,
    P2pHandle, RpcClient, SyncShared,
};
use sov_shielded::{
    decode_shielded_v2, encode_shielded, encode_shielded_v2, mint_to_shielded,
    shielded_transfer_with_change, unshield_amount_multi, AnyAddress, NoteStore, Receiver,
    ShieldedBundle, ShieldedKey, ShieldedParams, UnifiedAddress,
};
use sov_shielded_pq::bundle::SpendBundle;
use sov_shielded_pq::hd::PqShieldedKey;
use sov_shielded_pq::scan::PqNoteStore;
use sov_shielded_pq::wallet::{authorize_for_carrier, build_shield, build_spend};
use sov_shielded_pq::wire::decode_bundle;
use sov_shielded_pq::wire::encode_bundle;
use sov_types::{Action, SignedTransaction, Transaction};
use sov_wallet::{generate_mnemonic, HdWallet};
use zeroize::Zeroize;

use crate::auction::{
    self, Auction, Outlook, Pressure, SendCost, SendState, SentTx, FEE_AUCTION_DEPLOYMENT,
};
use crate::vault;

/// Accounts the wallet panel watches by default: the station's own miner and the
/// two perpetual mining-tax recipients (consensus constants).
// Genesis-bound accounts worth watching by default. (A wallet's own implicit
// account is added to the watch list when it is created/imported.)
/// Named accounts the dashboard tracks balances for out of the box. Empty: the
/// coinbase pays the miner directly (no tax accounts), and a user adds any named
/// accounts they care about themselves.
const DEFAULT_ACCOUNTS: [&str; 0] = [];

/// The local block explorer (started with `node src/server.js` in `explorer/`).
/// Block heights in the Blocks tab deep-link into it.
const EXPLORER_URL: &str = "http://127.0.0.1:8730";

/// One miner-registry row.
#[derive(Clone, Default)]
struct MinerRow {
    account: String,
    blocks: u64,
    first: u64,
    last: u64,
}

// ── External-mining freshness (SHARE-AWARE, with hysteresis) ──────────────────────
//
// The only liveness signal the registry gives us is `lastSeenHeight` — the height of the
// account's LAST WON BLOCK, not a heartbeat. A recent `lastSeen` proves a PAST win; it
// NEVER proves the miner is running right now. So MINING is a present-tense claim Station
// must WITNESS, not infer from a stale height: the light turns on ONLY when an owner
// account's `blocksMined` rises while THIS session is watching (the delta path). At a cold
// start there is no prior poll to diff against, so there is nothing witnessed yet and the
// account reads NOT mining — a miner that won a block shortly before launch and then
// STOPPED must not be asserted "mining" off its recent `lastSeen` alone (the v0.2.4 bug).
//
// Recency is then HYSTERESIS-ONLY. Once a witnessed win has lit an account, the last win
// legitimately falls many blocks behind the head before the next one (a small-share miner
// wins only every ~1/share blocks), so a flat window would strobe the light off between
// wins. To HOLD an already-witnessed-active account lit across that gap — and only to hold
// it, never to enter — we keep it on while its last win is within a window that scales
// with the account's EXPECTED gap between wins ≈ 1/share blocks (`network_blocks/blocks`),
// widened by hysteresis. A truly stopped miner's last win eventually falls past that hold
// window and it goes idle. Recency can only ever KEEP the light on, never turn it on.

/// Floor on the recency window (blocks). Keeps a HIGH-share miner from strobing between
/// its own fast wins, and bounds how tight the window can get.
const EXTERNAL_MINING_MIN_WINDOW: u64 = 30;
/// Cap on the recency window (blocks) ≈ 1.7 days at the 2.5-min cadence. The ceiling on
/// how long a STOPPED miner can keep reading MINING before it is declared idle — bounds
/// the widening window of a very-small-share miner so "stopped" is always eventually seen.
const EXTERNAL_MINING_MAX_WINDOW: u64 = 1_000;
/// Baseline width (in expected inter-win gaps) of the HOLD window for an account that has
/// just been lit by a witnessed win but is not (yet) in the sticky idle-hysteresis state.
/// Recency NEVER enters MINING — this only sizes how long a fresh win keeps the light on.
const EXTERNAL_MINING_ENTRY_GAPS: u64 = 2;
/// Hysteresis: once lit, KEEP an account MINING until its last win is more than this many
/// expected gaps behind the head. Larger than the baseline multiple so the state cannot flap.
const EXTERNAL_MINING_IDLE_GAPS: u64 = 6;

/// This account's EXPECTED number of blocks between its own wins ≈ `1 / share`, where
/// `share = blocks / network_blocks`. An account that has never won (or an empty registry)
/// has no meaningful cadence, so it gets the maximum window — it can only ever go active
/// via a fresh win (the `blocksMined` delta), never on stale recency alone.
fn expected_inter_win_gap(blocks: u64, network_blocks: u64) -> u64 {
    if blocks == 0 || network_blocks == 0 {
        return EXTERNAL_MINING_MAX_WINDOW;
    }
    (network_blocks / blocks).max(1)
}

/// The share-aware HOLD window for one already-witnessed-active account, in blocks. This
/// only ever KEEPS a lit account lit across the gap between its wins — it is never consulted
/// to ENTER the MINING state. `sticky` widens it (idle hysteresis) once the account has been
/// holding across polls, so the light cannot flap.
fn external_mining_window(blocks: u64, network_blocks: u64, sticky: bool) -> u64 {
    let gap = expected_inter_win_gap(blocks, network_blocks);
    let gaps = if sticky {
        EXTERNAL_MINING_IDLE_GAPS
    } else {
        EXTERNAL_MINING_ENTRY_GAPS
    };
    gap.saturating_mul(gaps)
        .clamp(EXTERNAL_MINING_MIN_WINDOW, EXTERNAL_MINING_MAX_WINDOW)
}

/// What Station can see about an OUT-OF-PROCESS miner (e.g. the standalone XUS Miner)
/// mining to one of the operator's own accounts, derived purely from the on-chain miner
/// registry (`sov_getMiners`). The in-process miner is measured separately via
/// `local_hashrate`; this is the only window Station has onto an external one.
#[derive(Clone, Default)]
struct ExternalMinerFacts {
    /// The operator account (registry id) with the most blocks — their main miner.
    account: String,
    /// Blocks the operator's account(s) have won (registry lifetime), summed.
    blocks_won: u64,
    /// Highest `lastSeenHeight` across the operator's miner rows.
    last_seen: u64,
    /// Chain head at the moment this was assessed, so the UI can show "N blocks ago"
    /// without a second read.
    head: u64,
    /// Total blocks across the WHOLE registry — the denominator of the share estimate.
    network_blocks: u64,
    /// Whether the freshness rule says this miner is mining RIGHT NOW.
    active: bool,
}

/// The result of one assessment: the facts to display, plus the SET of the operator's
/// accounts judged actively mining this poll. The poller feeds `active_accounts` back in
/// as the next poll's `prev_active` so the per-account hysteresis persists across polls.
#[derive(Clone, Default)]
struct MiningAssessment {
    facts: Option<ExternalMinerFacts>,
    active_accounts: HashSet<String>,
}

/// Decide, from the on-chain miner registry, whether an external miner is mining to one
/// of the operator's own accounts right now, and gather the facts to show them.
///
/// `owner` is the SET of accounts VERIFIED to belong to the operator (managed non-watch
/// wallets and operate-as names whose control is `Mine`) — never a merely-watched or
/// foreign account, so foreign hashrate can't light the chip. `prev_blocks` is the
/// previous poll's `account → blocksMined` (the fresh-win signal), and `prev_active` is
/// the set that was mining last poll (the hysteresis state).
///
/// "Actively mining now" is ENTERED exactly one way: the WITNESSED signal — `blocksMined`
/// rose since a previous poll THIS session actually recorded ⇒ mining now. Recency alone
/// NEVER enters the state, so a cold start (empty `prev_blocks` and `prev_active`) always
/// reads NOT mining: a recent `lastSeen` proves only a PAST win. Once an account has been
/// lit by a witnessed win, a SHARE-AWARE recency window (see [`external_mining_window`])
/// acts as HYSTERESIS ONLY — it keeps that already-active account lit across the expected
/// gap between its wins, and only for an account that was active last poll (`prev_active`).
/// A held account whose last win finally falls beyond that window, with no new win, goes
/// idle. Recency can keep the light on; it can never turn it on.
fn assess_external_mining(
    miners: &[MinerRow],
    owner: &HashSet<String>,
    head: Option<u64>,
    prev_blocks: &HashMap<String, u64>,
    prev_active: &HashSet<String>,
) -> MiningAssessment {
    let owned: Vec<&MinerRow> = miners
        .iter()
        .filter(|m| owner.contains(&m.account))
        .collect();
    if owned.is_empty() {
        return MiningAssessment::default();
    }
    let head = head.unwrap_or(0);
    let network_blocks: u64 = miners.iter().map(|m| m.blocks).sum();
    let mut facts = ExternalMinerFacts {
        head,
        network_blocks,
        ..Default::default()
    };
    let mut active_accounts = HashSet::new();
    let mut primary_blocks = 0u64;
    let mut have_primary = false;
    for m in &owned {
        facts.blocks_won = facts.blocks_won.saturating_add(m.blocks);
        facts.last_seen = facts.last_seen.max(m.last);
        // ENTRY — the ONLY way MINING turns on: a WITNESSED fresh win. `blocksMined` rose
        // since a previous poll THIS session recorded. At a cold start `prev_blocks` is
        // empty, so this is false for every account — recency can never enter the state.
        let won_more = prev_blocks.get(&m.account).is_some_and(|&p| m.blocks > p);
        // HOLD (hysteresis only) — keeps an ALREADY-witnessed-active account (`was_active`)
        // lit across the gap between its wins, so a modest-share miner does not flicker off.
        // Gated on `was_active`, so recency alone (a stale `lastSeen`) can NEVER light a
        // cold or long-idle account. `m.last <= head` guards a row claiming to be ahead of
        // head; the window widens once the account is holding, so the state cannot flap.
        let was_active = prev_active.contains(&m.account);
        let window = external_mining_window(m.blocks, network_blocks, was_active);
        let recent = head > 0 && m.last <= head && head - m.last <= window;
        if won_more || (was_active && recent) {
            active_accounts.insert(m.account.clone());
        }
        // The operator's "main" miner row is the one that has won the most. `>=` with a
        // seen-flag so the FIRST row is always chosen even when every row has 0 blocks.
        if !have_primary || m.blocks >= primary_blocks {
            primary_blocks = m.blocks;
            facts.account = m.account.clone();
            have_primary = true;
        }
    }
    facts.active = !active_accounts.is_empty();
    MiningAssessment {
        facts: Some(facts),
        active_accounts,
    }
}

/// One watched account's live state.
#[derive(Clone, Default)]
struct AccountRow {
    account: String,
    balance: String,
    nonce: String,
    key_state: String,
    /// The bound controlling key (`hybrid65:0x…`), if any — lets a wallet
    /// recognize a named account its key controls and operate as it.
    key: String,
}

/// One recent block's coinbase (issuance, paid entirely to the miner), in grains.
#[derive(Clone, Default)]
struct BlockRow {
    height: u64,
    /// The block header's wall-clock timestamp (Unix ms), surfaced in the Blocks tab.
    timestamp_ms: u64,
    /// The proof-of-work nonce that sealed this block — the literal "work"
    /// surfaced in the Mining tab's recent-proofs list.
    nonce: u64,
    miner: String,
    reward: String,
    miner_amount: String,
    /// Header identity + seal, for the in-app block-detail view (click a block in the
    /// Blocks tab). All from `sov_getBlockDigest`.
    hash: String,
    prev_hash: String,
    state_root: String,
    /// The compact PoW target (`nBits`) the nonce satisfied.
    bits: u32,
    /// Number of transactions in the block (a coinbase-only block has 0).
    tx_count: usize,
}

/// Pool v2 (post-quantum shielded) state, exactly as `sov_getShieldedV2Info` reported
/// it. Every field is a real number the node supplied; nothing here is derived or
/// estimated. The struct existing at all means the node ANSWERED — see [`PoolState`]
/// for what its absence means.
#[derive(Clone, Default, PartialEq, Eq)]
struct ShieldedV2Info {
    /// Whether the `shielded-v2` deployment (signal bit 2) is live at `height`.
    /// While false, `Action::ShieldedV2` is a hard consensus reject on every node.
    active: bool,
    pool_grains: u128,
    note_count: u64,
    nullifier_count: u64,
    /// The current pool-v2 anchor (Merkle root) a spend would prove membership against.
    anchor: String,
    deshieldable_now: u128,
    deshield_limit: u128,
    deshield_window_blocks: u64,
    window_resets_at: u64,
    height: u64,
}

/// Which shielded pool a surface is describing. The two are NOT interchangeable and
/// the difference is the entire reason v2 exists, so it is carried in the type rather
/// than left to whoever writes the label.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pool {
    /// Pool v1 — Zcash Orchard / Halo2. Live, and **not** post-quantum: its hiding is
    /// discrete-log based, so a future quantum adversary who recorded the chain could
    /// break the privacy of transactions made today ("harvest now, decrypt later").
    V1,
    /// Pool v2 — ML-KEM-768 note carriers with a STARK spend proof. Post-quantum, and
    /// dormant: consensus signal bit 2 is not armed.
    V2,
}

impl Pool {
    fn name(self) -> &'static str {
        match self {
            Pool::V1 => "Pool v1",
            Pool::V2 => "Pool v2",
        }
    }

    /// The cryptography, named exactly. Never "quantum-safe" for v1 — the whole point.
    fn crypto(self) -> &'static str {
        match self {
            Pool::V1 => "Orchard / Halo2",
            Pool::V2 => "ML-KEM-768 / STARK",
        }
    }

    /// The post-quantum claim, stated as the plain truth in both directions.
    fn pq_claim(self) -> &'static str {
        match self {
            Pool::V1 => "NOT post-quantum",
            Pool::V2 => "post-quantum",
        }
    }

    /// A distinct SHAPE per pool, so which pool is armed is identifiable at a
    /// glance and in greyscale. The post-quantum distinction is a money-safety
    /// cue; it may never rest on colour, which a screenshot, a projector, or a
    /// colour-vision deficiency can all remove.
    ///
    /// Open ring for v1 (its privacy has a hole a quantum adversary can widen),
    /// solid diamond for v2 (closed under the same adversary).
    fn glyph(self) -> &'static str {
        match self {
            Pool::V1 => "○",
            Pool::V2 => "◆",
        }
    }

    /// The post-quantum status as a short WORD, for a badge beside the name.
    /// Spelled out, never implied by a colour or a checkmark.
    fn pq_badge(self) -> &'static str {
        match self {
            Pool::V1 => "NOT PQ",
            Pool::V2 => "PQ",
        }
    }

    /// The pool as ONE unambiguous line, for a control where the operator is
    /// CHOOSING between the two. The three facts are never separated: a selector
    /// reading only "Pool v1 / Pool v2" makes the most consequential property of
    /// the choice — whether the privacy survives a quantum adversary — invisible
    /// at the moment of choosing.
    fn selector_label(self) -> String {
        format!(
            "{} {} · {} · {}",
            self.glyph(),
            self.name(),
            self.crypto(),
            self.pq_claim()
        )
    }

    /// The receiving-address prefix that belongs to this pool. The pools are
    /// separate value spaces; an address of the other pool is never coerced.
    fn address_hint(self) -> &'static str {
        match self {
            Pool::V1 => "xus1…/uxus1…",
            Pool::V2 => "xusq1…",
        }
    }
}

/// The three states a shielded-pool surface can be in. **These must never be collapsed.**
///
/// The whole reason this enum exists: an operator who reads "not active yet" as "empty"
/// concludes their funds vanished, and an operator who reads "unavailable" as "empty"
/// concludes the same. A bare `0` next to the word "balance" is capable of causing that
/// mistake, so no pool surface in this app renders one without the state beside it.
///
/// The distinction is not cosmetic — it is three genuinely different facts:
///   * [`Unavailable`](Self::Unavailable) — we asked and got nothing. We do not know
///     the pool value. Not zero: *unknown*.
///   * [`Dormant`](Self::Dormant)     — we know the value, and we know it is zero
///     **because consensus forbids anything else**: no `Action::ShieldedV2` has ever
///     been accepted, so no note can exist. Zero is a proof, not a balance.
///   * [`Active`](Self::Active)       — we know the value and it is a live balance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PoolState {
    Unavailable,
    Dormant,
    Active,
}

impl PoolState {
    /// Classify pool v2 from what the poller actually obtained. `online` is the node's
    /// reachability; `info` is `Some` only when `sov_getShieldedV2Info` answered with a
    /// reply we could read the activation flag out of.
    ///
    /// Note the ordering: an unreachable node is `Unavailable` even if a stale `info`
    /// is still in the snapshot, because a figure we can no longer confirm is not a
    /// figure we may present as current.
    fn classify_v2(online: bool, info: Option<&ShieldedV2Info>) -> Self {
        match (online, info) {
            (false, _) | (true, None) => PoolState::Unavailable,
            (true, Some(i)) if i.active => PoolState::Active,
            (true, Some(_)) => PoolState::Dormant,
        }
    }

    /// Classify pool v1. v1 has been live since genesis, so it is never `Dormant` — the
    /// only question is whether this node told us anything. `available` is set by the
    /// poller when `sov_getShieldedInfo` ANSWERED.
    ///
    /// It matters that this returns `Unavailable` rather than showing a zero: a node
    /// that does not serve the method leaves the v1 figures unknown, and an operator
    /// with a real shielded balance must not be shown "0".
    fn classify_v1(online: bool, available: bool) -> Self {
        if online && available {
            PoolState::Active
        } else {
            PoolState::Unavailable
        }
    }

    /// The state as a WORD — always rendered, never replaced by colour alone.
    fn word(self) -> &'static str {
        match self {
            PoolState::Unavailable => "UNAVAILABLE",
            PoolState::Dormant => "NOT ACTIVE YET",
            PoolState::Active => "ACTIVE",
        }
    }

    /// The state as a distinct SHAPE — legible in greyscale, so the signal survives
    /// any colour-vision deficiency and any monochrome screenshot.
    fn glyph(self) -> &'static str {
        match self {
            PoolState::Unavailable => "?", // we do not know
            PoolState::Dormant => "◌",     // defined, not filled in
            PoolState::Active => "●",      // live
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            PoolState::Unavailable => palette::unknown(),
            PoolState::Dormant => palette::dormant(),
            PoolState::Active => palette::success(),
        }
    }

    /// True when figures from this pool are real readings that may be rendered as
    /// numbers. False means every figure must render as [`num_unknown`] instead — the
    /// single rule that keeps "we don't know" from ever printing as "0".
    fn figures_are_real(self) -> bool {
        !matches!(self, PoolState::Unavailable)
    }

    /// The one-sentence explanation that must accompany any zero on a pool surface.
    /// Phrased so that each state is unmistakable for the other two.
    fn explanation(self, pool: Pool) -> &'static str {
        match (self, pool) {
            (PoolState::Unavailable, Pool::V2) => {
                "This node did not report pool-v2 state — it is unreachable, or it \
                 predates pool v2. The pool's value is UNKNOWN from here; it is not zero. \
                 Point the station at a node that serves sov_getShieldedV2Info."
            }
            (PoolState::Unavailable, Pool::V1) => {
                "This node did not report pool-v1 state — it is unreachable, or it does \
                 not serve sov_getShieldedInfo. The pool's value is UNKNOWN from here; it \
                 is not zero, and it is not a sign that anything is missing."
            }
            (PoolState::Dormant, _) => {
                "Pool v2 is defined in consensus but its activation signal (bit 2) is not \
                 armed, so every v2 spend is rejected by every node. Nothing has ever \
                 entered this pool and nothing can yet — a zero here is the deployment \
                 being dormant, NOT a balance that went missing."
            }
            (PoolState::Active, Pool::V2) => {
                "Pool v2 is live at this height. The figures below are real balances."
            }
            (PoolState::Active, Pool::V1) => {
                "Pool v1 is live and has been since genesis. The figures below are real \
                 balances. v1 is NOT post-quantum — it is Orchard/Halo2."
            }
        }
    }
}

/// The live state the poller writes and the UI reads.
#[derive(Clone, Default)]
struct Snapshot {
    online: bool,
    chain_id: String,
    height: Option<u64>,
    head_hash: String,
    state_root: String,
    supply_mined: String,
    supply_total: String,
    difficulty: String,
    /// Proof-of-work seal in force ("Sha256d" / "RandomX"), the consensus target
    /// block interval, and the head block's winning nonce + compact target — the
    /// raw "how work is proven" facts surfaced in the Mining tab.
    pow_algo: String,
    target_block_ms: u64,
    head_nonce: Option<u64>,
    head_bits: Option<u32>,
    mempool: Option<usize>,
    reward: String,
    miners: Vec<MinerRow>,
    accounts: Vec<AccountRow>,
    blocks: Vec<BlockRow>,
    /// Shielded pool value (grains) and the live de-shield drain-limiter budget,
    /// so the wallet can show how much can be de-shielded right now and when the
    /// window resets — making the circuit breaker visible instead of a silent
    /// transaction failure. `None` while offline or on a node without the RPC.
    shielded_pool: String,
    deshieldable_now: Option<u128>,
    deshield_resets_at: Option<u64>,
    /// The de-shield drain-limiter's full per-window cap (grains), so the wallet can
    /// show "X of LIMIT this window". `None`/0 when the limiter is disabled.
    deshield_limit: Option<u128>,
    /// True when `sov_getShieldedInfo` ANSWERED this poll. Distinct from "the pool is
    /// empty": a node that does not serve the method leaves every v1 figure unknown,
    /// and the UI must say so rather than render a zero.
    shielded_v1_available: bool,
    /// Pool v2 (post-quantum) state from `sov_getShieldedV2Info`. `None` means the
    /// node did not answer — it is offline, or too old to know pool v2 exists. That
    /// is a THIRD state, distinct from both "dormant" and "empty"; see [`PoolState`].
    shielded_v2: Option<ShieldedV2Info>,
    error: Option<String>,
    updated_ms: u64,
    /// LIVE peer/sync telemetry, read in-process from the embedded node every frame
    /// (not over RPC), so the Node tab shows a rolling, never-stale picture even while
    /// the loopback RPC poller is momentarily unreachable.
    ///
    /// `peers` is the count of DISTINCT authenticated remote nodes (a redundant link is
    /// never double-counted). `best_peer_height` is the tallest peer chain we have heard
    /// of. `syncing` means we are still catching up to a heavier peer chain — while true
    /// the node is downloading, not mining (it joins the existing chain before extending
    /// it). `None`/false when there is no embedded node or no P2P.
    peers: Option<usize>,
    best_peer_height: Option<u64>,
    syncing: bool,
    /// This node's measured proof-of-work rate (H/s); 0 when not actively mining.
    local_hashrate: u64,
    /// What Station can see about an OUT-OF-PROCESS miner (the standalone XUS Miner)
    /// mining to one of the operator's own accounts, read from the on-chain miner
    /// registry. `None` means no registry row belongs to the operator (or no node
    /// answered) — never a false "mining". See [`assess_external_mining`].
    external_miner: Option<ExternalMinerFacts>,
    /// The exact network fee (grains) a wallet send would pay right now, per route,
    /// straight from `sov_estimateFee` (0 on a fee-free testnet, the real cost on
    /// mainnet). Shown in the send-review modal so the spender sees the full cost.
    fee_transfer_grains: u128,
    fee_shielded_grains: u128,
    /// The node's live gas price (grains per gas unit). Needed to price the tip
    /// envelope's extra gas, which `sov_estimateFee` cannot express — it takes a
    /// route, not "route wrapped in a tip envelope".
    gas_price_grains: u128,
    /// The live blockspace auction (v0.1.98): the next-block floor, the pooled
    /// fee-rate distribution, and whether the `fee-auction` deployment is Active.
    /// Its `available` flag distinguishes "the auction is clear" from "this node
    /// did not tell us" — see [`Auction`].
    auction: Auction,
}

impl Snapshot {
    /// True iff the operator is mining RIGHT NOW, by either path: an external miner
    /// mining to one of their accounts (from the registry), or this node's own
    /// in-process miner (`local_hashrate`). This is the single source of truth the
    /// heartbeat and Mining tab read — it must never be true merely because a stale
    /// registry row exists (see [`assess_external_mining`]).
    fn is_mining(&self) -> bool {
        self.external_miner.as_ref().is_some_and(|m| m.active) || self.local_hashrate > 0
    }
}

/// UI-editable polling config, shared with the poller thread.
#[derive(Clone)]
struct Config {
    rpc: String,
    /// Accounts the poller watches for BALANCE/nonce. A superset of `mining_accounts`:
    /// it may include watch-only and operate-as names bound to a different key, which
    /// are fine to display but must NOT be trusted for mining attribution.
    accounts: Vec<String>,
    /// Accounts the operator PROVABLY controls — non-watch wallet ids (key-derived from
    /// their seed) and operate-as names verified `Control::Mine`. Only these are matched
    /// against the miner registry, so foreign hashrate can never light the MINING chip.
    mining_accounts: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock `HH:MM:SS` for log line timestamps.
fn clock_hms() -> String {
    let secs = (now_ms() / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Append a timestamped line to the shared node log, capping the buffer so it
/// cannot grow without bound. Real operational logs (startup, replay timing, RPC
/// up, block production, errors), surfaced in the Node tab.
fn push_log(logs: &Arc<Mutex<Vec<String>>>, msg: impl Into<String>) {
    let line = format!("{}  {}", clock_hms(), msg.into());
    // PERSIST FIRST. This buffer used to be memory-only, so every operational
    // log an operator might need — the sync that stalled, the error before a
    // close — died with the process. A log you cannot read after a crash is
    // not a log; the crash is exactly when you need it.
    append_session_log(&line);
    if let Ok(mut v) = logs.lock() {
        v.push(line);
        let n = v.len();
        // Keep a deep ring buffer so an operator can scroll back through a whole
        // session's history (peering churn, sync, restarts) when diagnosing.
        if n > 5_000 {
            v.drain(0..n - 5_000);
        }
    }
}

/// Path of this session's log: `<station_dir>/logs/station-<unix_secs>.log`.
///
/// One file per run, stamped at first write, so a crash's log is never mixed
/// with the next launch's — the first question after a close is "what did THAT
/// run do", and interleaved sessions make it unanswerable.
fn session_log_path() -> Option<&'static std::path::Path> {
    use std::sync::OnceLock;
    static PATH: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = station_dir().ok()?.join("logs");
        std::fs::create_dir_all(&dir).ok()?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("station-{stamp}.log"));
        // Head the file with the build, so a log always identifies which binary
        // produced it. Version confusion is not hypothetical here.
        let _ = std::fs::write(
            &path,
            format!("sov-station {} — session log\n", env!("CARGO_PKG_VERSION")),
        );
        prune_old_session_logs(&dir);
        Some(path)
    })
    .as_deref()
}

/// Append one line to the session log. Best-effort and never fatal: logging
/// that can take the app down is worse than no logging.
fn append_session_log(line: &str) {
    use std::io::Write;
    let Some(path) = session_log_path() else {
        return;
    };
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Keep the newest [`MAX_SESSION_LOGS`] logs; delete the rest.
///
/// Unbounded logs are their own failure — a wallet that fills the disk is a
/// wallet that stops working.
fn prune_old_session_logs(dir: &std::path::Path) {
    const MAX_SESSION_LOGS: usize = 20;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut logs: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("station-"))
        .collect();
    if logs.len() <= MAX_SESSION_LOGS {
        return;
    }
    // Oldest first by name — the stamp is fixed-width unix seconds, so
    // lexicographic order IS chronological order.
    logs.sort_by_key(|e| e.file_name());
    let excess = logs.len() - MAX_SESSION_LOGS;
    for e in logs.into_iter().take(excess) {
        let _ = std::fs::remove_file(e.path());
    }
}

/// Lowercase hex of `bytes` (for writing a seed into the node keystore).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Abbreviate a long (implicit) account id for display: `abcd1234…wxyz`.
fn short_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..8], &id[id.len() - 4..])
    }
}

/// Abbreviate a hybrid65 public key for display, keeping the scheme prefix:
/// `hybrid65:0x15b0fbad…37ffe7656` (the full value is on the copy button).
fn short_pubkey(pk: &str) -> String {
    match pk.split_once("0x") {
        Some((prefix, hex)) if hex.len() > 16 => {
            format!("{prefix}0x{}…{}", &hex[..8], &hex[hex.len() - 6..])
        }
        _ => pk.to_string(),
    }
}

/// Whether `account` is a human-readable NAMED account (e.g. `name.reserve.sov`)
/// rather than an implicit, key-derived hash id. This is the "named vs not yet"
/// distinction surfaced in the wallet UI.
fn is_named_account(account: &str) -> bool {
    AccountId::new(account)
        .map(|id| !id.is_implicit())
        .unwrap_or(false)
}

/// SOV Station palette — one cohesive, bank-grade theme in two MODES (a GitHub dark
/// family and a clean "retail bank" light family): a slate/white base, restrained
/// hairline borders, a confident SOV-green accent, and unambiguous success / error /
/// warning signal colors. All UI color flows from here through mode-aware accessors,
/// so flipping [`set_dark`] re-skins every panel, card, banner, pill and badge at once
/// (not just egui's base visuals) — no dark islands on a light background.
mod palette {
    use eframe::egui::Color32;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The active mode (dark by default). A process-wide atomic so every free-function
    /// panel can read it without threading state through; flipped by the ☀/🌙 toggle.
    static DARK: AtomicBool = AtomicBool::new(true);
    pub fn set_dark(dark: bool) {
        DARK.store(dark, Ordering::Relaxed);
    }
    pub fn is_dark() -> bool {
        DARK.load(Ordering::Relaxed)
    }
    /// Pick the dark or light value for the current mode.
    fn pick(dark: Color32, light: Color32) -> Color32 {
        if is_dark() {
            dark
        } else {
            light
        }
    }

    const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
        Color32::from_rgb(r, g, b)
    }

    // Each accessor returns the dark value / the calibrated light value.
    pub fn bg() -> Color32 {
        pick(rgb(13, 17, 23), rgb(246, 248, 250))
    } // app background
    pub fn panel() -> Color32 {
        pick(rgb(22, 27, 34), rgb(255, 255, 255))
    } // cards / windows
    pub fn surface() -> Color32 {
        pick(rgb(33, 38, 45), rgb(240, 242, 245))
    } // buttons / inputs at rest
    pub fn surface_hi() -> Color32 {
        pick(rgb(48, 54, 61), rgb(225, 228, 232))
    } // hovered
    pub fn field() -> Color32 {
        pick(rgb(9, 12, 17), rgb(255, 255, 255))
    } // recessed input wells
    pub fn border() -> Color32 {
        pick(rgb(48, 54, 61), rgb(208, 215, 222))
    } // hairline borders
    pub fn text() -> Color32 {
        pick(rgb(230, 237, 243), rgb(31, 35, 40))
    } // primary text
    pub fn text_dim() -> Color32 {
        pick(rgb(139, 148, 158), rgb(101, 109, 118))
    } // secondary text
    pub fn accent() -> Color32 {
        pick(rgb(46, 160, 67), rgb(31, 136, 61))
    } // SOV green — primary action
    pub fn accent_hi() -> Color32 {
        pick(rgb(63, 185, 80), rgb(46, 160, 67))
    }
    pub fn success() -> Color32 {
        pick(rgb(63, 185, 80), rgb(26, 127, 55))
    } // a transaction landed
    pub fn error() -> Color32 {
        pick(rgb(248, 81, 73), rgb(207, 34, 46))
    } // a transaction failed
    pub fn warning() -> Color32 {
        pick(rgb(210, 153, 34), rgb(154, 103, 0))
    }
    pub fn link() -> Color32 {
        pick(rgb(88, 166, 255), rgb(9, 105, 218))
    }
    /// "Actively mining" — a warm GOLD, deliberately its own hue so the MINING state on
    /// the heartbeat never reads as SYNCED green or SYNCING amber. Gold ≙ freshly minted.
    pub fn mining() -> Color32 {
        pick(rgb(240, 185, 66), rgb(214, 158, 40))
    }
    /// A faint translucent tint of `c` (for status-banner fills/strokes).
    pub fn tint(c: Color32, alpha: u8) -> Color32 {
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
    }

    /// "Armed but not yet in force" — a deployment that is defined in consensus and
    /// waiting on activation. Deliberately NOT `warning` (nothing is wrong) and NOT
    /// `error` (nothing failed): a dormant pool is the system working as designed.
    /// A cool slate-blue, distinguishable from the green/amber/red signal family for
    /// the common red-green deficiencies — and never used without a word beside it.
    pub fn dormant() -> Color32 {
        pick(rgb(125, 148, 176), rgb(85, 105, 133))
    }

    /// "We do not know" — the node did not answer. Deliberately the dimmest thing on
    /// screen: absent knowledge must never look like a measured value.
    pub fn unknown() -> Color32 {
        pick(rgb(110, 118, 129), rgb(130, 138, 148))
    }
}

/// The type scale, in points. ONE ladder, adhered to — the codebase had a scatter of
/// ad-hoc `.size(11.0) / .size(15.0) / .size(26.0)` calls with no relationship between
/// them. Ratios are ~1.2 (minor third), which keeps the steps distinguishable without
/// the jump to a consumer-app "hero" scale. An operator console earns attention with
/// weight and position, not size.
mod ty {
    /// The single largest number on a screen (a hero metric). At most one per panel.
    pub const HERO: f32 = 24.0;
    /// Panel headings.
    pub const TITLE: f32 = 16.0;
    /// Section headings inside a panel.
    pub const SECTION: f32 = 13.5;
    /// Default body text.
    pub const BODY: f32 = 13.0;
    /// Secondary/explanatory text and dense table cells.
    pub const SMALL: f32 = 11.5;
    /// The uppercase micro-label above a statistic.
    pub const MICRO: f32 = 10.5;
}

/// The spacing scale, in points — a 4pt grid. Every `add_space` in code this agent
/// touches uses one of these, so vertical rhythm is consistent instead of a drift of
/// 2.0/4.0/6.0/8.0/10.0/28.0 magic numbers.
mod sp {
    pub const XS: f32 = 2.0;
    pub const S: f32 = 4.0;
    pub const M: f32 = 8.0;
    pub const L: f32 = 12.0;
    pub const XL: f32 = 20.0;
}

/// A NUMBER that changes: rendered in the monospace face so its digits are tabular
/// and the value does not jitter horizontally as it ticks. Every live figure in this
/// app — heights, balances, hashrate, counters, anchors — goes through here.
///
/// This is not decoration. On a proportional face `1` is narrower than `8`, so a
/// height counting 11111 → 11112 visibly shifts every column to its right once a
/// second, which is exactly the motion an operator's eye is drawn to. Tabular figures
/// make a changing number readable at a glance.
fn num(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).monospace()
}

/// A number that is UNKNOWN — the node did not supply it. An em-dash in the dimmest
/// colour, never a zero. The whole honesty posture of this app in one function: a
/// value we do not have must not be renderable as a value we do.
fn num_unknown() -> egui::RichText {
    egui::RichText::new("—")
        .monospace()
        .color(palette::unknown())
}

/// One statistic: a dim uppercase micro-label with the value in tabular figures
/// beneath it. `unit` is rendered small and dim beside the value so the magnitude
/// reads first and the unit second. `value` of `None` renders as explicitly unknown.
fn stat(ui: &mut egui::Ui, label: &str, value: Option<&str>, unit: &str, size: f32) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(label.to_uppercase())
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = sp::S;
            match value {
                Some(v) => ui.label(num(v).size(size).strong().color(palette::text())),
                None => ui.label(num_unknown().size(size)),
            };
            if !unit.is_empty() && value.is_some() {
                ui.label(
                    egui::RichText::new(unit)
                        .size(ty::SMALL)
                        .color(palette::text_dim()),
                );
            }
        });
    });
}

/// A status chip that encodes state with a SHAPE GLYPH + a WORD + a colour — never
/// colour alone. `glyph` must differ per state (not just hue): this is a financial
/// tool and a colourblind operator has to read it correctly in greyscale.
fn state_chip(ui: &mut egui::Ui, glyph: &str, word: &str, col: egui::Color32) {
    egui::Frame::none()
        .fill(palette::tint(col, 28))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 140)))
        .rounding(egui::Rounding::same(4.0))
        .inner_margin(egui::Margin::symmetric(7.0, 2.0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = sp::S;
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(glyph).size(ty::SMALL).color(col));
                ui.label(
                    egui::RichText::new(word)
                        .size(ty::MICRO)
                        .strong()
                        .color(col),
                );
            });
        });
}

/// Install the cohesive theme in the requested mode (dark or light). Sets the active
/// `palette` mode FIRST (so every accessor returns the right family), then the whole
/// widget palette (rest / hover / press), recessed input wells, accent selection, link
/// color, and a little more breathing room — so every panel inherits one consistent
/// look. Called at startup and again whenever the ☀/🌙 toggle flips the mode.
fn install_theme(ctx: &egui::Context, dark: bool) {
    use egui::{Rounding, Stroke};
    palette::set_dark(dark);
    let mut style = (*ctx.style()).clone();
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let r = Rounding::same(6.0);

    v.widgets.noninteractive.bg_fill = palette::panel();
    v.widgets.noninteractive.weak_bg_fill = palette::panel();
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.noninteractive.rounding = r;

    v.widgets.inactive.bg_fill = palette::surface();
    v.widgets.inactive.weak_bg_fill = palette::surface();
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.inactive.rounding = r;

    v.widgets.hovered.bg_fill = palette::surface_hi();
    v.widgets.hovered.weak_bg_fill = palette::surface_hi();
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, palette::accent());
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.hovered.rounding = r;

    v.widgets.active.bg_fill = palette::accent();
    v.widgets.active.weak_bg_fill = palette::accent();
    v.widgets.active.bg_stroke = Stroke::new(1.0, palette::accent_hi());
    v.widgets.active.fg_stroke = Stroke::new(1.0, egui::Color32::WHITE);
    v.widgets.active.rounding = r;

    v.widgets.open = v.widgets.inactive;

    v.selection.bg_fill = palette::tint(palette::accent(), 90);
    v.selection.stroke = Stroke::new(1.0, palette::accent_hi());
    v.hyperlink_color = palette::link();
    v.warn_fg_color = palette::warning();
    v.error_fg_color = palette::error();
    v.window_fill = palette::panel();
    v.window_stroke = Stroke::new(1.0, palette::border());
    v.window_rounding = Rounding::same(10.0);
    v.panel_fill = palette::bg();
    v.extreme_bg_color = palette::field(); // text-edit / code wells
                                           // Striped rows + code wells, mode-aware (a faint stripe on whichever base).
    v.faint_bg_color = if dark {
        egui::Color32::from_rgb(26, 31, 38)
    } else {
        egui::Color32::from_rgb(244, 246, 249)
    };
    v.code_bg_color = if dark {
        egui::Color32::from_rgb(28, 33, 40)
    } else {
        egui::Color32::from_rgb(235, 238, 242)
    };

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 24.0;
    style.spacing.indent = 18.0;
    ctx.set_style(style);
}

/// The outcome of an action/transaction, for at-a-glance green/red coloring.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TxStatus {
    Ok,
    Err,
    Info,
}

/// Classify a result message as success, failure, or neutral. Robust to BOTH
/// conventions in this codebase — a leading `✓` / `✗` marker AND plain
/// "… failed: …" strings — so a failure for ANY reason colors red.
fn tx_status(msg: &str) -> TxStatus {
    if msg.contains('✗') {
        return TxStatus::Err;
    }
    let lower = msg.to_ascii_lowercase();
    const FAIL: &[&str] = &[
        "fail",
        "error",
        "reject",
        "insufficient",
        "invalid",
        "unable",
        "denied",
        "unauthorized",
        "unrecognized",
        "not a ",
        "no such",
        "too ",
        "exceeded",
        "refused",
        "timed out",
        "timeout",
        "cannot",
        "can't",
    ];
    if FAIL.iter().any(|k| lower.contains(k)) {
        return TxStatus::Err;
    }
    if msg.contains('✓') {
        return TxStatus::Ok;
    }
    TxStatus::Info
}

/// The signal color for a status (green / red / neutral).
fn status_color(s: TxStatus) -> egui::Color32 {
    match s {
        TxStatus::Ok => palette::success(),
        TxStatus::Err => palette::error(),
        TxStatus::Info => palette::text_dim(),
    }
}

/// Strip the leading status glyph (✓/✗/•) the action layer prepends, leaving the
/// human message. Shared by the result banner and the status-bar toast.
fn strip_status_glyph(msg: &str) -> &str {
    msg.trim_start_matches('✓')
        .trim_start_matches('✗')
        .trim_start_matches('•')
        .trim_start()
}

/// The text for the single-line status-bar toast: the message with its glyph stripped
/// and capped to `max_chars` (char-safe, ellipsis on overflow) so a long error can
/// never blow out the bottom-bar layout. The full text still shows in the Wallet
/// status banner.
fn toast_chip_text(msg: &str, max_chars: usize) -> String {
    let body = strip_status_glyph(msg);
    if body.chars().count() > max_chars {
        let keep = max_chars.saturating_sub(1);
        let mut s: String = body.chars().take(keep).collect();
        s.push('…');
        s
    } else {
        body.to_string()
    }
}

/// A highlighted result banner — a faint status-tinted card with the message in the
/// success (green) or failure (red) color. This is the at-a-glance "did my
/// transaction land?" signal the wallet shows after every action.
fn status_banner(ui: &mut egui::Ui, msg: &str) {
    if msg.is_empty() {
        return;
    }
    let st = tx_status(msg);
    let col = status_color(st);
    let glyph = match st {
        TxStatus::Ok => "✓",
        TxStatus::Err => "✗",
        TxStatus::Info => "•",
    };
    let body = strip_status_glyph(msg);
    egui::Frame::none()
        .fill(palette::tint(col, 28))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 130)))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 7.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(glyph).color(col).strong());
                ui.label(egui::RichText::new(body).color(col));
            });
        });
}

/// Render a one-line result message colored by outcome — green on success, red on
/// failure (for any reason), dim for neutral/progress. The inline counterpart to
/// [`status_banner`], used for the per-panel result lines (tokens, swaps, register…).
fn status_label(ui: &mut egui::Ui, msg: &str) {
    if msg.is_empty() {
        return;
    }
    ui.label(egui::RichText::new(msg).color(status_color(tx_status(msg))));
}

/// A small colored pill identifying the network (e.g. `● TESTNET · SHA-256d`),
/// tinted amber for testnet / green for mainnet — the at-a-glance "where am I".
fn network_badge(ui: &mut egui::Ui, net: Network) {
    let col = net.color();
    egui::Frame::none()
        .fill(palette::tint(col, 30))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 150)))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 3.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("● {} · {}", net.label(), net.pow_algo()))
                    .small()
                    .strong()
                    .color(col),
            );
        });
}

/// A small tinted status pill (e.g. `PRIVATE`, `PUBLIC`) in the given signal color.
fn pill(ui: &mut egui::Ui, text: &str, col: egui::Color32) {
    egui::Frame::none()
        .fill(palette::tint(col, 30))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 150)))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 3.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).small().strong().color(col));
        });
}

/// Green for a named account, amber for an unnamed (implicit) one — the colors
/// the wallet UI uses everywhere to delineate the two at a glance.
fn named_color(named: bool) -> egui::Color32 {
    if named {
        palette::success()
    } else {
        palette::warning()
    }
}

/// A deterministic, good-looking badge color for a token/asset/collectible,
/// derived from a stable key (its asset id or symbol) — so the same asset always
/// wears the same color, the wallet-UI stand-in for a token logo.
fn avatar_color(key: &str) -> egui::Color32 {
    const HUES: [(u8, u8, u8); 12] = [
        (99, 102, 241), // indigo
        (236, 72, 153), // pink
        (34, 197, 94),  // green
        (249, 115, 22), // orange
        (14, 165, 233), // sky
        (168, 85, 247), // purple
        (234, 179, 8),  // amber
        (20, 184, 166), // teal
        (239, 68, 68),  // red
        (59, 130, 246), // blue
        (132, 204, 22), // lime
        (217, 70, 239), // fuchsia
    ];
    // FNV-1a over the key: stable across runs, well-spread across the palette.
    let mut h: u32 = 2_166_136_261;
    for b in key.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    let (r, g, b) = HUES[(h as usize) % HUES.len()];
    egui::Color32::from_rgb(r, g, b)
}

/// The 1–2 letter initials shown inside a badge (uppercase alphanumerics).
fn initials_of(s: &str) -> String {
    let it: String = s
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_uppercase();
    if it.is_empty() {
        "?".to_string()
    } else {
        it
    }
}

/// Draw a circular token badge (a colored disc with the asset's initials).
fn token_avatar(ui: &mut egui::Ui, key: &str, symbol: &str, diameter: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(diameter, diameter), egui::Sense::hover());
    let color = avatar_color(key);
    let painter = ui.painter();
    painter.circle_filled(rect.center(), diameter / 2.0, color);
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initials_of(symbol),
        egui::FontId::proportional(diameter * 0.42),
        egui::Color32::WHITE,
    );
}

/// One token holding as a Phantom-style row: colored badge, symbol + short asset
/// id, and the balance right-aligned. Fills the available width.
fn token_card(ui: &mut egui::Ui, asset: &str, symbol: &str, balance_grains: &str) {
    egui::Frame::none()
        .fill(palette::surface())
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            let w = ui.available_width();
            ui.set_width(w);
            ui.horizontal(|ui| {
                token_avatar(ui, asset, symbol, 34.0);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(symbol).strong().size(15.0));
                    ui.label(
                        egui::RichText::new(short_id(asset))
                            .color(palette::text_dim())
                            .monospace()
                            .small(),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(xus(balance_grains)).strong().size(15.0));
                });
            });
        });
}

/// One registry entry as a row: badge, symbol + issuer, total supply right-aligned.
fn registry_card(ui: &mut egui::Ui, asset: &str, symbol: &str, issuer: &str, supply: &str) {
    egui::Frame::none()
        .fill(palette::surface())
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            let w = ui.available_width();
            ui.set_width(w);
            ui.horizontal(|ui| {
                token_avatar(ui, asset, symbol, 30.0);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(symbol).strong());
                    ui.label(
                        egui::RichText::new(format!("issuer {}", short_id(issuer)))
                            .color(palette::text_dim())
                            .monospace()
                            .small(),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("{} supply", xus(supply))).strong());
                });
            });
        });
}

/// A collectible tile (NFT / SNS name): a colored thumbnail with initials and a
/// caption. Returns a click response so the grid can wire "send".
fn nft_tile(ui: &mut egui::Ui, display: &str, is_sns: bool, coll: &str) -> egui::Response {
    let tile = 132.0;
    let resp = egui::Frame::none()
        .fill(palette::surface())
        .rounding(10.0)
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_width(tile);
            ui.vertical_centered(|ui| {
                let side = tile - 20.0;
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
                let color = avatar_color(if is_sns { display } else { coll });
                let painter = ui.painter();
                painter.rect_filled(rect, 8.0, color);
                painter.text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    initials_of(display),
                    egui::FontId::proportional(28.0),
                    egui::Color32::WHITE,
                );
                ui.add_space(6.0);
                ui.label(egui::RichText::new(short_id(display)).strong().small());
                if is_sns {
                    ui.label(
                        egui::RichText::new("SNS name")
                            .color(palette::success())
                            .small(),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("NFT")
                            .color(palette::text_dim())
                            .small(),
                    );
                }
            });
        })
        .response;
    resp.interact(egui::Sense::click())
}

/// A soft empty-state card: a bold title and a dim one-line explanation.
fn empty_hint(ui: &mut egui::Ui, title: &str, body: &str) {
    egui::Frame::none()
        .fill(palette::surface())
        .rounding(10.0)
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            let w = ui.available_width();
            ui.set_width(w);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(title).strong());
                ui.label(egui::RichText::new(body).color(palette::text_dim()).small());
            });
        });
}

/// Render `data` as a QR code, drawn directly with the egui painter (no image
/// backend) at roughly `size` pixels square, with a white quiet-zone border.
fn qr_widget(ui: &mut egui::Ui, data: &str, size: f32) {
    let code = match qrcode::QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            ui.label(egui::RichText::new("(QR unavailable for this address)").weak());
            return;
        }
    };
    let w = code.width();
    let colors = code.to_colors();
    let quiet = 2usize; // modules of quiet zone, each side
    let n = w + quiet * 2;
    let (rect, _resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, egui::Color32::WHITE);
    let cell = size / n as f32;
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let min = egui::pos2(
                    rect.min.x + (x + quiet) as f32 * cell,
                    rect.min.y + (y + quiet) as f32 * cell,
                );
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }
    }
}

/// Write a wallet's pool-v2 address to a plain text file under `~/.sov-station/`, with
/// a header naming what it is and stating plainly that the pool is not active. Returns
/// the path written.
///
/// This exists because **a file is the honest transport for 1,957 characters.** A QR
/// code cannot hold it legibly and no one will retype it; the realistic ways this
/// address reaches a counterparty are the clipboard and a file, so the app provides
/// both rather than pretending a scan is possible.
///
/// One cell of the pool comparison table.
///
/// The variants exist to keep four *different* absences from collapsing into one
/// ambiguous blank, which is the same discipline the three-state model applies to the
/// pool as a whole:
///   * [`Unknown`](Self::Unknown)     — the node did not answer, so we have no reading.
///   * [`NotReported`](Self::NotReported) — the node answered, but this pool's RPC does
///     not expose this figure. The pool HAS the quantity; we simply are not told it.
///     Reporting that as "unknown" would imply the node is degraded when it is not.
///   * [`Impossible`](Self::Impossible) — the quantity cannot exist yet. A dormant v2
///     pool has no balance because consensus rejects every v2 spend, which is a
///     stronger and more reassuring fact than "unknown".
///   * [`Amount`](Self::Amount)/[`Count`](Self::Count) — a real reading.
enum Cell {
    Text(String),
    Amount(u128),
    Count(u64),
    Hash(String),
    Unknown,
    NotReported(&'static str),
    Impossible(&'static str),
}

impl Cell {
    /// An amount that is only real when `real`; otherwise the explicit unknown.
    fn amount(v: Option<u128>) -> Self {
        match v {
            Some(g) => Cell::Amount(g),
            None => Cell::Unknown,
        }
    }

    fn render(&self, ui: &mut egui::Ui) {
        match self {
            Cell::Text(t) => {
                ui.label(
                    egui::RichText::new(t)
                        .size(ty::SMALL)
                        .color(palette::text()),
                );
            }
            Cell::Amount(g) => {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = sp::S;
                    ui.label(num(xus(&g.to_string())).size(ty::BODY).strong());
                    ui.label(
                        egui::RichText::new("XUS")
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                    );
                });
            }
            Cell::Count(n) => {
                ui.label(num(group_thousands(*n as u128)).size(ty::BODY).strong());
            }
            Cell::Hash(h) => {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = sp::S;
                    ui.label(num(short(h)).size(ty::SMALL));
                    copy_glyph(ui, h);
                });
            }
            // The three absences, each visually distinct and each explained on hover.
            Cell::Unknown => {
                ui.label(num_unknown().size(ty::BODY))
                    .on_hover_text("The node did not report this. It is unknown — not zero.");
            }
            Cell::NotReported(why) => {
                ui.label(
                    egui::RichText::new("not reported")
                        .size(ty::SMALL)
                        .italics()
                        .color(palette::text_dim()),
                )
                .on_hover_text(*why);
            }
            Cell::Impossible(why) => {
                ui.label(
                    egui::RichText::new("cannot exist yet")
                        .size(ty::SMALL)
                        .italics()
                        .color(palette::dormant()),
                )
                .on_hover_text(*why);
            }
        }
    }
}

/// One row of the comparison: a label and the same quantity for each pool.
struct PoolRow {
    label: &'static str,
    v1: Cell,
    v2: Cell,
}

/// Build the rows. Pure data, so the table's CONTENT is decided in one place and the
/// rendering below is only layout — which is what makes the two pools provably
/// row-aligned rather than aligned by careful hand-editing of two separate columns.
fn pool_rows(
    s: &Snapshot,
    v1_own: Option<(u128, usize, u64)>,
    v2_own: Option<(u128, usize, u64)>,
) -> Vec<PoolRow> {
    let v1_state = PoolState::classify_v1(s.online, s.shielded_v1_available);
    let v2_state = PoolState::classify_v2(s.online, s.shielded_v2.as_ref());
    let v1_real = v1_state.figures_are_real();
    let v2_real = v2_state.figures_are_real();
    let info = s.shielded_v2.clone().unwrap_or_default();

    // v1's RPC simply does not carry these; that is not a fault and must not read as one.
    const V1_NO_NOTES: &str =
        "sov_getShieldedInfo does not report pool-v1 note or nullifier counts. The pool \
         has them; this node's RPC does not expose them.";
    const V1_NO_ANCHOR: &str =
        "sov_getShieldedInfo does not report the pool-v1 anchor. The pool has one; this \
         node's RPC does not expose it.";
    // While v2 is dormant no note can exist, so this is stronger than "unknown".
    const V2_DORMANT: &str =
        "Pool v2 is not active: consensus rejects every v2 spend while signal bit 2 is \
         unarmed, so no note, nullifier or balance can exist yet. This is not a missing \
         balance.";

    // A quantity that only exists once v2 is live. Dormant ⇒ provably nothing;
    // unavailable ⇒ genuinely unknown; active ⇒ the real reading.
    let v2_live = |c: Cell| match v2_state {
        PoolState::Active => c,
        PoolState::Dormant => Cell::Impossible(V2_DORMANT),
        PoolState::Unavailable => Cell::Unknown,
    };

    vec![
        // No STATUS row: each pool's panel heading already carries its state
        // chip. Repeating it here drew the same chip twice in the same column,
        // inches apart, which is noise rather than emphasis.
        PoolRow {
            label: "cryptography",
            v1: Cell::Text(Pool::V1.crypto().to_string()),
            v2: Cell::Text(Pool::V2.crypto().to_string()),
        },
        PoolRow {
            // Stated in words for BOTH pools, including the negative one. v1 is
            // Orchard/Halo2 and its privacy is discrete-log based; presenting it as
            // quantum-safe is the most damaging thing this table could do.
            label: "post-quantum",
            v1: Cell::Text(Pool::V1.pq_claim().to_string()),
            v2: Cell::Text(Pool::V2.pq_claim().to_string()),
        },
        PoolRow {
            label: "your balance",
            v1: match (v1_real, v1_own) {
                (false, _) => Cell::Unknown,
                // Not scanned is UNKNOWN, never zero — a user with real shielded funds
                // must not be told they have none because a scan has not run.
                (true, None) => Cell::NotReported(
                    "This wallet has not been scanned yet, so its shielded balance is \
                     unknown — which is not the same as zero. Press \"Scan pool\" below.",
                ),
                (true, Some((b, _, _))) => Cell::Amount(b),
            },
            // Pool v2 is scanned by trial decapsulation, so the same rule as v1
            // applies: an unscanned wallet is UNKNOWN, never zero.
            v2: match (v2_state, v2_own) {
                (PoolState::Dormant, _) => Cell::Impossible(V2_DORMANT),
                (PoolState::Unavailable, _) => Cell::Unknown,
                (PoolState::Active, None) => Cell::NotReported(
                    "This wallet's pool-v2 notes have not been scanned yet, so its balance is \
                     unknown — which is not the same as zero. Press \"Scan pool v2\" below.",
                ),
                (PoolState::Active, Some((b, _, _))) => Cell::Amount(b),
            },
        },
        PoolRow {
            label: "pool total",
            v1: Cell::amount(v1_real.then(|| s.shielded_pool.parse::<u128>().unwrap_or(0))),
            v2: v2_live(Cell::Amount(info.pool_grains)),
        },
        PoolRow {
            label: "de-shieldable now",
            v1: Cell::amount(s.deshieldable_now.filter(|_| v1_real)),
            v2: v2_live(Cell::Amount(info.deshieldable_now)),
        },
        PoolRow {
            label: "de-shield cap / window",
            v1: Cell::amount(s.deshield_limit.filter(|_| v1_real)),
            v2: if v2_real {
                Cell::Amount(info.deshield_limit)
            } else {
                Cell::Unknown
            },
        },
        PoolRow {
            label: "window",
            v1: match (v1_real, s.deshield_resets_at) {
                (true, Some(h)) => {
                    Cell::Text(format!("resets at block {}", group_thousands(h as u128)))
                }
                (true, None) => {
                    Cell::NotReported("This node did not report a window reset height.")
                }
                (false, _) => Cell::Unknown,
            },
            v2: if v2_real {
                Cell::Text(format!(
                    "{} blocks",
                    group_thousands(info.deshield_window_blocks as u128)
                ))
            } else {
                Cell::Unknown
            },
        },
        PoolRow {
            label: "notes in pool",
            v1: if v1_real {
                Cell::NotReported(V1_NO_NOTES)
            } else {
                Cell::Unknown
            },
            v2: v2_live(Cell::Count(info.note_count)),
        },
        PoolRow {
            label: "nullifiers spent",
            v1: if v1_real {
                Cell::NotReported(V1_NO_NOTES)
            } else {
                Cell::Unknown
            },
            v2: v2_live(Cell::Count(info.nullifier_count)),
        },
        PoolRow {
            label: "anchor",
            v1: if v1_real {
                Cell::NotReported(V1_NO_ANCHOR)
            } else {
                Cell::Unknown
            },
            v2: match (v2_state, info.anchor.is_empty()) {
                (PoolState::Active, false) => Cell::Hash(info.anchor.clone()),
                (PoolState::Active, true) => Cell::Unknown,
                (PoolState::Dormant, _) => Cell::Impossible(V2_DORMANT),
                (PoolState::Unavailable, _) => Cell::Unknown,
            },
        },
    ]
}

/// The per-pool prose that must accompany any zero: the state sentence, plus the
/// wallet-specific note where there is one.
fn pool_note(ui: &mut egui::Ui, pool: Pool, state: PoolState, extra: &str) {
    // No title and no state chip here: this renders INSIDE the pool's own panel,
    // which already carries both. It used to repeat them — the chip was drawn
    // three times per pool (panel heading, STATUS row, and again here) and the
    // name twice, which is most of what made the view look noisy.
    {
        ui.label(
            egui::RichText::new(state.explanation(pool))
                .size(ty::SMALL)
                .color(if state.figures_are_real() {
                    palette::text_dim()
                } else {
                    palette::text()
                }),
        );
        if !extra.is_empty() {
            ui.add_space(sp::XS);
            ui.label(
                egui::RichText::new(extra)
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
            );
        }
    }
}

/// **The two-pool view.** SOV has two shielded pools, and the single most dangerous
/// thing this app can do is let an operator confuse them — or confuse "not active yet"
/// with "your money is gone".
///
/// ## Why a table, and why it is responsive rather than user-draggable
///
/// This was first built as two side-by-side cards. That looked reasonable and was
/// subtly wrong: two independently-flowing columns only line up by coincidence. As
/// soon as one pool's explanatory line wrapped to two lines, or one column had an
/// extra figure, every row below it drifted against its counterpart — so "pool total"
/// in v1 sat beside "de-shieldable now" in v2. For a comparison, that is not cosmetic:
/// the whole value of putting the pools together is reading ACROSS a row, and drift
/// makes the reader compare the wrong quantities.
///
/// A `Grid` fixes it by construction — a row's height is the max of its cells, so the
/// two pools cannot drift — and the three column widths are pinned in the header, so
/// the pools are always exactly equal and never sized by whichever happened to contain
/// the longer string.
///
/// It is deliberately NOT user-resizable. A draggable splitter here would let the
/// operator make the two pools unequal, destroying the one property the layout exists
/// to guarantee. Instead it is fully responsive: the columns divide the available
/// width, and below the point where a value column would become too narrow to hold a
/// figure like `110,557.53450464 XUS` the table collapses to one pool above the other,
/// each full width. That threshold is computed from the width the content actually
/// needs, not guessed.
fn shielded_pools_view(
    ui: &mut egui::Ui,
    s: &Snapshot,
    v1_own: Option<(u128, usize, u64)>,
    v2_own: Option<(u128, usize, u64)>,
) {
    let v1_state = PoolState::classify_v1(s.online, s.shielded_v1_available);
    let v2_state = PoolState::classify_v2(s.online, s.shielded_v2.as_ref());
    let rows = pool_rows(s, v1_own, v2_own);

    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = sp::M;
        ui.label(
            egui::RichText::new("SHIELDED POOLS")
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.label(
            egui::RichText::new(
                "Two independent pools. Value in one is not value in the other, and \
                 neither can be spent into the other except through a transparent balance.",
            )
            .size(ty::SMALL)
            .color(palette::text_dim()),
        );
    });
    ui.add_space(sp::M);

    // ── Column sizing, from the content ───────────────────────────────────────
    //
    // The widest value any cell holds is a full-precision amount plus its unit
    // (`110,557.53450464 XUS`), measured in the real font rather than assumed, so the
    // collapse threshold tracks the actual type scale instead of a magic number.
    let value_w = ui
        .fonts(|f| {
            f.layout_no_wrap(
                "110,557.53450464 XUS".to_owned(),
                egui::FontId::monospace(ty::BODY),
                palette::text(),
            )
            .size()
            .x
        })
        .max(120.0);
    let label_w = ui
        .fonts(|f| {
            f.layout_no_wrap(
                "de-shield cap / window".to_owned(),
                egui::FontId::proportional(ty::SMALL),
                palette::text(),
            )
            .size()
            .x
        })
        .max(100.0);

    let gap = 18.0;
    let avail = ui.available_width();
    // Two value columns plus the label column, plus the grid's own spacing.
    let needed = label_w + 2.0 * value_w + 3.0 * gap;
    let side_by_side = avail >= needed;

    // ── The prose that must sit beside any zero ───────────────────────────────
    let v1_extra = match (v1_state, v1_own) {
        (PoolState::Unavailable, _) => String::new(),
        (_, None) => "Not scanned yet — press \"Scan pool\" below. Your balance is unknown \
                      until then, which is not the same as zero."
            .to_string(),
        (_, Some((_, notes, h))) => format!(
            "{} unspent note(s), scanned to height {}.",
            group_thousands(notes as u128),
            group_thousands(h as u128)
        ),
    };
    let v2_extra = match v2_state {
        PoolState::Dormant => "No v2 note can exist yet: consensus rejects every v2 spend \
                               while bit 2 is unarmed. This is not a missing balance."
            .to_string(),
        _ => String::new(),
    };

    // ── Two INDEPENDENT panels, with a draggable split ────────────────────────
    //
    // Previously this was one wide grid holding both pools, which had two faults
    // an operator could see at a glance: the value columns split ALL remaining
    // width, so on a wide window each pool's figures sat at the far left of an
    // enormous cell with a canyon between them; and the pools then appeared a
    // SECOND time below as prose cards, so everything was stated twice.
    //
    // Each pool is now a self-contained panel — its own heading, state chip,
    // rows and note — and the divider between them is draggable, so an operator
    // can widen whichever pool they are actually reading. The split is a
    // FRACTION, so it survives window resizing instead of stranding a pane.
    // ── Two EQUAL panels, responsive and capped ───────────────────────────────
    //
    // Equal by construction, because the whole point of putting the pools side
    // by side is comparison: unequal panes make one look more substantial than
    // the other and invite reading a layout accident as a difference in the
    // data. A draggable split is deliberately NOT offered — it can only make
    // them unequal, which destroys the one property this layout exists for.
    //
    // Capped, because uncapped they stretched to opposite edges of a wide
    // display with a canyon of dead space between the figures. The cap is the
    // width the content actually needs — the label column plus the widest real
    // value plus padding — so a wider window centres the pair instead of
    // inflating it.
    if side_by_side {
        let avail = ui.available_width();
        let gap = sp::L;
        let natural = label_w + value_w + 4.0 * sp::M;
        let col_w = ((avail - gap) * 0.5).min(natural).max(value_w);
        // LEFT-ALIGNED, not centred. Centring left a wide empty margin on the
        // left of a large window while every other element on the page starts
        // at the same gutter — the pools looked detached from the panel rather
        // than part of it.
        ui.horizontal_top(|ui| {
            for (pool, state, extra, pick) in [
                (Pool::V1, v1_state, &v1_extra, 1usize),
                (Pool::V2, v2_state, &v2_extra, 2usize),
            ] {
                ui.allocate_ui_with_layout(
                    egui::vec2(col_w, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(col_w);
                        ui.set_max_width(col_w);
                        pool_panel(ui, pool, state, &rows, pick, label_w, extra);
                    },
                );
                if pick == 1 {
                    ui.add_space(gap);
                }
            }
        });
    } else {
        // Narrow: stacked, full width each. The wallet panel is already inside a
        // vertical ScrollArea, so extra height scrolls rather than clipping —
        // nothing becomes unreachable at the minimum window size.
        pool_panel(ui, Pool::V1, v1_state, &rows, 1, label_w, &v1_extra);
        ui.add_space(sp::M);
        pool_panel(ui, Pool::V2, v2_state, &rows, 2, label_w, &v2_extra);
    }
}

/// One pool, complete and self-contained: heading, state chip, its rows, and the
/// prose that must accompany a zero. `pick` selects which side of each row to
/// render (1 = v1, 2 = v2).
#[allow(clippy::too_many_arguments)]
fn pool_panel(
    ui: &mut egui::Ui,
    pool: Pool,
    state: PoolState,
    rows: &[PoolRow],
    pick: usize,
    label_w: f32,
    extra: &str,
) {
    card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = sp::M;
            ui.label(
                egui::RichText::new(pool.name())
                    .size(ty::SECTION)
                    .strong()
                    .color(palette::text()),
            );
            state_chip(ui, state.glyph(), state.word(), state.color());
        });
        ui.add_space(sp::S);
        egui::Grid::new(format!("pool-grid-{pick}"))
            .num_columns(2)
            .striped(true)
            .spacing([sp::M, 6.0])
            .show(ui, |ui| {
                for r in rows {
                    ui.horizontal(|ui| {
                        ui.set_min_width(label_w);
                        ui.label(
                            egui::RichText::new(r.label.to_uppercase())
                                .size(ty::MICRO)
                                .color(palette::text_dim()),
                        );
                    });
                    if pick == 1 {
                        r.v1.render(ui);
                    } else {
                        r.v2.render(ui);
                    }
                    ui.end_row();
                }
            });
        // The prose belongs INSIDE the pool it describes. It used to be repeated
        // as a separate card below both pools, which said everything twice; the
        // sentences themselves are load-bearing, though — they are what stops an
        // operator reading a dormant or unscanned zero as vanished funds.
        ui.add_space(sp::S);
        pool_note(ui, pool, state, extra);
    });
}

/// The address is PUBLIC key material — a receiving address, not a secret — so it is
/// written with normal permissions, unlike the keystore.
fn export_v2_address(addr: &str, owner_tag: &str) -> Result<String, String> {
    // Through `station_dir`, NOT `home_dir().join(".sov-station")` — otherwise a dev
    // build with `SOV_STATION_DIR` set would still write into the operator's live
    // wallet directory, which is the entire thing that override exists to prevent.
    let dir = station_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(v2_address_filename(owner_tag));
    let body = format!(
        "SOV pool-v2 (post-quantum shielded) receiving address\n\
         owner tag : {owner_tag}\n\
         length    : {} characters\n\
         \n\
         POOL V2 IS NOT ACTIVE. Its consensus activation signal (bit 2) is not armed,\n\
         so every pool-v2 spend is rejected by every node. Nothing can be sent to this\n\
         address yet. It is derived from your seed and is safe to record now.\n\
         \n\
         {addr}\n",
        addr.chars().count()
    );
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

/// The pool-v2 receive presentation.
///
/// ## Why this looks nothing like the other three receive addresses
///
/// A `xusq1…` address carries an ML-KEM-768 encapsulation key: 1,184 bytes of public
/// key material plus a 32-byte owner tag, which is 1,216 bytes and ~1,957 bech32m
/// characters. That is not a long string, it is three orders of magnitude past what an
/// address widget is built for, and it does not compress — the bytes are pseudorandom
/// by construction.
///
/// Four presentations were considered:
///   * **QR code — rejected.** The payload needs QR version 40 (177×177 modules) even
///     in uppercase-alphanumeric mode. In the 132 px the other addresses use, one
///     module is under a pixel; at a scannable ~4 px/module it would need a 700 px
///     square, larger than the panel, and would still fail on a phone camera at any
///     realistic distance. Rendering one would be a control that *looks* like it works.
///   * **Full inline wrap — rejected.** ~25 wrapped lines pushes every control below it
///     off screen and makes the Receive view unusable for the addresses that do work.
///   * **Truncation only — rejected.** Nothing to hand a counterparty.
///   * **Adopted: a verifiable fingerprint, an elided address, a bounded scroll well,
///     and two real export paths.** The 32-byte owner tag is what a human can actually
///     compare aloud or by eye; the head…tail elision confirms at a glance that the
///     right thing is on the clipboard; the scroll well makes the full value inspectable
///     without letting it consume the layout; and clipboard + file are the only two ways
///     a string this size genuinely moves between machines.
///
/// The dormancy disclosure is rendered FIRST, above the address, so it cannot be
/// scrolled past or missed.
fn v2_address_block(
    ui: &mut egui::Ui,
    addr: &str,
    owner_tag: &str,
    state: PoolState,
    did_copy: &mut bool,
) {
    ui.add_space(sp::S);
    card(ui, |ui| {
        // 1. State first — before the address, never after it.
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("POOL V2 · POST-QUANTUM")
                    .size(ty::MICRO)
                    .color(palette::text_dim()),
            );
            state_chip(ui, state.glyph(), state.word(), state.color());
        });
        ui.add_space(sp::S);
        ui.label(
            egui::RichText::new(state.explanation(Pool::V2))
                .size(ty::SMALL)
                .color(palette::text()),
        );
        if state != PoolState::Active {
            ui.add_space(sp::XS);
            ui.label(
                egui::RichText::new(
                    "This address is derived from your seed, so it is correct and worth \
                     recording now — but no one can pay it until the pool activates.",
                )
                .size(ty::SMALL)
                .color(palette::text_dim()),
            );
        }

        ui.add_space(sp::M);
        ui.separator();
        ui.add_space(sp::M);

        // 2. The fingerprint an operator can actually verify by eye.
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("OWNER TAG")
                    .size(ty::MICRO)
                    .color(palette::text_dim()),
            );
            ui.label(num(owner_tag).size(ty::SMALL).color(palette::text()));
            copy_glyph(ui, owner_tag);
        });
        ui.label(
            egui::RichText::new(
                "The address's 32-byte fingerprint — short enough to read out or compare \
                 against a backup. The full address below is too long to check by eye.",
            )
            .size(ty::SMALL)
            .color(palette::text_dim()),
        );

        ui.add_space(sp::M);

        // 3. The address: elided head…tail for at-a-glance identity.
        let len = addr.chars().count();
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("ADDRESS")
                    .size(ty::MICRO)
                    .color(palette::text_dim()),
            );
            ui.label(
                egui::RichText::new(format!("{} characters", group_thousands(len as u128)))
                    .size(ty::MICRO)
                    .color(palette::text_dim()),
            );
        });
        ui.label(num(truncate_middle(addr, 22, 12)).size(ty::SMALL));

        ui.add_space(sp::S);

        // 4. The full value — inspectable, but bounded so it can never eat the panel.
        egui::Frame::none()
            .fill(palette::field())
            .stroke(egui::Stroke::new(1.0, palette::border()))
            .rounding(egui::Rounding::same(4.0))
            .inner_margin(egui::Margin::same(6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .id_salt("v2_addr_full")
                    .max_height(84.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // Selectable so it can be copied by hand in part, e.g. to
                        // diff two addresses; `wrap` keeps it inside the well.
                        ui.add(
                            egui::Label::new(num(addr).size(10.5).color(palette::text_dim()))
                                .wrap()
                                .selectable(true),
                        );
                    });
            });

        ui.add_space(sp::M);

        // 5. The two transports that actually work at this size.
        ui.horizontal(|ui| {
            if ui
                .button("Copy address")
                .on_hover_text("Put all of it on the clipboard.")
                .clicked()
            {
                ui.output_mut(|o| o.copied_text = addr.to_owned());
                *did_copy = true;
            }
            if ui
                .button("Export to file…")
                .on_hover_text(
                    "Write the address to a text file under ~/.sov-station/, with a header \
                     recording that the pool is not active yet.",
                )
                .clicked()
            {
                let msg = match export_v2_address(addr, owner_tag) {
                    Ok(p) => format!("✓ v2 address written to {p}"),
                    Err(e) => format!("✗ could not write the v2 address file: {e}"),
                };
                ui.ctx()
                    .data_mut(|d| d.insert_temp(v2_export_msg_id(), msg));
            }
            ui.label(
                egui::RichText::new("no QR code — see below")
                    .size(ty::MICRO)
                    .color(palette::text_dim()),
            );
        });
        // The export result, if one happened this session.
        if let Some(msg) = ui.ctx().data(|d| d.get_temp::<String>(v2_export_msg_id())) {
            ui.add_space(sp::S);
            status_label(ui, &msg);
        }

        ui.add_space(sp::S);
        // The absent QR is a deliberate decision, so it is explained rather than
        // silently missing — an operator wondering "where is the QR?" gets an answer.
        ui.label(
            egui::RichText::new(
                "No QR code is shown: an ML-KEM-768 encapsulation key needs a 177×177-module \
                 QR, which is not scannable at any size that fits this window. Post-quantum \
                 key material does not compress. Use Copy or Export instead.",
            )
            .size(ty::SMALL)
            .color(palette::text_dim()),
        );
    });
}

/// egui-memory key for the last v2-address export result (so the message survives the
/// frame the button was clicked in, without adding a `Station` field).
fn v2_export_msg_id() -> egui::Id {
    egui::Id::new("sov_v2_export_msg")
}

fn field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Grains → a trimmed `XUS` decimal string (1 XUS = 100,000,000 grains).
fn xus(grains: &str) -> String {
    let g: u128 = grains.parse().unwrap_or(0);
    let whole = g / 100_000_000;
    let frac = g % 100_000_000;
    let whole = group_thousands(whole);
    if frac == 0 {
        whole
    } else {
        let s = format!("{frac:08}");
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

/// Group an integer with comma thousands separators: `1234567` → `1,234,567`.
fn group_thousands(n: u128) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn short(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..12], &s[s.len() - 6..])
    }
}

/// Elide the middle of a long string, keeping `head` leading and `tail` trailing
/// CHARACTERS. Char-safe (never splits a UTF-8 sequence, so it cannot panic on any
/// input), and a no-op when the string already fits — so a short address is shown
/// whole rather than pointlessly ellipsised.
///
/// This is the display half of the pool-v2 address problem: an `xusq1…` address is
/// ~1,957 characters, and the only parts a human can meaningfully verify by eye are
/// its ends. The full value is always available to copy — this never becomes the only
/// form on screen.
fn truncate_middle(s: &str, head: usize, tail: usize) -> String {
    let n = s.chars().count();
    if n <= head + tail + 1 {
        return s.to_string();
    }
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(n - tail).collect();
    format!("{start}…{end}")
}

/// A filesystem-safe filename for exporting a pool-v2 address, bound to the owner tag
/// so two wallets' exports can never be confused for one another. The tag is hex from
/// the chain, but this defends against any non-hex input reaching a path anyway.
fn v2_address_filename(owner_tag_hex: &str) -> String {
    let tag: String = owner_tag_hex
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(16)
        .collect();
    if tag.is_empty() {
        "sov-pool-v2-address.txt".to_string()
    } else {
        format!("sov-pool-v2-address-{tag}.txt")
    }
}

/// A grains figure that arrived as a JSON *string* (the wire form for values that can
/// exceed 2^53). Absent or unparseable → 0, but callers only reach here once the RPC
/// has ANSWERED, so a 0 is the node's own reading and never a stand-in for "unknown" —
/// that case is the absence of the whole [`ShieldedV2Info`].
fn grains_field(v: &Value, key: &str) -> u128 {
    v.get(key)
        .and_then(Value::as_str)
        .and_then(|x| x.parse::<u128>().ok())
        .unwrap_or(0)
}

/// Parse a `sov_getShieldedV2Info` reply. Pure — the unit under test for the wire→UI
/// mapping, so a field rename on the node side fails a test rather than silently
/// rendering zeros in a wallet.
///
/// Returns `None` unless the reply is an object carrying a BOOLEAN `active` field.
/// That guard is load-bearing, not defensive tidiness: `active` is the only thing
/// that separates [`PoolState::Dormant`] from [`PoolState::Active`], so a reply we
/// cannot read it from is a reply we cannot classify — and an unclassifiable pool is
/// UNAVAILABLE, never "dormant with a zero balance". Without this, a node answering
/// `null`, or a future node that renames the flag, would render a confident
/// "NOT ACTIVE YET — 0 XUS" that we did not actually learn from anybody.
fn shielded_v2_info(v: &Value) -> Option<ShieldedV2Info> {
    let active = v.get("active").and_then(Value::as_bool)?;
    Some(ShieldedV2Info {
        active,
        // `poolValue` is a Balance, which serialises as a grains string.
        pool_grains: field(v, "poolValue").parse::<u128>().unwrap_or(0),
        note_count: v.get("noteCount").and_then(Value::as_u64).unwrap_or(0),
        nullifier_count: v.get("nullifierCount").and_then(Value::as_u64).unwrap_or(0),
        anchor: field(v, "anchor"),
        deshieldable_now: grains_field(v, "deshieldableNowGrains"),
        deshield_limit: grains_field(v, "deshieldLimitGrains"),
        deshield_window_blocks: v
            .get("deshieldWindowBlocks")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        window_resets_at: v
            .get("windowResetsAtHeight")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        height: v.get("height").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// One full poll of the node into a fresh snapshot.
fn poll(client: &RpcClient, cfg: &Config) -> Snapshot {
    let mut s = Snapshot::default();
    match client.chain_id() {
        Ok(id) => {
            s.online = true;
            s.chain_id = id;
        }
        Err(e) => {
            s.error = Some(e.to_string());
            s.updated_ms = now_ms();
            return s;
        }
    }
    s.height = client.height().ok();
    if let Ok(head) = client.head() {
        s.head_hash = head.hash().to_hex();
        // The head block's proof of work: the nonce a miner found and the compact
        // target it had to beat. These are the literal "work" of Nakamoto consensus.
        s.head_nonce = Some(head.header.nonce);
        s.head_bits = Some(head.header.bits);
    }
    if let Ok(v) = client.call("sov_getStateRoot", json!({})) {
        s.state_root = v.as_str().unwrap_or_default().to_string();
    }
    if let Ok(v) = client.call("sov_getSupply", json!({})) {
        s.supply_mined = field(&v, "mined");
        s.supply_total = field(&v, "total");
    }
    if let Ok(v) = client.call("sov_getShieldedInfo", json!({})) {
        s.shielded_v1_available = true;
        s.shielded_pool = field(&v, "poolValue");
        s.deshieldable_now = v
            .get("deshieldableNowGrains")
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<u128>().ok());
        s.deshield_resets_at = v.get("windowResetsAtHeight").and_then(Value::as_u64);
        s.deshield_limit = v
            .get("deshieldLimitGrains")
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<u128>().ok());
    }
    // Pool v2 (post-quantum). A node too old to know the method exists simply errors,
    // and we leave this `None` — which the UI renders as the explicitly UNAVAILABLE
    // state, never as an empty pool. Served even while the deployment is dormant, so
    // an answer here is a real reading whatever `active` says.
    s.shielded_v2 = client
        .call("sov_getShieldedV2Info", json!({}))
        .ok()
        .and_then(|v| shielded_v2_info(&v));
    if let Ok(v) = client.call("sov_getDifficulty", json!({})) {
        s.difficulty = field(&v, "sha256d");
        s.pow_algo = field(&v, "algo");
        s.target_block_ms = v.get("targetBlockMs").and_then(Value::as_u64).unwrap_or(0);
    }
    // The live per-route network fee, straight from consensus (0 on a fee-free
    // testnet, the real cost on mainnet) — surfaced in the send-review modal. A node
    // without the method just reports no fee (graceful on older peers).
    let estimate = |kind: &str| -> Option<Value> {
        client.call("sov_estimateFee", json!({ "kind": kind })).ok()
    };
    let fee_field = |v: &Option<Value>, key: &str| -> u128 {
        v.as_ref()
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .and_then(|g| g.parse::<u128>().ok())
            .unwrap_or(0)
    };
    let transfer_estimate = estimate("transfer");
    let shielded_estimate = estimate("shielded");
    s.fee_transfer_grains = fee_field(&transfer_estimate, "feeGrains");
    s.fee_shielded_grains = fee_field(&shielded_estimate, "feeGrains");
    // The node's live gas price, so Station can price the one thing
    // `sov_estimateFee` has no parameter for: the extra gas a tip ENVELOPE costs
    // on top of the bare route (see `auction::route_fee_grains`).
    s.gas_price_grains = fee_field(&transfer_estimate, "gasPriceGrains");
    // The live blockspace auction. All three calls are ADDITIVE and optional: a
    // node too old to serve them errors, and `Auction::from_rpc` then reports
    // `available = false`, which the send form renders as an explicit UNKNOWN.
    // Station must keep working against an old node, so nothing here is fatal.
    let histogram = client.call("sov_getMempoolHistogram", json!({})).ok();
    let mempool_info = client.call("sov_getMempoolInfo", json!({})).ok();
    // Tips are only LEGAL once the `fee-auction` deployment is Active — below
    // that height an `Action::Tipped` is a hard consensus rejection, so a wallet
    // that tipped anyway would build a transaction that can never be mined.
    let fee_auction_active = client
        .call("sov_getDeployments", json!({}))
        .ok()
        .is_some_and(|v| auction::deployment_active(&v, FEE_AUCTION_DEPLOYMENT));
    s.auction = Auction::from_rpc(
        histogram.as_ref(),
        mempool_info.as_ref(),
        fee_auction_active,
    );
    s.mempool = client.mempool_size().ok();
    if let Ok(r) = client.mint_reward() {
        s.reward = r.grains().to_string();
    }
    if let Ok(Value::Array(rows)) = client.call("sov_getMiners", json!({})) {
        s.miners = rows
            .iter()
            .map(|r| MinerRow {
                account: field(r, "account"),
                blocks: r.get("blocksMined").and_then(Value::as_u64).unwrap_or(0),
                first: r
                    .get("firstSeenHeight")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                last: r.get("lastSeenHeight").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect();
    }
    for acct in &cfg.accounts {
        s.accounts.push(account_row(client, acct));
    }
    if let Some(h) = s.height {
        let from = h.saturating_sub(11);
        for height in (from..=h).rev() {
            if let Ok(d) = client.call("sov_getBlockDigest", json!({ "height": height })) {
                if !d.is_null() {
                    s.blocks.push(block_row(height, &d));
                }
            }
        }
    }
    s.updated_ms = now_ms();
    s
}

fn account_row(client: &RpcClient, account: &str) -> AccountRow {
    let id = match AccountId::new(account) {
        Ok(id) => id,
        Err(_) => {
            return AccountRow {
                account: account.to_string(),
                balance: "invalid id".to_string(),
                ..Default::default()
            }
        }
    };
    let balance = client.balance(&id).map(|b| b.grains().to_string()).ok();
    let nonce = client.nonce(&id).ok();
    let (key_state, key) = match client.account(&id) {
        Ok(Some(a)) => match a.key {
            Some(k) => ("key set", k.to_string()),
            None => ("keyless", String::new()),
        },
        Ok(None) => ("absent", String::new()),
        Err(_) => ("unknown", String::new()),
    };
    AccountRow {
        account: account.to_string(),
        balance: balance.unwrap_or_else(|| "—".to_string()),
        nonce: nonce
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
        key_state: key_state.to_string(),
        key,
    }
}

fn block_row(height: u64, digest: &Value) -> BlockRow {
    let mut row = BlockRow {
        height,
        timestamp_ms: digest
            .get("timestampMs")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        nonce: digest.get("nonce").and_then(Value::as_u64).unwrap_or(0),
        hash: digest
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        prev_hash: digest
            .get("prevHash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        state_root: digest
            .get("stateRoot")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        bits: digest.get("bits").and_then(Value::as_u64).unwrap_or(0) as u32,
        tx_count: digest
            .get("txIds")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0),
        ..Default::default()
    };
    let cb = digest.get("coinbase");
    if let Some(cb) = cb.filter(|c| !c.is_null()) {
        row.reward = field(cb, "reward");
        if let Some(Value::Array(recips)) = cb.get("recipients") {
            for r in recips {
                let amt = field(r, "amount");
                if r.get("role").and_then(Value::as_str) == Some("miner") {
                    row.miner = field(r, "account");
                    row.miner_amount = amt;
                }
            }
        }
    }
    row
}

/// A wallet held for the session. The on-chain `account` is **key-derived**
/// (an implicit id = `hex(blake3(pubkey))`), so it cannot collide with — or be
/// squatted onto — anyone else's account; the user-supplied `label` is a local
/// display name only. The 32-byte `seed` is the secret; the signing keypair is
/// re-derived from it on demand (`Keypair` is deliberately neither `Clone` nor
/// stored), and the shielded + unified addresses follow from the same seed.
struct LoadedWallet {
    label: String,
    account: String,
    public_key: String,
    seed: [u8; 32],
    shielded: String,
    unified: String,
    /// The POOL-V2 (post-quantum) receiving address this seed controls, `xusq1…`.
    /// Derived exactly as `sov-wallet z2-address <seed_hex>` does — same key, same
    /// encoding — so the two always agree.
    ///
    /// Derived and displayable TODAY even though the pool is dormant: the address is
    /// a property of the seed, not of the deployment, so an operator can record it in
    /// their backup now. Nothing can be sent to it until bit 2 arms, and every surface
    /// that shows it says so.
    shielded_v2: String,
    /// The v2 owner tag (32-byte hex) — the short, human-checkable fingerprint of the
    /// v2 address. At ~1,957 characters the address itself cannot be compared by eye;
    /// this can.
    v2_owner_tag: String,
    /// The BIP-39 recovery phrase, when known (generated/imported here, or loaded
    /// from a keystore that stored it). `None` for a wallet restored from a raw
    /// seed only — that wallet still works, but its phrase cannot be re-shown
    /// (BIP-39 → seed is one-way). Held in-session; persisted only in the
    /// encrypted keystore.
    mnemonic: Option<String>,
    /// A NAMED account this wallet's key also controls (e.g. a genesis-bound
    /// `name.reserve.sov`). When set, send/activate/de-shield act AS this account,
    /// signing with the same key. `None` = operate the wallet's own implicit id.
    operate_as: Option<String>,
    /// Watch-only: added from a PUBLIC KEY with no private key on this machine, so
    /// it can monitor balances/names/NFTs but cannot sign. Spending is done via the
    /// air-gapped flow (build unsigned here → sign on the offline machine that
    /// holds the seed → broadcast here). `seed` is unused (zeroed) when true.
    watch_only: bool,
}

impl LoadedWallet {
    fn from_seed(label: String, seed: [u8; 32], mnemonic: Option<String>) -> Result<Self, String> {
        // The on-chain identity IS the key's fingerprint — never a typed name —
        // so a coinbase paid here is claimable only by this wallet's key.
        let pk = Keypair::hybrid_from_seed(seed).public_key();
        let account = pk.implicit_account_id().to_string();
        // The full `hybrid65:0x…` key — what you hand over to bind a NAMED
        // genesis account (e.g. a tax account) to this wallet. Safe to share.
        let public_key = pk.to_string();
        let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
        let shielded = encode_shielded(&zkey.address());
        let unified = AccountId::new(&account)
            .ok()
            .and_then(|id| UnifiedAddress::new(Some(id), Some(zkey.address())).ok())
            .map(|u| u.encode())
            .unwrap_or_default();
        // Pool v2 (post-quantum). Same derivation the CLI's `z2-address` uses, so the
        // station and the wallet binary always agree on what a seed controls.
        let pqkey = PqShieldedKey::from_leaf_seed(&seed);
        let shielded_v2 = encode_shielded_v2(&pqkey.address());
        let v2_owner_tag = hex_lower(&pqkey.owner_tag().to_bytes());
        Ok(LoadedWallet {
            label,
            account,
            public_key,
            seed,
            shielded,
            unified,
            shielded_v2,
            v2_owner_tag,
            mnemonic,
            operate_as: None,
            watch_only: false,
        })
    }

    /// Build a WATCH-ONLY wallet from a public key (the `hybrid65:0x…` form, or a
    /// bare Ed25519 hex). It derives the same implicit account a real wallet would,
    /// so it monitors that account — but holds no private key and cannot sign.
    fn watch_only(label: String, public_key_str: &str) -> Result<Self, String> {
        let pk: PublicKey =
            serde_json::from_value(serde_json::Value::String(public_key_str.trim().to_string()))
                .map_err(|e| format!("not a valid public key: {e}"))?;
        let account = pk.implicit_account_id().to_string();
        Ok(LoadedWallet {
            label,
            account,
            public_key: pk.to_string(),
            seed: [0u8; 32],
            shielded: String::new(), // no viewing key without the seed
            unified: String::new(),
            // A watch-only wallet holds no seed, so it cannot derive a v2 address.
            // Left empty and rendered as "not derivable" — never as a placeholder.
            shielded_v2: String::new(),
            v2_owner_tag: String::new(),
            mnemonic: None,
            operate_as: None,
            watch_only: true,
        })
    }

    /// The account this wallet currently acts as: a linked named account if one
    /// is set, else the wallet's own implicit id. All on-chain actions sign with
    /// this wallet's key but name this account as the transaction signer.
    fn effective_account(&self) -> String {
        self.operate_as
            .clone()
            .unwrap_or_else(|| self.account.clone())
    }

    /// The key under which this wallet's SCANNED POOL VIEWS are stored (see
    /// [`ScannedPools`]). It is the wallet's own implicit id — the fingerprint of
    /// the key that decrypts those notes — deliberately NOT `effective_account()`:
    /// linking or unlinking a named account changes who signs, never which notes
    /// the seed controls, so a scan must not be filed under a name that can move.
    fn scan_key(&self) -> String {
        self.account.clone()
    }
}

/// Memory hygiene: when a wallet is dropped (removed, replaced, or on shutdown)
/// scrub every byte that could reconstruct or spend the key — the seed, the BIP-39
/// phrase, and the shielded viewing key — so they don't survive in freed heap, a
/// swap page, or a core dump. The public id / account / unified address are not
/// secret and are left as-is.
impl Drop for LoadedWallet {
    fn drop(&mut self) {
        self.seed.zeroize();
        if let Some(phrase) = self.mnemonic.as_mut() {
            phrase.zeroize();
        }
        self.shielded.zeroize();
    }
}

/// Status of the most recent wallet action. `generate`/`import` are instant;
/// `send`/`activate` run on a worker thread (a shielded send first builds the
/// Halo2 prover), so the UI shows progress without freezing.
#[derive(Clone, Default)]
struct ActionState {
    busy: bool,
    message: String,
}

/// The selected wallet's scanned shielded-pool view (recomputed on demand by
/// trial-decrypting the chain — the pool is private, so only the holder can).
#[derive(Clone, Default)]
struct ShieldedView {
    scanning: bool,
    account: String,
    balance: u64, // unspent pool balance, in grains
    notes: usize, // unspent note count
    scanned_height: u64,
    message: String,
}

impl ShieldedView {
    /// What this view may CLAIM for `account`: `Some((balance_grains, notes,
    /// scanned_height))` only when it was scanned FOR that wallet and a scan has
    /// actually completed. `None` is UNKNOWN — which every caller renders as
    /// unknown, never as a zero balance (a wallet nobody scanned is not empty;
    /// it is unexamined).
    ///
    /// A pure function so the "whose figures are these?" decision is testable
    /// rather than re-derived inside paint code.
    fn own_figures(&self, account: &str) -> Option<(u128, usize, u64)> {
        (self.account == account && self.scanned_height > 0).then_some((
            self.balance as u128,
            self.notes,
            self.scanned_height,
        ))
    }
}

/// Everything the UI knows when deciding whether a pool-v2 action may proceed.
///
/// This exists so that NO money-moving decision lives inside a UI closure. The
/// closure gathers facts; [`v2_allows`] decides. That makes the decision a pure
/// function of stated inputs, which can then be swept exhaustively in tests
/// rather than reasoned about by reading paint code.
#[derive(Clone, Copy, Debug)]
struct V2Guard {
    /// Signal bit 2 is Active at this height.
    pool_active: bool,
    /// The scanned view belongs to the wallet currently selected.
    for_this_wallet: bool,
    /// This wallet's pool-v2 notes have actually been scanned.
    scanned: bool,
    /// Unspent pool-v2 note count.
    notes: usize,
    /// Another action (or a scan) is already running.
    busy: bool,
    /// Scanned pool-v2 balance, in grains.
    balance_grains: u128,
    /// The node's live per-window de-shield budget, if it reports one.
    window_budget: Option<u128>,
}

impl V2Guard {
    /// The most that may leave the pool right now: balance, capped by the
    /// window budget when the node reports one.
    fn deshield_cap(&self) -> u128 {
        match self.window_budget {
            Some(b) => self.balance_grains.min(b),
            None => self.balance_grains,
        }
    }
}

/// A pool-v2 action awaiting permission.
#[derive(Clone, Copy, Debug)]
enum V2Intent<'a> {
    /// Transparent -> pool v2. Spends no notes, so it needs no scan.
    /// `to` empty shields to THIS wallet; otherwise it must be a pool-v2
    /// address (shielding to a third party, the v2 analogue of a v1 transfer
    /// to an `xus1…` recipient).
    Shield { to: &'a str, amount: Option<u128> },
    /// Pool v2 -> transparent. Spends notes; bounded by the window budget.
    Deshield { amount: Option<u128> },
    /// Pool v2 -> pool v2. Spends notes; the recipient must be pool v2.
    Send { to: &'a str, amount: Option<u128> },
}

/// Decide whether a pool-v2 action may proceed, and if not, say why in words a
/// user can act on.
///
/// `Ok(())` is the ONLY thing that may enable a button. Every refusal returns
/// the reason, so the UI never has to invent one — and can never enable an
/// action for which no reason was checked.
///
/// The ordering is deliberate: conditions that are true of the whole pool come
/// first, then wallet state, then the specific request. A user is told the most
/// fundamental blocker rather than a downstream symptom of it.
fn v2_allows(g: &V2Guard, intent: V2Intent<'_>) -> Result<(), &'static str> {
    // Pool-wide conditions. A dormant pool rejects every v2 spend at every
    // node, so proving one would waste ~25 s to earn a guaranteed rejection.
    if !g.pool_active {
        return Err("pool v2 is not active on this chain yet");
    }
    if !g.for_this_wallet {
        return Err("this pool-v2 view belongs to a different wallet");
    }
    if g.busy {
        return Err("another action is still running");
    }

    // Spending notes requires having scanned them. An unscanned wallet has an
    // UNKNOWN balance, which is not the same as zero — acting on it could
    // build a spend against notes we cannot witness.
    let needs_notes = !matches!(intent, V2Intent::Shield { .. });
    if needs_notes {
        if !g.scanned {
            return Err("scan pool v2 first — its balance is unknown until then");
        }
        if g.notes == 0 {
            return Err("no pool-v2 notes to spend — shield into pool v2 first");
        }
    }

    match intent {
        V2Intent::Shield { to, amount } => {
            // A blank recipient means "shield to myself". A NON-blank one must
            // be a real pool-v2 address: a pool-v1 address here would move
            // value into a pool the named recipient cannot spend from.
            let to = to.trim();
            if !to.is_empty() {
                if !to.starts_with("xusq1") {
                    return Err(
                        "the shield recipient must be a POOL-V2 (xusq1…) address, or blank to \
                         shield to yourself — pool-v1 xus1… addresses are a separate value space",
                    );
                }
                if decode_shielded_v2(to).is_err() {
                    return Err("that pool-v2 address is not valid (checksum failed)");
                }
            }
            let a = amount.ok_or("enter an amount")?;
            if a == 0 {
                return Err("enter an amount greater than zero");
            }
            Ok(())
        }
        V2Intent::Deshield { amount } => {
            let a = amount.ok_or("enter an amount")?;
            if a == 0 {
                return Err("enter an amount greater than zero");
            }
            if a > g.balance_grains {
                return Err("amount exceeds your pool-v2 balance");
            }
            // The per-window drain limiter. Over budget the transaction would
            // be mined and REJECTED, which reads as value stuck in the pool.
            if a > g.deshield_cap() {
                return Err("amount exceeds the per-window de-shield limit — de-shield in batches");
            }
            Ok(())
        }
        V2Intent::Send { to, amount } => {
            let to = to.trim();
            if to.is_empty() {
                return Err("enter the recipient's xusq1… pool-v2 address");
            }
            // THE cross-pool guard. A pool-v1 `xus1…` address here would pay a
            // different recipient in a different value space. It is refused,
            // never coerced. Checked by prefix AND by decode, so a string that
            // merely looks right cannot pass.
            if !to.starts_with("xusq1") {
                return Err(
                    "recipient must be a POOL-V2 (xusq1…) address — pool-v1 xus1… addresses \
                     cannot receive here, the pools are separate value spaces",
                );
            }
            if decode_shielded_v2(to).is_err() {
                return Err("that pool-v2 address is not valid (checksum failed)");
            }
            let a = amount.ok_or("enter an amount")?;
            if a == 0 {
                return Err("enter an amount greater than zero");
            }
            if a > g.balance_grains {
                return Err("amount exceeds your pool-v2 balance");
            }
            Ok(())
        }
    }
}

/// Which pool-v2 action a worker is running. The three share one worker.
#[derive(Debug, Clone, Copy)]
enum V2Action {
    Shield,
    Deshield,
    Send,
}

impl V2Action {
    fn starting(self) -> &'static str {
        match self {
            V2Action::Shield => "shielding into pool v2 (proving)…",
            V2Action::Deshield => "de-shielding from pool v2 (proving)…",
            V2Action::Send => "sending privately in pool v2 (proving)…",
        }
    }
    fn done(self) -> &'static str {
        match self {
            V2Action::Shield => "shielded into pool v2",
            V2Action::Deshield => "de-shielded from pool v2",
            V2Action::Send => "sent privately in pool v2",
        }
    }
    fn noun(self) -> &'static str {
        match self {
            V2Action::Shield => "pool-v2 shield",
            V2Action::Deshield => "pool-v2 de-shield",
            V2Action::Send => "pool-v2 private send",
        }
    }
}

/// The selected wallet's scanned POOL-V2 view. Separate from [`ShieldedView`]
/// because the pools are separate value spaces: a v1 balance must never be
/// displayed as, or mistaken for, a v2 one.
#[derive(Clone, Default)]
struct ShieldedV2View {
    scanning: bool,
    account: String,
    balance: u64, // unspent pool-v2 balance, in grains
    notes: usize, // unspent v2 note count
    scanned_height: u64,
    message: String,
}

impl ShieldedV2View {
    /// As [`ShieldedView::own_figures`], for pool v2. Deliberately a second
    /// method on a second type rather than a shared one: the pools are separate
    /// value spaces, and no code path should be able to hand v1 figures to a v2
    /// caller by accident.
    fn own_figures(&self, account: &str) -> Option<(u128, usize, u64)> {
        (self.account == account && self.scanned_height > 0).then_some((
            self.balance as u128,
            self.notes,
            self.scanned_height,
        ))
    }

    /// Build the pool-v2 permission guard from THIS view, for `account`.
    ///
    /// The guard is assembled here, from a view that was looked up by account,
    /// rather than in a paint closure — so the facts a money-moving decision rests
    /// on are produced by one pure function that tests can sweep. A view scanned
    /// for a different wallet can only ever produce `for_this_wallet: false` and
    /// `scanned: false`, i.e. a guard that refuses every spend.
    fn guard(
        &self,
        account: &str,
        pool_active: bool,
        busy: bool,
        window_budget: Option<u128>,
    ) -> V2Guard {
        let mine = self.account == account;
        V2Guard {
            pool_active,
            // An untouched view (no scan yet, anywhere) belongs to nobody and so
            // is not "a different wallet's" — but it is not `scanned`, so it can
            // still authorise nothing that spends notes.
            for_this_wallet: self.account.is_empty() || mine,
            scanned: mine && self.scanned_height > 0,
            notes: if mine { self.notes } else { 0 },
            busy: busy || self.scanning,
            balance_grains: if mine { self.balance as u128 } else { 0 },
            window_budget,
        }
    }
}

/// Every wallet's scanned pool view, held SIDE BY SIDE and keyed by the wallet
/// the scan was run for.
///
/// There used to be exactly one slot per pool, so scanning wallet B overwrote
/// wallet A's scanned view: switching back to A showed "unknown" until a full
/// re-scan, and the only thing standing between A's figures and B's screen was a
/// single equality check written by hand at each paint site. Keyed storage makes
/// that mistake unrepresentable — a view is looked up BY the account it belongs
/// to, so there is no way to read a figure without naming whose it is.
///
/// The key is the wallet's own IMPLICIT ACCOUNT ID (see
/// [`LoadedWallet::scan_key`]): the fingerprint of the key that can actually
/// decrypt those notes. Never the display label (renameable, duplicable), and
/// never `effective_account()` — a linked named account can be attached or
/// detached without changing which notes the seed controls.
///
/// An account with no entry is UNSCANNED. [`Self::view_for`] returns the default
/// view, whose `scanned_height` is 0, which every caller renders as an UNKNOWN
/// balance — never as zero.
#[derive(Default)]
struct ScannedPools<V> {
    by_account: HashMap<String, V>,
}

impl<V: Clone + Default> ScannedPools<V> {
    /// This account's scanned view, or the default (= unscanned) view when it has
    /// never been scanned. Never another wallet's view.
    fn view_for(&self, account: &str) -> V {
        self.by_account.get(account).cloned().unwrap_or_default()
    }

    /// This account's entry, created unscanned if absent. Every writer names the
    /// account it is writing for, so a background scan that finishes while a
    /// DIFFERENT wallet is selected lands in its own entry and cannot paint into
    /// the selected one.
    fn entry_mut(&mut self, account: &str) -> &mut V {
        self.by_account.entry(account.to_string()).or_default()
    }

    /// Drop a forgotten wallet's view, so the map cannot accumulate entries for
    /// wallets nothing can select any more.
    fn forget(&mut self, account: &str) {
        self.by_account.remove(account);
    }
}

/// Cumulative coinbase your wallets have earned, summed from the chain's per-block
/// coinbase (paid entirely to the miner). Computed on demand (a full scan), cached here.
#[derive(Clone, Default)]
struct EarningsView {
    computing: bool,
    scanned_height: u64,
    total_grains: u128,
    rows: Vec<EarningRow>,
    message: String,
}

/// Cached token view: this wallet's token balances + ONE PAGE of the chain's
/// token registry (paged so the registry never loads unbounded).
#[derive(Clone, Default)]
struct TokensView {
    loading: bool,
    account: String,
    holdings: Vec<(String, String, String)>, // (asset hex, symbol, balance grains)
    registry: Vec<(String, String, String, String)>, // (asset, symbol, issuer, supply grains)
    offset: usize,                           // the registry page's starting offset
    has_more: bool,                          // another registry page exists after this one
    // Owned NFTs: (display, is_sns, collection_hex, token_id_hex) — SNS names too.
    nfts: Vec<(String, bool, String, String)>,
    message: String,
}

/// Cached HTLC lookup for the Swaps tab.
#[derive(Clone, Default)]
struct SwapsView {
    looking: bool,
    id: String,
    found: Option<(String, String, String, String, u64)>, // locker, recipient, amount, hashlock, timeout
    message: String,
}

/// One account's mining earnings: blocks it was paid in and the grains total.
#[derive(Clone)]
struct EarningRow {
    label: String,
    account: String,
    role: String,
    blocks: u64,
    grains: u128,
}

/// Parse a decimal XUS amount ("1.5") into grains (1 XUS = 100,000,000 grains).
fn parse_xus(s: &str) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 8 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u128 = whole.parse().ok()?;
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }
    let frac: u128 = frac_padded.parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

/// Format grains as a plain decimal XUS string (no thousands separators) — for
/// putting a computed value back INTO an input field (e.g. the Max button).
fn grains_to_xus_plain(grains: u128) -> String {
    let whole = grains / 100_000_000;
    let frac = grains % 100_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
    }
}

/// The detected destination tier for a "To" string, used to validate and label
/// a send before it is broadcast.
enum SendRoute {
    Empty,
    Invalid,
    Transparent(String), // a named account (public)
    Shielded,            // xus1… (private)
    Unified,             // uxus1… (routes shielded when possible)
    // A post-quantum pool-v2 receiver. The address PARSES — it is well-formed,
    // not garbage — but signal bit 2 is defined and NOT armed, so no v2 spend
    // can execute on any chain. Kept distinct from `Invalid` on purpose: telling
    // an operator a valid address is "unrecognized" would send them hunting for
    // a typo that is not there.
    ShieldedV2Unsupported,
}

impl SendRoute {
    fn detect(to: &str) -> Self {
        let to = to.trim();
        if to.is_empty() {
            return SendRoute::Empty;
        }
        match AnyAddress::parse(to) {
            Ok(AnyAddress::Transparent(id)) => SendRoute::Transparent(id.to_string()),
            Ok(AnyAddress::Shielded(_)) => SendRoute::Shielded,
            Ok(AnyAddress::Unified(_)) => SendRoute::Unified,
            Ok(AnyAddress::ShieldedV2(_)) => SendRoute::ShieldedV2Unsupported,
            Err(_) => SendRoute::Invalid,
        }
    }
    fn is_valid(&self) -> bool {
        // `ShieldedV2Unsupported` is deliberately NOT valid: the address is
        // well-formed but unspendable while bit 2 is unarmed, so the Send
        // control must stay disabled rather than let an operator broadcast a
        // transaction the chain will hard-reject.
        !matches!(
            self,
            SendRoute::Empty | SendRoute::Invalid | SendRoute::ShieldedV2Unsupported
        )
    }
    /// True when the route keeps the amount/recipient private.
    fn private(&self) -> bool {
        matches!(self, SendRoute::Shielded | SendRoute::Unified)
    }
    /// A short human label + color for inline display.
    fn label(&self) -> (String, egui::Color32) {
        match self {
            SendRoute::Empty => (String::new(), palette::text_dim()),
            SendRoute::Invalid => ("✗ unrecognized address".into(), palette::error()),
            SendRoute::Transparent(a) => {
                (format!("→ transparent · {a} (public)"), palette::warning())
            }
            SendRoute::Shielded => ("→ shielded (private)".into(), palette::success()),
            SendRoute::Unified => (
                "→ unified (routes shielded — private)".into(),
                palette::success(),
            ),
            SendRoute::ShieldedV2Unsupported => (
                "✗ post-quantum (v2) address — that pool is not active yet".into(),
                palette::error(),
            ),
        }
    }
}

/// Why pool v2 cannot be spent from yet, with the height an operator can check
/// for themselves rather than take on trust.
///
/// The number is derived, not invented: mainnet arms signal bit 2 at start
/// height 14,976 on 288-block windows, so the deployment can Lock-in no earlier
/// than 15,264 and go Active no earlier than one period after that — 15,552.
/// It is the EARLIEST possible height, contingent on miner signaling, and is
/// worded that way. Until then `Action::ShieldedV2` is a hard consensus reject.
const V2_DORMANT_REASON: &str =
    "Pool v2 is not active on this chain yet — signal bit 2 activates no earlier than block \
     15,552 on mainnet, and consensus REJECTS every pool-v2 spend until then";

/// Validate a private-send recipient **against the pool the operator selected**.
///
/// The two pools are separate value spaces, so the same string is right in one
/// and wrong in the other. Getting this wrong in either direction is a lost
/// payment, which is why a cross-pool address never yields a generic "invalid":
/// it names the pool the address actually belongs to and the one action that
/// fixes it. Pure, so the whole matrix is swept in tests rather than clicked.
fn pool_recipient_check(pool: Pool, to: &str) -> Result<(), &'static str> {
    match (pool, SendRoute::detect(to)) {
        (Pool::V1, SendRoute::Empty) => Err("enter the recipient’s pool-v1 xus1…/uxus1… address"),
        (Pool::V2, SendRoute::Empty) => Err("enter the recipient’s pool-v2 xusq1… address"),

        // The address belongs to the selected pool. The only two Ok arms.
        (Pool::V1, SendRoute::Shielded | SendRoute::Unified) => Ok(()),
        (Pool::V2, SendRoute::ShieldedV2Unsupported) => Ok(()),

        // Cross-pool: well-formed, and for the OTHER pool. Say which, and say
        // the fix — never "unrecognized", which sends an operator hunting for a
        // typo that is not there.
        (Pool::V1, SendRoute::ShieldedV2Unsupported) => Err(
            "that is a POOL-V2 (xusq1…) address — switch the selector to Pool v2, or paste a \
             pool-v1 xus1…/uxus1… address; the two pools are separate value spaces",
        ),
        (Pool::V2, SendRoute::Shielded | SendRoute::Unified) => Err(
            "that is a POOL-V1 (xus1…) address — switch the selector to Pool v1, or paste a \
             pool-v2 xusq1… address; the two pools are separate value spaces",
        ),

        // Transparent: a real account, but paying it would publish the amount
        // and the recipient — the opposite of what this form is for.
        (Pool::V1, SendRoute::Transparent(_)) => Err(
            "that is a transparent account — a private send needs a shielded xus1…/uxus1… \
             address (use the Send form above to pay an account publicly)",
        ),
        (Pool::V2, SendRoute::Transparent(_)) => Err(
            "that is a transparent account — a pool-v2 private send needs a xusq1… address \
             (use the Send form above to pay an account publicly)",
        ),

        (Pool::V1, SendRoute::Invalid) => {
            Err("unrecognized address — a pool-v1 private send needs a xus1…/uxus1… address")
        }
        (Pool::V2, SendRoute::Invalid) => {
            Err("unrecognized address — a pool-v2 private send needs a xusq1… address")
        }
    }
}

/// Which pool a private send actually dispatches to, **re-decided at submit
/// time**.
///
/// The selector is a preference; this is the authority. Render-time enabling can
/// go stale between paint and click — the node can drop offline, or a chain can
/// be re-selected — so every path that moves pool-v2 value calls this again with
/// the state observed at that instant. A dormant pool is refused with the reason,
/// never silently downgraded to v1: moving value into a different pool than the
/// operator chose would be worse than refusing.
fn private_send_dispatch(pool: Pool, v2: PoolState) -> Result<Pool, &'static str> {
    match pool {
        Pool::V1 => Ok(Pool::V1),
        Pool::V2 if v2 == PoolState::Active => Ok(Pool::V2),
        Pool::V2 => Err(V2_DORMANT_REASON),
    }
}

/// Why nothing can be sent yet when the operator has not picked a pool.
///
/// There is deliberately NO default. A pre-selected pool is a choice made on the
/// operator's behalf, and the thing being chosen is whether the privacy of this
/// payment survives a quantum adversary — so it is not a decision the app may
/// make quietly. Until a pool is picked, nothing is armed and nothing can be
/// sent.
const NO_POOL_CHOSEN: &str =
    "no pool is armed — choose Pool v1 or Pool v2 above before sending privately";

/// What is ARMED right now: the single authority for "which pool would this send
/// actually spend from", given what the operator picked and what the chain says.
///
/// `Err` is not a nuance — it means **nothing is armed**, and no send may be
/// built. Critically, a v2 choice on a non-Active chain resolves to `Err`, never
/// to `Ok(Pool::V1)`: falling back to the non-post-quantum pool because the
/// post-quantum one is unavailable would hand the operator the exact privacy
/// property they were trying to avoid, silently.
fn armed_pool(chosen: Option<Pool>, v2: PoolState) -> Result<Pool, &'static str> {
    match chosen {
        None => Err(NO_POOL_CHOSEN),
        Some(pool) => private_send_dispatch(pool, v2),
    }
}

/// The operator's pool choice, together with the wallet it was made FOR.
///
/// A choice is about a specific wallet's notes in a specific pool. Carrying it
/// silently onto a different wallet would arm a pool the operator never picked
/// for that wallet — so the account is stored alongside the choice and the
/// choice is dropped the moment they disagree. The pairing is the invariant;
/// there is no way to read the pool without naming the account it must match.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct PoolSelection {
    pool: Option<Pool>,
    /// The account the choice was made for. Empty when nothing is chosen.
    for_account: String,
}

impl PoolSelection {
    /// The pool chosen FOR `account`, dropping a choice made for any other
    /// wallet. Called once per paint, so a wallet switch disarms before a single
    /// control is drawn.
    fn chosen_for(&mut self, account: &str) -> Option<Pool> {
        if self.pool.is_some() && self.for_account != account {
            self.clear();
        }
        self.pool
    }

    /// Record a deliberate choice.
    fn choose(&mut self, pool: Pool, account: &str) {
        self.pool = Some(pool);
        self.for_account = account.to_string();
    }

    /// Disarm. Used after a send completes — the choice was for THAT payment,
    /// and leaving it armed invites the next one to inherit it unexamined.
    fn clear(&mut self) {
        self.pool = None;
        self.for_account.clear();
    }
}

/// Where a pending send draws its value from.
///
/// This is an enum rather than a `from_pool: bool` plus an optional pool so that
/// **a pool spend cannot exist without naming its pool**. The review modal reads
/// its statement straight off this type via [`SendSource::confirm_line`], which
/// is total — so there is no reachable path to a confirm screen that fails to
/// say which pool moves and whether it is post-quantum.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SendSource {
    /// A transparent account. Nothing is shielded; the pools are not involved.
    Transparent,
    /// A shielded pool, named.
    Pool(Pool),
}

impl SendSource {
    fn pool(self) -> Option<Pool> {
        match self {
            SendSource::Transparent => None,
            SendSource::Pool(p) => Some(p),
        }
    }

    /// True for a fully-private spend out of a shielded pool — dispatched
    /// through that pool's shielded path, not the transparent send.
    fn is_pool_spend(self) -> bool {
        matches!(self, SendSource::Pool(_))
    }

    /// The sentence the confirm screen shows, in the terms that decide whether
    /// this payment's privacy is durable: the pool, its cryptography by name,
    /// and the plain post-quantum truth. Never colour alone — the glyph and the
    /// words carry it in greyscale.
    fn confirm_line(self) -> String {
        match self {
            SendSource::Transparent => {
                "⚠ PUBLIC — transparent account · nothing is shielded · sender, recipient, and \
                 amount are visible on-chain"
                    .to_string()
            }
            SendSource::Pool(p) => format!(
                "{} SPENDING FROM {} · {} · {}",
                p.glyph(),
                p.name(),
                p.crypto(),
                p.pq_claim()
            ),
        }
    }
}

/// The armed-pool statement, in words and shapes — no colour required to read
/// it, and no inference required to understand it.
///
/// `Err` renders as "NOTHING IS ARMED" rather than as a hint about the pool that
/// happens to still be highlighted. That distinction is the point of failure
/// mode 7: an operator who picked v2 on a dormant chain must be told nothing is
/// armed, not left to assume the send will simply go out some other way.
fn arm_statement(armed: Result<Pool, &'static str>) -> String {
    match armed {
        Ok(p) => format!(
            "▶ ARMED · {} {} · {} · {} — this send spends {} notes",
            p.glyph(),
            p.name(),
            p.crypto(),
            p.pq_claim(),
            p.name()
        ),
        Err(why) => format!("⛔ NOTHING IS ARMED — {why}"),
    }
}

/// Render [`arm_statement`] as the app's standard emphatic line. Used at both
/// ends of the send form so the two can never disagree.
fn arm_banner(ui: &mut egui::Ui, armed: Result<Pool, &'static str>) {
    let color = match armed {
        Ok(Pool::V1) => palette::warning(),
        Ok(Pool::V2) => palette::success(),
        Err(_) => palette::error(),
    };
    ui.label(
        egui::RichText::new(arm_statement(armed))
            .strong()
            .monospace()
            .color(color),
    );
}

/// The line written to the activity log and the status banner once a private
/// send lands. It names the pool and its post-quantum status, so the RECORD of
/// what happened is unambiguous after the fact — not just the moment of choosing.
fn pool_send_receipt(pool: Pool, grains: u128, txid: &str) -> String {
    format!(
        "sent {} XUS privately from {} · {} · {} (tx {})",
        xus(&grains.to_string()),
        pool.name(),
        pool.crypto(),
        pool.pq_claim(),
        &txid[..txid.len().min(14)]
    )
}

/// Which of a wallet's addresses the Receive view shows (shielded is the private
/// default).
#[derive(PartialEq, Eq, Clone, Copy)]
enum ReceiveKind {
    Shielded,
    Unified,
    Account,
    /// The pool-v2 (post-quantum) receiving address. Selectable so an operator can
    /// SEE and BACK UP the address their seed controls — it is derivable today. It is
    /// not payable today, and the view says so before showing the address, never after.
    ShieldedV2,
}

/// A send awaiting the user's explicit confirmation (the review-before-broadcast
/// step). Captured when "Review" is clicked; cleared on Confirm or Cancel.
#[derive(Clone)]
struct PendingSend {
    from_label: String,
    from_account: String,
    to: String,
    amount_grains: u128,
    /// The spendable balance (grains) of the source the amount is drawn from — the
    /// transparent account for a normal send, the shielded pool for a pool spend —
    /// so the review modal can show the resulting balance after amount + fee.
    from_balance_grains: u128,
    route_label: String,
    self_send: bool,
    /// True when BOTH ends are public (transparent→transparent): the amount and
    /// both parties are visible on-chain — the privacy downgrade to warn about.
    links_public: bool,
    /// WHERE the value comes from — a transparent account, or a NAMED shielded
    /// pool. Carried on the pending send rather than re-derived at confirm time,
    /// so the modal states, and the dispatch uses, exactly the pool the operator
    /// armed. Being an enum rather than a flag plus an optional pool is the
    /// point: a pool spend cannot be constructed without naming its pool, so the
    /// confirm screen can never omit which pool moves.
    source: SendSource,
    /// The exact network fee consensus charges for this route (`sov_estimateFee`),
    /// captured at review time.
    fee_grains: u128,
    /// The blockspace-auction bid this send will carry, captured at review time so
    /// the modal shows the SAME number that gets signed — not a figure that could
    /// drift with the pool between review and confirm.
    tip_grains: u128,
}

impl PendingSend {
    /// The pool this send leaves, if any. Reads straight off [`SendSource`], so
    /// there is no second place where "which pool" could be recorded wrongly.
    fn pool(&self) -> Option<Pool> {
        self.source.pool()
    }

    /// True for a fully-private spend out of a shielded pool.
    fn is_pool_spend(&self) -> bool {
        self.source.is_pool_spend()
    }
}

/// The local node, running **in-process** inside sov-station (the Bitcoin Core
/// `bitcoin-qt` model: the wallet *is* the node). Holds the daemon's RPC +
/// block-production threads and optional P2P engine. Shutting it down — explicitly
/// (Stop) or when the window closes (Drop/`on_exit`) — halts the node; there is no
/// separate process, so a node can never be orphaned or outlive its UI.
struct EmbeddedNode {
    daemon: DaemonHandle,
    p2p: Option<P2pHandle>,
    /// The account the node mines its coinbase to (for the status badge).
    account: String,
    /// Live sync telemetry, written by the P2P engine and read by the production loop
    /// (to gate mining) and the UI (for a rolling status). Shared by clone with both.
    sync: Arc<SyncShared>,
    /// The UPnP mapping, if the router accepted one. Owned here so stopping the
    /// node RELEASES it rather than leaving the router forwarding a port to
    /// nothing until the lease lapses.
    port_mapper: Option<(Arc<sov_network::PortMapper>, u16)>,
}

/// A socket-free, in-process snapshot of the embedded node's CHAIN state — read every
/// frame so the Node tab rolls in real time even when the loopback RPC poller blips.
/// Requires the node lock (so it can be momentarily unavailable mid-commit; the
/// lock-free [`SyncView`] is not).
struct ChainView {
    height: u64,
    chain_id: String,
    head_hash: String,
    state_root: String,
    /// Total mined supply, in grains (every coin is mined; genesis supply is zero).
    supply_grains: String,
    mempool: usize,
}

/// A lock-free view of peering/sync, always available (atomics) so the Node tab's peer
/// and sync status never blank out just because the node is busy committing a block.
struct SyncView {
    /// Distinct authenticated peer nodes (never double-counts a redundant link).
    peers: usize,
    /// Tallest peer chain height we have heard of (0 if none).
    best_peer_height: u64,
    /// Still catching up to a heavier peer chain — downloading, not mining.
    syncing: bool,
    /// This node's measured proof-of-work rate (H/s); 0 when not actively mining.
    local_hashrate: u64,
}

impl EmbeddedNode {
    /// Stop block production, the RPC server, and P2P, joining their threads.
    fn shutdown(self) {
        // Release the router mapping FIRST. It is the only state that lives
        // outside this machine, and the only piece another device is actively
        // relying on — leaving it makes the router forward a port to nothing
        // until the lease lapses.
        if let Some((mapper, port)) = self.port_mapper {
            mapper.shutdown(port);
        }
        if let Some(p2p) = self.p2p {
            p2p.shutdown();
        }
        self.daemon.shutdown();
    }

    /// Whether this node is currently mining. `false` = connecting/serving/syncing only
    /// (the default the app starts in — no proof-of-work burning the CPU).
    fn is_mining(&self) -> bool {
        self.daemon.is_mining()
    }

    /// Turn mining on/off at runtime — no node restart, peers and sync are unaffected.
    /// Enabling is refused (with the reason) if the coinbase account is not key-bound.
    fn set_mining(&self, on: bool) -> Result<(), String> {
        self.daemon.set_mining(on)
    }

    /// Dial a peer now — non-blocking; the engine keeps retrying so the link forms
    /// once the peer is reachable. Tolerant of the address form (`ip:port`,
    /// `host:port`, or a bare ip / hostname → default P2P port appended). Returns the
    /// concrete target(s) queued (so the UI can show exactly what it is dialing), or
    /// an error for an unresolvable address / a node that is not running — never a
    /// silent no-op.
    fn dial(&self, addr: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        match &self.p2p {
            Some(p2p) => p2p.tcp().request_reconnect(addr),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "P2P is not running on this node",
            )),
        }
    }

    /// Number of currently-connected peers (live, read straight from the in-process
    /// transport — no RPC needed since the node runs inside this app).
    fn peer_count(&self) -> usize {
        self.p2p.as_ref().map(|p| p.tcp().peer_count()).unwrap_or(0)
    }

    /// A SOCKET-FREE read of the embedded node's CHAIN state, straight from the
    /// in-process chain. Uses `try_lock`, so a momentarily-busy node (mid-commit /
    /// mid-reorg) returns `None` rather than blocking the UI — the node is still up,
    /// just busy this instant. This is why the desktop app never needs to "connect" to
    /// its own node over a loopback RPC socket (the source of the spurious "Transport:
    /// … did not properly respond" on Windows).
    fn chain_view(&self) -> Option<ChainView> {
        let node = self.daemon.node();
        let guard = node.try_lock().ok()?;
        let chain = guard.chain();
        Some(ChainView {
            height: chain.height(),
            chain_id: chain.chain_id().to_string(),
            head_hash: chain.head().hash().to_hex(),
            state_root: chain.ledger().state_root().to_hex(),
            supply_grains: chain
                .ledger()
                .total_supply()
                .map(|b| b.grains().to_string())
                .unwrap_or_default(),
            mempool: guard.mempool_len(),
        })
    }

    /// A LOCK-FREE read of peering/sync telemetry (atomics, written by the P2P engine),
    /// so the peer count and sync status never blank just because the node is busy
    /// committing. The peer count is DISTINCT authenticated nodes — a redundant link is
    /// never shown as a ghost.
    fn sync_view(&self) -> SyncView {
        SyncView {
            peers: self.sync.authed_peers(),
            best_peer_height: self.sync.best_peer_height(),
            // "Syncing" = a real initial download (many blocks behind), not a 1-block
            // race — so a node racing at the tip reads as "Synced", not perpetually
            // "Syncing". Matches the mining gate exactly.
            syncing: self.sync.should_gate_mining(),
            local_hashrate: self.sync.local_hashrate(),
        }
    }
}

/// Lifecycle state of the embedded node, shared between the UI thread and the
/// background start worker (which builds the daemon and replays the block log off
/// the UI thread, so the window never freezes during startup).
// The `Running` variant owns the live node handles (intentionally the large one); it
// is held in a single long-lived slot, not stored in bulk, so boxing it would only add
// indirection on every status read.
#[allow(clippy::large_enum_variant)]
#[derive(Default)]
enum NodeRun {
    /// No node running.
    #[default]
    Stopped,
    /// A start is in flight: building the daemon and replaying the block log.
    Starting,
    /// The node is up, serving RPC and producing blocks.
    Running(EmbeddedNode),
    /// The last start attempt failed; the message explains why.
    Failed(String),
}

/// The application window.
pub struct Station {
    snapshot: Arc<Mutex<Snapshot>>,
    config: Arc<Mutex<Config>>,
    tab: Tab,
    rpc_field: String,
    // The node runs IN-PROCESS (embedded), not as a subprocess: its lifetime is the
    // app's, so it can never orphan or desync from the GUI. Shared with the start
    // worker thread (which builds + replays off the UI thread).
    node_run: Arc<Mutex<NodeRun>>,
    node_status: String,
    // Real, timestamped node logs (startup, replay timing, RPC up, block production,
    // errors), shared with the start worker + poller and shown in the Node tab.
    node_logs: Arc<Mutex<Vec<String>>>,
    // Last-logged node observables, so a CHANGE — peer count, RPC online/offline,
    // height progress — is appended to the node log as it happens (live visibility
    // into peering churn and sync, the things the operator is watching for).
    log_prev_peers: Option<usize>,
    log_prev_online: Option<bool>,
    log_prev_height: Option<u64>,
    // Sync-pipeline observables, so the operator SEES the join progress stage by stage
    // (authenticated peers, catch-up starting/finishing, the peer chain height we are
    // pulling toward) instead of a silent "connected but nothing happening".
    log_prev_authed: Option<usize>,
    log_prev_syncing: Option<bool>,
    log_prev_best: Option<u64>,
    // A peer to bootstrap the local node to (`host:port`), so two machines join the
    // SAME testnet (same genesis + a P2P link). Persisted in the node config.
    peer_addr: String,
    // UI theme mode (dark by default). Persisted across launches; flipped by the ☀/🌙
    // toggle, which re-installs the theme live.
    dark_mode: bool,
    // This machine's LAN address to hand to the OTHER machine (cached at launch).
    lan_addr: Option<String>,
    // Whether the local node's JSON-RPC binds the LAN (0.0.0.0) instead of loopback.
    // Default OFF: the RPC surface is unauthenticated, so it is reachable only from this
    // machine unless the operator explicitly opts in (for the explorer / conformance
    // tools). Persisted across launches; threaded into `build_and_run_node`.
    expose_rpc_lan: bool,
    network: Network,
    // Wallet state (held in-session; secrets never leave this process).
    wallets: Vec<LoadedWallet>,
    selected: usize,
    mining_account: Option<String>, // the wallet account the local node mines to (badge)
    rename_field: String,           // editable label for the active wallet
    forget_armed: bool,             // remove-wallet confirmation modal is open
    forget_confirm: String,         // typed text that must match the label to remove
    reveal_phrase: bool,            // show the active wallet's recovery phrase (export)
    receive_kind: ReceiveKind,      // which address the Receive view shows
    pending_send: Option<PendingSend>, // a send awaiting confirmation (review modal)
    // ── Blockspace auction (v0.1.98) ────────────────────────────────────────
    // Every send this session, with the nonce and recipient needed to REBUILD it
    // at the same slot for a replace-by-fee bump. Shared with the poller, which
    // keeps each entry's pending/confirmed state live.
    outbox: Arc<Mutex<Vec<SentTx>>>,
    // The tip to attach to the next send, as typed (XUS). Empty means "use the
    // suggestion derived from the live pool".
    send_tip: String,
    // True once the spender has typed in the tip field. Until then the field
    // tracks the live suggestion as the pool moves; after, it is THEIRS and
    // Station never rewrites it under their cursor.
    send_tip_edited: bool,
    // A bump awaiting explicit confirmation. The modal exists because "bump"
    // must never be mistaken for "send again" — see [`Self::bump_send`].
    pending_bump: Option<SentTx>,
    block_detail: Option<u64>, // height of the block open in the detail view
    vault_ui: VaultUi,         // all state for the Vault (multisig) tab; isolated
    wallets_dirty: bool,       // wallets exist that aren't saved to the keystore
    confirm_quit: bool,        // quit requested with unsaved wallets — show guard
    gen_name: String,
    import_name: String,
    import_mnemonic: String,
    watch_label: String,  // label for a new watch-only wallet
    watch_pubkey: String, // public key to watch (hybrid65:0x…)
    // Air-gapped (offline) signing: build an unsigned tx here (online), sign it on
    // the machine that holds the seed, broadcast the signed result here.
    ofl_to: String,           // unsigned transfer recipient
    ofl_amount: String,       // unsigned transfer amount (XUS)
    ofl_unsigned: String,     // built unsigned-tx JSON (export → offline machine)
    ofl_sign_in: String,      // pasted unsigned-tx JSON to sign (offline machine)
    ofl_signed: String,       // signed-tx JSON output (→ back to an online node)
    ofl_broadcast_in: String, // pasted signed-tx JSON to broadcast
    ofl_msg: String,          // offline-tools status line
    send_to: String,
    send_amount: String,
    /// Which shielded pool the private-send form spends from, and the wallet
    /// that choice was made for. A deliberate, visible choice rather than an
    /// inference from the recipient's prefix — and, because it starts empty,
    /// never a choice this app makes on the operator's behalf.
    pool_selection: PoolSelection,
    private_to: String, // recipient for a fully-private (shielded→shielded) send
    private_amount: String, // amount (XUS) for the private send
    deshield_amount: String, // amount (XUS) to de-shield (pool → transparent), variable
    // Tokens tab form fields + cached view.
    tok_symbol: String,
    tok_issue_amount: String,
    tok_issue_to: String,
    tok_xfer_asset: String,
    tok_xfer_to: String,
    tok_xfer_amount: String,
    nft_send_to: String, // recipient for an NFT (or SNS name) transfer
    tok_offset: usize,   // current registry page offset
    tokens_view: Arc<Mutex<TokensView>>,
    // Swaps (HTLC) tab form fields + cached lookup.
    htlc_recipient: String,
    htlc_amount: String,
    htlc_preimage: String,
    htlc_timeout: String,
    htlc_lookup_id: String,
    swaps_view: Arc<Mutex<SwapsView>>,
    backup_mnemonic: Option<(String, String)>, // (account, mnemonic) shown once
    operate_as_field: String,                  // named account to link to the selected wallet
    operate_msg: String,                       // result of the last control check
    name_field: String,                        // SNS name to register (e.g. alice.sov)
    name_check: Arc<Mutex<NameCheck>>,         // live availability/format check for name_field
    // SNS is foundational: every loaded wallet's on-chain names are cached here,
    // keyed by the account they resolve to, so a wallet's name is shown uniformly
    // everywhere (header, switch list, your-names) — not just for the active one.
    names_by_account: Arc<Mutex<HashMap<String, Vec<String>>>>,
    names_refreshed_at: Option<Instant>, // last SNS-cache refresh (for periodic re-poll)
    shielded_scan_for: String,           // account auto-scanned for the shielded pool (debounce)
    rescan_armed: bool, // "Rescan from scratch" confirmation is open (destructive cache wipe)
    action: Arc<Mutex<ActionState>>,
    params: Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    /// Scanned pool-v1 views, one per wallet (keyed by `LoadedWallet::scan_key`),
    /// so switching wallets shows THAT wallet's own scanned figures — or its
    /// honest unscanned state — instead of whatever was scanned last.
    shielded: Arc<Mutex<ScannedPools<ShieldedView>>>,
    /// Scanned pool-v2 views, one per wallet. Same keying, separate map: the two
    /// pools are separate value spaces and their figures must never be mixed.
    shielded_v2: Arc<Mutex<ScannedPools<ShieldedV2View>>>,
    shield_v2_amount_in: String,
    shield_v2_to: String,
    deshield_v2_amount_in: String,
    private_v2_to: String,
    private_v2_amount: String,
    earnings: Arc<Mutex<EarningsView>>,
    /// The MASTER session passphrase that encrypts the wallet store. Set ONLY via a
    /// confirmed first-run setup or a VERIFIED unlock/keystore-load — never typed
    /// once and used directly (see `passphrase_set`).
    passphrase: String,
    keystore_msg: String,
    /// True when an encrypted wallet store exists on disk that hasn't been unlocked
    /// this session — the UI shows the unlock screen and nothing else until the
    /// passphrase is entered. The decryption key is never stored, so this is the
    /// gate on every launch.
    locked: bool,
    unlock_error: String,
    /// Set once we've revealed the passphrase FINGERPRINT (e.g. `SOV-4F9A`) after the
    /// first save, so the reveal toast fires exactly once — thereafter it lives on the
    /// lock screen. The code is a salt-bound hash of the Argon2 key (see
    /// `keystore_stored_fingerprint`), so the user can recognize their passphrase
    /// across launches and a typo shows a different code.
    code_shown_once: bool,
    /// First-run passphrase SETUP, shown before the master passphrase is ever used
    /// to encrypt. Two inputs that must MATCH (and meet a length floor) — so a typo
    /// can't silently become the key and lock you out.
    show_setup: bool,
    setup_pw: String,
    setup_pw2: String,
    /// True once the master passphrase has been established by a CONFIRMED setup or a
    /// VERIFIED unlock / keystore-load — the only paths allowed to encrypt the store.
    /// Typing into the portable-keystore field never sets this.
    passphrase_set: bool,
    /// Passphrase for the PORTABLE keystore file (Save/Load backup), kept separate
    /// from the master so opening a backup can't silently re-key the live store.
    keystore_pass: String,
    copied_at: Option<u64>, // ms timestamp of the last copy, for the toast
    activity: Arc<Mutex<Vec<String>>>, // recent action log (newest first), with txids
    pending_network: Option<Network>, // a mainnet switch awaiting confirmation
    /// The most recent action result surfaced as a transient toast (`message`,
    /// `shown_at_ms`), visible from ANY tab, and the message already toasted (so each
    /// result toasts once). Green on success, red on failure (`tx_status`).
    toast: Option<(String, u64)>,
    toast_seen: String,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Node,
    Mining,
    Wallet,
    Tokens,
    Swaps,
    Vault,
    Blocks,
    Activity,
}

/// All transient UI state for the Vault (treasury multisig) tab — grouped in ONE
/// struct so the whole feature is a single Station field. None of this is persisted
/// in the wallet/keystore; saved vault definitions live in their own public file (see
/// [`vault`]). Remove this field + the `Tab::Vault` arm to delete the feature cleanly.
#[derive(Default)]
struct VaultUi {
    vaults: Vec<vault::Vault>,
    loaded: bool,
    // Create-a-vault form
    new_name: String,
    new_account: String,
    new_member_name: String,
    new_member_key: String,
    new_members: Vec<vault::Member>,
    new_threshold: u16,
    create_msg: String,
    // Send-from-a-vault form (becomes a proposal)
    send_vault: usize,
    send_to: String,
    send_amount: String,
    send_msg: String,
    // The approval inbox, filled by a background fetch off `sov_getMultisigProposals`.
    inbox: Arc<Mutex<Inbox>>,
    last_fetch: Option<Instant>,
}

/// The pending-proposals inbox, shared with the fetch worker.
#[derive(Default)]
struct Inbox {
    proposals: Vec<ProposalView>,
    fetching: bool,
    error: String,
}

/// One pending vault spend, decoded for display. The chain is the source of truth;
/// this is just what `sov_getMultisigProposals` returned, plus whether the selected
/// wallet still needs to approve it.
#[derive(Clone, Default)]
struct ProposalView {
    vault_name: String,
    account: String,
    id_hex: String,
    to: String,
    amount_grains: u128,
    approved: usize,
    threshold: u16,
    /// The selected wallet is a member of this vault who has NOT yet approved.
    can_approve: bool,
    /// The selected wallet is a member (so it may at least cancel).
    is_member: bool,
}

/// The network the app is pointed at. Wallets are key material and work on ANY
/// network unchanged, so switching never touches them — only the chain view (RPC,
/// balances, blocks) follows. Testnet is a local sandbox (mine + reset); Mainnet
/// is the real chain (no destructive reset; connect to a real node).
#[derive(PartialEq, Eq, Clone, Copy)]
enum Network {
    Testnet,
    Mainnet,
}

impl Network {
    /// Short display name (also the top-bar chip text).
    fn label(self) -> &'static str {
        match self {
            Network::Testnet => "TESTNET",
            Network::Mainnet => "MAINNET",
        }
    }

    /// The chain-id a node on this network must report — used as a safety guard
    /// against acting on the wrong chain.
    fn chain_id(self) -> &'static str {
        match self {
            Network::Testnet => "sov-testnet-1",
            Network::Mainnet => "sov-mainnet",
        }
    }

    /// The default RPC endpoint to point at when this network is selected.
    fn default_rpc(self) -> &'static str {
        // Both default to the local node today; mainnet seeds are configured by
        // the operator (or hardcoded) at launch.
        "127.0.0.1:8645"
    }

    /// The frozen chain-spec file (under `chain/specs/`) a local node of this
    /// network is built from. Mainnet's spec does not exist until launch.
    fn spec_filename(self) -> &'static str {
        match self {
            Network::Testnet => "testnet-1.json",
            Network::Mainnet => "mainnet.json",
        }
    }

    /// The per-network data-dir suffix, so testnet and mainnet chains live in
    /// SEPARATE directories and can never collide (mainnet blocks must never land in
    /// the testnet log, and vice-versa).
    fn data_subdir(self) -> &'static str {
        match self {
            Network::Testnet => "testnet",
            Network::Mainnet => "mainnet",
        }
    }

    /// Whether this network is a local sandbox: self-mining and a destructive
    /// "reset chain" are offered ONLY here. A real chain (mainnet) is never
    /// wipeable from the wallet, so those controls are hidden.
    fn is_sandbox(self) -> bool {
        matches!(self, Network::Testnet)
    }

    /// The chip color: amber for testnet (caution: not real value), green for
    /// mainnet (live).
    fn color(self) -> egui::Color32 {
        match self {
            Network::Testnet => palette::warning(),
            Network::Mainnet => palette::success(),
        }
    }

    /// The proof-of-work algorithm a node on this network mines with — shown next to
    /// the network selector. Fixed per network by the chain-spec's `pow` (not an
    /// independent choice): testnet runs **SHA-256d** (fast, single-box friendly);
    /// mainnet runs **RandomX** (Monero's memory-hard, ASIC-resistant CPU PoW).
    fn pow_algo(self) -> &'static str {
        match self {
            Network::Testnet => "SHA-256d",
            Network::Mainnet => "RandomX",
        }
    }
}

impl Station {
    fn new(
        snapshot: Arc<Mutex<Snapshot>>,
        config: Arc<Mutex<Config>>,
        outbox: Arc<Mutex<Vec<SentTx>>>,
    ) -> Self {
        let rpc_field = config.lock().map(|c| c.rpc.clone()).unwrap_or_default();
        let mut station = Station {
            snapshot,
            config,
            outbox,
            send_tip: String::new(),
            send_tip_edited: false,
            pending_bump: None,
            tab: Tab::Node,
            rpc_field,
            node_run: Arc::new(Mutex::new(NodeRun::Stopped)),
            node_status: String::new(),
            node_logs: Arc::new(Mutex::new(Vec::new())),
            log_prev_peers: None,
            log_prev_online: None,
            log_prev_height: None,
            log_prev_authed: None,
            log_prev_syncing: None,
            log_prev_best: None,
            peer_addr: read_saved_peer(Network::Mainnet),
            dark_mode: read_saved_theme(),
            lan_addr: lan_ipv4(),
            expose_rpc_lan: read_expose_rpc_lan(),
            // Default to MAINNET — the live network (genesis cb0272ff). The top tab
            // opens on Mainnet; Testnet is an explicit opt-in sandbox from there.
            network: Network::Mainnet,
            wallets: Vec::new(),
            selected: 0,
            mining_account: None,
            rename_field: String::new(),
            forget_armed: false,
            forget_confirm: String::new(),
            reveal_phrase: false,
            receive_kind: ReceiveKind::Shielded,
            pending_send: None,
            block_detail: None,
            vault_ui: VaultUi::default(),
            wallets_dirty: false,
            confirm_quit: false,
            gen_name: "my-wallet".to_string(),
            import_name: "imported".to_string(),
            import_mnemonic: String::new(),
            watch_label: String::new(),
            watch_pubkey: String::new(),
            ofl_to: String::new(),
            ofl_amount: String::new(),
            ofl_unsigned: String::new(),
            ofl_sign_in: String::new(),
            ofl_signed: String::new(),
            ofl_broadcast_in: String::new(),
            ofl_msg: String::new(),
            send_to: String::new(),
            send_amount: String::new(),
            // NOTHING is armed until the operator picks. There is no default,
            // because a default here is a privacy property chosen for them.
            pool_selection: PoolSelection::default(),
            private_to: String::new(),
            private_amount: String::new(),
            deshield_amount: String::new(),
            tok_symbol: String::new(),
            tok_issue_amount: String::new(),
            tok_issue_to: String::new(),
            tok_xfer_asset: String::new(),
            tok_xfer_to: String::new(),
            nft_send_to: String::new(),
            tok_xfer_amount: String::new(),
            tok_offset: 0,
            tokens_view: Arc::new(Mutex::new(TokensView::default())),
            htlc_recipient: String::new(),
            htlc_amount: String::new(),
            htlc_preimage: String::new(),
            htlc_timeout: String::new(),
            htlc_lookup_id: String::new(),
            swaps_view: Arc::new(Mutex::new(SwapsView::default())),
            backup_mnemonic: None,
            operate_as_field: String::new(),
            operate_msg: String::new(),
            name_field: String::new(),
            name_check: Arc::new(Mutex::new(NameCheck::default())),
            names_by_account: Arc::new(Mutex::new(HashMap::new())),
            names_refreshed_at: None,
            shielded_scan_for: String::new(),
            rescan_armed: false,
            action: Arc::new(Mutex::new(ActionState::default())),
            params: Arc::new(Mutex::new(None)),
            shielded: Arc::new(Mutex::new(ScannedPools::default())),
            shielded_v2: Arc::new(Mutex::new(ScannedPools::default())),
            shield_v2_amount_in: String::new(),
            shield_v2_to: String::new(),
            deshield_v2_amount_in: String::new(),
            private_v2_to: String::new(),
            private_v2_amount: String::new(),
            earnings: Arc::new(Mutex::new(EarningsView::default())),
            copied_at: None,
            activity: Arc::new(Mutex::new(Vec::new())),
            pending_network: None,
            toast: None,
            toast_seen: String::new(),
            passphrase: String::new(),
            keystore_msg: String::new(),
            locked: false,
            unlock_error: String::new(),
            code_shown_once: false,
            show_setup: false,
            setup_pw: String::new(),
            setup_pw2: String::new(),
            passphrase_set: false,
            keystore_pass: String::new(),
        };
        // If an encrypted wallet store exists, start LOCKED — the wallets load only
        // once the passphrase is entered (its key is never stored on disk). With no
        // store yet, stay unlocked; the passphrase is set when the first wallet is
        // created. The legacy device-key store also triggers the lock screen and is
        // migrated to passphrase encryption on first unlock.
        station.locked = autosave_path().map(|p| p.exists()).unwrap_or(false);
        // Migration / safety: this version runs the node IN-PROCESS, so there should
        // be no external node. Kill any legacy `sov-rpcd` subprocess left over from
        // an older build (tracked by its pidfile) so it can't hold the RPC/P2P ports
        // or keep mining headless. From here on, the node's lifetime is the app's.
        stop_tracked_node();
        let _ = std::fs::remove_file(node_pid_path());
        // First-run guidance: a node mines to a wallet, so with no wallet yet, open
        // on the Wallet tab (where you create/import one) rather than the Node tab
        // with a silently-greyed "Start". With a wallet present, the app IS the node:
        // bring the embedded node up automatically (closing the app stops it). Safe —
        // `build_and_run_node` refuses to touch a chain mined to a different wallet.
        if station.wallets.is_empty() {
            station.tab = Tab::Wallet;
        } else if station.network.is_sandbox() {
            station.start_local_node();
        }
        station
    }

    /// Track this account's balance in the poller, and watch the wallet list.
    fn register_wallet(&mut self, wallet: LoadedWallet) {
        if let Ok(mut c) = self.config.lock() {
            if !c.accounts.contains(&wallet.account) {
                c.accounts.push(wallet.account.clone());
            }
            // A NON-watch wallet's own id is the implicit account derived from the seed on
            // this machine — provably the operator's and spendable — so it is eligible for
            // mining attribution. A watch-only wallet holds no key and must never be.
            if !wallet.watch_only && !c.mining_accounts.contains(&wallet.account) {
                c.mining_accounts.push(wallet.account.clone());
            }
        }
        self.wallets.push(wallet);
        self.selected = self.wallets.len() - 1;
        self.wallets_dirty = true;
    }

    /// A passphrase must be set before the first wallet is created, so the encrypted
    /// store always has a key. Returns true when one is set; otherwise flashes a
    /// pointer to the passphrase field and returns false.
    fn require_passphrase(&mut self) -> bool {
        if self.passphrase_set && !self.passphrase.is_empty() {
            true
        } else {
            // No confirmed master passphrase yet → open the create-with-confirm
            // screen rather than encrypting under an unverified string.
            self.show_setup = true;
            false
        }
    }

    /// Generate a brand-new wallet (fresh mnemonic + hybrid PQ key). Instant and
    /// offline; the mnemonic is shown once for backup and never leaves the process.
    fn generate_wallet(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        // The typed text is a display LABEL only — the on-chain account id is
        // derived from the new key, so it can never collide with another
        // account or inherit its funds.
        let label = self.gen_name.trim();
        let label = if label.is_empty() { "wallet" } else { label }.to_string();
        let mnemonic = match generate_mnemonic(24) {
            Ok(m) => m,
            Err(e) => return self.set_action(&format!("generate failed: {e}")),
        };
        let mut seed = match HdWallet::from_mnemonic(&mnemonic, "") {
            Ok(w) => w.derive_seed(0, 0),
            Err(e) => return self.set_action(&format!("derive failed: {e}")),
        };
        let result = LoadedWallet::from_seed(label.clone(), seed, Some(mnemonic.clone()));
        seed.zeroize(); // wipe the stack copy; the wallet owns its own (also zeroized)
        match result {
            Ok(w) => {
                let account = w.account.clone();
                self.register_wallet(w);
                self.backup_mnemonic = Some((account, mnemonic));
                self.set_action("wallet generated — BACK UP THE MNEMONIC");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("derive failed: {e}")),
        }
    }

    /// Import a wallet from an existing BIP-39 mnemonic.
    fn import_wallet(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        // The typed text is a display LABEL only; the on-chain id is re-derived
        // deterministically from the mnemonic's key.
        let label = self.import_name.trim();
        let label = if label.is_empty() { "wallet" } else { label }.to_string();
        let input = self.import_mnemonic.trim().to_string();
        // Accept EITHER a BIP-39 mnemonic OR a raw 32-byte hex seed (64 hex chars). The
        // hex-seed path imports a seed-only wallet — e.g. the one the atomic-swap desk
        // hands out — reproducing the exact account via `hybrid_from_seed` (byte-identical
        // to the SDK). Its recovery phrase can't be re-shown (there is none), but it spends
        // normally.
        let is_hex_seed = input.len() == 64 && input.bytes().all(|b| b.is_ascii_hexdigit());
        let (mut seed, mnemonic_opt): ([u8; 32], Option<String>) = if is_hex_seed {
            let mut s = [0u8; 32];
            for i in 0..32 {
                match u8::from_str_radix(&input[i * 2..i * 2 + 2], 16) {
                    Ok(b) => s[i] = b,
                    Err(_) => return self.set_action("invalid seed hex (need 64 hex chars)"),
                }
            }
            (s, None)
        } else {
            let seed = match HdWallet::from_mnemonic(&input, "") {
                Ok(w) => w.derive_seed(0, 0),
                Err(e) => return self.set_action(&format!("invalid mnemonic or 64-hex seed: {e}")),
            };
            (seed, Some(input.clone()))
        };
        let result = LoadedWallet::from_seed(label, seed, mnemonic_opt);
        seed.zeroize(); // wipe the stack copy; the wallet owns its own (also zeroized)
        match result {
            Ok(w) => {
                self.register_wallet(w);
                // `.clear()` only resets the length — scrub the bytes first so the
                // typed phrase doesn't linger in the field's freed capacity.
                self.import_mnemonic.zeroize();
                self.import_mnemonic.clear();
                self.set_action("wallet imported");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("import failed: {e}")),
        }
    }

    /// Add a WATCH-ONLY wallet from a public key: monitor an account with no
    /// private key on this machine (it cannot sign). Persisted like any wallet.
    fn add_watch_only(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        let label = self.watch_label.trim();
        let label = if label.is_empty() { "Watch" } else { label }.to_string();
        let pk = self.watch_pubkey.trim().to_string();
        if pk.is_empty() {
            return self.set_action("enter a public key to watch");
        }
        match LoadedWallet::watch_only(label, &pk) {
            Ok(w) => {
                if self.wallets.iter().any(|x| x.account == w.account) {
                    return self.set_action("that account is already loaded");
                }
                self.watch_pubkey.clear();
                self.watch_label.clear();
                self.register_wallet(w);
                self.set_action("👁 watch-only wallet added");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("watch-only: {e}")),
        }
    }

    /// Whether the active wallet can sign. A watch-only wallet cannot — it sets a
    /// status message pointing to the offline-signing tools and returns false.
    fn require_signing(&self) -> bool {
        let watch = self
            .wallets
            .get(self.selected)
            .map(|w| w.watch_only)
            .unwrap_or(false);
        if watch {
            self.set_action(
                "👁 watch-only wallet — cannot sign here. Build an unsigned tx below, sign it on \
                 the machine that holds the seed, then broadcast.",
            );
        }
        !watch
    }

    /// Build an UNSIGNED transfer for the active wallet's account and put its JSON
    /// in `ofl_unsigned` to carry to an air-gapped machine. Uses the account's
    /// current on-chain nonce (from the live poll) — no key needed, so it works
    /// from a watch-only wallet.
    fn build_unsigned(&mut self) {
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let signer = w.effective_account();
        let pk_str = w.public_key.clone();
        let to = self.ofl_to.trim().to_string();
        let Some(grains) = parse_xus(&self.ofl_amount) else {
            self.ofl_msg = "amount must be a number (e.g. 1.5)".into();
            return;
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let build = (|| -> Result<(String, u64), String> {
            let signer_id = AccountId::new(&signer).map_err(|e| e.to_string())?;
            let to_id = AccountId::new(&to).map_err(|e| e.to_string())?;
            let public_key: PublicKey = serde_json::from_value(serde_json::Value::String(pk_str))
                .map_err(|e| e.to_string())?;
            // The signer's next queue-aware nonce (on-chain + pending) so the
            // offline-signed tx is immediately includable AND queues behind any tx
            // already pending, instead of colliding with its slot.
            let nonce = RpcClient::new(rpc)
                .with_timeout(Duration::from_secs(8))
                .next_nonce(&signer_id)
                .map_err(|e| e.to_string())?;
            let tx = Transaction {
                signer: signer_id,
                public_key,
                nonce,
                action: Action::Transfer {
                    to: to_id,
                    amount: Balance::from_grains(grains),
                },
            };
            Ok((
                serde_json::to_string_pretty(&tx).map_err(|e| e.to_string())?,
                nonce,
            ))
        })();
        match build {
            Ok((json, nonce)) => {
                self.ofl_unsigned = json;
                self.ofl_msg = format!(
                    "✓ unsigned tx built (nonce {nonce}) — copy it to your offline machine to sign"
                );
            }
            Err(e) => self.ofl_msg = format!("build failed: {e}"),
        }
    }

    /// Sign a pasted unsigned-tx JSON with the active wallet's key (offline; no
    /// network). The wallet's key must match the transaction's `public_key`.
    fn sign_offline(&mut self) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let input = self.ofl_sign_in.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let signed = (|| -> Result<(String, bool), String> {
            let tx: Transaction = serde_json::from_str(&input).map_err(|e| e.to_string())?;
            let kp = Keypair::hybrid_from_seed(seed);
            // Best-effort tx-domain query: if a node is reachable and the
            // `tx-domain` fork is ACTIVE, bind the signature to this network;
            // on a genuinely air-gapped machine (no node reachable) or while the
            // fork is dormant, fall back to the legacy (un-bound) signature —
            // exactly what pre-fork verification expects.
            let domain = match RpcClient::new(rpc)
                .with_timeout(Duration::from_secs(3))
                .signing_domain()
            {
                Ok(d) => d,
                // A genuinely air-gapped machine (no node reachable) surfaces as a
                // TRANSPORT error → fall back to the legacy (un-bound) signature. Any
                // OTHER error (a reachable node returning a malformed/unexpected
                // domain) is surfaced, not silently downgraded to a legacy signature
                // that a post-activation node would reject at broadcast.
                Err(sov_rpc::RpcClientError::Io(_)) => None,
                Err(e) => return Err(format!("signing domain query failed: {e}")),
            };
            // SignedTransaction::sign_in refuses if the keypair's key isn't the one
            // the transaction names — exactly the cross-wallet guard we want.
            let stx =
                SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&stx).map_err(|e| e.to_string())?;
            Ok((json, domain.is_some()))
        })();
        match signed {
            Ok((json, bound)) => {
                self.ofl_signed = json;
                self.ofl_msg = if bound {
                    "✓ signed (network-bound) — copy this to an online node and broadcast".into()
                } else {
                    "✓ signed — copy this to an online node and broadcast".into()
                };
            }
            Err(e) => self.ofl_msg = format!("sign failed: {e}"),
        }
    }

    /// Broadcast a pasted signed-tx JSON to the connected node.
    fn broadcast_signed(&mut self, ctx: &egui::Context) {
        let input = self.ofl_broadcast_in.trim().to_string();
        if input.is_empty() {
            self.ofl_msg = "paste a signed transaction to broadcast".into();
            return;
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "broadcasting signed tx…");
        std::thread::spawn(move || {
            let msg = (|| -> Result<String, String> {
                let stx: SignedTransaction =
                    serde_json::from_str(&input).map_err(|e| format!("not a signed tx: {e}"))?;
                let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(15));
                let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
                Ok(format!("✓ broadcast — tx {}", &txid.to_hex()[..14]))
            })()
            .unwrap_or_else(|e| format!("✗ broadcast failed: {e}"));
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    fn set_action(&self, message: &str) {
        if let Ok(mut a) = self.action.lock() {
            a.busy = false;
            a.message = message.to_string();
        }
    }

    /// Link a named account to the selected wallet so send/activate act AS it.
    /// Checks on-chain (real key comparison) whether this wallet controls it, but
    /// links it regardless — the account may be about to be genesis-bound to this
    /// key. The named account is added to the poller's watch list for its balance.
    fn set_operate_as(&mut self) {
        let name = self.operate_as_field.trim().to_string();
        let id = match AccountId::new(&name) {
            Ok(id) => id,
            Err(e) => {
                self.operate_msg = format!("invalid account id: {e}");
                return;
            }
        };
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        // One control query drives both the status message AND the mining-attribution
        // decision, so we never trust a name this wallet cannot actually spend.
        let control = account_control(&rpc, seed, &id);
        self.operate_msg = control_message(&name, &control);
        let is_mine = matches!(control, Control::Mine);
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.operate_as = Some(name.clone());
        }
        if let Ok(mut c) = self.config.lock() {
            if !c.accounts.contains(&name) {
                c.accounts.push(name.clone());
            }
            // Only an account whose bound key IS this wallet's may count toward mining
            // attribution — a `DifferentKey` name is foreign hashrate, watched but never
            // "you are mining". If control could not be verified, we do NOT add it.
            if is_mine && !c.mining_accounts.contains(&name) {
                c.mining_accounts.push(name);
            }
        }
    }

    /// Stop operating a linked named account; revert to the wallet's own id.
    fn clear_operate_as(&mut self) {
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.operate_as = None;
        }
        self.operate_msg.clear();
    }

    /// Rename the active wallet's display label (local only — the on-chain id is
    /// the key's fingerprint and never changes).
    fn rename_selected(&mut self) {
        let label = self.rename_field.trim().to_string();
        if label.is_empty() {
            return;
        }
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.label = label;
        }
        self.rename_field.clear();
        self.auto_save();
    }

    /// Forget the active wallet (remove it from the session). Irreversible
    /// without its recovery phrase or a saved keystore — guarded by a two-click
    /// confirm in the UI. Never touches on-chain state.
    fn forget_selected(&mut self) {
        if self.selected < self.wallets.len() {
            let gone = self.wallets.remove(self.selected);
            // Drop it from the poller's watch list (unless another wallet shares
            // the account, which cannot happen for distinct keys).
            if let Ok(mut c) = self.config.lock() {
                c.accounts.retain(|a| a != &gone.account);
            }
            if self.mining_account.as_deref() == Some(gone.account.as_str()) {
                self.mining_account = None;
            }
            // Drop its scanned pool views. They describe notes only that seed can
            // decrypt, and the seed is gone — keeping them would leave figures in
            // memory for a wallet nothing can select.
            if let Ok(mut m) = self.shielded.lock() {
                m.forget(&gone.account);
            }
            if let Ok(mut m) = self.shielded_v2.lock() {
                m.forget(&gone.account);
            }
        }
        self.selected = self.selected.min(self.wallets.len().saturating_sub(1));
        self.forget_armed = false;
        self.rename_field.clear();
        self.auto_save();
    }

    /// Register a NEW human-readable `*.sov` name on-chain (ENS/SNS-style),
    /// binding it as an **alias that resolves to this wallet's account**. The
    /// wallet keeps its own identity and funds — the name just points at it, so
    /// others can pay `alice.sov` instead of the key fingerprint. First-come;
    /// pays a one-time registration fee (earned by miners) from this wallet's
    /// balance. Submitted on a worker; the registry updates once the tx is mined.
    fn register_named(&mut self, ctx: &egui::Context) {
        let name = self.name_field.trim().to_string();
        if let Err(e) = validate_name_format(&name) {
            self.operate_msg = format!("✗ {e}");
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let signer = w.effective_account();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();

        let action = self.action.clone();
        let activity = self.activity.clone();
        let cache = self.names_by_account.clone();
        let ctx = ctx.clone();
        begin(&action, &format!("registering {name} on-chain…"));
        std::thread::spawn(move || {
            let msg = match register_name_onchain(&rpc, seed, &signer, &name) {
                Ok(tx) => format!(
                    "✓ {name} registered — it will resolve to your account once mined (tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ register failed: {e}"),
            };
            // Best-effort cache refresh for this account (the new name shows once
            // the tx is mined; the periodic refresh picks it up regardless).
            if let Ok(names) = fetch_names_of(&rpc, &signer) {
                if let Ok(mut m) = cache.lock() {
                    m.insert(signer.clone(), names);
                }
            }
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    /// Send `amount` to `to` (a named account, a `xus1…` shielded address, or a
    /// `uxus1…` unified address). Routing + Halo2 proving happen on a worker.
    /// The blockspace-auction panel of the send form: what a slot costs right now,
    /// what this send is bidding, and what that bid is likely to buy. Returns the
    /// tip (in grains) the send will carry.
    ///
    /// The whole tip control is gated on the `fee-auction` deployment being Active,
    /// because below its activation height an `Action::Tipped` is a hard consensus
    /// rejection — offering a tip there would not be a worse price, it would be an
    /// unmineable transaction. When it is dormant the panel still shows the pool,
    /// and says plainly that tips are not live.
    fn auction_controls(&mut self, ui: &mut egui::Ui, a: &Auction) -> u128 {
        ui.add_space(sp::M);
        card(ui, |ui| {
            auction_readout(ui, a);
            // The bid. Kept in sync with the live suggestion until the spender
            // touches the field — after that it is theirs, and Station never
            // rewrites a number under their cursor.
            let suggested = a.suggested_tip_grains();
            if !self.send_tip_edited {
                self.send_tip = grains_to_xus_plain(suggested);
            }
            if a.fee_auction_active {
                ui.add_space(sp::M);
                ui.horizontal(|ui| {
                    ui.label("Tip XUS");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.send_tip)
                            .desired_width(140.0)
                            .hint_text("0"),
                    );
                    if r.changed() {
                        self.send_tip_edited = true;
                    }
                    if ui
                        .add_enabled(self.send_tip_edited, egui::Button::new("Suggested"))
                        .on_hover_text(
                            "go back to the tip derived from the live pool, and keep tracking it",
                        )
                        .clicked()
                    {
                        self.send_tip_edited = false;
                        self.send_tip = grains_to_xus_plain(suggested);
                    }
                });
                ui.add_space(sp::XS);
                ui.label(
                    egui::RichText::new(tip_rationale(a))
                        .size(ty::SMALL)
                        .color(palette::text_dim()),
                );
            } else {
                ui.add_space(sp::M);
                ui.label(
                    egui::RichText::new(
                        "the fee auction is not active on this chain — sends carry no tip and \
                         are included first-come. Nothing to bid.",
                    )
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
                );
            }
            let tip = self.tip_for(a);
            if self.send_tip_edited && parse_xus(&self.send_tip).is_none() {
                ui.label(
                    egui::RichText::new(
                        "✗ tip must be a number of XUS (e.g. 0.0001) — treating it as 0",
                    )
                    .size(ty::SMALL)
                    .color(palette::error()),
                );
            }
            bid_outlook_view(ui, a, tip);
            tip
        })
    }

    /// The tip a send would carry against auction reading `a`: what the spender
    /// typed, or the live suggestion while they have not touched the field — and
    /// unconditionally zero while the `fee-auction` deployment is dormant.
    fn tip_for(&self, a: &Auction) -> u128 {
        if !a.fee_auction_active {
            return 0;
        }
        if self.send_tip_edited {
            parse_xus(&self.send_tip).unwrap_or(0)
        } else {
            a.suggested_tip_grains()
        }
    }

    /// This session's sends, with a one-click BUMP for anything still pooled.
    ///
    /// This is the lever the wallet did not have: a send that lands below the floor
    /// used to sit in the mempool with nothing the user could do about it.
    fn pending_sends_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, a: &Auction) {
        // Only THIS wallet's sends: a bump re-signs with the selected wallet's key,
        // so showing another wallet's pending transaction here would offer a lever
        // that cannot work.
        let Some(me) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        else {
            return;
        };
        let entries: Vec<SentTx> = self
            .outbox
            .lock()
            .map(|o| o.iter().filter(|t| t.from_account == me).cloned().collect())
            .unwrap_or_default();
        if entries.is_empty() {
            return;
        }
        let now = now_ms();
        let mut bump_target: Option<SentTx> = None;
        ui.add_space(sp::L);
        ui.label(egui::RichText::new("This session's sends").strong());
        ui.add_space(sp::S);
        card(ui, |ui| {
            // Newest first — the one you are worried about is the one you just sent.
            for t in entries.iter().rev() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = sp::M;
                    let (glyph, col) = match t.state {
                        SendState::Pending => ("⏳", palette::warning()),
                        SendState::Confirmed => ("✓", palette::success()),
                        SendState::Failed => ("✗", palette::error()),
                        SendState::Replaced => ("⇄", palette::unknown()),
                        SendState::Superseded => ("·", palette::unknown()),
                    };
                    state_chip(ui, glyph, t.state.label(), col);
                    ui.label(
                        num(format!("{} XUS", xus(&t.amount_grains.to_string())))
                            .size(ty::SMALL)
                            .color(palette::text()),
                    );
                    ui.label(
                        egui::RichText::new(format!("→ {}", short_id(&t.to)))
                            .size(ty::SMALL)
                            .color(palette::text_dim()),
                    );
                    ui.label(
                        num(format!("nonce {}", t.nonce))
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                    );
                    ui.label(
                        num(format!("tip {} XUS", xus(&t.tip_grains.to_string())))
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                    );
                    if t.state.is_pending() {
                        ui.label(
                            num(format!(
                                "waiting {}s",
                                now.saturating_sub(t.submitted_ms) / 1000
                            ))
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if t.bumpable(a) {
                            if ui
                                .button("Bump fee →")
                                .on_hover_text(
                                    "REPLACE this pending transaction with the same payment at a \
                                     higher tip. It does not send a second payment.",
                                )
                                .clicked()
                            {
                                bump_target = Some(t.clone());
                            }
                        } else if t.state.is_pending() && !a.fee_auction_active {
                            ui.label(
                                egui::RichText::new("no bump — tips dormant on this chain")
                                    .size(ty::MICRO)
                                    .color(palette::text_dim()),
                            );
                        }
                    });
                });
                if !t.note.is_empty() {
                    ui.label(
                        egui::RichText::new(&t.note)
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                    );
                }
            }
        });
        if let Some(t) = bump_target {
            self.pending_bump = Some(t);
        }

        // ── Bump confirmation ────────────────────────────────────────────────
        // The single most dangerous misunderstanding available in this whole
        // feature is "did I just pay twice?". This modal exists to make that
        // impossible to believe: it names the ONE payment, the ONE nonce slot the
        // two transactions contest, and states outright that the original can no
        // longer confirm.
        let Some(p) = self.pending_bump.clone() else {
            return;
        };
        let new_tip = auction::bump_tip_grains(p.tip_grains, a);
        let mut do_bump = false;
        let modal_ctx = ui.ctx().clone();
        egui::Window::new(egui::RichText::new("Replace this transaction").strong())
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(&modal_ctx, |ui| {
                ui.set_max_width(460.0);
                ui.add_space(sp::XS);
                bump_explainer(ui, &p, new_tip);
                ui.add_space(sp::M);
                ui.separator();
                ui.add_space(sp::S);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("⇄ Replace & raise tip")
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(palette::accent()),
                        )
                        .clicked()
                    {
                        do_bump = true;
                    }
                    if ui.button("Keep waiting").clicked() {
                        self.pending_bump = None;
                    }
                });
            });
        if do_bump {
            self.pending_bump = None;
            self.bump_send(&p, ctx);
        }
    }

    /// Broadcast the send the spender just confirmed, at exactly `tip_grains` —
    /// the bid captured when they clicked Review, NOT a fresh read of the live
    /// suggestion. The pool moves every second; signing a different number than
    /// the one on the confirmation screen would be the wallet spending money the
    /// user did not approve.
    fn send(&self, ctx: &egui::Context, tip_grains: u128) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // Spend from whichever account this wallet operates (own implicit id, or
        // a linked named account such as a tax account), signing with its key.
        let from = w.effective_account();
        let to = self.send_to.trim().to_string();
        let Some(grains) = parse_xus(&self.send_amount) else {
            return self.set_action("amount must be a number of XUS (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let activity = self.activity.clone();
        let outbox = self.outbox.clone();
        // The bid the spender confirmed. Re-gated on the deployment here as well
        // as at capture: below its activation height a tipped transaction is a HARD
        // consensus rejection, so an unarmed chain must get the bare, legal form
        // even if a stale tip somehow reached this point.
        let tip = if self.fee_auction_active() {
            tip_grains
        } else {
            0
        };
        let ctx = ctx.clone();
        begin(&action, "sending…");
        std::thread::spawn(move || {
            let terms = SendTerms {
                amount_grains: grains,
                tip_grains: tip,
                replace_nonce: None,
            };
            let msg = send_payment(&rpc, seed, &from, &to, terms, &params, &action)
                .map(|sent| {
                    let id = sent.txid.clone();
                    let bid = if sent.tip_grains > 0 {
                        format!(" · tip {} XUS", xus(&sent.tip_grains.to_string()))
                    } else {
                        String::new()
                    };
                    // Record it BEFORE reporting success: the outbox is what makes the
                    // send bumpable, and a send you can see but cannot rescue is the
                    // exact failure this slice exists to remove.
                    if let Ok(mut o) = outbox.lock() {
                        o.push(sent);
                    }
                    format!(
                    "✓ submitted {} XUS → {to}{bid} — in the mempool, confirms next block (tx {})",
                    xus(&grains.to_string()),
                    &id[..id.len().min(14)]
                )
                })
                .unwrap_or_else(|e| format!("✗ send failed: {e}"));
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    /// Whether a tip is LEGAL on this chain right now (the `fee-auction`
    /// deployment is Active).
    ///
    /// Below its activation height consensus rejects an `Action::Tipped`
    /// outright — a wallet that tipped anyway would not overpay, it would build a
    /// transaction no block can carry.
    fn fee_auction_active(&self) -> bool {
        self.snapshot
            .lock()
            .map(|s| s.auction.fee_auction_active)
            .unwrap_or(false)
    }

    /// REPLACE a stuck send by re-signing its slot with a higher bid.
    ///
    /// This is replace-by-fee, and it is emphatically NOT a second payment: the
    /// replacement reuses the original's signer and NONCE, so the two are rival
    /// claims on one slot and the chain can only ever apply one of them. The
    /// recipient is paid the original amount exactly once.
    ///
    /// The bid is [`auction::bump_tip_grains`], which satisfies both the
    /// mempool's `new_tip >= old_tip + MIN_RBF_BUMP_GRAINS` admission rule and
    /// the live next-block floor — read from the mempool crate, not restated, so
    /// it cannot drift out of agreement with the node that judges it.
    fn bump_send(&mut self, sent: &SentTx, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // The replacement is signed by the SELECTED wallet's key, so it must be the
        // key that signed the original. A wallet switch between sending and bumping
        // would otherwise sign for an account this key does not control — refused
        // here rather than left for the node to reject after the fact.
        if w.effective_account() != sent.from_account {
            return self.set_action(&format!(
                "that transaction was sent from {} — select that wallet to bump it",
                short_id(&sent.from_account)
            ));
        }
        let auction = self
            .snapshot
            .lock()
            .map(|s| s.auction.clone())
            .unwrap_or_default();
        if !auction.fee_auction_active {
            return self.set_action(
                "the fee auction is not active on this chain — a tip would be rejected",
            );
        }
        let new_tip = auction::bump_tip_grains(sent.tip_grains, &auction);
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let activity = self.activity.clone();
        let outbox = self.outbox.clone();
        let old = sent.clone();
        let ctx = ctx.clone();
        begin(
            &action,
            "replacing the pending transaction with a higher bid…",
        );
        std::thread::spawn(move || {
            let terms = SendTerms {
                amount_grains: old.amount_grains,
                tip_grains: new_tip,
                // THE replacement bit: reuse the original's slot.
                replace_nonce: Some(old.nonce),
            };
            let msg = send_payment(&rpc, seed, &old.from_account, &old.to, terms, &params, &action)
                .map(|replacement| {
                let id = replacement.txid.clone();
                if let Ok(mut o) = outbox.lock() {
                    // Mark the original REPLACED, then record the replacement. The
                    // original can no longer confirm: its slot now belongs to the
                    // higher bid, and the pool swapped them atomically.
                    for entry in o.iter_mut() {
                        if entry.txid == old.txid {
                            entry.state = SendState::Replaced;
                            entry.note = format!("replaced by {}", &id[..id.len().min(14)]);
                        }
                    }
                    o.push(replacement);
                }
                format!(
                    "✓ replaced tx {} — same nonce {}, tip raised {} → {} XUS (one payment, not two; new tx {})",
                    &old.txid[..old.txid.len().min(14)],
                    old.nonce,
                    xus(&old.tip_grains.to_string()),
                    xus(&new_tip.to_string()),
                    &id[..id.len().min(14)]
                )
            })
            .unwrap_or_else(|e| format!("✗ bump failed (the original is untouched): {e}"));
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    /// Scan the chain for the selected wallet's shielded notes and total its
    /// unspent pool balance. The pool is private, so this trial-decrypts every
    /// shielded bundle with the wallet's key — only the holder can.
    fn scan_shielded(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return; // watch-only has no shielded viewing key (no seed)
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // The wallet this scan is FOR. Both the "scanning" mark and the result are
        // filed under it, so a scan that finishes after the operator has switched
        // wallets updates its own entry and never the selected one.
        let account = w.scan_key();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.shielded.clone();
        let ctx = ctx.clone();
        if let Ok(mut m) = view.lock() {
            let v = m.entry_mut(&account);
            v.scanning = true;
            v.account = account.clone();
            v.message = "scanning the shielded pool…".to_string();
        }
        std::thread::spawn(move || {
            let result = scan_store(&rpc, seed);
            if let Ok(mut m) = view.lock() {
                let v = m.entry_mut(&account);
                v.scanning = false;
                match result {
                    Ok(store) => {
                        v.account = account.clone();
                        v.balance = store.balance();
                        v.notes = store.unspent_count();
                        v.scanned_height = store.scanned_height();
                        v.message = format!("scanned to height {}", store.scanned_height());
                    }
                    Err(e) => v.message = format!("scan failed: {e}"),
                }
            }
            ctx.request_repaint();
        });
    }

    /// Scan the selected wallet's POOL-V2 notes off-thread. Mirrors
    /// [`Self::scan_shielded`]; the two views are independent so a v1 scan
    /// failure can never blank a v2 balance (or the reverse).
    fn scan_shielded_v2(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return; // watch-only has no spend key
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // Filed under the wallet being scanned — see [`Self::scan_shielded`].
        let account = w.scan_key();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.shielded_v2.clone();
        let ctx = ctx.clone();
        if let Ok(mut m) = view.lock() {
            let v = m.entry_mut(&account);
            v.scanning = true;
            v.account = account.clone();
            v.message = "scanning pool v2 (trial decapsulation)…".to_string();
        }
        std::thread::spawn(move || {
            let result = scan_store_v2(&rpc, seed);
            if let Ok(mut m) = view.lock() {
                let v = m.entry_mut(&account);
                v.scanning = false;
                match result {
                    Ok(store) => {
                        v.account = account.clone();
                        v.balance = store.balance();
                        v.notes = store.unspent_count();
                        v.scanned_height = store.scanned_height();
                        v.message = format!("scanned to height {}", store.scanned_height());
                    }
                    Err(e) => v.message = format!("pool-v2 scan failed: {e}"),
                }
            }
            ctx.request_repaint();
        });
    }

    /// Wipe the active wallet's note-store cache file and re-scan the whole chain from
    /// its birthday. The store is a rebuildable index (encrypted note secrets keyed by
    /// this wallet's implicit id); deleting it forces `scan_store` to start from
    /// `NoteStore::new(0)`, so a contaminated store (e.g. one written before the
    /// receipt-status filter existed) is cleanly rebuilt from the canonical chain. The
    /// on-chain shielded pool is untouched — this only rebuilds local wallet state.
    fn rescan_shielded(&mut self, ctx: &egui::Context) {
        if !self.require_signing() {
            return; // watch-only has no shielded viewing key (no seed)
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        // Delete this wallet's cache file (keyed by its stable implicit id), matching the
        // path `scan_store` writes. A missing file just forces a fresh full scan.
        let scan_key = w.scan_key();
        let store_id = Keypair::hybrid_from_seed(w.seed)
            .public_key()
            .implicit_account_id()
            .to_string();
        if let Ok(path) = note_store_path(&store_id) {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                // Already gone ⇒ nothing to wipe; a fresh scan rebuilds it anyway.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    if let Ok(mut m) = self.shielded.lock() {
                        m.entry_mut(&scan_key).message =
                            format!("could not delete note cache: {e}");
                    }
                    return;
                }
            }
        }
        // Reset THIS wallet's in-memory view + the debounce so the auto-scan does not
        // race, then kick off a full scan (now starting from an empty store on disk).
        // Other wallets' scanned views are untouched — nothing about them changed.
        self.shielded_scan_for.clear();
        if let Ok(mut m) = self.shielded.lock() {
            let v = m.entry_mut(&scan_key);
            *v = ShieldedView::default();
            v.account = scan_key.clone();
            v.scanning = true;
            v.message = "rescanning from scratch…".to_string();
        }
        self.scan_shielded(ctx);
    }

    /// De-shield the largest unspent note back to this wallet's transparent
    /// account (a real Halo2 spend). Re-scans to rebuild the witness tree.
    fn deshield(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // Sign with the account this wallet OPERATES (the key-bound named account
        // when attached), not its keyless implicit id — that account both pays the
        // fee and receives the de-shielded funds. Using the implicit id would be
        // rejected ("unauthorized") because it has no key bound on-chain.
        let account = w.effective_account();
        // The wallet whose scanned view this spend changes — its own implicit id,
        // not the account it signs as.
        let scan_key = w.scan_key();
        // The variable amount to de-shield (XUS → grains). Must be a positive
        // amount; the UI only enables the button when it is within budget.
        let Some(grains) = parse_xus(&self.deshield_amount).filter(|g| *g > 0) else {
            finish(&self.action, "enter an amount to de-shield");
            return;
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let shielded = self.shielded.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "de-shielding (rebuilding witness + proving)…");
        std::thread::spawn(move || {
            match deshield_amount(&rpc, seed, &account, grains, &params, &action) {
                Ok(id) => {
                    let line = format!("de-shielded to {account} (tx {})", &id[..id.len().min(14)]);
                    finish(&action, &format!("{line} — updating balance…"));
                    record(&activity, &line);
                    ctx.request_repaint();
                    refresh_shielded_view(&rpc, seed, &scan_key, &shielded, &ctx);
                    finish(&action, "de-shield confirmed — shielded balance updated");
                }
                Err(e) => {
                    let msg = format!("de-shield failed: {e}");
                    finish(&action, &msg);
                    record(&activity, &msg);
                }
            }
            ctx.request_repaint();
        });
    }

    /// Shield transparent value INTO pool v2 (post-quantum).
    fn shield_v2(&self, ctx: &egui::Context) {
        self.run_v2_action(ctx, V2Action::Shield);
    }

    /// De-shield value OUT of pool v2 to this wallet's transparent account.
    fn deshield_v2(&self, ctx: &egui::Context) {
        self.run_v2_action(ctx, V2Action::Deshield);
    }

    /// Fully-private pool-v2 transfer to another `xusq1…` address.
    fn send_private_v2(&self, ctx: &egui::Context) {
        self.run_v2_action(ctx, V2Action::Send);
    }

    /// The one worker behind all three pool-v2 actions. They differ only in
    /// which builder runs and what the log line says, so they share a single
    /// spawn/action/rescan path — one place for the locking discipline rather
    /// than three that can drift.
    fn run_v2_action(&self, ctx: &egui::Context, what: V2Action) {
        if !self.require_signing() {
            return;
        }
        // Dormancy is re-checked HERE, at submit, against the state observed at
        // this instant — not inherited from whatever the last paint decided. A
        // disabled button is a courtesy; this is the guarantee. Without it a
        // selector left on Pool v2 while the node goes offline, or a stale
        // pending send confirmed after the classification changed, would spend
        // ~25 s building a proof for a transaction consensus hard-rejects.
        let v2_state = self
            .snapshot
            .lock()
            .map(|s| PoolState::classify_v2(s.online, s.shielded_v2.as_ref()))
            .unwrap_or(PoolState::Unavailable);
        if let Err(why) = private_send_dispatch(Pool::V2, v2_state) {
            finish(&self.action, why);
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let account = w.effective_account();
        // The wallet whose pool-v2 view this spend changes. Keyed by its own
        // implicit id: the notes belong to the SEED, so filing the post-spend
        // re-scan under a linked named account would strand the result where no
        // wallet's view can find it.
        let scan_key = w.scan_key();
        let field = match what {
            V2Action::Shield => &self.shield_v2_amount_in,
            V2Action::Deshield => &self.deshield_v2_amount_in,
            V2Action::Send => &self.private_v2_amount,
        };
        let Some(grains) = parse_xus(field).filter(|g| *g > 0) else {
            finish(&self.action, "enter an amount");
            return;
        };
        let shield_to = self.shield_v2_to.trim().to_string();
        let to = self.private_v2_to.trim().to_string();
        // Re-checked at SUBMIT, not merely at render: the recipient must belong
        // to POOL V2. A pool-v1 `xus1…` address reaching here would pay a
        // different recipient in a different value space, out of a pool the
        // operator did not arm. Refused with the specific reason, never coerced.
        if matches!(what, V2Action::Send) {
            if let Err(why) = pool_recipient_check(Pool::V2, &to) {
                finish(&self.action, why);
                return;
            }
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let view = self.shielded_v2.clone();
        let activity = self.activity.clone();
        // Tracked to a real terminal state by the receipt poller, exactly like a
        // transparent send — pool v2 is no longer the one path that forgets.
        let outbox = self.outbox.clone();
        let ctx = ctx.clone();
        begin(&action, what.starting());
        std::thread::spawn(move || {
            let result = match what {
                V2Action::Shield => {
                    shield_v2_amount(&rpc, seed, &account, &shield_to, grains, &action)
                }
                V2Action::Deshield => deshield_v2_amount(&rpc, seed, &account, grains, &action),
                V2Action::Send => zsend_v2_amount(&rpc, seed, &account, &to, grains, &action),
            };
            match result {
                // ON THE NETWORK. Register it in the outbox FIRST — before any
                // message is chosen — so a pool-v2 transaction is tracked to a real
                // terminal state by the same receipt poller that tracks transparent
                // sends. Previously nothing here was tracked at all: past the inline
                // wait the station simply forgot the transaction existed.
                Ok(sub) => {
                    let short_tx = sub.txid[..sub.txid.len().min(14)].to_string();
                    // The counterparty, ELIDED. A xusq1… address carries an
                    // ML-KEM-768 key (~1.2 KiB) and would otherwise blow out every
                    // row it appears in.
                    let counterparty = match what {
                        V2Action::Shield => {
                            if shield_to.is_empty() {
                                format!("{} (own address)", Pool::V2.name())
                            } else {
                                truncate_middle(&shield_to, 14, 8)
                            }
                        }
                        V2Action::Deshield => account.clone(),
                        V2Action::Send => truncate_middle(&to, 14, 8),
                    };
                    if let Ok(mut o) = outbox.lock() {
                        o.push(SentTx {
                            txid: sub.txid.clone(),
                            from_account: account.clone(),
                            to: counterparty.clone(),
                            amount_grains: grains,
                            nonce: sub.nonce,
                            tip_grains: 0,
                            shielded_route: true,
                            submitted_ms: now_ms(),
                            state: match &sub.status {
                                ReceiptStatus::Confirmed => SendState::Confirmed,
                                ReceiptStatus::Pending => SendState::Pending,
                                ReceiptStatus::Rejected(_) => SendState::Failed,
                            },
                            note: match &sub.status {
                                ReceiptStatus::Rejected(why) => why.clone(),
                                _ => String::new(),
                            },
                        });
                    }
                    match &sub.status {
                        ReceiptStatus::Confirmed => {
                            let line = match what {
                                V2Action::Send => pool_send_receipt(Pool::V2, grains, &sub.txid),
                                _ => format!("{} (tx {short_tx})", what.done()),
                            };
                            finish(&action, &format!("{line} — updating pool-v2 balance…"));
                            record(&activity, &line);
                            ctx.request_repaint();
                            // Re-scan so the spent note drops and change appears; a
                            // stale view after a confirmed spend reads as value gone.
                            if let Ok(store) = scan_store_v2(&rpc, seed) {
                                if let Ok(mut m) = view.lock() {
                                    // Per-wallet slot (PR #44): a rescan must land in
                                    // THIS wallet's entry, never a shared one.
                                    let v = m.entry_mut(&scan_key);
                                    v.account = scan_key.clone();
                                    v.balance = store.balance();
                                    v.notes = store.unspent_count();
                                    v.scanned_height = store.scanned_height();
                                    v.message =
                                        format!("scanned to height {}", store.scanned_height());
                                }
                            }
                            finish(
                                &action,
                                &format!(
                                    "CONFIRMED on-chain — {} · {} · {} · balance updated (tx {short_tx})",
                                    Pool::V2.name(),
                                    Pool::V2.crypto(),
                                    Pool::V2.pq_claim()
                                ),
                            );
                        }
                        // THE FIX. This is not a failure and must never read as one:
                        // the transaction is in the mempool and may be mined at any
                        // time. Saying "failed" here invited a resend — a second
                        // transaction for one intended action.
                        ReceiptStatus::Pending => {
                            let line = v2_status_line(what, &sub.status, &short_tx);
                            finish(&action, &line);
                            record(&activity, &line);
                        }
                        // A receipt exists and says rejected: a real, terminal failure,
                        // reported with the chain's own reason.
                        ReceiptStatus::Rejected(_) => {
                            let line = v2_status_line(what, &sub.status, &short_tx);
                            finish(&action, &line);
                            record(&activity, &line);
                        }
                    }
                }
                // NEVER BROADCAST. The nonce is untouched and nothing exists on the
                // network, so this is the one case where retrying is correct — and
                // the wording says so, instead of leaving the operator guessing
                // whether value is in flight.
                Err(e) => {
                    let msg = v2_not_broadcast_line(what, &e);
                    finish(&action, &msg);
                    record(&activity, &msg);
                }
            }
            ctx.request_repaint();
        });
    }

    /// Fully-private send (shielded → shielded): spend this wallet's scanned
    /// notes to pay `private_to`, with private change back. Sender, recipient, and
    /// amount are all hidden. Re-scans for a fresh witness, then proves on a worker.
    fn send_private(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let signer = w.effective_account();
        let to = self.private_to.trim().to_string();
        // Re-checked at SUBMIT, not merely at render: the recipient must belong
        // to the pool this path spends from. A pool-v2 address reaching the v1
        // spender would pay a recipient who cannot spend it, in a pool the
        // operator did not arm. It is refused, never coerced.
        if let Err(why) = pool_recipient_check(Pool::V1, &to) {
            return self.set_action(why);
        }
        let Some(grains) = parse_xus(&self.private_amount) else {
            return self.set_action("amount must be a number of XUS (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        // The wallet whose scanned view this spend changes (its own implicit id).
        let scan_key = self
            .wallets
            .get(self.selected)
            .map(|w| w.scan_key())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let shielded = self.shielded.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "private send (rebuilding witness + proving)…");
        std::thread::spawn(move || {
            match shielded_send(&rpc, seed, &signer, &to, grains, &params, &action) {
                Ok(id) => {
                    // The record names the pool and its post-quantum status, so
                    // "which pool moved" is unambiguous after the fact and not
                    // only at the moment of choosing.
                    let line = pool_send_receipt(Pool::V1, grains, &id);
                    finish(&action, &format!("{line} — updating balance…"));
                    record(&activity, &line);
                    ctx.request_repaint();
                    // The spend's nullifier lands when the tx is mined; re-scan so
                    // the shielded view drops the spent note (no stale balance).
                    refresh_shielded_view(&rpc, seed, &scan_key, &shielded, &ctx);
                    finish(
                        &action,
                        &format!(
                            "private send confirmed — {} · {} · {} balance updated",
                            Pool::V1.name(),
                            Pool::V1.crypto(),
                            Pool::V1.pq_claim()
                        ),
                    );
                }
                Err(e) => {
                    let msg = format!("private send failed: {e}");
                    finish(&action, &msg);
                    record(&activity, &msg);
                }
            }
            ctx.request_repaint();
        });
    }

    /// Serialize the in-session wallets into a keystore (label + seed + phrase).
    /// The on-chain id re-derives from the seed on load (it is the key's
    /// fingerprint); the phrase is stored so it can be exported after a restart.
    fn wallets_to_keystore(&self) -> Keystore {
        Keystore {
            miners: self
                .wallets
                .iter()
                .map(|w| KeystoreEntry {
                    account: w.label.clone(),
                    // Watch-only entries carry no seed — just the watched key.
                    seed_hex: if w.watch_only {
                        String::new()
                    } else {
                        hex_lower(&w.seed)
                    },
                    scheme: Some("hybrid65".to_string()),
                    mnemonic: w.mnemonic.clone(),
                    public_key: if w.watch_only {
                        Some(w.public_key.clone())
                    } else {
                        None
                    },
                })
                .collect(),
        }
    }

    /// Persist wallets to the auto-file, encrypted under the session PASSPHRASE
    /// (Argon2id) — the decryption key is derived from what you type and is never
    /// written to disk. Called on every change so "once unlocked, it stays".
    /// Requires the wallet to be unlocked (a passphrase set); a no-op otherwise so
    /// it can never overwrite the encrypted store with something weaker.
    fn auto_save(&mut self) {
        let Ok(path) = autosave_path() else { return };
        if self.wallets.is_empty() {
            // No wallets → remove the file so the empty state also persists.
            let _ = std::fs::remove_file(&path);
            self.wallets_dirty = false;
            return;
        }
        if self.passphrase.is_empty() {
            // Should not happen (creation is gated on a passphrase), but never fall
            // back to a weaker, keyless save.
            self.keystore_msg = "set a passphrase to save your wallet".to_string();
            return;
        }
        match self
            .wallets_to_keystore()
            .to_encrypted_json(&self.passphrase)
        {
            Ok(json) => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if std::fs::write(&path, &json).is_ok() {
                    restrict_to_owner(&path);
                    self.wallets_dirty = false;
                    // Reveal the passphrase fingerprint ONCE, right after the store is
                    // first sealed (the code is bound to this envelope's salt, so it
                    // doesn't exist until now). Thereafter it lives on the lock screen.
                    if !self.code_shown_once {
                        if let Some(code) = sov_rpc::keystore_stored_fingerprint(&json) {
                            self.code_shown_once = true;
                            self.set_action(&format!(
                                "wallet saved · your passphrase code is {code} — you'll \
                                 confirm this on the lock screen each launch; a different \
                                 code means a typo"
                            ));
                        }
                    }
                } else {
                    self.keystore_msg = "auto-save failed to write".to_string();
                }
            }
            Err(e) => self.keystore_msg = format!("auto-save failed: {e}"),
        }
    }

    /// Build wallets from a decrypted keystore into the live set (dedup by derived
    /// account). Shared by unlock and the portable-keystore import.
    fn load_keystore_entries(&mut self, ks: &Keystore) -> usize {
        let mut loaded = 0;
        for entry in &ks.miners {
            // A watch-only entry carries a public key and no seed; a normal entry
            // carries a seed.
            let built = if let Some(pk) = &entry.public_key {
                LoadedWallet::watch_only(entry.account.clone(), pk)
            } else {
                match hex_decode32(&entry.seed_hex) {
                    Ok(bytes) => LoadedWallet::from_seed(
                        entry.account.clone(),
                        bytes,
                        entry.mnemonic.clone(),
                    ),
                    Err(_) => continue,
                }
            };
            let Ok(w) = built else {
                continue;
            };
            if self.wallets.iter().any(|x| x.account == w.account) {
                continue;
            }
            self.register_wallet(w);
            loaded += 1;
        }
        loaded
    }

    /// Unlock the wallet store with the typed passphrase. On success the wallets
    /// load and the app unlocks. A LEGACY store (encrypted under the old on-disk
    /// device key) is transparently MIGRATED on first unlock: decrypt with the
    /// device key, re-encrypt under this passphrase, and delete the device key — so
    /// no decryption key is ever left on disk again. Existing wallets are never
    /// orphaned: as long as the device key is present, any passphrase migrates them.
    fn try_unlock(&mut self) {
        if self.passphrase.is_empty() {
            self.unlock_error = "enter your passphrase".to_string();
            return;
        }
        let Ok(path) = autosave_path() else {
            self.locked = false;
            return;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            // Nothing saved → nothing to unlock; treat the typed passphrase as the
            // new one for the wallets you're about to create.
            self.locked = false;
            self.unlock_error.clear();
            return;
        };
        // 1) Current format: passphrase-encrypted.
        if let Ok(ks) = Keystore::from_encrypted_or_plain(&text, Some(&self.passphrase)) {
            self.load_keystore_entries(&ks);
            self.locked = false;
            self.passphrase_set = true; // verified against the store
            self.unlock_error.clear();
            self.wallets_dirty = false;
            return;
        }
        // 2) Legacy format: encrypted under the on-disk device key → migrate.
        if let Ok(dkey) = legacy_device_key_hex() {
            if let Ok(ks) = Keystore::from_encrypted_or_plain(&text, Some(&dkey)) {
                self.load_keystore_entries(&ks);
                self.locked = false;
                self.passphrase_set = true; // verified via migration
                self.unlock_error.clear();
                // Re-encrypt under the passphrase, then remove the device key.
                self.auto_save();
                remove_legacy_device_key();
                self.set_action("wallet migrated to passphrase encryption");
                return;
            }
        }
        // Wrong passphrase. Use the salt-bound fingerprints to tell a near-miss typo
        // from an entirely different passphrase or a foreign/corrupt file — matching
        // either code still costs a full Argon2, so this leaks no brute-force shortcut.
        let typed = sov_rpc::keystore_fingerprint_of(&text, &self.passphrase);
        let stored = sov_rpc::keystore_stored_fingerprint(&text);
        self.unlock_error = match (typed, stored) {
            (Some(t), Some(s)) => {
                format!("wrong passphrase — you entered {t}, but this wallet is {s}")
            }
            _ => "wrong passphrase".to_string(),
        };
    }

    /// The full-window unlock screen shown while [`locked`](Self#structfield.locked).
    /// Nothing else renders until the passphrase decrypts the store.
    fn show_unlock_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(60.0);
            ui.vertical_centered(|ui| {
                ui.heading("🔒  Wallet locked");
                ui.add_space(8.0);
                ui.label(
                    "Enter your passphrase to decrypt this device's wallets. The key is \
                     derived from your passphrase and is never stored — so it's required \
                     every launch.",
                );
                // The wallet's own recognition code, read straight from the envelope
                // (a stored hash — no passphrase or KDF needed, so this is cheap). Seeing
                // the SAME code you memorized confirms it's your store; a wrong file shows
                // a different one. Absent for a store sealed before codes existed.
                if let Some(code) = autosave_path()
                    .ok()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .and_then(|t| sov_rpc::keystore_stored_fingerprint(&t))
                {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(format!("this wallet's code: {code}"))
                            .small()
                            .weak(),
                    );
                }
                ui.add_space(16.0);
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.passphrase)
                        .password(true)
                        .hint_text("passphrase")
                        .desired_width(280.0),
                );
                ui.add_space(10.0);
                let submit = ui.button("Unlock").clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if submit {
                    self.try_unlock();
                }
                if !self.unlock_error.is_empty() {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), &self.unlock_error);
                }
                ui.add_space(20.0);
                ui.label(
                    egui::RichText::new(
                        "Forgot it? Re-import each wallet from its 24-word recovery phrase. \
                         An older wallet from a previous version is upgraded automatically on \
                         first unlock.",
                    )
                    .small()
                    .weak(),
                );
            });
        });
    }

    /// The first-run passphrase CREATION screen — two inputs that must match before
    /// the master passphrase is set, so a typo can't become the encryption key and
    /// lock you out. Shown when a wallet action needs a passphrase and none is set.
    fn show_setup_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(50.0);
            let action = ui
                .vertical_centered(|ui| {
                    render_passphrase_setup(ui, &mut self.setup_pw, &mut self.setup_pw2).0
                })
                .inner;
            match action {
                SetupAction::Set => {
                    // Committed only because the two inputs matched (button was enabled).
                    self.passphrase.zeroize();
                    self.passphrase = self.setup_pw.clone();
                    self.passphrase_set = true;
                    self.setup_pw.zeroize();
                    self.setup_pw.clear();
                    self.setup_pw2.zeroize();
                    self.setup_pw2.clear();
                    self.show_setup = false;
                    self.set_action("passphrase set — now create or import a wallet");
                }
                SetupAction::Cancel => {
                    self.setup_pw.zeroize();
                    self.setup_pw.clear();
                    self.setup_pw2.zeroize();
                    self.setup_pw2.clear();
                    self.show_setup = false;
                }
                SetupAction::None => {}
            }
        });
    }

    /// The Vault tab — easy-mode treasury multisig (M-of-N). Drives the already-shipped
    /// On-chain coordination: an approval inbox (polled from `sov_getMultisigProposals`)
    /// shows each pending spend with a one-tap Approve; proposing is the Send form. No
    /// codes. Actions are normal member transactions via the isolated [`vault`] module.
    fn vault_panel(&mut self, ui: &mut egui::Ui) {
        if !self.vault_ui.loaded {
            self.vault_ui.vaults = vault::load_vaults();
            self.vault_ui.loaded = true;
            if self.vault_ui.new_threshold == 0 {
                self.vault_ui.new_threshold = 2;
            }
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        // Pre-extract the selected wallet's identity so closures never borrow self.wallets.
        let sel = self.wallets.get(self.selected);
        let my_account = sel.map(|w| w.effective_account()).unwrap_or_default();
        let my_key = sel.map(|w| w.public_key.clone()).unwrap_or_default();
        let my_seed = sel.filter(|w| !w.watch_only).map(|w| w.seed);

        // Auto-refresh the approval inbox from the chain while the tab is open.
        let stale = self
            .vault_ui
            .last_fetch
            .map(|t| t.elapsed() >= Duration::from_secs(4))
            .unwrap_or(true);
        if stale && !self.vault_ui.vaults.is_empty() {
            self.vault_ui.last_fetch = Some(Instant::now());
            self.fetch_proposals(&rpc, my_key.clone(), ui.ctx().clone());
        }

        ui.heading("🛡 Shared Vault");
        ui.label(
            egui::RichText::new(
                "A vault is an account several members must approve before it spends. \
                 Send from it like any account — co-signers just tap Approve below. The \
                 chain coordinates everything; there are no codes to copy.",
            )
            .weak(),
        );
        ui.separator();

        // Intents collected inside closures, executed afterwards (so closures never
        // need to borrow `self` to call a method).
        let mut do_create = false;
        let mut do_send = false;
        let mut refresh = false;
        let mut approve: Option<(String, String)> = None; // (vault account, proposal id hex)
        let mut cancel: Option<(String, String)> = None;

        // ── Needs your approval (the inbox, filled from the chain) ──
        egui::CollapsingHeader::new(egui::RichText::new("Needs your approval").strong())
            .default_open(true)
            .show(ui, |ui| {
                let (proposals, fetching, error) = self
                    .vault_ui
                    .inbox
                    .lock()
                    .map(|i| (i.proposals.clone(), i.fetching, i.error.clone()))
                    .unwrap_or_default();
                if ui.small_button("⟳ Refresh").clicked() {
                    refresh = true;
                }
                if fetching {
                    ui.label(egui::RichText::new("checking the chain…").small().weak());
                }
                if !error.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(220, 160, 60), &error);
                }
                let mine: Vec<&ProposalView> = proposals.iter().filter(|p| p.is_member).collect();
                if mine.is_empty() && !fetching {
                    ui.label(egui::RichText::new("nothing waiting on you").weak());
                }
                for p in mine {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Send {} XUS → {}",
                                grains_to_xus_plain(p.amount_grains),
                                p.to
                            ))
                            .strong(),
                        );
                        ui.label(
                            egui::RichText::new(format!("from “{}” ({})", p.vault_name, p.account))
                                .small()
                                .weak(),
                        );
                        ui.horizontal(|ui| {
                            let dots: String = (0..p.threshold as usize)
                                .map(|i| if i < p.approved { '✓' } else { '○' })
                                .collect();
                            ui.label(format!("{} of {}  {dots}", p.approved, p.threshold));
                            if p.can_approve {
                                if ui
                                    .add_enabled(my_seed.is_some(), egui::Button::new("Approve"))
                                    .clicked()
                                {
                                    approve = Some((p.account.clone(), p.id_hex.clone()));
                                }
                            } else {
                                ui.label(egui::RichText::new("✓ you approved").small().weak());
                            }
                            if ui.small_button("Cancel").clicked() {
                                cancel = Some((p.account.clone(), p.id_hex.clone()));
                            }
                        });
                    });
                }
            });

        // ── Your vaults ──
        egui::CollapsingHeader::new(egui::RichText::new("Your vaults").strong())
            .default_open(true)
            .show(ui, |ui| {
                if self.vault_ui.vaults.is_empty() {
                    ui.label(egui::RichText::new("none yet — create one below").weak());
                }
                let mut forget: Option<usize> = None;
                for (i, v) in self.vault_ui.vaults.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "“{}” — {}  ({} of {})",
                            v.name,
                            v.account,
                            v.threshold,
                            v.members.len()
                        ));
                        if ui.small_button("Forget").clicked() {
                            forget = Some(i);
                        }
                    });
                }
                if let Some(i) = forget {
                    self.vault_ui.vaults.remove(i);
                    let _ = vault::save_vaults(&self.vault_ui.vaults);
                }
            });

        // ── Create a vault ──
        egui::CollapsingHeader::new(egui::RichText::new("Create a vault").strong()).show(
            ui,
            |ui| {
                ui.horizontal(|ui| {
                    ui.label("Vault name");
                    ui.text_edit_singleline(&mut self.vault_ui.new_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Account to secure");
                    ui.text_edit_singleline(&mut self.vault_ui.new_account);
                    if !my_account.is_empty() && ui.button("Use selected wallet").clicked() {
                        self.vault_ui.new_account = my_account.clone();
                    }
                });
                ui.add_space(4.0);
                ui.label("Members — each holder's name + public key:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.new_member_name)
                            .hint_text("name")
                            .desired_width(110.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.new_member_key)
                            .hint_text("hybrid65:0x…")
                            .desired_width(260.0),
                    );
                    if ui.button("Add").clicked() {
                        match vault::parse_pubkey(&self.vault_ui.new_member_key) {
                            Ok(_) => {
                                let name = if self.vault_ui.new_member_name.trim().is_empty() {
                                    format!("member {}", self.vault_ui.new_members.len() + 1)
                                } else {
                                    self.vault_ui.new_member_name.trim().to_string()
                                };
                                self.vault_ui.new_members.push(vault::Member {
                                    name,
                                    pubkey: self.vault_ui.new_member_key.trim().to_string(),
                                });
                                self.vault_ui.new_member_name.clear();
                                self.vault_ui.new_member_key.clear();
                                self.vault_ui.create_msg.clear();
                            }
                            Err(e) => self.vault_ui.create_msg = e,
                        }
                    }
                    if !my_key.is_empty()
                        && ui.button("Add me").clicked()
                        && !self.vault_ui.new_members.iter().any(|m| m.pubkey == my_key)
                    {
                        self.vault_ui.new_members.push(vault::Member {
                            name: "Me".to_string(),
                            pubkey: my_key.clone(),
                        });
                    }
                });
                let mut drop_member: Option<usize> = None;
                for (i, m) in self.vault_ui.new_members.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!("• {} — {}", m.name, short_pubkey(&m.pubkey)));
                        if ui.small_button("✕").clicked() {
                            drop_member = Some(i);
                        }
                    });
                }
                if let Some(i) = drop_member {
                    self.vault_ui.new_members.remove(i);
                }
                let n = self.vault_ui.new_members.len().max(1) as u16;
                ui.horizontal(|ui| {
                    ui.label("Approvals required");
                    ui.add(egui::DragValue::new(&mut self.vault_ui.new_threshold).range(1..=n));
                    ui.label(format!("of {}", self.vault_ui.new_members.len()));
                });
                if ui
                    .add_enabled(
                        my_seed.is_some(),
                        egui::Button::new("Create vault on-chain"),
                    )
                    .clicked()
                {
                    do_create = true;
                }
                if my_seed.is_none() {
                    ui.label(
                        egui::RichText::new("select a signing wallet (not watch-only) first")
                            .small()
                            .weak(),
                    );
                }
                if !self.vault_ui.create_msg.is_empty() {
                    ui.label(egui::RichText::new(&self.vault_ui.create_msg).weak());
                }
            },
        );

        // ── Send from a vault (this PROPOSES the spend; co-signers approve above) ──
        egui::CollapsingHeader::new(egui::RichText::new("Send from a vault").strong()).show(
            ui,
            |ui| {
                if self.vault_ui.vaults.is_empty() {
                    ui.label(egui::RichText::new("create a vault first").weak());
                    return;
                }
                let names: Vec<String> = self
                    .vault_ui
                    .vaults
                    .iter()
                    .map(|v| format!("{} ({})", v.name, v.account))
                    .collect();
                if self.vault_ui.send_vault >= names.len() {
                    self.vault_ui.send_vault = 0;
                }
                egui::ComboBox::from_label("vault")
                    .selected_text(names[self.vault_ui.send_vault].clone())
                    .show_ui(ui, |ui| {
                        for (i, n) in names.iter().enumerate() {
                            ui.selectable_value(&mut self.vault_ui.send_vault, i, n);
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Send to");
                    ui.text_edit_singleline(&mut self.vault_ui.send_to);
                });
                ui.horizontal(|ui| {
                    ui.label("Amount (XUS)");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.send_amount)
                            .desired_width(120.0),
                    );
                });
                if ui
                    .add_enabled(my_seed.is_some(), egui::Button::new("Propose spend"))
                    .clicked()
                {
                    do_send = true;
                }
                if my_seed.is_none() {
                    ui.label(
                        egui::RichText::new("select a signing wallet that is a vault member first")
                            .small()
                            .weak(),
                    );
                }
                if !self.vault_ui.send_msg.is_empty() {
                    ui.label(egui::RichText::new(&self.vault_ui.send_msg).weak());
                }
            },
        );

        // ── Execute collected intents (clean &mut self here) ──
        if refresh {
            self.vault_ui.last_fetch = None; // force a fetch on the next frame
        }
        if do_create {
            self.vault_create(&rpc, my_seed);
        }
        if do_send {
            self.vault_propose(&rpc, my_seed);
        }
        if let Some((account, id)) = approve {
            self.vault_decide(&rpc, my_seed, &account, &id, true);
        }
        if let Some((account, id)) = cancel {
            self.vault_decide(&rpc, my_seed, &account, &id, false);
        }
    }

    /// Build a vault from the create-form fields, save it locally, and submit the
    /// `SetMultisig` that opts the account into M-of-N (signed by the selected wallet).
    fn vault_create(&mut self, rpc: &str, my_seed: Option<[u8; 32]>) {
        let Some(seed) = my_seed else {
            self.vault_ui.create_msg = "select a signing wallet first".to_string();
            return;
        };
        let v = vault::Vault {
            name: if self.vault_ui.new_name.trim().is_empty() {
                "Vault".to_string()
            } else {
                self.vault_ui.new_name.trim().to_string()
            },
            account: self.vault_ui.new_account.trim().to_string(),
            members: self.vault_ui.new_members.clone(),
            threshold: self.vault_ui.new_threshold,
        };
        let action = match v.set_multisig_action() {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.create_msg = e;
                return;
            }
        };
        // Save the definition locally so it's usable immediately (public data only).
        if !self.vault_ui.vaults.iter().any(|x| x.account == v.account) {
            self.vault_ui.vaults.push(v.clone());
            let _ = vault::save_vaults(&self.vault_ui.vaults);
        }
        // Reset the form.
        self.vault_ui.new_name.clear();
        self.vault_ui.new_account.clear();
        self.vault_ui.new_members.clear();
        self.vault_ui.new_threshold = 2;
        self.vault_ui.create_msg = "saved — submitting SetMultisig…".to_string();
        // Dispatch the on-chain opt-in (signed by the account's current controller).
        let rpc = rpc.to_string();
        let signer = v.account.clone();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, "securing the account as a vault…");
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &signer, action) {
                Ok(tx) => format!(
                    "✓ vault secured (SetMultisig tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ could not secure vault: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// PROPOSE a spend from the selected vault. Submitted as the member's OWN
    /// transaction (their key/nonce/fee); their signature is their first approval.
    fn vault_propose(&mut self, rpc: &str, my_seed: Option<[u8; 32]>) {
        let Some(seed) = my_seed else {
            self.vault_ui.send_msg = "select a signing wallet first".to_string();
            return;
        };
        let Some(member) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        else {
            return;
        };
        let Some(v) = self.vault_ui.vaults.get(self.vault_ui.send_vault).cloned() else {
            self.vault_ui.send_msg = "pick a vault".to_string();
            return;
        };
        let to = self.vault_ui.send_to.trim().to_string();
        if to.is_empty() {
            self.vault_ui.send_msg = "enter a recipient".to_string();
            return;
        }
        let Some(grains) = parse_xus(&self.vault_ui.send_amount) else {
            self.vault_ui.send_msg = "amount must be a number of XUS".to_string();
            return;
        };
        let account = match AccountId::new(&v.account) {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.send_msg = format!("bad vault account: {e}");
                return;
            }
        };
        let to_id = match AccountId::new(&to) {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.send_msg = format!("bad recipient: {e}");
                return;
            }
        };
        let action = Action::ProposeMultisig {
            account,
            action: Box::new(Action::Transfer {
                to: to_id,
                amount: Balance::from_grains(grains),
            }),
        };
        self.vault_ui.send_to.clear();
        self.vault_ui.send_amount.clear();
        self.vault_ui.send_msg = "proposing…".to_string();
        self.vault_ui.last_fetch = None; // refresh the inbox right after
        let rpc = rpc.to_string();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, "proposing the vault spend…");
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &member, action) {
                Ok(tx) => format!(
                    "✓ proposed — co-signers can now approve it (tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ propose failed: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// APPROVE (or CANCEL) a pending proposal — the member's own one-tap transaction.
    fn vault_decide(
        &mut self,
        rpc: &str,
        my_seed: Option<[u8; 32]>,
        account: &str,
        id_hex: &str,
        approve: bool,
    ) {
        let Some(seed) = my_seed else {
            self.set_action("select a signing wallet first");
            return;
        };
        let Some(member) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        else {
            return;
        };
        let acct = match AccountId::new(account) {
            Ok(a) => a,
            Err(e) => return self.set_action(&format!("bad vault account: {e}")),
        };
        let pid = match Hash::from_hex(id_hex) {
            Ok(h) => h,
            Err(e) => return self.set_action(&format!("bad proposal id: {e}")),
        };
        let action = if approve {
            Action::ApproveMultisig {
                account: acct,
                proposal: pid,
            }
        } else {
            Action::CancelMultisig {
                account: acct,
                proposal: pid,
            }
        };
        self.vault_ui.last_fetch = None; // refresh the inbox right after
        let verb = if approve { "approving" } else { "cancelling" };
        let rpc = rpc.to_string();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, &format!("{verb} the vault spend…"));
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &member, action) {
                Ok(tx) => format!("✓ {verb} submitted (tx {})", &tx[..tx.len().min(14)]),
                Err(e) => format!("✗ {verb} failed: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// Refresh the approval inbox: query `sov_getMultisigProposals` for every saved
    /// vault on a worker, decode each pending spend, and flag the ones the selected
    /// wallet still needs to approve. Runs off the UI thread; repaints when done.
    fn fetch_proposals(&self, rpc: &str, my_key: String, ctx: egui::Context) {
        if let Ok(mut i) = self.vault_ui.inbox.lock() {
            i.fetching = true;
        }
        let vaults = self.vault_ui.vaults.clone();
        let inbox = self.vault_ui.inbox.clone();
        let rpc = rpc.to_string();
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(6));
            let mut out: Vec<ProposalView> = Vec::new();
            let mut error = String::new();
            for v in &vaults {
                match client.call("sov_getMultisigProposals", json!({ "account": v.account })) {
                    Ok(Value::Array(arr)) => {
                        for p in &arr {
                            let action = p.get("action");
                            let to = action
                                .and_then(|a| a.get("to"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let amount_grains = action
                                .and_then(|a| a.get("amount"))
                                .and_then(Value::as_str)
                                .and_then(|s| s.parse::<u128>().ok())
                                .unwrap_or(0);
                            let approved =
                                p.get("approved").and_then(Value::as_u64).unwrap_or(0) as usize;
                            let threshold =
                                p.get("threshold").and_then(Value::as_u64).unwrap_or(0) as u16;
                            let approvers: Vec<u16> = p
                                .get("approvers")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_u64().map(|n| n as u16))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let my_idx = v.member_index(&my_key);
                            out.push(ProposalView {
                                vault_name: v.name.clone(),
                                account: v.account.clone(),
                                id_hex: field(p, "id"),
                                to,
                                amount_grains,
                                approved,
                                threshold,
                                can_approve: my_idx
                                    .map(|i| !approvers.contains(&i))
                                    .unwrap_or(false),
                                is_member: my_idx.is_some(),
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(e) => error = format!("could not read proposals: {e}"),
                }
            }
            if let Ok(mut i) = inbox.lock() {
                i.proposals = out;
                i.fetching = false;
                i.error = error;
            }
            ctx.request_repaint();
        });
    }

    /// Export all wallets to the passphrase-encrypted PORTABLE keystore (a backup
    /// you can move between machines). Day-to-day persistence is automatic via
    /// [`auto_save`](Self::auto_save); this is the hardened/portable copy.
    fn save_wallets(&mut self) {
        if self.keystore_pass.is_empty() {
            self.keystore_msg = "enter a passphrase for the backup file first".to_string();
            return;
        }
        if self.wallets.is_empty() {
            self.keystore_msg = "no wallets to save".to_string();
            return;
        }
        self.keystore_msg = match self
            .wallets_to_keystore()
            .to_encrypted_json(&self.keystore_pass)
        {
            Ok(json) => match write_keystore(&json) {
                Ok(path) => format!("exported {} wallet(s) → {path}", self.wallets.len()),
                Err(e) => format!("save failed: {e}"),
            },
            Err(e) => format!("encrypt failed: {e}"),
        };
    }

    /// Load + decrypt wallets from the portable backup file under its passphrase.
    fn load_wallets(&mut self) {
        if self.keystore_pass.is_empty() {
            self.keystore_msg = "enter the backup file's passphrase first".to_string();
            return;
        }
        let text = match read_keystore() {
            Ok(t) => t,
            Err(e) => {
                self.keystore_msg = format!("load failed: {e}");
                return;
            }
        };
        let ks = match Keystore::from_encrypted_or_plain(&text, Some(&self.keystore_pass)) {
            Ok(k) => k,
            Err(e) => {
                self.keystore_msg = format!("decrypt failed: {e}");
                return;
            }
        };
        let mut loaded = 0;
        for entry in &ks.miners {
            let Ok(bytes) = hex_decode32(&entry.seed_hex) else {
                continue;
            };
            // `entry.account` is the saved display label; the on-chain id is
            // re-derived from the seed. Dedup by that derived id. The phrase is
            // restored when the keystore carried it (so it can be re-exported).
            let Ok(w) =
                LoadedWallet::from_seed(entry.account.clone(), bytes, entry.mnemonic.clone())
            else {
                continue;
            };
            if self.wallets.iter().any(|x| x.account == w.account) {
                continue;
            }
            self.register_wallet(w);
            loaded += 1;
        }
        // If there's no master passphrase yet, adopt the backup's so the loaded
        // wallets persist on this device; otherwise keep the existing master.
        if !self.passphrase_set {
            self.passphrase = self.keystore_pass.clone();
            self.passphrase_set = true;
        }
        // Persist the imported backup to this device too, so it auto-loads next time.
        self.auto_save();
        self.keystore_msg = format!("loaded {loaded} wallet(s)");
    }

    /// Launch a local testnet-1 node the station supervises, and point the poller
    /// at it. If a wallet is selected, the node mines to it — so the wallet
    /// self-funds from coinbase. Reuses the proven `sov-testnet join` + `sov-rpcd`.
    fn start_local_node(&mut self) {
        // A node must mine to a wallet the user controls — refuse otherwise, so
        // coinbase can never accrue to an account nobody holds the key for.
        let Some(w) = self.wallets.get(self.selected) else {
            self.node_status =
                "create or open a wallet first — a node mines to a wallet you control".to_string();
            return;
        };
        // Idempotent: never start a second node on top of a running/starting one.
        if self.local_node_running() {
            return;
        }
        let label = w.label.clone();
        let account = w.account.clone();
        let seed = w.seed;
        let spec = self.network.spec_filename().to_string();
        let net = self.network.data_subdir().to_string();

        *self.node_run.lock().unwrap() = NodeRun::Starting;
        // The selected wallet is the coinbase target IF the user later enables mining;
        // the node itself starts in sync-only mode (no proof-of-work) until then.
        self.mining_account = Some(account.clone());
        self.node_status =
            "starting node (replaying chain) — connecting + syncing (mining off)…".to_string();
        if let Ok(mut c) = self.config.lock() {
            c.rpc = "127.0.0.1:8645".to_string();
            self.rpc_field = c.rpc.clone();
        }
        push_log(
            &self.node_logs,
            format!(
                "start requested — sync-only; enable mining in the Mining tab (coinbase → {label})"
            ),
        );

        // Build + replay the node OFF the UI thread (replaying thousands of blocks
        // would otherwise freeze the window), then publish the running handle.
        let run = Arc::clone(&self.node_run);
        let logs = Arc::clone(&self.node_logs);
        let peer = self.peer_addr.clone();
        // The master passphrase seals the miner keystore at rest. Clone into a
        // Zeroizing so this copy is wiped when the build thread finishes.
        let passphrase = zeroize::Zeroizing::new(self.passphrase.clone());
        let expose_lan = self.expose_rpc_lan;
        std::thread::spawn(move || {
            let result = build_and_run_node(
                &spec,
                &net,
                &account,
                seed,
                &peer,
                &passphrase,
                expose_lan,
                &logs,
            );
            let mut slot = run.lock().unwrap();
            match result {
                Ok(node) => {
                    // If the user pressed Stop while we were building, don't run —
                    // shut the just-built node down so it can't become a ghost.
                    if matches!(*slot, NodeRun::Starting) {
                        *slot = NodeRun::Running(node);
                    } else {
                        drop(slot);
                        node.shutdown();
                        push_log(&logs, "start cancelled — node shut down");
                    }
                }
                Err(e) => {
                    push_log(&logs, format!("start FAILED: {e}"));
                    if matches!(*slot, NodeRun::Starting) {
                        *slot = NodeRun::Failed(e);
                    }
                }
            }
        });
    }

    /// For the in-process embedded node, trust the DIRECT read over any loopback-RPC
    /// poll: a Running local node is ONLINE (it lives in this process), its height and
    /// chain id come straight from the chain, and a transient poll error is cleared —
    /// the node is never reached over a socket, so a socket timeout is meaningless and
    /// must not surface as "offline" / a transport error (the Windows symptom). On a
    /// momentary `try_lock` miss (node mid-commit) we keep the last height; it's still
    /// online.
    fn apply_local_status(&self, snap: &mut Snapshot) {
        if let NodeRun::Running(node) = &*self.node_run.lock().unwrap() {
            snap.online = true;
            snap.error = None;
            // Lock-free peer/sync telemetry — always available, so these never blank
            // out while the node is mid-commit.
            let sv = node.sync_view();
            snap.peers = Some(sv.peers);
            snap.best_peer_height = Some(sv.best_peer_height);
            snap.syncing = sv.syncing;
            snap.local_hashrate = sv.local_hashrate;
            // Live chain state, read in-process every frame so height + supply + head
            // ROLL in real time (no dependency on the loopback RPC poller, which blips
            // on Windows). Skipped silently if the node is busy this instant.
            if let Some(cv) = node.chain_view() {
                snap.height = Some(cv.height);
                if !cv.chain_id.is_empty() {
                    snap.chain_id = cv.chain_id;
                }
                snap.head_hash = cv.head_hash;
                snap.state_root = cv.state_root;
                snap.supply_mined = cv.supply_grains;
                snap.mempool = Some(cv.mempool);
            }
        }
    }

    /// Render the current transaction toast (if any) INLINE in the status bar — a
    /// colored, auto-dismissing chip (green on success, red on failure) drawn at the
    /// left of the bottom bar so a result is never missed from any tab, and never
    /// floats over the top-bar node-status line. Returns `true` while a toast is live
    /// (the caller then suppresses the staleness indicator for its brief lifetime).
    fn show_bottom_toast(&mut self, ui: &mut egui::Ui) -> bool {
        const TOAST_MS: u64 = 5_000;
        let Some((msg, at)) = self.toast.clone() else {
            return false;
        };
        if now_ms().saturating_sub(at) >= TOAST_MS {
            self.toast = None;
            return false;
        }
        let st = tx_status(&msg);
        let col = status_color(st);
        let glyph = match st {
            TxStatus::Ok => "✓",
            TxStatus::Err => "✗",
            TxStatus::Info => "•",
        };
        // The status bar is a single line shared with the version label — cap the
        // message so a long error can never blow out the layout.
        let shown = toast_chip_text(&msg, 96);
        ui.label(
            egui::RichText::new(format!("{glyph}  {shown}"))
                .color(col)
                .strong(),
        );
        // Keep repainting so the toast dismisses on time even if nothing else changes.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(200));
        true
    }

    /// One tab in the top toolbar: a leading glyph + label, a clear active state
    /// (accent-filled pill via the selectable's selection styling), and built-in hover
    /// feedback. Replaces the plain text `selectable_value` row.
    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, glyph: &str, label: &str) {
        let selected = self.tab == tab;
        let text = egui::RichText::new(format!("{glyph}  {label}"));
        let text = if selected {
            text.strong().color(palette::text())
        } else {
            text.color(palette::text_dim())
        };
        if ui.selectable_label(selected, text).clicked() {
            self.tab = tab;
        }
    }

    /// Append a node-log line whenever a watched observable changes — the live peer
    /// count (in-process), RPC online/offline, and head height — so the Node log shows
    /// peering churn and sync progress as they happen instead of a frozen number. Only
    /// transitions are logged (most frames change nothing), so the log stays readable.
    fn log_node_changes(&mut self, snap: &Snapshot) {
        let peers = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => Some(node.peer_count()),
            _ => None,
        };
        match (self.log_prev_peers, peers) {
            (Some(prev), Some(now)) if prev != now => {
                // RAW TCP links (an inbound + an outbound to one node briefly count as
                // two before dedup collapses them) — distinct from "authenticated peers"
                // below, which is the real remote-node count. Labeling them apart stops a
                // transient link reading as a ghost peer.
                push_log(&self.node_logs, format!("TCP links {prev} → {now}"));
                self.log_prev_peers = Some(now);
            }
            (None, Some(now)) => self.log_prev_peers = Some(now),
            (Some(_), None) => self.log_prev_peers = None, // node stopped
            _ => {}
        }
        // RPC reachability transitions (this is the "offline up top" the user sees).
        if self.log_prev_online != Some(snap.online) {
            if let Some(prev) = self.log_prev_online {
                if prev != snap.online {
                    push_log(
                        &self.node_logs,
                        if snap.online {
                            "RPC online — node responding".to_string()
                        } else {
                            "RPC OFFLINE — node not responding".to_string()
                        },
                    );
                }
            }
            self.log_prev_online = Some(snap.online);
        }
        // Head-height progress (mining and/or sync catching up).
        if let Some(h) = snap.height {
            match self.log_prev_height {
                Some(prev) if prev != h => {
                    push_log(&self.node_logs, format!("height {prev} → {h}"));
                    self.log_prev_height = Some(h);
                }
                None => self.log_prev_height = Some(h),
                _ => {}
            }
        }
        // Authenticated-peer transitions — the stage AFTER raw TCP connect: a peer is
        // only counted here once it has proven same chain + genesis + key over the
        // encrypted channel. If raw peers climb but this stays 0, the operator can see
        // the handshake is the thing failing (wrong network / version), not the sync.
        if let Some(now) = snap.peers {
            match self.log_prev_authed {
                Some(prev) if prev != now => {
                    push_log(
                        &self.node_logs,
                        format!("authenticated peers {prev} → {now}"),
                    );
                    self.log_prev_authed = Some(now);
                }
                None => self.log_prev_authed = Some(now),
                _ => {}
            }
        }
        // The height of the peer chain we are pulling toward — so a catch-up shows a
        // concrete target ("syncing to 8400"), not an opaque spinner.
        if let Some(best) = snap.best_peer_height.filter(|b| *b > 0) {
            match self.log_prev_best {
                Some(prev) if prev != best => {
                    push_log(&self.node_logs, format!("peer chain height: {best}"));
                    self.log_prev_best = Some(best);
                }
                None => self.log_prev_best = Some(best),
                _ => {}
            }
        }
        // Catch-up start/finish: the explicit "downloading vs mining" state the user
        // asked to see — the node downloads the existing chain first, then mines.
        if self.log_prev_syncing != Some(snap.syncing) {
            if self.log_prev_syncing.is_some() {
                push_log(
                    &self.node_logs,
                    if snap.syncing {
                        "syncing — downloading the existing chain from a peer (mining paused)"
                            .to_string()
                    } else {
                        "✓ synced — caught up to the network tip, mining enabled".to_string()
                    },
                );
            }
            self.log_prev_syncing = Some(snap.syncing);
        }
    }

    /// Whether the embedded node is up or coming up. In-process, so this is the true
    /// state — there is no external process to fall out of sync with.
    fn local_node_running(&self) -> bool {
        matches!(
            *self.node_run.lock().unwrap(),
            NodeRun::Running(_) | NodeRun::Starting
        )
    }

    fn stop_local_node(&mut self) {
        // Take the running node out and shut it down SYNCHRONOUSLY: shutdown joins the
        // production + RPC + P2P threads and releases the listen ports BEFORE we
        // return, so a subsequent Start/Reset can never race the old listeners (the
        // "address already in use" / ghost-miner class of bug). It is fast (flags +
        // short joins), so the brief UI pause is acceptable for an explicit Stop.
        let prev = std::mem::replace(&mut *self.node_run.lock().unwrap(), NodeRun::Stopped);
        if let NodeRun::Running(node) = prev {
            node.shutdown();
        }
        self.mining_account = None;
        self.node_status = "local node stopped".to_string();
        push_log(
            &self.node_logs,
            "node stopped — RPC + P2P halted, ports released",
        );
    }

    /// Node-tab peering controls (Bitcoin/Zcash style): designate a seed peer once;
    /// it is persisted and **auto-dialed on every start**, and gossip discovers the
    /// rest of the network from there. Also shows the live peer count and this
    /// machine's own dial-able address so the other node can seed back to it.
    fn node_peering_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.separator();
        ui.heading("Peering");
        let help = if self.network.is_sandbox() {
            "Join other machines to this test network. Enter one peer's address — it is \
             saved for TESTNET only and auto-dialed every start. LAN discovery and peer \
             gossip find the rest automatically."
        } else {
            "Mainnet automatically dials both public relays and discovers same-LAN nodes. \
             Add a miner's address here for a direct link; it is saved for MAINNET only. \
             A peer counts only after matching mainnet's chain id and frozen genesis."
        };
        ui.label(egui::RichText::new(help).weak());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Seed peer");
            ui.add(
                egui::TextEdit::singleline(&mut self.peer_addr)
                    .hint_text("other machine's IP — port optional (e.g. 192.168.0.244)")
                    .desired_width(320.0),
            );
            if ui
                .button("Connect")
                .on_hover_text("save + dial now, and auto-dial on every start")
                .clicked()
            {
                let p = self.peer_addr.trim().to_string();
                self.peer_addr = p.clone();
                save_peer(self.network, &p);
                if p.is_empty() {
                    self.node_status = "seed peer cleared".into();
                    push_log(&self.node_logs, "seed peer cleared".to_string());
                } else {
                    // Dial NOW if the node is up; report the REAL outcome — the resolved
                    // target (with any appended/looked-up port) or the actual error — so
                    // the box never "appears to dial but does nothing".
                    let outcome = match &*self.node_run.lock().unwrap() {
                        NodeRun::Running(node) => Some(node.dial(&p)),
                        _ => None,
                    };
                    match outcome {
                        Some(Ok(addrs)) => {
                            let list = addrs
                                .iter()
                                .map(|a| a.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            self.node_status = format!("dialing {list} (auto-dial on)");
                            push_log(&self.node_logs, format!("seed peer {p} → dialing {list}"));
                        }
                        Some(Err(e)) => {
                            self.node_status = format!("seed peer '{p}' rejected: {e}");
                            push_log(&self.node_logs, format!("seed peer '{p}' rejected: {e}"));
                        }
                        None => {
                            // Node not started yet: saved, and auto-dialed on next start.
                            self.node_status =
                                format!("seed peer saved ({p}) — start the node to dial");
                            push_log(
                                &self.node_logs,
                                format!("seed peer saved: {p} (auto-dials when the node starts)"),
                            );
                        }
                    }
                }
            }
            // Windows only: a one-click firewall fix (re-request the inbound allow),
            // for the case where the first-run UAC prompt was dismissed.
            if cfg!(windows)
                && ui
                    .button("Allow through Windows Firewall")
                    .on_hover_text("re-add the inbound allow rule (one UAC prompt)")
                    .clicked()
            {
                add_firewall_rule();
                self.node_status =
                    "requested Windows Firewall allow — accept the UAC prompt".into();
                push_log(
                    &self.node_logs,
                    "re-requested Windows Firewall inbound allow",
                );
            }
        });
        // Live peer count, read straight from the in-process transport.
        let peers = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => Some(node.sync_view().peers),
            _ => None,
        };
        match peers {
            Some(n) if n > 0 => {
                ui.colored_label(
                    palette::success(),
                    format!("● {n} peer(s) connected — on the same network"),
                );
            }
            Some(_) => {
                ui.colored_label(
                    palette::error(),
                    "● 0 peers — NOT connected. Set the other machine's address above + Connect.",
                );
            }
            None => {
                ui.label(egui::RichText::new("node stopped").weak());
            }
        }
        // RPC bind posture opt-in. The node's JSON-RPC is unauthenticated, so it binds
        // LOOPBACK by default; only tick this to reach it from the OTHER machine / the
        // explorer / the conformance sweep. Takes effect on the next node (re)start.
        ui.add_space(2.0);
        if ui
            .checkbox(
                &mut self.expose_rpc_lan,
                "Expose node RPC on LAN (for XUS Miner/explorer/conformance tools)",
            )
            .on_hover_text(
                "Off (default): the node's RPC is reachable only from this machine (127.0.0.1). \
                 On: binds 0.0.0.0 so LAN tools can reach it — the RPC is unauthenticated, so \
                 only enable this on a trusted network. Applies on the next node start.",
            )
            .changed()
        {
            save_expose_rpc_lan(self.expose_rpc_lan);
        }
        if let Some(ip) = &self.lan_addr {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!(
                    "This machine's address (enter THIS in the other node's Seed peer): {ip}:9645",
                ))
                .monospace()
                .size(12.0),
            );
            // Only advertise the LAN RPC address when the operator opted in; otherwise the
            // node binds loopback and only 127.0.0.1 can reach it.
            let rpc_disp = if self.expose_rpc_lan {
                format!("{ip}:8645")
            } else {
                "127.0.0.1:8645".to_string()
            };
            ui.label(
                egui::RichText::new(format!(
                    "RPC for tools/explorer (e.g. the conformance sweep): {rpc_disp}",
                ))
                .monospace()
                .size(12.0)
                .color(palette::text_dim()),
            );
        }
    }

    /// Wipe the local node's chain entirely — back to genesis (height 0). Stops
    /// the node first. The next "Start local node" rebuilds a fresh chain from
    /// the current spec, mining to the active wallet. Use after a genesis change
    /// (e.g. binding tax keys) or to clear coins mined to an old account.
    fn reset_local_chain(&mut self) {
        self.stop_local_node();
        let dir = match local_node_dir(self.network.data_subdir()) {
            Ok(d) => d,
            Err(e) => {
                self.node_status = format!("could not locate the local chain: {e}");
                return;
            }
        };
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                self.node_status =
                    "local chain wiped — Start local node to mine a fresh chain from genesis"
                        .to_string()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.node_status = "no local chain to wipe — already clean".to_string()
            }
            Err(e) => self.node_status = format!("could not wipe local chain: {e}"),
        }
    }

    /// Switch the app between networks. Wallets are untouched (keys work on any
    /// network); only the chain view changes. Any supervised local node is
    /// stopped first (never leave a testnet node running under a mainnet view),
    /// and the RPC endpoint resets to the new network's default.
    fn switch_network(&mut self, to: Network) {
        if to == self.network {
            return;
        }
        self.stop_local_node();
        self.network = to;
        self.peer_addr = read_saved_peer(to);
        let rpc = to.default_rpc().to_string();
        if let Ok(mut c) = self.config.lock() {
            c.rpc = rpc.clone();
        }
        self.rpc_field = rpc;
        self.node_status = format!("switched to {} — wallets unchanged", to.label());
    }
}

impl Station {
    /// Halt the embedded node, joining its threads. Called on window close (Drop and
    /// eframe's `on_exit`) so the node's lifetime is exactly the app's — it can never
    /// linger as an orphan daemon with no UI to control it.
    fn shutdown_node(&mut self) {
        let prev = std::mem::replace(&mut *self.node_run.lock().unwrap(), NodeRun::Stopped);
        if let NodeRun::Running(node) = prev {
            node.shutdown();
        }
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        self.shutdown_node();
        // Scrub typed secrets that aren't owned by a LoadedWallet: the unlock/keystore
        // passphrase, the recovery phrase being typed into the Import field, and the
        // one-time phrase shown right after generating a wallet. (Each LoadedWallet
        // wipes its own seed/phrase/viewing-key via its Drop impl.)
        self.passphrase.zeroize();
        self.keystore_pass.zeroize();
        self.setup_pw.zeroize();
        self.setup_pw2.zeroize();
        self.import_mnemonic.zeroize();
        self.htlc_preimage.zeroize();
        if let Some((_, phrase)) = self.backup_mnemonic.as_mut() {
            phrase.zeroize();
        }
    }
}

impl eframe::App for Station {
    /// eframe may signal exit without dropping the app; halt the node here too so
    /// closing the window always stops it.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_node();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Locked: an encrypted wallet store exists but hasn't been unlocked this
        // session. Show ONLY the unlock screen — no wallets, no node — until the
        // passphrase decrypts the store.
        if self.locked {
            self.show_unlock_screen(ctx);
            return;
        }
        // First-run: create a passphrase (with confirmation) before anything can be
        // encrypted under it.
        if self.show_setup {
            self.show_setup_screen(ctx);
            return;
        }
        let mut snap = self.snapshot.lock().map(|s| s.clone()).unwrap_or_default();

        // The desktop app's node runs IN-PROCESS — read its status DIRECTLY rather than
        // trusting a loopback-RPC poll that can spuriously time out ("Transport: … did
        // not properly respond") and falsely read offline. A running local node is
        // online, period; its height/chain come straight from the chain.
        self.apply_local_status(&mut snap);

        // Live change-logging: append peer-count / online-offline / height changes to
        // the node log the moment they happen, so the operator sees peering churn and
        // sync progress as it occurs (not just a frozen number).
        self.log_node_changes(&snap);

        // Surface each new action RESULT as a transient toast — visible from ANY tab,
        // not just Wallet — so you always see the moment a send lands (green) or fails
        // (red). Detected once per distinct result message; rendered in the bottom bar
        // (see `show_bottom_toast`) so it never floats over the top-bar node status.
        {
            let (busy, msg) = self
                .action
                .lock()
                .map(|a| (a.busy, a.message.clone()))
                .unwrap_or((false, String::new()));
            if !busy && !msg.is_empty() && msg != self.toast_seen {
                self.toast = Some((msg.clone(), now_ms()));
                self.toast_seen = msg;
            }
        }

        // Keep the window title in sync with the selected network.
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
            "SOV Station — {}",
            self.network.label()
        )));

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("SOV Station");
                ui.separator();
                // Network selector — one colored chip that IS the switcher (no more
                // redundant "TESTNET TESTNET"); you ALWAYS know which network you're on,
                // and switching keeps every wallet (keys are network-agnostic).
                let mut chosen = self.network;
                egui::ComboBox::from_id_salt("network")
                    .selected_text(
                        egui::RichText::new(format!("● {}", self.network.label()))
                            .strong()
                            .color(self.network.color()),
                    )
                    .width(120.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut chosen, Network::Testnet, "Testnet");
                        ui.selectable_value(&mut chosen, Network::Mainnet, "Mainnet");
                    });
                if chosen != self.network {
                    // Switching TO mainnet is consequential (real value) — confirm
                    // first. Switching back to testnet is harmless, so do it now.
                    match chosen {
                        Network::Mainnet => self.pending_network = Some(Network::Mainnet),
                        Network::Testnet => self.switch_network(Network::Testnet),
                    }
                }
                // PoW algorithm for the selected network (fixed by its chain-spec, not a
                // separate choice): SHA-256d on testnet, RandomX on mainnet. Shown so the
                // operator always knows exactly what their CPU is mining.
                ui.label(
                    egui::RichText::new(format!("⛏ {}", self.network.pow_algo()))
                        .strong()
                        .color(palette::link()),
                )
                .on_hover_text(
                    "Proof-of-work algorithm for this network. Testnet: SHA-256d (fast). \
                     Mainnet: RandomX (Monero's memory-hard, ASIC-resistant CPU PoW). \
                     Reward rate is proportional to your hashpower.",
                );
                ui.separator();
                let (dot, label) = if snap.online {
                    (palette::success(), "online")
                } else {
                    (palette::error(), "offline")
                };
                ui.colored_label(dot, "●");
                ui.label(label);
                if !snap.chain_id.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new(&snap.chain_id).monospace());
                    // SAFETY GUARD: the connected node must be on the selected
                    // network. A mismatch (e.g. a testnet node while "Mainnet" is
                    // chosen) is flagged loudly so no action lands on the wrong chain.
                    if snap.online && snap.chain_id != self.network.chain_id() {
                        ui.colored_label(
                            palette::error(),
                            format!(
                                "⚠ not {} — expected {}",
                                self.network.label(),
                                self.network.chain_id()
                            ),
                        );
                    }
                }
                // Theme toggle (right-aligned): flip dark/light live + persist the choice.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (glyph, hint) = if self.dark_mode {
                        ("☀", "Switch to light mode")
                    } else {
                        ("🌙", "Switch to dark mode")
                    };
                    if ui.button(glyph).on_hover_text(hint).clicked() {
                        self.dark_mode = !self.dark_mode;
                        install_theme(ui.ctx(), self.dark_mode);
                        save_theme(self.dark_mode);
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("RPC");
                ui.add(egui::TextEdit::singleline(&mut self.rpc_field).desired_width(220.0));
                if ui.button("Connect").clicked() {
                    if let Ok(mut c) = self.config.lock() {
                        c.rpc = self.rpc_field.trim().to_string();
                    }
                }
                ui.separator();
                // A local node runs IN-STATION on BOTH networks: tap Start and it mines
                // this network's chain (testnet sandbox OR the real mainnet genesis) to
                // the active wallet — same flow either way. (Reset wipes only THIS
                // machine's local copy; on mainnet it simply re-syncs/re-mines.)
                if self.local_node_running() {
                    if ui.button("Stop local node").clicked() {
                        self.stop_local_node();
                    }
                } else {
                    // Mining is bound to a wallet: disable until one is active,
                    // and name the target so it's unmistakable which earns.
                    let target = self.wallets.get(self.selected).map(|w| w.label.clone());
                    let enabled = target.is_some();
                    let label = format!("Start local node ({})", self.network.label());
                    let btn = ui.add_enabled(enabled, egui::Button::new(label));
                    let btn = match &target {
                        Some(l) => btn.on_hover_text(format!(
                            "mines the {} chain to “{l}” (the active wallet)",
                            self.network.label()
                        )),
                        None => btn.on_hover_text("create or open a wallet first"),
                    };
                    if btn.clicked() {
                        self.start_local_node();
                    }
                    if ui
                        .button("Reset local chain")
                        .on_hover_text(
                            "Wipe THIS machine's local chain back to genesis (height 0). \
                             Only affects local data — on mainnet the node simply re-syncs \
                             from peers afterward.",
                        )
                        .clicked()
                    {
                        self.reset_local_chain();
                    }
                    // VISIBLE guidance (not just a hover) for the most common
                    // first-run confusion: a greyed "Start" because there is no
                    // wallet yet. A node must mine to a wallet you control.
                    if !enabled {
                        ui.label(
                            egui::RichText::new(
                                "← create or import a wallet in the Wallet tab first \
                                 (a node mines to a wallet you control)",
                            )
                            .color(palette::warning()),
                        );
                    }
                }
                // Live status derived from the ACTUAL in-process run state, so it
                // always reflects reality — "starting (replaying)" instead of a bare
                // connection error, the mining account when up, the reason on failure.
                let live = match &*self.node_run.lock().unwrap() {
                    NodeRun::Stopped => None,
                    NodeRun::Starting => {
                        Some("● starting node — replaying chain, RPC up shortly…".to_string())
                    }
                    NodeRun::Running(n) => Some(format!(
                        "● node running in-process — mining to {} on 127.0.0.1:8645",
                        short_id(&n.account)
                    )),
                    NodeRun::Failed(e) => Some(format!("✗ node failed to start: {e}")),
                };
                match live {
                    Some(s) => {
                        ui.label(egui::RichText::new(s).weak());
                    }
                    None if !self.node_status.is_empty() => {
                        ui.label(egui::RichText::new(&self.node_status).weak());
                    }
                    None => {}
                }
            });
            ui.add_space(6.0);
            // A real toolbar: a glyph per tab, a clear active state, and a hairline
            // separating it from the content below.
            ui.horizontal(|ui| {
                self.tab_button(ui, Tab::Node, "◧", "Node");
                self.tab_button(ui, Tab::Mining, "⛏", "Mining");
                self.tab_button(ui, Tab::Wallet, "👛", "Wallet");
                self.tab_button(ui, Tab::Tokens, "⬡", "Tokens");
                self.tab_button(ui, Tab::Swaps, "⇄", "Swaps");
                self.tab_button(ui, Tab::Vault, "🛡", "Vault");
                self.tab_button(ui, Tab::Blocks, "▦", "Blocks");
                self.tab_button(ui, Tab::Activity, "◷", "Activity");
            });
            ui.add_space(4.0);
            ui.separator();
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                // A live transaction toast owns the left of the status bar for its brief
                // lifetime (green/red) — more important in that moment than staleness or a
                // node error, and it can never collide with the top-bar node status here.
                if !self.show_bottom_toast(ui) {
                    if let Some(err) = &snap.error {
                        ui.colored_label(palette::error(), format!("⚠ {err}"));
                    } else if snap.updated_ms > 0 {
                        let age = now_ms().saturating_sub(snap.updated_ms);
                        ui.label(egui::RichText::new(format!("updated {age} ms ago")).weak());
                    }
                }
                // Right-aligned: the app version (always visible) + a "copied ✓" toast.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "SOV Station v{} · {}",
                            env!("CARGO_PKG_VERSION"),
                            self.network.label()
                        ))
                        .weak()
                        .monospace(),
                    );
                    // A copy from an explicit button (`self.copied_at`) OR from any
                    // `copy_glyph` affordance (egui memory) shows the same confirmation.
                    let last_copy = self.copied_at.into_iter().chain(copied_recent(ctx)).max();
                    if let Some(t) = last_copy {
                        if now_ms().saturating_sub(t) < 1500 {
                            ui.separator();
                            ui.colored_label(palette::success(), "copied ✓");
                            ctx.request_repaint(); // keep ticking so it fades on time
                        } else {
                            self.copied_at = None;
                        }
                    }
                });
            });
            ui.add_space(3.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Every tab scrolls — the wallet in particular has many sections and
            // must never clip below the window. (Blocks scrolls its own table.)
            match self.tab {
                Tab::Node => {
                    let logs = self.node_logs.lock().map(|v| v.clone()).unwrap_or_default();
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_node")
                        .show(ui, |ui| {
                            node_panel(ui, &snap);
                            self.node_peering_ui(ui);
                            node_log_panel(ui, &logs);
                        });
                }
                Tab::Mining => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_mining")
                        .show(ui, |ui| {
                            self.mining_control_ui(ui);
                            self.mining_earnings_section(ui);
                            mining_panel(ui, &snap);
                        });
                }
                Tab::Wallet => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_wallet")
                        .show(ui, |ui| self.wallet_panel(ui, &snap));
                }
                Tab::Tokens => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_tokens")
                        .show(ui, |ui| self.tokens_panel(ui));
                }
                Tab::Swaps => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_swaps")
                        .show(ui, |ui| self.swaps_panel(ui));
                }
                Tab::Vault => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_vault")
                        .show(ui, |ui| self.vault_panel(ui));
                }
                Tab::Blocks => blocks_panel(ui, &snap, &mut self.block_detail),
                Tab::Activity => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_activity")
                        .show(ui, |ui| self.activity_panel(ui));
                }
            }
        });

        // ── Live node HEARTBEAT — floats bottom-right over every tab. ──
        self.draw_heartbeat(ctx, &snap);

        // ── Warn on quit if wallets aren't saved ──
        if ctx.input(|i| i.viewport().close_requested())
            && self.wallets_dirty
            && !self.wallets.is_empty()
        {
            self.confirm_quit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        if self.confirm_quit {
            egui::Window::new("Unsaved wallets")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        "You have wallets that aren't saved to disk. Quitting now loses any wallet \
                         you haven't backed up (recovery phrase) or saved to the keystore.",
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(egui::RichText::new("Quit anyway").color(palette::error()))
                            .clicked()
                        {
                            self.wallets_dirty = false; // accept the loss
                            self.confirm_quit = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if ui.button("Stay (let me save)").clicked() {
                            self.confirm_quit = false;
                        }
                    });
                });
        }

        // ── Confirm switching to MAINNET (real value, not a sandbox) ──
        if self.pending_network == Some(Network::Mainnet) {
            egui::Window::new("Switch to MAINNET?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.colored_label(
                        Network::Mainnet.color(),
                        "MAINNET is the live network — real value. Your wallets are unchanged; the \
                         view switches to the mainnet chain. Sandbox mining/reset are not offered \
                         there.",
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                egui::RichText::new("Switch to MAINNET")
                                    .strong()
                                    .color(Network::Mainnet.color()),
                            )
                            .clicked()
                        {
                            self.pending_network = None;
                            self.switch_network(Network::Mainnet);
                        }
                        if ui.button("Stay on Testnet").clicked() {
                            self.pending_network = None;
                        }
                    });
                });
        }

        // Keep the live view ticking even without input events.
        // Repaint frequently so the connection/sync status, peer count, height, and
        // logs update LIVE (not stale) — the operator sees peers connect in real time.
        ctx.request_repaint_after(Duration::from_millis(300));
    }
}

fn kv(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.label(egui::RichText::new(k).weak());
    ui.label(egui::RichText::new(if v.is_empty() { "—" } else { v }).monospace());
    ui.end_row();
}

/// Stable egui-memory key for "something was just copied", set by [`copy_glyph`] from
/// any panel (free functions can't touch `self.copied_at`) and read by the bottom bar,
/// so a copy from anywhere shows the same "copied ✓" confirmation.
fn copied_memory_id() -> egui::Id {
    egui::Id::new("sov_copied_at")
}

/// The most recent copy timestamp recorded in egui memory by [`copy_glyph`], if any.
fn copied_recent(ctx: &egui::Context) -> Option<u64> {
    ctx.data(|d| d.get_temp::<u64>(copied_memory_id()))
}

/// A compact copy-to-clipboard affordance — a small 📋 button that copies `value`.
/// A free function (no `&self`) so it works from every panel; confirmation is the
/// shared bottom-bar "copied ✓" (signalled through egui memory), so there is no
/// per-row layout shift. No-op for an empty / placeholder value.
fn copy_glyph(ui: &mut egui::Ui, value: &str) {
    if value.is_empty() || value == "—" {
        return;
    }
    let resp = ui
        .add(
            egui::Button::new(
                egui::RichText::new("📋")
                    .size(11.0)
                    .color(palette::text_dim()),
            )
            .frame(false),
        )
        .on_hover_text("Copy");
    if resp.clicked() {
        ui.output_mut(|o| o.copied_text = value.to_owned());
        let now = now_ms();
        ui.ctx()
            .data_mut(|d| d.insert_temp(copied_memory_id(), now));
    }
}

/// A key/value grid row whose value is a hash or address: a shortened, monospace
/// display with a copy affordance that puts the FULL value on the clipboard.
fn kv_copy(ui: &mut egui::Ui, k: &str, full: &str) {
    ui.label(egui::RichText::new(k).weak());
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(if full.is_empty() {
                "—".to_string()
            } else {
                short(full)
            })
            .monospace(),
        );
        copy_glyph(ui, full);
    });
    ui.end_row();
}

/// A friendly empty-state block — a large glyph "illustration" + a title and a hint —
/// shown where a list or feed has nothing yet, so a panel never reads as broken or
/// blank but instead tells the user what will appear and how to make it happen.
fn empty_state(ui: &mut egui::Ui, glyph: &str, title: &str, hint: &str) {
    ui.add_space(28.0);
    ui.vertical_centered(|ui| {
        ui.label(
            egui::RichText::new(glyph)
                .size(40.0)
                .color(palette::text_dim()),
        );
        ui.add_space(8.0);
        ui.label(egui::RichText::new(title).strong().size(15.0));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(hint).weak());
    });
    ui.add_space(28.0);
}

/// Real node logs — the embedded node's startup, replay timing, RPC/P2P bring-up,
/// and errors — in a monospace, newest-last view so the user can see exactly what
/// the node is doing (and why a start was slow or failed).
fn node_log_panel(ui: &mut egui::Ui, logs: &[String]) {
    ui.add_space(10.0);
    ui.separator();
    ui.horizontal(|ui| {
        ui.heading("Node log");
        ui.label(
            egui::RichText::new(format!(
                "(embedded node — in-process · {} lines)",
                logs.len()
            ))
            .weak(),
        );
    });
    ui.add_space(4.0);
    if logs.is_empty() {
        ui.label(egui::RichText::new("no node activity yet — Start local node to begin").weak());
        return;
    }
    // A tall, scrollable, monospace view so an operator can watch live activity and
    // scroll back through the whole session — the primary window into what the node
    // is doing (peering, sync, restarts, errors).
    // USER-RESIZABLE, gripped from the TOP.
    //
    // The log is the bottom-most thing on the tab, so the natural gesture is to
    // pull its top edge UPWARD to make it taller — the same way a docked console
    // drawer behaves. A handle underneath would ask the operator to drag the
    // page downward to reveal more of something already below the fold.
    //
    // Two bugs made the first attempt inert. The panel renders INSIDE the Node
    // tab's `ScrollArea`, where `available_height()` is not the visible height —
    // so the clamp computed from it was meaningless — and a bare
    // `allocate_exact_size` drag inside a scroll area is swallowed as a scroll.
    // The ceiling now comes from the actual viewport, and the handle is an
    // explicit `interact` with its own id, so the drag belongs to the handle.
    const LOG_MIN_H: f32 = 160.0;
    const LOG_DEFAULT_H: f32 = 520.0;
    let h_id = ui.id().with("node_log_height");
    let mut h = ui
        .ctx()
        .data(|d| d.get_temp::<f32>(h_id))
        .unwrap_or(LOG_DEFAULT_H);
    // Ceiling from the real viewport, leaving room for the chrome above.
    let max_h = (ui.ctx().screen_rect().height() - 260.0).max(LOG_MIN_H);
    h = h.clamp(LOG_MIN_H, max_h);

    // ── The grip, ABOVE the log ───────────────────────────────────────────────
    let (bar, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
    let resp = ui.interact(bar, h_id.with("grip"), egui::Sense::drag());
    if resp.hovered() || resp.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
    }
    if resp.dragged() {
        // Dragging UP (negative y) makes it TALLER.
        h = (h - resp.drag_delta().y).clamp(LOG_MIN_H, max_h);
        ui.ctx().data_mut(|d| d.insert_temp(h_id, h));
    }
    if resp.double_clicked() {
        ui.ctx().data_mut(|d| d.insert_temp(h_id, LOG_DEFAULT_H));
    }
    let col = if resp.dragged() {
        palette::accent()
    } else if resp.hovered() {
        palette::accent_hi()
    } else {
        palette::border()
    };
    let cx = bar.center().x;
    for dy in [-2.5f32, 0.5, 3.5] {
        ui.painter().line_segment(
            [
                egui::pos2(cx - 18.0, bar.center().y + dy),
                egui::pos2(cx + 18.0, bar.center().y + dy),
            ],
            egui::Stroke::new(1.0, col),
        );
    }

    // A tall, scrollable, monospace view so an operator can watch live activity and
    // scroll back through the whole session — the primary window into what the node
    // is doing (peering, sync, restarts, errors).
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_height(h);
        ui.set_max_height(h);
        egui::ScrollArea::vertical()
            .id_salt("node_log_scroll")
            .max_height(h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in logs.iter().rev().take(2_000).rev() {
                    ui.label(egui::RichText::new(line).monospace().size(12.5));
                }
            });
    });
}

/// The node's link state, as one value. Extracted from the ad-hoc `if` chain that used
/// to compute it inline so the STATUS BAND and the rest of the panel cannot disagree
/// about what the node is doing, and so it is unit-testable.
///
/// Each variant carries a DISTINCT GLYPH as well as a distinct colour. The previous
/// code drew `●` in green for CONNECTED, `●` in red for NOT CONNECTED, and `●` in red
/// for OFFLINE — three different facts separated by hue alone, which is exactly the
/// failure mode a red-green colourblind operator cannot recover from. Now the shape
/// differs too, and the word is always present.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkState {
    /// No node answered at all.
    Offline,
    /// Connected to peers but still downloading a heavier chain.
    Syncing,
    /// At the tip with peers.
    Connected,
    /// The node is up but has no peers — it is not on the network.
    Isolated,
}

impl LinkState {
    fn of(s: &Snapshot) -> Self {
        if !s.online {
            return LinkState::Offline;
        }
        if s.syncing {
            return LinkState::Syncing;
        }
        if s.peers.unwrap_or(0) > 0 {
            LinkState::Connected
        } else {
            LinkState::Isolated
        }
    }

    /// Shape first, so the state survives greyscale and colour-vision deficiency.
    fn glyph(self) -> &'static str {
        match self {
            LinkState::Offline => "✕",
            LinkState::Syncing => "⟳",
            LinkState::Connected => "●",
            LinkState::Isolated => "○",
        }
    }

    fn word(self) -> &'static str {
        match self {
            LinkState::Offline => "OFFLINE",
            LinkState::Syncing => "SYNCING",
            LinkState::Connected => "CONNECTED",
            LinkState::Isolated => "NOT CONNECTED",
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            LinkState::Offline => palette::error(),
            LinkState::Syncing => palette::warning(),
            LinkState::Connected => palette::success(),
            LinkState::Isolated => palette::error(),
        }
    }
}

/// The heartbeat chip's PRIMARY state, chosen purely from the snapshot so it can be
/// asserted directly in a test. OFFLINE and SYNCING dominate — you are not "mining" if
/// the node is down or still catching up (mining is gated on being synced). Otherwise
/// active mining — external OR in-process — is its own headline state, distinct from the
/// quiet SOLO/SYNCED a non-mining node falls through to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BeatState {
    Offline,
    Syncing,
    Mining,
    Solo,
    Synced,
}

impl BeatState {
    fn of(s: &Snapshot) -> Self {
        if !s.online {
            return BeatState::Offline;
        }
        if s.syncing {
            return BeatState::Syncing;
        }
        if s.is_mining() {
            return BeatState::Mining;
        }
        if s.peers.unwrap_or(0) == 0 {
            BeatState::Solo
        } else {
            BeatState::Synced
        }
    }

    fn word(self) -> &'static str {
        match self {
            BeatState::Offline => "OFFLINE",
            BeatState::Syncing => "SYNCING",
            BeatState::Mining => "MINING",
            BeatState::Solo => "SOLO",
            BeatState::Synced => "SYNCED",
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            BeatState::Offline => palette::error(),
            BeatState::Syncing => palette::warning(),
            // Its own gold hue — never SYNCING's amber nor SYNCED's green.
            BeatState::Mining => palette::mining(),
            BeatState::Solo => palette::link(),
            BeatState::Synced => palette::success(),
        }
    }

    /// Beats-per-minute — more "alive" ⇒ faster heart. A mining node is healthy and
    /// working, so it beats a touch quicker than an idle-synced one but far calmer than
    /// the racing catch-up of SYNCING.
    fn bpm(self) -> f64 {
        match self {
            BeatState::Offline => 0.0,
            BeatState::Syncing => 132.0,
            BeatState::Mining => 72.0,
            BeatState::Solo => 80.0,
            BeatState::Synced => 60.0,
        }
    }
}

fn node_panel(ui: &mut egui::Ui, s: &Snapshot) {
    ui.label(egui::RichText::new("Node").size(ty::TITLE).strong());
    ui.add_space(sp::M);

    // ── STATUS BAND ───────────────────────────────────────────────────────────
    // The three things an operator checks first — am I connected, how far along, and
    // how many peers — promoted above the reference data. They used to sit BELOW a
    // nine-row key/value dump, which put the only actionable facts on the screen last.
    let link = LinkState::of(s);
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = sp::M;
            state_chip(ui, link.glyph(), link.word(), link.color());
            ui.label(
                egui::RichText::new(match link {
                    LinkState::Offline => "No node is answering. Start a local node below.",
                    LinkState::Syncing => "Downloading a heavier chain from peers. Not mining.",
                    LinkState::Connected => "At the tip, extending the chain.",
                    LinkState::Isolated => {
                        "The node is up but has no peers. Set the other machine's \
                         address in Seed peer below and press Connect."
                    }
                })
                .size(ty::SMALL)
                .color(palette::text_dim()),
            );
        });
        ui.add_space(sp::L);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 32.0;
            // Height is the number an operator reads most often and the one that ticks,
            // so it is the hero and it is in tabular figures.
            stat(
                ui,
                "height",
                s.height.map(|h| group_thousands(h as u128)).as_deref(),
                "",
                ty::HERO,
            );
            // Only meaningful while syncing — shown then, absent otherwise, rather
            // than permanently occupying the band with "0 behind".
            if link == LinkState::Syncing {
                let behind = s
                    .best_peer_height
                    .zip(s.height)
                    .map(|(b, h)| group_thousands(b.saturating_sub(h) as u128));
                stat(ui, "blocks behind", behind.as_deref(), "", ty::HERO);
            }
            stat(
                ui,
                "peers",
                s.peers.map(|p| group_thousands(p as u128)).as_deref(),
                "",
                ty::HERO,
            );
            stat(
                ui,
                "mempool",
                s.mempool.map(|m| group_thousands(m as u128)).as_deref(),
                "tx",
                ty::HERO,
            );
        });
    });

    ui.add_space(sp::L);

    // ── Reference data — stable facts, demoted below the band ─────────────────
    card(ui, |ui| {
        ui.label(
            egui::RichText::new("CHAIN")
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.add_space(sp::S);
        egui::Grid::new("node-kv")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                kv(ui, "Chain", &s.chain_id);
                kv_copy(ui, "Head", &s.head_hash);
                kv_copy(ui, "State root", &s.state_root);
                kv(
                    ui,
                    "Supply (mined)",
                    &format!("{} XUS", xus(&s.supply_mined)),
                );
                kv(
                    ui,
                    "Supply (total)",
                    &format!("{} XUS", xus(&s.supply_total)),
                );
                kv(ui, "Difficulty", &fmt_difficulty(&s.difficulty));
            });
    });
    // ── Sync progress — drawn ONLY while syncing ──────────────────────────────
    // A progress bar that is permanently full is noise, so it appears only when it is
    // reporting something. The numbers are always shown beside it: a bar alone encodes
    // progress as length and colour, which is not readable as "12,570 of 12,604".
    if link == LinkState::Syncing {
        if let (Some(local_h), Some(best)) = (s.height, s.best_peer_height) {
            ui.add_space(sp::M);
            card(ui, |ui| {
                ui.label(
                    egui::RichText::new("SYNC PROGRESS")
                        .size(ty::MICRO)
                        .color(palette::text_dim()),
                );
                ui.add_space(sp::S);
                let frac = if best > 0 {
                    (local_h as f32 / best as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                ui.add(
                    egui::ProgressBar::new(frac)
                        .desired_height(6.0)
                        .fill(palette::warning()),
                );
                ui.add_space(sp::S);
                ui.label(
                    num(format!(
                        "{} / {}   ({} behind)",
                        group_thousands(local_h as u128),
                        group_thousands(best as u128),
                        group_thousands(best.saturating_sub(local_h) as u128),
                    ))
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
                );
            });
        }
    }
}

/// Difficulty as a readable magnitude. The node reports it as a bare float string
/// (e.g. `"1234567.8901"`), which is neither groupable nor comparable at a glance;
/// this groups the integer part and drops the fraction, which is below the resolution
/// anyone reads difficulty at. Empty input stays empty so [`kv`] renders its dash —
/// a value we did not receive must not become "0".
fn fmt_difficulty(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    match raw.split('.').next().and_then(|i| i.parse::<u128>().ok()) {
        Some(n) => group_thousands(n),
        // Not a number we recognise — show exactly what the node said rather than
        // silently substituting something prettier and wrong.
        None => raw.to_string(),
    }
}

/// "1.23 MH/s" — a human hashrate from hashes-per-second.
fn fmt_hashrate(hps: f64) -> String {
    if hps >= 1e9 {
        format!("{:.2} GH/s", hps / 1e9)
    } else if hps >= 1e6 {
        format!("{:.2} MH/s", hps / 1e6)
    } else if hps >= 1e3 {
        format!("{:.2} kH/s", hps / 1e3)
    } else {
        format!("{hps:.0} H/s")
    }
}

/// Friendly name for the raw PoW algo string the node reports.
fn pow_algo_display(raw: &str) -> &str {
    match raw {
        "Sha256d" => "SHA-256d",
        "RandomX" => "RandomX",
        "" => "—",
        other => other,
    }
}

/// Average gap (ms) between recent blocks' timestamps (newest-first) — the observed
/// block time, for the cadence + hashrate estimate. `None` with fewer than two blocks.
fn avg_block_interval_ms(blocks: &[BlockRow]) -> Option<u64> {
    let mut total = 0u64;
    let mut n = 0u64;
    for w in blocks.windows(2) {
        if w[0].timestamp_ms > w[1].timestamp_ms {
            total += w[0].timestamp_ms - w[1].timestamp_ms;
            n += 1;
        }
    }
    (n > 0).then(|| total / n)
}

/// A bordered section card (the cohesive container used across the richer panels).
/// The live auction, read out: pressure chip, the next-block floor, the pool's
/// ready/queued occupancy, and how long the oldest entry has waited.
///
/// The unknown case is rendered as unknown — an em-dash and an explicit sentence,
/// never a zero. "Blockspace is free" and "we could not ask what blockspace costs"
/// are opposite pieces of advice, and a wallet that renders them identically is
/// lying by omission at exactly the moment it matters.
fn auction_readout(ui: &mut egui::Ui, a: &Auction) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("BLOCKSPACE AUCTION")
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Shape glyph + word + colour — never colour alone.
            match a.pressure() {
                Pressure::Unknown => state_chip(ui, "?", "UNKNOWN", palette::unknown()),
                Pressure::Clear => state_chip(ui, "○", "CLEAR", palette::success()),
                Pressure::Contested => state_chip(ui, "▲", "CONTESTED", palette::warning()),
            }
            if !a.fee_auction_active {
                state_chip(ui, "·", "TIPS DORMANT", palette::unknown());
            }
        });
    });
    ui.add_space(sp::S);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = sp::XL;
        let floor = a.available.then(|| {
            if a.next_block_floor_grains == 0 {
                "0".to_string()
            } else {
                xus(&a.next_block_floor_grains.to_string())
            }
        });
        stat(ui, "next-block floor", floor.as_deref(), "XUS", ty::BODY);
        stat(
            ui,
            "ready",
            a.available
                .then(|| group_thousands(a.ready_txs as u128))
                .as_deref(),
            "tx",
            ty::BODY,
        );
        stat(
            ui,
            "queued",
            a.available
                .then(|| group_thousands(a.queued_txs as u128))
                .as_deref(),
            "tx",
            ty::BODY,
        );
        stat(
            ui,
            "oldest wait",
            a.oldest_pending_age_ms
                .map(|ms| group_thousands(u128::from(ms / 1000)))
                .as_deref(),
            "s",
            ty::BODY,
        );
    });
    if !a.available {
        ui.add_space(sp::S);
        ui.label(
            egui::RichText::new(
                "this node did not report mempool state (offline, or too old to serve \
                 sov_getMempoolInfo) — the floor is unknown, not zero",
            )
            .size(ty::SMALL)
            .color(palette::text_dim()),
        );
    }
}

/// WHY the suggested tip is what it is, in one sentence.
///
/// A default the spender cannot account for is a default they cannot judge, and
/// this one is spending their money. Every branch names the reading it came from.
fn tip_rationale(a: &Auction) -> String {
    let suggested = a.suggested_tip_grains();
    if !a.available {
        "suggested 0 — no live reading of the pool, so no bid is invented".to_string()
    } else if suggested == 0 {
        "suggested 0 — the next block still has room, so a tip buys nothing".to_string()
    } else {
        format!(
            "suggested {} XUS — the live floor ({} XUS) plus the network's minimum bid \
             increment, the cheapest bid that clears it",
            xus(&suggested.to_string()),
            xus(&a.next_block_floor_grains.to_string())
        )
    }
}

/// What the current bid is likely to buy, plus the distribution it is bidding
/// against. Drawn only where a tip means anything.
fn bid_outlook_view(ui: &mut egui::Ui, a: &Auction, tip_grains: u128) {
    if a.fee_auction_active {
        let (glyph, text, col) = match a.outlook(tip_grains) {
            Outlook::Unknown => (
                "?",
                "no live reading — this send may or may not make the next block".to_string(),
                palette::unknown(),
            ),
            Outlook::NextBlock => (
                "✓",
                "this bid clears the floor — expected in the next block".to_string(),
                palette::success(),
            ),
            Outlook::Behind { txs_ahead } => (
                "⏳",
                format!(
                    "outbid — at least {} pooled transaction(s) are ahead of this one; it waits \
                     until the backlog clears or you raise the tip",
                    group_thousands(txs_ahead as u128)
                ),
                palette::warning(),
            ),
        };
        ui.add_space(sp::S);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(glyph).size(ty::SMALL).color(col));
            ui.label(egui::RichText::new(text).size(ty::SMALL).color(col));
        });
    }
    if a.available && !a.buckets.is_empty() {
        ui.add_space(sp::S);
        ui.label(
            egui::RichText::new("WHAT YOU ARE BIDDING AGAINST")
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.add_space(sp::XS);
        fee_histogram(ui, &a.buckets, tip_grains);
    }
}

/// The body of the bump confirmation: what a replace-by-fee IS, in the terms a
/// spender is actually afraid of.
///
/// The single most dangerous misunderstanding this whole feature makes available
/// is "did I just pay twice?". Every line here exists to make that impossible to
/// believe: one payment, one nonce slot, one of the two versions can ever apply,
/// and the only new money is the tip increase.
fn bump_explainer(ui: &mut egui::Ui, p: &SentTx, new_tip_grains: u128) {
    ui.horizontal(|ui| {
        state_chip(ui, "⇄", "REPLACE — NOT A SECOND SEND", palette::accent());
    });
    ui.add_space(sp::M);
    ui.label(
        egui::RichText::new(format!(
            "{} XUS has already been sent to this recipient once, and is waiting in the mempool. \
             Raising the tip re-signs THE SAME PAYMENT in THE SAME nonce slot ({}), so the two \
             versions compete for one slot and the chain can only ever apply one of them.",
            xus(&p.amount_grains.to_string()),
            p.nonce
        ))
        .color(palette::text()),
    );
    ui.add_space(sp::M);
    egui::Grid::new("bump_grid")
        .num_columns(2)
        .spacing([16.0, 8.0])
        .show(ui, |ui| {
            kv(ui, "Recipient", &p.to);
            kv(
                ui,
                "Amount",
                &format!(
                    "{} XUS — paid ONCE, either way",
                    xus(&p.amount_grains.to_string())
                ),
            );
            kv(ui, "Nonce slot", &format!("{} (unchanged)", p.nonce));
            kv(
                ui,
                "Tip",
                &format!(
                    "{} → {} XUS",
                    xus(&p.tip_grains.to_string()),
                    xus(&new_tip_grains.to_string())
                ),
            );
            kv(
                ui,
                "Extra cost",
                &format!(
                    "{} XUS — only the tip increase; the amount is not spent twice",
                    xus(&new_tip_grains.saturating_sub(p.tip_grains).to_string())
                ),
            );
            kv(ui, "Replacing tx", &short_id(&p.txid));
        });
    ui.add_space(sp::M);
    ui.colored_label(
        palette::success(),
        "✓ The recipient receives the amount exactly once. The original transaction can no longer \
         confirm — its slot belongs to the replacement.",
    );
    if p.shielded_route {
        ui.add_space(sp::S);
        ui.colored_label(
            palette::text_dim(),
            "This is a shielded route, so the replacement re-proves the bundle (a few seconds). \
             Still one payment.",
        );
    }
}

/// The pooled fee-rate distribution as a horizontal bar per bucket, highest bid
/// first — what the spender is bidding against, at a glance.
///
/// Bars are scaled by TRANSACTION COUNT, which is the node's own auction key
/// (`Mempool::select` orders by absolute effective tip, and the floor is the
/// marginal one), so the picture matches the order inclusion actually uses. A
/// bucket whose lower edge is above `bid_grains` is drawn in the warning colour:
/// that is competition already ahead of this send.
fn fee_histogram(ui: &mut egui::Ui, buckets: &[auction::FeeBucket], bid_grains: u128) {
    let max = buckets.iter().map(|b| b.tx_count).max().unwrap_or(0).max(1) as f32;
    // Deep backlogs are bounded by the node at HISTOGRAM_MAX_BUCKETS; show the
    // most expensive few, which are the ones a bid has to get past.
    for b in buckets.iter().take(6) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = sp::M;
            ui.add_sized(
                [110.0, 14.0],
                egui::Label::new(
                    num(format!("≥ {} XUS", xus(&b.min_tip_grains.to_string())))
                        .size(ty::SMALL)
                        .color(palette::text_dim()),
                ),
            );
            let (rect, _) = ui.allocate_exact_size(egui::vec2(120.0, 10.0), egui::Sense::hover());
            let ahead = b.min_tip_grains > bid_grains;
            let col = if ahead {
                palette::warning()
            } else {
                palette::success()
            };
            let w = (b.tx_count as f32 / max) * rect.width();
            ui.painter_at(rect).rect_filled(
                egui::Rect::from_min_size(rect.left_top(), egui::vec2(w.max(2.0), rect.height())),
                egui::Rounding::same(2.0),
                col,
            );
            ui.label(
                num(group_thousands(b.tx_count as u128))
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
            );
            ui.label(
                egui::RichText::new(if ahead {
                    "ahead of you"
                } else {
                    "below your bid"
                })
                .size(ty::MICRO)
                .color(palette::text_dim()),
            );
        });
    }
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::group(ui.style())
        .fill(palette::panel())
        .stroke(egui::Stroke::new(1.0, palette::border()))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, add)
        .inner
}

/// Draw a small bar sparkline of recent block intervals (oldest→newest, left→right),
/// each bar colored by how close it is to the target cadence (green ≤2×, amber ≤4×,
/// red beyond), with a dashed target reference line — block cadence at a glance.
fn interval_sparkline(ui: &mut egui::Ui, blocks: &[BlockRow], target_ms: u64) {
    let mut intervals: Vec<f32> = Vec::new();
    for w in blocks.windows(2) {
        if w[0].timestamp_ms > w[1].timestamp_ms {
            intervals.push((w[0].timestamp_ms - w[1].timestamp_ms) as f32 / 1000.0);
        }
    }
    intervals.reverse(); // oldest first, so the newest block is on the right
    if intervals.is_empty() {
        return;
    }
    let target_s = (target_ms as f32 / 1000.0).max(0.001);
    let max = intervals
        .iter()
        .copied()
        .fold(target_s, f32::max)
        .max(0.001);
    let (w, h) = (240.0_f32, 38.0_f32);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let n = intervals.len() as f32;
    let slot = w / n;
    for (i, &v) in intervals.iter().enumerate() {
        let x = rect.left() + i as f32 * slot;
        let bar_h = (v / max) * h;
        let col = if v <= target_s * 2.0 {
            palette::success()
        } else if v <= target_s * 4.0 {
            palette::warning()
        } else {
            palette::error()
        };
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x, rect.bottom() - bar_h),
                egui::pos2(x + (slot * 0.7).max(1.0), rect.bottom()),
            ),
            egui::Rounding::same(1.0),
            col,
        );
    }
    // The target cadence as a reference line.
    let ty = rect.bottom() - (target_s / max) * h;
    painter.line_segment(
        [egui::pos2(rect.left(), ty), egui::pos2(rect.right(), ty)],
        egui::Stroke::new(1.0, palette::tint(palette::text_dim(), 170)),
    );
}

/// A coarse "1 block every …" duration for the external-miner share estimate. Minutes up
/// to a couple of hours, then hours, then days — precision beyond this would fake a
/// certainty the estimate does not have.
fn fmt_block_interval(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "—".to_string();
    }
    let mins = secs / 60.0;
    if mins < 90.0 {
        format!("{:.0} min", mins.max(1.0))
    } else if mins < 60.0 * 48.0 {
        format!("{:.1} h", mins / 60.0)
    } else {
        format!("{:.1} days", mins / 60.0 / 24.0)
    }
}

/// The Mining tab's external-miner card — everything Station can honestly say about an
/// out-of-process miner (the standalone XUS Miner) from the on-chain registry alone. For
/// such a miner `local_hashrate` is 0, so the hero above cannot describe it; the chain can.
fn external_miner_card(ui: &mut egui::Ui, s: &Snapshot, m: &ExternalMinerFacts) {
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("YOUR EXTERNAL MINER")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if m.active {
                    state_chip(ui, "⛏", "MINING", palette::mining());
                } else {
                    // No live win has been WITNESSED this session, so we must not claim
                    // MINING — nor show a bare "IDLE", which reads as a present-tense claim
                    // Station cannot back. State the FACT instead: how long since the last
                    // won block. The gold MINING chip returns only on a witnessed win.
                    let behind = m.head.saturating_sub(m.last_seen);
                    let word = if behind == 0 {
                        "LAST WON AT HEAD".to_string()
                    } else {
                        format!(
                            "LAST WON {} BLOCK{} AGO",
                            group_thousands(behind as u128),
                            if behind == 1 { "" } else { "S" }
                        )
                    };
                    state_chip(ui, "○", &word, palette::text_dim());
                }
            });
        });
        ui.add_space(6.0);
        // How recently the registry last saw this account at the head — the freshness the
        // active/idle decision turns on.
        let behind = m.head.saturating_sub(m.last_seen);
        // Share of ALL mined blocks in the registry — a lifetime hashpower proxy, LABELLED
        // as such so it is never read as an instantaneous rate.
        let share = if m.network_blocks > 0 {
            m.blocks_won as f64 / m.network_blocks as f64
        } else {
            0.0
        };
        egui::Grid::new("external-miner-kv")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                kv(ui, "Account", &short_id(&m.account));
                kv(ui, "Blocks won", &group_thousands(m.blocks_won as u128));
                kv(
                    ui,
                    "Last block",
                    &format!(
                        "#{}  ({})",
                        group_thousands(m.last_seen as u128),
                        if behind == 0 {
                            "at the head".to_string()
                        } else {
                            format!(
                                "{} block{} ago",
                                group_thousands(behind as u128),
                                if behind == 1 { "" } else { "s" }
                            )
                        }
                    ),
                );
                if m.network_blocks > 0 {
                    kv(
                        ui,
                        "Share (registry, lifetime)",
                        &format!(
                            "≈ {:.1}%  ({} of {})",
                            share * 100.0,
                            group_thousands(m.blocks_won as u128),
                            group_thousands(m.network_blocks as u128)
                        ),
                    );
                }
                // Expected time between YOUR blocks at this share, derived honestly from
                // the network cadence — target block time ÷ share. An ESTIMATE, and named
                // one; a real reading requires actually winning blocks over time.
                if share > 0.0 && s.target_block_ms > 0 {
                    let secs = (s.target_block_ms as f64 / 1000.0) / share;
                    kv(ui, "≈ 1 block every (est.)", &fmt_block_interval(secs));
                }
            });
    });
}

fn mining_panel(ui: &mut egui::Ui, s: &Snapshot) {
    ui.label(egui::RichText::new("Mining").size(ty::TITLE).strong());
    ui.label(
        egui::RichText::new(
            "Proof of work: a miner hashes the block header with a changing nonce until the seal \
             falls below the target. The winning nonce is the block's proof — one hash to verify, \
             the whole network's effort to find. Block rewards track HASHPOWER, not machine count: \
             a node with N× the hashrate earns ~N× the blocks. Compare \"Your hashrate\" across \
             machines to see the split is fair.",
        )
        .weak()
        .small(),
    );
    ui.add_space(8.0);

    let diff = s.difficulty.parse::<f64>().ok();
    let obs = avg_block_interval_ms(&s.blocks);
    let net_hps = match (diff, obs) {
        (Some(d), Some(ms)) if ms > 0 => Some(d / (ms as f64 / 1000.0)),
        _ => None,
    };

    // ── Hashpower hero — your measured rate vs the estimated network rate, up front ──
    //
    // Both figures go through `stat`, so they share the micro-label + tabular-figure
    // treatment used everywhere else and the two columns line up on the same baseline.
    // The network figure is an ESTIMATE derived from difficulty and observed block
    // times, and its label says so — it is never presented as a measurement.
    card(ui, |ui| {
        ui.columns(2, |c| {
            let yours = if s.local_hashrate > 0 {
                Some(fmt_hashrate(s.local_hashrate as f64))
            } else {
                // Not measured. While syncing that has a reason worth stating; either
                // way it is NOT "0 H/s", which would read as hardware failure.
                None
            };
            stat(&mut c[0], "your hashpower", yours.as_deref(), "", ty::HERO);
            if yours.is_none() {
                // `local_hashrate` measures only THIS node's in-process miner. When it is
                // zero we may still be mining externally (the standalone XUS Miner), which
                // Station sees through the registry — so don't say "not mining" then, or
                // the tab looks broken for an operator who is actively mining. Full facts
                // live in the "your external miner" card just below.
                let external_active = s.external_miner.as_ref().is_some_and(|m| m.active);
                c[0].label(
                    egui::RichText::new(if external_active {
                        "measured here as 0 — you are mining with an EXTERNAL miner (see below)"
                    } else if s.syncing {
                        "paused while syncing — the node joins the chain before extending it"
                    } else {
                        "not mining"
                    })
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
                );
            }
            let net = net_hps.map(fmt_hashrate);
            stat(
                &mut c[1],
                "network hashpower (estimated)",
                net.as_deref(),
                "",
                ty::HERO,
            );
            c[1].label(
                egui::RichText::new(if net.is_some() {
                    "estimate: difficulty ÷ observed block interval"
                } else {
                    "needs difficulty and two recent blocks to estimate"
                })
                .size(ty::SMALL)
                .color(palette::text_dim()),
            );
        });
    });
    ui.add_space(sp::L);

    // ── Your external miner — facts from the on-chain registry ──
    // For an out-of-process miner (the standalone XUS Miner) `local_hashrate` is 0, so the
    // hero above cannot describe it. The chain can: `sov_getMiners` lists blocks won and
    // how recently this operator's account was last seen at the head.
    if let Some(m) = &s.external_miner {
        external_miner_card(ui, s, m);
        ui.add_space(sp::L);
    }

    // ── Block cadence sparkline — recent intervals at a glance ──
    if s.blocks.len() > 2 {
        ui.label(
            egui::RichText::new("BLOCK CADENCE — RECENT INTERVALS (NEWEST →)")
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        interval_sparkline(ui, &s.blocks, s.target_block_ms);
        // The bars encode interval as HEIGHT and band as colour. Height alone is
        // readable in greyscale, but the band boundaries are not, so they are named
        // here rather than left to the reader to infer from hue.
        ui.label(
            egui::RichText::new(
                "bar height = interval · line = target · within 2× target, 2–4×, beyond 4×",
            )
            .size(ty::MICRO)
            .color(palette::text_dim()),
        );
        ui.add_space(sp::L);
    }

    // ── Proof-of-Work card — the algorithm, difficulty, target, and the live proof ──
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("PROOF OF WORK")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("⛏ {}", pow_algo_display(&s.pow_algo)))
                        .strong()
                        .color(palette::accent_hi()),
                );
            });
        });
        ui.add_space(6.0);
        egui::Grid::new("pow-kv")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                kv(ui, "Difficulty", &fmt_difficulty(&s.difficulty));
                if let Some(d) = diff {
                    if d > 1.0 {
                        kv(
                            ui,
                            "≈ work per block",
                            &format!("{:.1} leading zero bits", d.log2()),
                        );
                    }
                }
                if let Some(nb) = s.head_bits {
                    kv(ui, "Target (nBits)", &format!("0x{nb:08x}"));
                }
                if let Some(n) = s.head_nonce {
                    kv(ui, "Head nonce (the proof)", &n.to_string());
                }
                if let Some(ms) = obs {
                    kv(
                        ui,
                        "Observed block time",
                        &format!("{:.1}s", ms as f64 / 1000.0),
                    );
                }
                if s.target_block_ms > 0 {
                    kv(
                        ui,
                        "Target block time",
                        &format!("{:.0}s", s.target_block_ms as f64 / 1000.0),
                    );
                }
                kv(
                    ui,
                    "Height",
                    &s.height
                        .map(|h| group_thousands(h as u128))
                        .unwrap_or_default(),
                );
                kv(ui, "Block reward", &format!("{} XUS", xus(&s.reward)));
                kv(
                    ui,
                    "Mempool",
                    &s.mempool
                        .map(|m| group_thousands(m as u128))
                        .unwrap_or_default(),
                );
            });
    });

    // ── Latest block solved ──
    if let Some(b) = s.blocks.first() {
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(
                egui::RichText::new("LATEST BLOCK SOLVED")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.add_space(4.0);
            egui::Grid::new("latest-block-kv")
                .num_columns(2)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    kv(ui, "Height", &b.height.to_string());
                    ui.label(egui::RichText::new("Nonce").weak());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(b.nonce.to_string()).monospace());
                        copy_glyph(ui, &b.nonce.to_string());
                    });
                    ui.end_row();
                    kv(ui, "Solved", &block_time(b.timestamp_ms));
                    kv_copy(ui, "Miner", &b.miner);
                    if !s.head_hash.is_empty() {
                        kv_copy(ui, "Block hash", &s.head_hash);
                    }
                    kv(ui, "Coinbase", &format!("{} XUS", xus(&b.reward)));
                });
        });
    }

    // ── Recent proofs of work — per-block nonces + solve cadence ──
    if s.blocks.len() > 1 {
        ui.add_space(sp::XL);
        ui.label(
            egui::RichText::new("Recent proofs of work")
                .size(ty::SECTION)
                .strong(),
        );
        ui.add_space(sp::S);
        egui::ScrollArea::vertical()
            .id_salt("recent-pow")
            .max_height(180.0)
            .show(ui, |ui| {
                egui::Grid::new("recent-pow-grid")
                    .num_columns(4)
                    .striped(true)
                    .spacing([18.0, 4.0])
                    .show(ui, |ui| {
                        for h in ["Height", "Interval", "Nonce", "Miner"] {
                            ui.label(
                                egui::RichText::new(h.to_uppercase())
                                    .size(ty::MICRO)
                                    .color(palette::text_dim()),
                            );
                        }
                        ui.end_row();
                        for (i, b) in s.blocks.iter().enumerate() {
                            ui.label(num(group_thousands(b.height as u128)).size(ty::SMALL));
                            let interval = s
                                .blocks
                                .get(i + 1)
                                .and_then(|older| b.timestamp_ms.checked_sub(older.timestamp_ms));
                            // An interval needs the NEXT (older) block to exist. The
                            // oldest row in the window has none, so it is an explicit
                            // dash — not "0.0s", which would read as an instant block.
                            match interval {
                                Some(ms) => ui.label(
                                    num(format!("{:.1}s", ms as f64 / 1000.0)).size(ty::SMALL),
                                ),
                                None => ui.label(num_unknown().size(ty::SMALL)),
                            };
                            ui.label(num(group_thousands(b.nonce as u128)).size(ty::SMALL));
                            ui.label(num(short_id(&b.miner)).size(ty::SMALL));
                            ui.end_row();
                        }
                    });
            });
    }

    // ── Miner registry ──
    ui.add_space(sp::XL);
    ui.label(
        egui::RichText::new("Miner registry")
            .size(ty::SECTION)
            .strong(),
    );
    ui.add_space(sp::S);
    egui::Grid::new("miners")
        .num_columns(4)
        .striped(true)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            for h in ["Account", "Blocks", "First", "Last"] {
                ui.label(
                    egui::RichText::new(h.to_uppercase())
                        .size(ty::MICRO)
                        .color(palette::text_dim()),
                );
            }
            ui.end_row();
            if s.miners.is_empty() {
                ui.label(
                    egui::RichText::new(if s.online {
                        "no miner has been seen in the recent blocks this node holds"
                    } else {
                        "no node is answering — the miner registry is unknown, not empty"
                    })
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
                );
                ui.end_row();
            }
            for m in &s.miners {
                ui.label(num(short_id(&m.account)).size(ty::SMALL));
                ui.label(num(group_thousands(m.blocks as u128)).size(ty::SMALL));
                ui.label(num(group_thousands(m.first as u128)).size(ty::SMALL));
                ui.label(num(group_thousands(m.last as u128)).size(ty::SMALL));
                ui.end_row();
            }
        });
}

impl Station {
    /// The live node **HEARTBEAT** — floated bottom-right over every tab. A colored
    /// "lub-dub" orb with an expanding sonar ring, the peer count, sync state, and
    /// height. Everything is driven by REAL node telemetry:
    ///   • colour = health — green SYNCED · cyan SOLO · amber SYNCING · red OFFLINE
    ///   • beat RATE = how alive it is — calm 60bpm synced, racing while syncing,
    ///     flatlined when there is no node
    ///   • a bright thump on every beat, a sonar ring rippling outward, a mining spark.
    fn draw_heartbeat(&self, ctx: &egui::Context, snap: &Snapshot) {
        use egui::{Align2, Color32, Id, Order, Sense, Shadow, Stroke, Vec2};

        let peers = snap.peers.unwrap_or(0);
        let online = snap.online;
        // Mining — external (registry) OR in-process — is now its own PRIMARY state,
        // but OFFLINE/SYNCING still dominate (mining is gated on being synced).
        let state = BeatState::of(snap);
        let mining = state == BeatState::Mining;
        let (color, label, bpm) = (state.color(), state.word(), state.bpm());
        // When mining we still want to show WHETHER we are at the tip: a small secondary
        // chip carries the link word (SYNCED / SOLO) so the headline says "MINING" while
        // the chip beside it says the node is also at the tip on the network. A peerless
        // miner may be mining a FORK, so its SOLO chip is coloured for ATTENTION, never
        // success green — an isolated miner must not look healthy.
        let (tip_word, tip_color) = if peers == 0 {
            ("SOLO", palette::warning())
        } else {
            ("SYNCED", palette::success())
        };

        // Heartbeat waveform: a "lub-dub" double-thump each period, then a rest — the
        // sum of two narrow Gaussians. `ring_phase` sweeps 0→1 over the period to drive
        // the outward sonar ripple.
        let t = ctx.input(|i| i.time);
        let (pulse, ring_phase) = if bpm <= 0.0 {
            (0.0f32, 1.0f32)
        } else {
            let period = 60.0 / bpm;
            let p = (t % period) / period;
            let g = |c: f64, w: f64| (-(((p - c) / w).powi(2))).exp() as f32;
            ((g(0.0, 0.045) + 0.6 * g(0.17, 0.045)).min(1.0), p as f32)
        };

        let panel = palette::panel();
        let chip_fill = Color32::from_rgba_unmultiplied(
            panel.r(),
            panel.g(),
            panel.b(),
            if palette::is_dark() { 246 } else { 252 },
        );
        let shadow = Shadow {
            offset: Vec2::new(0.0, 4.0),
            blur: 14.0,
            spread: 0.0,
            color: Color32::from_black_alpha(if palette::is_dark() { 105 } else { 42 }),
        };

        egui::Area::new(Id::new("node_heartbeat"))
            // Clear the footer instead of covering its version/network text.
            .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-18.0, -42.0))
            .order(Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(chip_fill)
                    .rounding(egui::Rounding::same(12.0))
                    .shadow(shadow)
                    .stroke(Stroke::new(1.0, palette::tint(color, 92)))
                    .inner_margin(egui::Margin::symmetric(11.0, 8.0))
                    .show(ui, |ui| {
                        ui.set_min_width(164.0);
                        ui.spacing_mut().item_spacing.x = 10.0;
                        ui.horizontal(|ui| {
                            // A contained heartbeat sits first, so the chip reads like a
                            // status instrument instead of a label with a loose decoration.
                            let (rect, resp) =
                                ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
                            let painter = ui.painter();
                            let center = rect.center();
                            let base_r = 5.0;

                            if bpm > 0.0 {
                                // The ripple stays within its allocation, avoiding the
                                // clipped/overhanging ring from the previous treatment.
                                let rr = base_r + ring_phase * 8.0;
                                let a = ((1.0 - ring_phase) * 88.0) as u8;
                                painter.circle_stroke(
                                    center,
                                    rr,
                                    Stroke::new(1.25, palette::tint(color, a)),
                                );
                                let glow_r = base_r + 2.5 + pulse * 3.5;
                                painter.circle_filled(
                                    center,
                                    glow_r,
                                    palette::tint(color, (24.0 + pulse * 46.0) as u8),
                                );
                            }
                            painter.circle_filled(center, base_r + pulse * 1.6, color);
                            painter.circle_filled(
                                center + Vec2::new(-1.4, -1.4),
                                1.5 + pulse * 0.6,
                                palette::tint(Color32::WHITE, (105.0 + pulse * 105.0) as u8),
                            );
                            if mining {
                                painter.circle_filled(
                                    center + Vec2::new(base_r + 2.5, -(base_r + 2.5)),
                                    2.0,
                                    palette::mining(),
                                );
                            }

                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(label)
                                            .strong()
                                            .size(11.5)
                                            .color(color),
                                    );
                                    // Headline is already "MINING" here; the secondary
                                    // chip says we are ALSO at the tip, so the operator
                                    // reads both facts at once.
                                    if mining {
                                        ui.label(
                                            egui::RichText::new(tip_word)
                                                .strong()
                                                .size(8.5)
                                                .color(tip_color),
                                        );
                                    }
                                });
                                let sub = if online {
                                    let h = snap
                                        .height
                                        .map(|h| format!("#{}", group_thousands(h as u128)))
                                        .unwrap_or_else(|| "#—".into());
                                    let mut sub = format!(
                                        "{h}  ·  {peers} PEER{}",
                                        if peers == 1 { "" } else { "S" }
                                    );
                                    // When we are NOT mining but the operator has an owner
                                    // registry row, state the honest FACT — how long since
                                    // that account last won — instead of silently implying
                                    // nothing is theirs. This is the cold-start / restart
                                    // display: "last won N ago" under a neutral SYNCED/SOLO
                                    // headline, never the gold MINING claim.
                                    if !mining {
                                        if let Some(m) =
                                            snap.external_miner.as_ref().filter(|m| !m.active)
                                        {
                                            let behind = m.head.saturating_sub(m.last_seen);
                                            sub.push_str(&if behind == 0 {
                                                "  ·  MINER LAST WON AT HEAD".to_string()
                                            } else {
                                                format!(
                                                    "  ·  MINER LAST WON {} AGO",
                                                    group_thousands(behind as u128)
                                                )
                                            });
                                        }
                                    }
                                    sub
                                } else {
                                    "LOCAL NODE UNAVAILABLE".to_string()
                                };
                                ui.label(
                                    egui::RichText::new(sub)
                                        .monospace()
                                        .size(9.5)
                                        .color(palette::text_dim()),
                                );
                            });

                            // Distinguish the two ways we can be mining: this node's own
                            // in-process miner (a measured H/s) versus an external miner
                            // seen only through the on-chain registry (no local H/s).
                            let mining_line = if snap.local_hashrate > 0 {
                                "  ⛏ mining (this node)".to_string()
                            } else if let Some(m) = snap.external_miner.as_ref().filter(|m| m.active)
                            {
                                format!("  ⛏ external miner → {}", short_id(&m.account))
                            } else {
                                String::new()
                            };
                            resp.on_hover_text(format!(
                                "{label}\npeers: {peers}\nheight: {}\nbest peer: {}\nhashrate: {} H/s{}\nchain: {}\nbuild: v{}",
                                snap.height.map(|h| h.to_string()).unwrap_or_else(|| "—".into()),
                                snap.best_peer_height
                                    .map(|h| h.to_string())
                                    .unwrap_or_else(|| "—".into()),
                                snap.local_hashrate,
                                mining_line,
                                snap.chain_id,
                                env!("CARGO_PKG_VERSION"),
                            ));
                        });
                    });
            });

        // Keep the beat animating smoothly even when the app is otherwise idle.
        ctx.request_repaint_after(std::time::Duration::from_millis(33));
    }

    // ── Tokens tab: view / issue / transfer native SOV tokens (real on-chain). ──
    fn tokens_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Tokens");
        let Some((signer, seed)) = self
            .wallets
            .get(self.selected)
            .map(|w| (w.effective_account(), w.seed))
        else {
            ui.label(egui::RichText::new("create or open a wallet to use tokens").weak());
            return;
        };
        let tv = self
            .tokens_view
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut do_refresh = false;
        let mut do_issue = false;
        let mut do_transfer = false;
        let mut do_prev = false;
        let mut do_next = false;

        // Header: a dim "holdings for <you>" line + a refresh affordance.
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("holdings for {}", short_id(&signer)))
                    .color(palette::text_dim())
                    .small(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if tv.loading {
                    ui.spinner();
                } else if ui.button("⟳ Refresh").clicked() {
                    do_refresh = true;
                }
            });
        });
        ui.add_space(8.0);

        // Your token holdings, as Phantom-style cards.
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Your tokens").strong());
            if tv.account == signer && !tv.holdings.is_empty() {
                ui.label(
                    egui::RichText::new(format!("· {}", tv.holdings.len()))
                        .color(palette::text_dim()),
                );
            }
        });
        ui.add_space(4.0);
        if tv.account == signer && !tv.holdings.is_empty() {
            for (asset, symbol, bal) in &tv.holdings {
                token_card(ui, asset, symbol, bal);
                ui.add_space(6.0);
            }
        } else {
            empty_hint(
                ui,
                "No tokens yet",
                "Tokens you hold appear here as cards. Issue one below, or Refresh to scan.",
            );
        }

        // Collectibles & names, as a wrapped grid of tiles. SNS names ARE NFTs, so a
        // registered name shows here and can be SENT (which re-points it).
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Collectibles & names").strong());
        ui.add_space(4.0);
        let mut send_nft: Option<(String, bool, String, String)> = None;
        if tv.account == signer && !tv.nfts.is_empty() {
            let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
            let has_to = !self.nft_send_to.trim().is_empty();
            ui.horizontal_wrapped(|ui| {
                for (display, is_sns, coll, tid) in &tv.nfts {
                    let resp = nft_tile(ui, display, *is_sns, coll).on_hover_text(if has_to {
                        "Click to send to the recipient below"
                    } else {
                        "Enter a recipient below, then click to send"
                    });
                    if resp.clicked() && !busy && has_to {
                        send_nft = Some((display.clone(), *is_sns, coll.clone(), tid.clone()));
                    }
                    ui.add_space(6.0);
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("send to").color(palette::text_dim()));
                ui.add(
                    egui::TextEdit::singleline(&mut self.nft_send_to)
                        .hint_text("recipient account id or a .sov name")
                        .desired_width(280.0),
                );
                ui.label(
                    egui::RichText::new("then click a collectible")
                        .color(palette::text_dim())
                        .small(),
                );
            });
        } else {
            empty_hint(
                ui,
                "No collectibles",
                "NFTs and .sov names you own show here. A name is an NFT — sending it re-points it.",
            );
        }
        if let Some((display, is_sns, coll, tid)) = send_nft {
            self.send_nft(ui.ctx(), signer.clone(), seed, display, is_sns, coll, tid);
        }

        // Issue / send + the chain's registry — tucked behind collapsibles so the
        // default view stays a clean, visual portfolio.
        ui.add_space(12.0);
        egui::CollapsingHeader::new(egui::RichText::new("Issue or send a token").strong())
            .default_open(false)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("Issue a new token (creates it on first issue)")
                        .color(palette::text_dim())
                        .small(),
                );
                ui.horizontal(|ui| {
                    ui.label("Symbol");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tok_symbol)
                            .hint_text("USD1")
                            .desired_width(90.0),
                    );
                    ui.label("Amount");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tok_issue_amount).desired_width(110.0),
                    );
                    ui.label("To");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tok_issue_to)
                            .hint_text("recipient (default: you)")
                            .desired_width(160.0),
                    );
                    if ui.button("Issue").clicked() {
                        do_issue = true;
                    }
                });
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("Send an existing token")
                        .color(palette::text_dim())
                        .small(),
                );
                ui.horizontal(|ui| {
                    ui.label("Asset");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tok_xfer_asset)
                            .hint_text("asset id (hex)")
                            .desired_width(200.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("To");
                    ui.add(egui::TextEdit::singleline(&mut self.tok_xfer_to).desired_width(200.0));
                    ui.label("Amount");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tok_xfer_amount).desired_width(110.0),
                    );
                    if ui.button("Send token").clicked() {
                        do_transfer = true;
                    }
                });
            });

        egui::CollapsingHeader::new(egui::RichText::new("Token registry").strong())
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(tv.offset > 0, |ui| {
                        if ui.button("‹ Prev").clicked() {
                            do_prev = true;
                        }
                    });
                    ui.label(
                        egui::RichText::new(format!(
                            "showing {}–{}",
                            if tv.registry.is_empty() {
                                0
                            } else {
                                tv.offset + 1
                            },
                            tv.offset + tv.registry.len()
                        ))
                        .color(palette::text_dim()),
                    );
                    ui.add_enabled_ui(tv.has_more, |ui| {
                        if ui.button("Next ›").clicked() {
                            do_next = true;
                        }
                    });
                });
                ui.add_space(4.0);
                if !tv.registry.is_empty() {
                    for (asset, symbol, issuer, supply) in &tv.registry {
                        registry_card(ui, asset, symbol, issuer, supply);
                        ui.add_space(6.0);
                    }
                } else {
                    ui.label(egui::RichText::new("none on this page — Refresh to load").weak());
                }
            });

        if !tv.message.is_empty() {
            ui.add_space(6.0);
            status_label(ui, &tv.message);
        }

        if do_prev {
            self.tok_offset = self.tok_offset.saturating_sub(50);
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_next {
            self.tok_offset += 50;
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_refresh {
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_issue {
            self.issue_token(ui.ctx(), signer.clone(), seed);
        }
        if do_transfer {
            self.transfer_token(ui.ctx(), signer, seed);
        }
    }

    fn refresh_tokens(&self, ctx: &egui::Context, signer: String, _seed: [u8; 32]) {
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let offset = self.tok_offset;
        const PAGE: usize = 50;
        let view = self.tokens_view.clone();
        let ctx = ctx.clone();
        if let Ok(mut v) = view.lock() {
            v.loading = true;
            v.message = "scanning tokens…".to_string();
        }
        ctx.request_repaint();
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(8));
            // Your holdings are bounded by what you actually hold.
            let holdings = client
                .call("sov_getTokenBalances", json!({ "account": signer }))
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| (field(r, "asset"), field(r, "symbol"), field(r, "balance")))
                .collect();
            // The registry is fetched ONE PAGE at a time (bounded response).
            let resp = client
                .call("sov_listTokens", json!({ "offset": offset, "limit": PAGE }))
                .unwrap_or(Value::Null);
            let registry = resp
                .get("tokens")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    (
                        field(r, "asset"),
                        field(r, "symbol"),
                        field(r, "issuer"),
                        field(r, "supply"),
                    )
                })
                .collect();
            let has_more = resp
                .get("hasMore")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // Owned NFTs (non-fungible) — includes SNS names, which ARE NFTs.
            let nfts: Vec<(String, bool, String, String)> = client
                .call("sov_nftsOf", json!({ "account": &signer }))
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    let is_sns = r.get("isSns").and_then(Value::as_bool).unwrap_or(false);
                    let token_id = field(r, "tokenId");
                    let collection = field(r, "collection");
                    let display = r
                        .get("tokenText")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("0x{}…", &token_id[..token_id.len().min(12)]));
                    (display, is_sns, collection, token_id)
                })
                .collect();
            if let Ok(mut v) = view.lock() {
                v.loading = false;
                v.account = signer;
                v.holdings = holdings;
                v.registry = registry;
                v.offset = offset;
                v.has_more = has_more;
                v.nfts = nfts;
                v.message = "tokens refreshed".to_string();
            }
            ctx.request_repaint();
        });
    }

    fn issue_token(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let symbol = self.tok_symbol.trim().to_string();
        let to = {
            let t = self.tok_issue_to.trim();
            if t.is_empty() {
                signer.clone()
            } else {
                t.to_string()
            }
        };
        let Some(grains) = parse_xus(&self.tok_issue_amount) else {
            return self.set_token_msg("amount must be a number (e.g. 100)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let to_id = match AccountId::new(&to) {
                Ok(id) => id,
                Err(e) => {
                    return set_token_view_msg(&view, &ctx, &format!("invalid recipient: {e}"))
                }
            };
            let action = Action::TokenIssue {
                symbol,
                amount: Balance::from_grains(grains),
                to: to_id,
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ issued token (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ issue failed: {e}"));
            record(&activity, &msg);
            set_token_view_msg(&view, &ctx, &msg);
        });
    }

    fn transfer_token(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let asset_hex = self.tok_xfer_asset.trim().to_string();
        let to = self.tok_xfer_to.trim().to_string();
        let Some(grains) = parse_xus(&self.tok_xfer_amount) else {
            return self.set_token_msg("amount must be a number (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let asset = match Hash::from_hex(&asset_hex) {
                Ok(h) => h,
                Err(_) => return set_token_view_msg(&view, &ctx, "asset id must be 64 hex chars"),
            };
            let to_id = match AccountId::new(&to) {
                Ok(id) => id,
                Err(e) => {
                    return set_token_view_msg(&view, &ctx, &format!("invalid recipient: {e}"))
                }
            };
            let action = Action::TokenTransfer {
                asset,
                to: to_id,
                amount: Balance::from_grains(grains),
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ sent token (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ token send failed: {e}"));
            record(&activity, &msg);
            set_token_view_msg(&view, &ctx, &msg);
        });
    }

    fn set_token_msg(&self, msg: &str) {
        if let Ok(mut v) = self.tokens_view.lock() {
            v.message = msg.to_string();
        }
    }

    /// Transfer an NFT to a recipient. An SNS name goes via `TransferName` (it
    /// re-points the name); any other NFT via `NftTransfer`. The recipient may be
    /// an account id or a `.sov` name (resolved first).
    #[allow(clippy::too_many_arguments)]
    fn send_nft(
        &self,
        ctx: &egui::Context,
        signer: String,
        seed: [u8; 32],
        display: String,
        is_sns: bool,
        collection_hex: String,
        token_id_hex: String,
    ) {
        let to_raw = self.nft_send_to.trim().to_string();
        if to_raw.is_empty() {
            return self.set_token_msg("enter a recipient first");
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // Resolve a `.sov`-name recipient to the account it points to.
            let to = resolve_payee(&rpc, &to_raw);
            let result = (|| -> Result<String, String> {
                let to_id = AccountId::new(&to).map_err(|e| e.to_string())?;
                let action = if is_sns {
                    Action::TransferName {
                        name: display.clone(),
                        to: to_id,
                    }
                } else {
                    Action::NftTransfer {
                        collection: Hash::from_hex(&collection_hex).map_err(|e| e.to_string())?,
                        token_id: hex_decode(&token_id_hex)?,
                        to: to_id,
                    }
                };
                let tx = submit_action(&rpc, seed, &signer, action)?;
                Ok(format!(
                    "✓ sent {display} → {} (tx {})",
                    short_id(&to),
                    &tx[..tx.len().min(14)]
                ))
            })()
            .unwrap_or_else(|e| format!("✗ send failed: {e}"));
            record(&activity, &result);
            set_token_view_msg(&view, &ctx, &result);
        });
    }

    // ── Swaps tab: hash-time-locked contracts (the SOV half of an atomic swap). ──
    fn swaps_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Atomic swaps (HTLC)");
        ui.label(
            egui::RichText::new(
                "Lock funds behind a hashlock + timeout. The recipient claims by revealing the \
                 secret (which lets you claim the other chain's leg); after the timeout you refund.",
            )
            .weak(),
        );
        let Some((signer, seed)) = self
            .wallets
            .get(self.selected)
            .map(|w| (w.effective_account(), w.seed))
        else {
            ui.label(egui::RichText::new("create or open a wallet to use swaps").weak());
            return;
        };
        ui.label(egui::RichText::new(format!("acting as {signer}")).weak());
        let sv = self
            .swaps_view
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut do_lock = false;
        let mut do_lookup = false;
        let mut do_claim = false;
        let mut do_refund = false;

        // Lock.
        ui.separator();
        ui.label(egui::RichText::new("Lock (open an HTLC)").strong());
        ui.horizontal(|ui| {
            ui.label("Recipient");
            ui.add(egui::TextEdit::singleline(&mut self.htlc_recipient).desired_width(200.0));
            ui.label("Amount XUS");
            ui.add(egui::TextEdit::singleline(&mut self.htlc_amount).desired_width(110.0));
        });
        ui.horizontal(|ui| {
            ui.label("Secret");
            // Masked: the preimage is a secret until it is revealed by a claim. Generate
            // fills it with 32 bytes of OS entropy (hex) — the safe default.
            ui.add(
                egui::TextEdit::singleline(&mut self.htlc_preimage)
                    .hint_text("shared secret (≥16 bytes) — or Generate")
                    .password(true)
                    .desired_width(220.0),
            );
            if ui
                .button("Generate")
                .on_hover_text("fill with 32 cryptographically-random bytes (OS RNG), hex-encoded")
                .clicked()
            {
                self.htlc_preimage = random_secret_hex();
                self.set_swap_msg(
                    "secret generated — SAVE IT before locking: you need it to claim the \
                     counterparty's leg, and it is not recoverable if lost",
                );
            }
        });
        ui.horizontal(|ui| {
            // Relative timeout: blocks past the CURRENT tip (resolved at lock time), with an
            // enforced floor — an absolute height is a foot-gun (easy to set in the past).
            ui.label("Timeout (+blocks)");
            ui.add(
                egui::TextEdit::singleline(&mut self.htlc_timeout)
                    .hint_text(format!("≥ {HTLC_MIN_TIMEOUT_BLOCKS}"))
                    .desired_width(90.0),
            );
            if ui.button("Lock").clicked() {
                do_lock = true;
            }
        });
        if !self.htlc_preimage.trim().is_empty() {
            ui.label(
                egui::RichText::new(format!(
                    "hashlock = sha256(secret) = {}",
                    sha256_hex(self.htlc_preimage.trim().as_bytes())
                ))
                .small()
                .weak(),
            );
        }

        // Lookup / claim / refund by id.
        ui.separator();
        ui.label(egui::RichText::new("Find / claim / refund").strong());
        ui.horizontal(|ui| {
            ui.label("HTLC id");
            ui.add(
                egui::TextEdit::singleline(&mut self.htlc_lookup_id)
                    .hint_text("the lock tx id (hex)")
                    .desired_width(360.0),
            );
            if ui.button("Look up").clicked() {
                do_lookup = true;
            }
        });
        if sv.id == self.htlc_lookup_id.trim() {
            if let Some((locker, recipient, amount, hashlock, timeout)) = &sv.found {
                egui::Grid::new("htlc_detail")
                    .num_columns(2)
                    .spacing([14.0, 4.0])
                    .show(ui, |ui| {
                        kv(ui, "Locker", locker);
                        kv(ui, "Recipient", recipient);
                        kv(ui, "Amount", &format!("{} XUS", xus(amount)));
                        kv(ui, "Hashlock", hashlock);
                        kv(ui, "Timeout height", &timeout.to_string());
                    });
            } else if !sv.message.is_empty() {
                status_label(ui, &sv.message);
            }
        }
        ui.horizontal(|ui| {
            if ui
                .button("Claim (reveal secret above)")
                .on_hover_text("claims the HTLC with the Secret field, revealing it on-chain")
                .clicked()
            {
                do_claim = true;
            }
            if ui.button("Refund (after timeout)").clicked() {
                do_refund = true;
            }
        });
        if !sv.message.is_empty() {
            ui.label(egui::RichText::new(&sv.message).weak());
        }

        if do_lock {
            self.htlc_lock(ui.ctx(), signer.clone(), seed);
        }
        if do_lookup {
            self.htlc_lookup(ui.ctx());
        }
        if do_claim {
            self.htlc_claim(ui.ctx(), signer.clone(), seed);
        }
        if do_refund {
            self.htlc_refund(ui.ctx(), signer, seed);
        }
    }

    fn htlc_lock(&mut self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let recipient = self.htlc_recipient.trim().to_string();
        let secret = self.htlc_preimage.trim().to_string();
        let Some(grains) = parse_xus(&self.htlc_amount) else {
            return self.set_swap_msg("amount must be a number (e.g. 1.5)");
        };
        // The timeout is now a RELATIVE offset in blocks past the live tip (resolved in
        // the worker), with an enforced floor — an absolute height was a foot-gun.
        let Ok(offset) = self.htlc_timeout.trim().parse::<u64>() else {
            return self.set_swap_msg("timeout must be a whole number of blocks (e.g. 20)");
        };
        if offset < HTLC_MIN_TIMEOUT_BLOCKS {
            return self.set_swap_msg(&format!(
                "timeout must be at least {HTLC_MIN_TIMEOUT_BLOCKS} blocks past the tip"
            ));
        }
        // Reject a weak/guessable secret before it ever hits the chain as a hashlock.
        if !htlc_secret_ok(&secret) {
            return self.set_swap_msg(
                "secret too weak — use ≥16 bytes of real entropy (or press Generate)",
            );
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        // NOTE: we deliberately do NOT wipe the persistent UI copy here. In an atomic
        // swap the party who generated this preimage and locks first must RETAIN it to
        // later claim the counterparty's leg — wiping on lock would strand the funds
        // until refund. The worker's local clone is still scrubbed after it is folded
        // into the hashlock (below), and the field is wiped on wallet lock / app close
        // (Station::Drop) so its lifetime is still bounded. The claim path, by contrast,
        // reveals the preimage on-chain, so it wipes the field immediately.
        std::thread::spawn(move || {
            let mut secret = secret;
            let recipient_id = match AccountId::new(&recipient) {
                Ok(id) => id,
                Err(e) => {
                    secret.zeroize();
                    return set_swap_view_msg(&view, &ctx, &format!("invalid recipient: {e}"));
                }
            };
            // Resolve the relative timeout against the live tip; never lock with a
            // non-future (or past) expiry.
            let client = RpcClient::new(rpc.clone()).with_timeout(Duration::from_secs(8));
            let tip = match client.height() {
                Ok(h) => h,
                Err(e) => {
                    secret.zeroize();
                    return set_swap_view_msg(
                        &view,
                        &ctx,
                        &format!("could not read tip height: {e}"),
                    );
                }
            };
            let timeout_height = tip.saturating_add(offset);
            if timeout_height <= tip {
                secret.zeroize();
                return set_swap_view_msg(&view, &ctx, "timeout must be in the future");
            }
            let action = Action::HtlcLock {
                recipient: recipient_id,
                amount: Balance::from_grains(grains),
                hashlock: sov_primitives::Hash::from_bytes(sha256_bytes(secret.as_bytes())),
                timeout_height,
            };
            secret.zeroize(); // preimage captured into the hashlock; scrub the clone
                              // Confirm on a real SUCCESS receipt, not mempool admission.
            let msg = submit_and_confirm(&rpc, seed, &signer, action, 90)
                .map(|id| format!("✓ HTLC opened (timeout at block {timeout_height}) — id = {id}"))
                .unwrap_or_else(|e| format!("✗ lock failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn htlc_lookup(&self, ctx: &egui::Context) {
        let id = self.htlc_lookup_id.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let ctx = ctx.clone();
        if let Ok(mut v) = view.lock() {
            v.looking = true;
            v.id = id.clone();
        }
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(5));
            let res = client.call("sov_getHtlc", json!({ "hash": id }));
            if let Ok(mut v) = view.lock() {
                v.looking = false;
                v.id = id;
                match res {
                    Ok(val) if !val.is_null() => {
                        v.found = Some((
                            field(&val, "locker"),
                            field(&val, "recipient"),
                            field(&val, "amount"),
                            field(&val, "hashlock"),
                            val.get("timeoutHeight")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        ));
                        v.message = "HTLC found".to_string();
                    }
                    Ok(_) => {
                        v.found = None;
                        v.message =
                            "no such HTLC (never opened, or already claimed/refunded)".to_string();
                    }
                    Err(e) => {
                        v.found = None;
                        v.message = format!("lookup failed: {e}");
                    }
                }
            }
            ctx.request_repaint();
        });
    }

    fn htlc_claim(&mut self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let id_hex = self.htlc_lookup_id.trim().to_string();
        let secret = self.htlc_preimage.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        // The preimage is captured into the worker; wipe the persistent UI copy. (A
        // claim reveals it on-chain anyway, so keeping it in the field buys nothing.)
        self.htlc_preimage.zeroize();
        std::thread::spawn(move || {
            let mut secret = secret;
            let htlc_id = match Hash::from_hex(&id_hex) {
                Ok(h) => h,
                Err(_) => {
                    secret.zeroize();
                    return set_swap_view_msg(&view, &ctx, "HTLC id must be 64 hex chars");
                }
            };
            let action = Action::HtlcClaim {
                htlc_id,
                preimage: secret.as_bytes().to_vec(),
            };
            secret.zeroize(); // preimage copied into the action; scrub the clone
                              // Confirm on a real SUCCESS receipt, not mempool admission.
            let msg = submit_and_confirm(&rpc, seed, &signer, action, 90)
                .map(|id| format!("✓ HTLC claimed (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ claim failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn htlc_refund(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let id_hex = self.htlc_lookup_id.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let htlc_id = match Hash::from_hex(&id_hex) {
                Ok(h) => h,
                Err(_) => return set_swap_view_msg(&view, &ctx, "HTLC id must be 64 hex chars"),
            };
            let action = Action::HtlcRefund { htlc_id };
            // Confirm on a real SUCCESS receipt, not mempool admission.
            let msg = submit_and_confirm(&rpc, seed, &signer, action, 90)
                .map(|id| format!("✓ HTLC refunded (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ refund failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn set_swap_msg(&self, msg: &str) {
        if let Ok(mut v) = self.swaps_view.lock() {
            v.message = msg.to_string();
        }
    }

    /// The Mining tab's mining ON/OFF control. The node CONNECTS and SYNCS without
    /// mining; proof-of-work is an explicit opt-in here, flipped live (no restart) via
    /// `EmbeddedNode::set_mining`. Kept OFF by default so a slow machine can catch up
    /// without RandomX starving the sync loop.
    fn mining_control_ui(&mut self, ui: &mut egui::Ui) {
        // Read node + mining state under a brief lock, then release it before mutating
        // self (status/logs) to keep borrows clean.
        let (running, mining) = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => (true, node.is_mining()),
            _ => (false, false),
        };

        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("MINING")
                        .small()
                        .color(palette::text_dim()),
                );
                let (state, color) = if !running {
                    ("node not running", palette::text_dim())
                } else if mining {
                    ("ON — grinding proof-of-work", palette::accent_hi())
                } else {
                    ("OFF — connected & syncing only", palette::text())
                };
                ui.label(egui::RichText::new(state).strong().color(color));
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Your node stays fully synced WITHOUT mining. Turn mining on only when you \
                     want this machine to grind proof-of-work — it is CPU-heavy (RandomX), so on \
                     an older/low-power machine leave it OFF and just run a wallet + synced node.",
                )
                .weak()
                .small(),
            );
            ui.add_space(6.0);

            if !running {
                ui.label(
                    egui::RichText::new("Start the node from the Node tab first.")
                        .small()
                        .color(palette::text_dim()),
                );
                return;
            }

            if mining {
                if ui.button("⏹  Stop mining").clicked() {
                    self.apply_set_mining(false);
                }
            } else {
                // Enabling needs a wallet to pay the coinbase to.
                let have_wallet = self.wallets.get(self.selected).is_some();
                let btn = ui.add_enabled(have_wallet, egui::Button::new("⛏  Start mining"));
                if btn.clicked() {
                    self.apply_set_mining(true);
                }
                if !have_wallet {
                    ui.label(
                        egui::RichText::new("select or create a wallet to mine to first")
                            .small()
                            .color(palette::text_dim()),
                    );
                }
            }
        });
        ui.add_space(8.0);
    }

    /// Flip the running node's mining switch and report the outcome. Enabling can be
    /// refused (coinbase not key-bound) — surfaced verbatim, never a silent no-op.
    fn apply_set_mining(&mut self, on: bool) {
        let result = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => Some(node.set_mining(on)),
            _ => None,
        };
        match result {
            Some(Ok(())) => {
                let msg = if on {
                    "mining ENABLED — will grind once caught up to the tip".to_string()
                } else {
                    "mining DISABLED — node keeps syncing + serving".to_string()
                };
                self.node_status = msg.clone();
                push_log(&self.node_logs, msg);
            }
            Some(Err(e)) => {
                let msg = format!("could not enable mining: {e}");
                self.node_status = msg.clone();
                push_log(&self.node_logs, msg);
            }
            None => {
                self.node_status = "start the node first".to_string();
            }
        }
    }

    /// The Mining tab's "earned by your wallet" panel: cumulative coinbase your
    /// wallets have actually received, summed from the chain on demand.
    fn mining_earnings_section(&self, ui: &mut egui::Ui) {
        ui.heading("Your mining earnings");
        let ev = self.earnings.lock().map(|e| e.clone()).unwrap_or_default();
        if self.wallets.is_empty() {
            ui.label(egui::RichText::new("create or open a wallet to track earnings").weak());
            ui.separator();
            return;
        }
        egui::Frame::group(ui.style())
            .fill(palette::tint(palette::success(), 30))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("TOTAL EARNED").small().weak());
                    ui.label(
                        egui::RichText::new(format!("{} XUS", xus(&ev.total_grains.to_string())))
                            .strong()
                            .size(18.0)
                            .color(palette::success()),
                    );
                    if ev.scanned_height > 0 {
                        ui.label(
                            egui::RichText::new(format!("(to height {})", ev.scanned_height))
                                .weak(),
                        );
                    }
                });
                if !ev.rows.is_empty() {
                    egui::Grid::new("earnings")
                        .num_columns(4)
                        .striped(true)
                        .spacing([18.0, 4.0])
                        .show(ui, |ui| {
                            for h in ["Wallet", "Role", "Blocks", "Earned XUS"] {
                                ui.label(egui::RichText::new(h).weak());
                            }
                            ui.end_row();
                            for r in &ev.rows {
                                ui.label(format!("{}  ({})", r.label, short_id(&r.account)));
                                ui.monospace(&r.role);
                                ui.monospace(r.blocks.to_string());
                                ui.monospace(xus(&r.grains.to_string()));
                                ui.end_row();
                            }
                        });
                }
            });
        ui.horizontal(|ui| {
            if ev.computing {
                ui.spinner();
                ui.label("scanning the chain for your coinbase…");
            } else if ui
                .button("Compute earnings")
                .on_hover_text("scan every block's coinbase for payments to your wallets")
                .clicked()
            {
                self.compute_earnings(ui.ctx());
            }
            if !ev.message.is_empty() {
                ui.label(egui::RichText::new(&ev.message).weak());
            }
        });
        ui.separator();
    }

    /// Scan the chain's per-block coinbase for payments to any account this
    /// wallet controls (its implicit id and any named account it operates), on a
    /// worker thread. Real on-chain data — every grain is a coinbase the chain paid.
    fn compute_earnings(&self, ctx: &egui::Context) {
        // account id -> display label, for every account the user controls.
        let mut accounts: HashMap<String, String> = HashMap::new();
        for w in &self.wallets {
            accounts.insert(w.account.clone(), w.label.clone());
            if let Some(named) = &w.operate_as {
                accounts.insert(named.clone(), w.label.clone());
            }
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let earnings = self.earnings.clone();
        let ctx = ctx.clone();
        if let Ok(mut e) = earnings.lock() {
            e.computing = true;
            e.message = "scanning…".to_string();
        }
        ctx.request_repaint();
        std::thread::spawn(move || {
            let result = scan_earnings(&rpc, &accounts);
            if let Ok(mut e) = earnings.lock() {
                e.computing = false;
                match result {
                    Ok((total, tip, rows)) => {
                        e.total_grains = total;
                        e.scanned_height = tip;
                        e.rows = rows;
                        e.message = format!("scanned {tip} blocks");
                    }
                    Err(err) => e.message = format!("scan failed: {err}"),
                }
            }
            ctx.request_repaint();
        });
    }

    /// The hero balance card — the first thing the Wallet tab shows: the selected
    /// wallet's spendable balance in large type, its label + account, the network
    /// badge, and live miner / watch-only / shielded-pool context. The at-a-glance
    /// "how much do I have, and where" that a bank app leads with.
    fn balance_card(&self, ui: &mut egui::Ui, s: &Snapshot) {
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let label = w.label.clone();
        let effective = w.effective_account();
        let watch_only = w.watch_only;
        let account = w.account.clone();
        let bal = s
            .accounts
            .iter()
            .find(|a| a.account == effective)
            .map(|a| xus(&a.balance))
            .unwrap_or_else(|| "—".to_string());
        let named = is_named_account(&effective);
        let is_miner = self.mining_account.as_deref() == Some(account.as_str());
        // Shielded (private) balance FOR THIS WALLET, if it has been scanned —
        // looked up by the wallet's own account, so it is this wallet's figure or
        // nothing at all. Unscanned shows no shielded line rather than a zero.
        let shielded = self
            .shielded
            .lock()
            .ok()
            .map(|m| m.view_for(&account))
            .filter(|v| v.account == account && v.balance > 0)
            .map(|v| grains_to_xus_plain(u128::from(v.balance)));

        egui::Frame::group(ui.style())
            .fill(palette::panel())
            .stroke(egui::Stroke::new(1.0, palette::border()))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("ACTIVE WALLET")
                            .small()
                            .color(palette::text_dim()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        network_badge(ui, self.network);
                        if is_miner {
                            ui.label(
                                egui::RichText::new("⛏ mining")
                                    .small()
                                    .color(palette::success()),
                            );
                        }
                        if watch_only {
                            ui.label(
                                egui::RichText::new("👁 watch-only")
                                    .small()
                                    .color(palette::text_dim()),
                            );
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&bal)
                            .size(34.0)
                            .strong()
                            .color(palette::text()),
                    );
                    ui.label(
                        egui::RichText::new("XUS")
                            .size(15.0)
                            .color(palette::text_dim()),
                    );
                    if let Some(sh) = &shielded {
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new(format!("🛡 {sh} private"))
                                .color(palette::accent_hi()),
                        );
                    }
                });
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&label).strong().color(palette::link()));
                    ui.label(egui::RichText::new("·").color(palette::text_dim()));
                    ui.label(
                        egui::RichText::new(short_id(&effective))
                            .monospace()
                            .color(palette::text_dim()),
                    );
                    if named {
                        ui.label(
                            egui::RichText::new("✓ named")
                                .small()
                                .color(palette::success()),
                        );
                    }
                });
                // In-flight transactions: anything in the node's mempool is waiting to be
                // mined into the next block. The big number above is the CONFIRMED on-chain
                // balance, so a just-sent tx shows here as pending until that block lands
                // (the funds aren't "still in your wallet" — they're committed to the
                // pending tx, which confirms in ~one block).
                if let Some(n) = s.mempool.filter(|n| *n > 0) {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "⏳ {n} transaction(s) in the mempool — confirming in the next block"
                        ))
                        .small()
                        .color(palette::warning()),
                    );
                }
            });
        ui.add_space(10.0);
    }

    /// The dedicated Activity tab — the full session history of submitted actions,
    /// newest first, each line timestamped and colored by outcome (green succeeded /
    /// red failed). The same feed the wallet shows, given room to breathe.
    fn activity_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Activity");
        ui.label(
            egui::RichText::new(
                "Every action you've submitted this session — newest first. Green where it \
                 succeeded, red where it failed.",
            )
            .weak()
            .small(),
        );
        ui.add_space(8.0);
        let log = self.activity.lock().map(|l| l.clone()).unwrap_or_default();
        if log.is_empty() {
            empty_state(
                ui,
                "◷",
                "No activity yet",
                "Send, shield, register a name, or open a swap — it shows up here.",
            );
            return;
        }
        if ui.button("Clear").clicked() {
            if let Ok(mut l) = self.activity.lock() {
                l.clear();
            }
        }
        ui.add_space(6.0);
        card(ui, |ui| {
            for line in &log {
                let (time, body) = line.split_once('\t').unwrap_or(("", line.as_str()));
                let col = status_color(tx_status(body));
                ui.horizontal_wrapped(|ui| {
                    if !time.is_empty() {
                        ui.label(
                            egui::RichText::new(time)
                                .monospace()
                                .size(11.0)
                                .color(palette::text_dim()),
                        );
                    }
                    ui.label(egui::RichText::new(body).monospace().size(12.0).color(col));
                });
            }
        });
    }

    /// A compact onboarding checklist — the create-wallet → start-node → mine → send
    /// journey — shown atop the Wallet tab until the user is up and running, so a
    /// first-time user always knows the next step. Auto-hides once fully set up.
    fn first_run_checklist(&self, ui: &mut egui::Ui, s: &Snapshot) {
        let has_wallet = !self.wallets.is_empty();
        let node_running = matches!(&*self.node_run.lock().unwrap(), NodeRun::Running(_));
        let acct = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account());
        let row = acct
            .as_ref()
            .and_then(|a| s.accounts.iter().find(|r| &r.account == a));
        let has_funds = row
            .and_then(|a| a.balance.parse::<u128>().ok())
            .map(|b| b > 0)
            .unwrap_or(false);
        let has_sent = row
            .and_then(|a| a.nonce.parse::<u64>().ok())
            .map(|n| n > 0)
            .unwrap_or(false);
        // Fully set up — the checklist has served its purpose, so get out of the way.
        if has_wallet && node_running && has_funds && has_sent {
            return;
        }
        fn step(ui: &mut egui::Ui, done: bool, current: bool, text: &str) {
            ui.horizontal(|ui| {
                let (glyph, col) = if done {
                    ("✓", palette::success())
                } else if current {
                    ("▸", palette::accent_hi())
                } else {
                    ("○", palette::text_dim())
                };
                ui.label(egui::RichText::new(glyph).color(col).strong());
                let t = egui::RichText::new(text);
                ui.label(if done {
                    t.color(palette::text_dim()).strikethrough()
                } else if current {
                    t.strong()
                } else {
                    t.color(palette::text_dim())
                });
            });
        }
        card(ui, |ui| {
            ui.label(
                egui::RichText::new("GET STARTED")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.add_space(4.0);
            // "current" highlights the first not-yet-done step.
            step(ui, has_wallet, !has_wallet, "Create or restore a wallet");
            step(
                ui,
                node_running,
                has_wallet && !node_running,
                "Start the local node (it mines to your wallet)",
            );
            step(
                ui,
                has_funds,
                node_running && !has_funds,
                "Mine your first block (wait for a coinbase)",
            );
            step(
                ui,
                has_sent,
                has_funds && !has_sent,
                "Send your first transaction",
            );
        });
        ui.add_space(8.0);
    }

    fn wallet_panel(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let ctx = ui.ctx().clone();
        ui.heading("Wallet");
        self.first_run_checklist(ui, s);

        // ── STATE 1 — Onboarding ──
        // Like every real wallet, you must create or restore a recovery phrase
        // before ANY other action. Nothing else in the wallet (and no node mining)
        // is reachable until a wallet exists.
        if self.wallets.is_empty() {
            ui.label(
                egui::RichText::new(
                    "Create or restore a wallet to begin. A recovery phrase is required before any \
                     action — and the local node mines to the wallet you select. Your on-chain \
                     account id is derived from your key (not the label), so it can never collide \
                     with — or inherit the funds of — another account.",
                )
                .weak(),
            );
            ui.add_space(10.0);
            let mut do_generate = false;
            let mut do_import = false;
            let mut do_load = false;
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Create a new wallet").strong());
                ui.horizontal(|ui| {
                    ui.label("Label (display only)");
                    ui.add(egui::TextEdit::singleline(&mut self.gen_name).desired_width(220.0));
                    if ui.button("Generate recovery phrase").clicked() {
                        do_generate = true;
                    }
                });
            });
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Restore from a recovery phrase").strong());
                ui.horizontal(|ui| {
                    ui.label("Label (display only)");
                    ui.add(egui::TextEdit::singleline(&mut self.import_name).desired_width(220.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Mnemonic / seed");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.import_mnemonic)
                            .desired_width(420.0)
                            .hint_text("24-word phrase OR 64-hex seed"),
                    );
                    if ui.button("Restore").clicked() {
                        do_import = true;
                    }
                });
            });
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Open an encrypted keystore").strong());
                ui.horizontal(|ui| {
                    ui.label("Passphrase");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keystore_pass)
                            .password(true)
                            .desired_width(200.0),
                    );
                    if ui.button("Unlock").clicked() {
                        do_load = true;
                    }
                });
            });
            let err = self
                .action
                .lock()
                .map(|a| a.message.clone())
                .unwrap_or_default();
            if !err.is_empty() {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(err).weak());
            }
            if !self.keystore_msg.is_empty() {
                ui.add_space(4.0);
                status_label(ui, &self.keystore_msg);
            }
            if do_generate {
                self.generate_wallet();
            }
            if do_import {
                self.import_wallet();
            }
            if do_load {
                self.load_wallets();
            }
            return;
        }

        // ── STATE 2 — Backup gate ──
        // A freshly generated phrase must be acknowledged (written down) before
        // the wallet can be used.
        if let Some((acct, mnem)) = self.backup_mnemonic.clone() {
            let mut acked = false;
            // The just-generated wallet's public key, for binding a named genesis
            // account (e.g. a tax account) to it. Public — safe to copy/share.
            let pubkey = self
                .wallets
                .iter()
                .find(|w| w.account == acct)
                .map(|w| w.public_key.clone())
                .unwrap_or_default();
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::warning(), 30))
                .show(ui, |ui| {
                    ui.colored_label(
                        palette::warning(),
                        "⚠ Write this recovery phrase down now — offline, in order. It is the ONLY \
                         way to restore this wallet, is shown once, and must never be shared.",
                    );
                    ui.label(egui::RichText::new(format!("account: {acct}")).monospace());
                    ui.label(egui::RichText::new(&mnem).monospace());
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(
                        egui::RichText::new(
                            "Public key (safe to share — hand this over to bind a named genesis \
                             account such as a tax account):",
                        )
                        .weak(),
                    );
                    ui.label(egui::RichText::new(short_pubkey(&pubkey)).monospace());
                    if ui.button("Copy public key").clicked() {
                        ui.output_mut(|o| o.copied_text = pubkey.clone());
                    }
                    ui.add_space(6.0);
                    if ui.button("I have written it down — continue").clicked() {
                        acked = true;
                    }
                });
            if acked {
                if let Some((_, phrase)) = self.backup_mnemonic.as_mut() {
                    phrase.zeroize(); // scrub before the Option drops the String
                }
                self.backup_mnemonic = None;
            }
            return;
        }

        // ── STATE 3 — Full wallet (a wallet exists and its phrase is backed up) ──
        let mut do_generate = false;
        let mut do_import = false;
        let mut do_add_watch = false;
        let mut select: Option<usize> = None;
        let mut do_rename = false;
        let mut do_forget = false;
        let mut do_save = false;

        // ── Auto-attach: if a wallet's key controls a watched NAMED account (e.g.
        // a genesis-bound tax account), operate as it automatically so its balance
        // shows — no manual "attach" step. Pure key match against polled data; the
        // chain already proved the binding. ──
        for w in self.wallets.iter_mut() {
            if w.operate_as.is_some() || w.public_key.is_empty() {
                continue;
            }
            if let Some(named) = s
                .accounts
                .iter()
                .find(|a| is_named_account(&a.account) && a.key == w.public_key)
            {
                w.operate_as = Some(named.account.clone());
            }
        }

        // The hero balance card — prominent spendable balance + network badge, up top.
        self.balance_card(ui, s);

        // ── Unsaved-wallets banner — nudge to persist before they can be lost ──
        if self.wallets_dirty && !self.wallets.is_empty() {
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::warning(), 30))
                .stroke(egui::Stroke::new(1.0, palette::warning()))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ {} wallet(s) not saved to disk — back them up so they survive a \
                                 restart.",
                                self.wallets.len()
                            ))
                            .color(palette::warning()),
                        );
                        if self.keystore_pass.is_empty() {
                            ui.label(
                                egui::RichText::new(
                                    "enter a backup passphrase in “Wallet file” below, then Save",
                                )
                                .small()
                                .weak(),
                            );
                        } else if ui.button("Save now").clicked() {
                            do_save = true;
                        }
                    });
                });
            ui.add_space(4.0);
        }

        // ── Add / import a wallet (at the top — the first thing you reach for) ──
        ui.collapsing("➕ Add or import a wallet", |ui| {
            let enter = |r: &egui::Response, ui: &egui::Ui| {
                r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            };
            ui.horizontal(|ui| {
                ui.label("New wallet label");
                let r = ui.add(egui::TextEdit::singleline(&mut self.gen_name).desired_width(200.0));
                if ui.button("Generate").clicked() || enter(&r, ui) {
                    do_generate = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Import label");
                ui.add(egui::TextEdit::singleline(&mut self.import_name).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("mnemonic / seed");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.import_mnemonic)
                        .desired_width(420.0)
                        .hint_text("24-word phrase OR 64-hex seed"),
                );
                if ui.button("Import").clicked() || enter(&r, ui) {
                    do_import = true;
                }
            });
            ui.separator();
            ui.label(
                egui::RichText::new(
                    "👁 Watch-only: monitor an account from its public key — no private key here, \
                     so it can't sign. Spend it via the offline-signing tools (build unsigned here \
                     → sign on the machine with the seed → broadcast).",
                )
                .weak()
                .small(),
            );
            ui.horizontal(|ui| {
                ui.label("Watch label");
                ui.add(egui::TextEdit::singleline(&mut self.watch_label).desired_width(150.0));
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.watch_pubkey)
                        .hint_text("public key — hybrid65:0x…")
                        .desired_width(320.0),
                );
                if ui.button("Add watch-only").clicked() || enter(&r, ui) {
                    do_add_watch = true;
                }
            });
        });
        ui.add_space(4.0);
        ui.separator();

        // ── Active-wallet banner: the unmistakable "who am I acting as" strip ──
        let balance_of = |acct: &str| {
            s.accounts
                .iter()
                .find(|a| a.account == acct)
                .map(|a| xus(&a.balance))
                .unwrap_or_else(|| "—".to_string())
        };
        if let Some(w) = self.wallets.get(self.selected) {
            let label = w.label.clone();
            let account = w.account.clone();
            let effective = w.effective_account();
            let is_miner = self.mining_account.as_deref() == Some(account.as_str());
            // Name state, shown CONSISTENTLY for both kinds of name: a wallet
            // operating AS a named account (e.g. name.reserve.sov) and a wallet
            // with an SNS alias resolving to it (e.g. claude.sov) are BOTH "named".
            // SNS names are trusted only when the cache is for THIS account (avoids
            // a one-frame flash of the previous wallet's names after switching).
            let operating_named = is_named_account(&effective);
            let sns_names: Vec<String> = self
                .names_by_account
                .lock()
                .ok()
                .and_then(|m| m.get(&effective).cloned())
                .unwrap_or_default();
            let has_sns = !sns_names.is_empty();
            let named = operating_named || has_sns;
            // A green border for a named wallet (operate-as OR SNS), amber for an
            // unnamed (implicit) one — the name-state is unmistakable at a glance.
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::link(), 30))
                .stroke(egui::Stroke::new(1.5, named_color(named)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("ACTIVE WALLET").small().weak());
                        ui.label(
                            egui::RichText::new(&label)
                                .strong()
                                .size(16.0)
                                .color(palette::link()),
                        );
                        ui.label(egui::RichText::new(short_id(&account)).monospace().weak());
                        if is_miner {
                            ui.label(
                                egui::RichText::new("⛏ mining")
                                    .small()
                                    .color(palette::success()),
                            );
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!("{} XUS", balance_of(&effective)))
                                    .strong(),
                            );
                        });
                    });
                    // Name-state line — consistent for both kinds of name.
                    if w.watch_only {
                        ui.label(
                            egui::RichText::new(
                                "👁 WATCH-ONLY  ·  no private key here — monitor only",
                            )
                            .strong()
                            .color(palette::link()),
                        );
                    } else if operating_named {
                        ui.label(
                            egui::RichText::new(format!("✓ NAMED ACCOUNT  ·  {effective}"))
                                .strong()
                                .color(named_color(true)),
                        );
                    } else if has_sns {
                        ui.label(
                            egui::RichText::new(format!("✓ SNS  ·  {}", sns_names.join(", ")))
                                .strong()
                                .color(named_color(true)),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "○ UNNAMED  ·  implicit address only — register an SNS name below \
                                 for a human-readable account",
                            )
                            .color(named_color(false)),
                        );
                    }
                    // Rename + remove the active wallet. Remove opens a deliberate
                    // type-to-confirm modal (handled below) — no one-click delete.
                    ui.horizontal(|ui| {
                        ui.label("Label");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rename_field)
                                .desired_width(180.0)
                                .hint_text(&label),
                        );
                        if ui.button("Rename").clicked() {
                            do_rename = true;
                        }
                        ui.separator();
                        if ui.button("🗑 Remove wallet").clicked() {
                            self.forget_armed = true;
                            self.forget_confirm.clear();
                        }
                    });
                });
        }

        // ── Remove-wallet confirmation modal: type the label to enable removal,
        // so a wallet can never be deleted by an accidental click. ──
        if self.forget_armed {
            let target_label = self
                .wallets
                .get(self.selected)
                .map(|w| w.label.clone())
                .unwrap_or_default();
            let ctx = ui.ctx().clone();
            let matches = self.forget_confirm.trim() == target_label && !target_label.is_empty();
            egui::Window::new("Remove wallet")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.colored_label(
                        palette::warning(),
                        "⚠ This removes the wallet from the app. It can ONLY be restored from its \
                         recovery phrase (or a saved backup). Export the phrase first if you need it.",
                    );
                    ui.add_space(6.0);
                    ui.label(format!("To confirm, type the wallet's label:  {target_label}"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.forget_confirm)
                            .hint_text(&target_label)
                            .desired_width(220.0),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(matches, |ui| {
                            if ui
                                .button(
                                    egui::RichText::new("Remove permanently")
                                        .color(palette::error()),
                                )
                                .clicked()
                            {
                                do_forget = true;
                                self.forget_armed = false;
                                self.forget_confirm.clear();
                            }
                        });
                        if ui.button("Cancel").clicked() {
                            self.forget_armed = false;
                            self.forget_confirm.clear();
                        }
                    });
                    if !matches && !self.forget_confirm.is_empty() {
                        ui.label(
                            egui::RichText::new("label doesn't match")
                                .small()
                                .color(palette::error()),
                        );
                    }
                });
        }

        // ── Wallet switcher: every wallet, one click to make active. Each row is
        // tagged NAMED (green) or unnamed (amber) so the distinction is obvious.
        ui.add_space(sp::M);
        ui.label(egui::RichText::new("Switch wallet").strong());
        ui.add_space(sp::XS);
        // Snapshot the per-account SNS name cache once, so each row's badge reflects
        // its registered name (not just an operate-as named account).
        let names_map: HashMap<String, Vec<String>> = self
            .names_by_account
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        // Fixed column widths, so the ids, badges, and balances line up down the
        // list no matter how long each wallet's label runs — the old single
        // concatenated string left every column ragged. Hierarchy: the NAME is
        // primary; the id and badge are secondary and dim; the balance is
        // right-aligned in tabular figures so its digits stack. The WHOLE row is
        // one hit target: the badge and the ⛏ marker select the wallet too,
        // instead of being dead zones beside the only clickable text.
        const WROW_NAME_W: f32 = 170.0;
        const WROW_ID_W: f32 = 110.0;
        const WROW_H: f32 = 18.0;
        for (i, w) in self.wallets.iter().enumerate() {
            let active = i == self.selected;
            let marker = if active { "●" } else { "○" };
            let is_miner = self.mining_account.as_deref() == Some(w.account.as_str());
            let effective = w.effective_account();
            let operating_named = is_named_account(&effective);
            let sns = names_map.get(&effective).cloned().unwrap_or_default();
            let named = operating_named || !sns.is_empty();
            let fill = if active {
                palette::tint(palette::link(), 26)
            } else {
                egui::Color32::TRANSPARENT
            };
            let row = egui::Frame::none()
                .fill(fill)
                .rounding(6.0)
                .inner_margin(egui::Margin::symmetric(sp::M, sp::S))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        // NAME — the primary fact, first and strongest.
                        ui.allocate_ui_with_layout(
                            egui::vec2(WROW_NAME_W, WROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new(marker).color(if active {
                                    palette::accent_hi()
                                } else {
                                    palette::text_dim()
                                }));
                                let name = if active {
                                    egui::RichText::new(&w.label).strong()
                                } else {
                                    egui::RichText::new(&w.label)
                                };
                                ui.add(egui::Label::new(name).truncate());
                                if is_miner {
                                    ui.label(
                                        egui::RichText::new("⛏").small().color(palette::success()),
                                    );
                                }
                            },
                        );
                        // ID — secondary: dim monospace in its own column.
                        ui.allocate_ui_with_layout(
                            egui::vec2(WROW_ID_W, WROW_H),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    num(short_id(&w.account))
                                        .size(ty::SMALL)
                                        .color(palette::text_dim()),
                                );
                            },
                        );
                        // BALANCE — right-aligned tabular figures so digits stack
                        // down the column. Shows the balance of the account this
                        // wallet OPERATES (its named account when attached, else
                        // its own implicit id) — so a tax wallet shows its real
                        // balance, not its empty implicit address.
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new("XUS")
                                    .size(ty::MICRO)
                                    .color(palette::text_dim()),
                            );
                            ui.label(num(balance_of(&effective)));
                            // Name-state badge — operate-as named account, else
                            // SNS name(s), else unnamed. Same SNS cache as the
                            // header. Fills the slack between id and balance,
                            // truncated so a long name never shoves the figures.
                            let badge = if operating_named {
                                format!("named · {effective}")
                            } else if !sns.is_empty() {
                                format!("SNS · {}", sns.join(", "))
                            } else {
                                "unnamed".to_string()
                            };
                            ui.add_space(sp::L);
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(badge)
                                                .size(ty::SMALL)
                                                .color(named_color(named)),
                                        )
                                        .truncate(),
                                    );
                                },
                            );
                        });
                    });
                })
                .response
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if row.clicked() {
                select = Some(i);
            }
        }

        // Selected wallet detail + actions (decoupled from the borrow via a clone).
        let sel = self.wallets.get(self.selected).map(|w| {
            (
                w.label.clone(),
                w.account.clone(),
                w.public_key.clone(),
                w.shielded.clone(),
                w.unified.clone(),
                w.operate_as.clone(),
                w.mnemonic.clone(),
                w.watch_only,
            )
        });
        // The pool-v2 address + its owner tag, cloned alongside `sel` (kept out of that
        // tuple so the existing destructuring is untouched). Empty for a watch-only
        // wallet, which holds no seed to derive them from.
        let (v2_addr, v2_tag) = self
            .wallets
            .get(self.selected)
            .map(|w| (w.shielded_v2.clone(), w.v2_owner_tag.clone()))
            .unwrap_or_default();
        let mut do_set_operate = false;
        let mut do_clear_operate = false;
        let mut do_register_named = false;
        let mut new_pending: Option<PendingSend> = None;
        let mut did_copy = false;
        let mut do_send = false;
        // The tip the spender CONFIRMED, carried from the review modal to the
        // dispatch below. Re-reading the live suggestion at send time would sign a
        // different bid than the one they approved — the pool moves every second.
        let mut confirmed_tip_grains = 0u128;
        let mut do_private_send = false;
        let mut do_scan = false;
        let mut do_scan_v2 = false;
        let mut do_shield_v2 = false;
        let mut do_deshield_v2 = false;
        let mut do_send_v2 = false;
        let mut do_rescan = false;
        let mut do_deshield = false;
        let mut do_build_unsigned = false;
        let mut do_sign_offline = false;
        let mut do_broadcast = false;
        if let Some((
            label,
            account,
            public_key,
            shielded,
            unified,
            operate_as,
            mnemonic,
            w_watch_only,
        )) = sel
        {
            // The account the wallet is acting as: a linked named account, or its
            // own implicit id. Balances/nonce/actions follow this.
            let effective = operate_as.clone().unwrap_or_else(|| account.clone());
            let onchain = s.accounts.iter().find(|a| a.account == effective);
            ui.add_space(6.0);
            egui::Grid::new("wdetail")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    kv(ui, "Label", &label);
                    kv(ui, "Your account", &account);
                    kv(ui, "Public key", &short_pubkey(&public_key));
                    if let Some(named) = &operate_as {
                        kv(ui, "▶ Operating as", named);
                    }
                    kv(
                        ui,
                        "Balance",
                        &format!(
                            "{} XUS",
                            onchain
                                .map(|a| xus(&a.balance))
                                .unwrap_or_else(|| "—".into())
                        ),
                    );
                    kv(
                        ui,
                        "On-chain",
                        onchain
                            .map(|a| a.key_state.as_str())
                            .unwrap_or("not yet on-chain"),
                    );
                    kv(
                        ui,
                        "Nonce",
                        onchain.map(|a| a.nonce.as_str()).unwrap_or("—"),
                    );
                    kv(ui, "Shielded", &shielded);
                    kv(ui, "Unified", &unified);
                });
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("copy:").weak());
                if ui.button("account").clicked() {
                    ui.output_mut(|o| o.copied_text = account.clone());
                    did_copy = true;
                }
                if ui.button("public key").clicked() {
                    ui.output_mut(|o| o.copied_text = public_key.clone());
                    did_copy = true;
                }
                if ui.button("shielded addr").clicked() {
                    ui.output_mut(|o| o.copied_text = shielded.clone());
                    did_copy = true;
                }
                if ui.button("unified addr").clicked() {
                    ui.output_mut(|o| o.copied_text = unified.clone());
                    did_copy = true;
                }
            });
            ui.label(
                egui::RichText::new(
                    "“public key” is the hybrid65:0x… line to hand over for binding a named \
                     genesis account (e.g. a tax account). Safe to share; never share the phrase.",
                )
                .weak(),
            );

            // Export / reveal the recovery phrase — re-displayable any time (not
            // just at generation), so the wallet can be backed up or moved.
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Recovery phrase").strong());
                match &mnemonic {
                    Some(_) if !self.reveal_phrase => {
                        if ui.button("Reveal / export").clicked() {
                            self.reveal_phrase = true;
                        }
                    }
                    Some(phrase) => {
                        if ui.button("Hide").clicked() {
                            self.reveal_phrase = false;
                        }
                        if ui.button("Copy phrase").clicked() {
                            ui.output_mut(|o| o.copied_text = phrase.clone());
                            did_copy = true;
                        }
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "not available (restored from a raw seed) — save the keystore to \
                                 keep it",
                            )
                            .weak(),
                        );
                    }
                }
            });
            if self.reveal_phrase {
                if let Some(phrase) = &mnemonic {
                    egui::Frame::group(ui.style())
                        .fill(palette::tint(palette::warning(), 30))
                        .show(ui, |ui| {
                            ui.colored_label(
                                palette::warning(),
                                "⚠ Anyone who sees these 24 words owns this wallet. Write them \
                                 down offline; never paste them online.",
                            );
                            ui.label(egui::RichText::new(phrase).monospace());
                        });
                }
            }

            // ── Name (ENS/SNS-style) ──────────────────────────────────────
            // Register a *.sov name that RESOLVES to this wallet's account. The
            // name is a pure alias — funds never leave the account.
            let typed_name = self.name_field.trim().to_string();
            let (name_ok, name_msg, name_busy) = self
                .name_check
                .lock()
                .ok()
                .map(|c| {
                    if c.name == typed_name {
                        (c.ok, c.message.clone(), c.checking)
                    } else {
                        (false, String::new(), !typed_name.is_empty())
                    }
                })
                .unwrap_or((false, String::new(), false));
            let my_names_list: Vec<String> = self
                .names_by_account
                .lock()
                .ok()
                .and_then(|m| m.get(&effective).cloned())
                .unwrap_or_default();
            ui.add_space(8.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Sovereign Name Service (SNS)").strong());
                ui.label(
                    egui::RichText::new(
                        "Your address is a key fingerprint. Register a “.sov” name so people can \
                         pay you by name — it resolves to THIS account and your funds never move. \
                         First-come; a one-time fee (earned by miners) applies.",
                    )
                    .weak(),
                );
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name_field)
                            .hint_text("alice.sov")
                            .desired_width(220.0),
                    );
                    let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
                    // The validation gate: enabled only once the name is well-
                    // formed AND confirmed available on-chain (so it WILL resolve).
                    let can = name_ok && !busy && !typed_name.is_empty();
                    if ui
                        .add_enabled(can, egui::Button::new("Register on-chain"))
                        .on_hover_text(
                            "Bind this .sov name as an alias to your account. Enabled only once \
                             the name is valid and available on the network.",
                        )
                        .clicked()
                    {
                        do_register_named = true;
                    }
                });
                // Live status: empty / checking / available / invalid / taken.
                if typed_name.is_empty() {
                    ui.label(egui::RichText::new("enter a name like alice.sov").weak());
                } else if name_busy {
                    ui.label(egui::RichText::new("checking the network…").weak());
                } else if !name_msg.is_empty() {
                    let col = if name_ok {
                        palette::success()
                    } else {
                        palette::error()
                    };
                    ui.colored_label(col, &name_msg);
                }
                if !my_names_list.is_empty() {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(format!("Your names: {}", my_names_list.join(", ")))
                            .color(named_color(true)),
                    );
                }
                if !self.operate_msg.is_empty() {
                    status_label(ui, &self.operate_msg);
                }
            });

            // ── Operate a named account you control (advanced) ─────────────
            // The genesis/tax-account path: act AS a named account this key
            // already controls. This is NOT name registration.
            ui.add_space(6.0);
            egui::CollapsingHeader::new("Operate a named account (advanced)")
                .default_open(operate_as.is_some())
                .show(ui, |ui| {
                    if let Some(named) = &operate_as {
                        ui.label(
                            egui::RichText::new(format!(
                                "✓ acting AS “{named}” — Send / Receive below use it, signed by \
                                 this wallet's key."
                            ))
                            .color(named_color(true)),
                        );
                        if ui
                            .button("Back to my key's own address")
                            .on_hover_text("Stop acting as the named account; use this wallet's implicit address.")
                            .clicked()
                        {
                            do_clear_operate = true;
                        }
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "Attach a named account this key already controls (e.g. a \
                                 genesis-bound tax/reserve account) and act as it — no transaction. \
                                 For a human-readable alias, use “Name” above instead.",
                            )
                            .weak(),
                        );
                        ui.horizontal(|ui| {
                            ui.label("Account");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.operate_as_field)
                                    .hint_text("name.reserve.sov")
                                    .desired_width(220.0),
                            );
                            if ui.button("Attach").clicked() {
                                do_set_operate = true;
                            }
                        });
                    }
                });

            // ── Receive ──
            ui.separator();
            ui.label(egui::RichText::new("Receive").strong().size(ty::SECTION));
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.receive_kind,
                    ReceiveKind::Shielded,
                    "Shielded (private)",
                );
                ui.selectable_value(&mut self.receive_kind, ReceiveKind::Unified, "Unified");
                ui.selectable_value(&mut self.receive_kind, ReceiveKind::Account, "Account");
                // Pool v2 is marked in the tab strip itself, so its state is visible
                // BEFORE it is selected — an operator never clicks in expecting a
                // working receive address and discovers the dormancy afterwards.
                ui.selectable_value(
                    &mut self.receive_kind,
                    ReceiveKind::ShieldedV2,
                    "Post-quantum (v2) ◌",
                )
                .on_hover_text(
                    "The xusq1… address this seed controls in the post-quantum shielded \
                     pool. The pool is NOT ACTIVE yet — the address is shown so you can \
                     record it, but nothing can be sent to it.",
                );
            });
            let recv_addr = match self.receive_kind {
                ReceiveKind::Shielded => shielded.clone(),
                ReceiveKind::Unified => unified.clone(),
                ReceiveKind::Account => account.clone(),
                ReceiveKind::ShieldedV2 => v2_addr.clone(),
            };
            if self.receive_kind == ReceiveKind::ShieldedV2 {
                // Pool v2 gets its own presentation. It is NOT a peer of the three
                // working addresses above, for two independent reasons — it is not
                // payable, and it is ~1,957 characters — and pretending otherwise
                // would be both dishonest and unusable.
                if v2_addr.is_empty() {
                    ui.add_space(sp::S);
                    empty_hint(
                        ui,
                        "No v2 address for this wallet",
                        "A pool-v2 address is derived from a seed. This wallet is \
                         watch-only — it holds a public key and no seed, so there is \
                         nothing to derive from. Load the wallet from its recovery \
                         phrase to see its v2 address.",
                    );
                } else {
                    let v2_state = PoolState::classify_v2(s.online, s.shielded_v2.as_ref());
                    v2_address_block(ui, &v2_addr, &v2_tag, v2_state, &mut did_copy);
                }
            } else {
                ui.horizontal(|ui| {
                    qr_widget(ui, &recv_addr, 132.0);
                    ui.vertical(|ui| {
                        if self.receive_kind == ReceiveKind::Shielded {
                            ui.label(
                                egui::RichText::new("✓ private — recommended receive address")
                                    .size(ty::SMALL)
                                    .color(named_color(true)),
                            );
                        }
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&recv_addr).monospace().size(ty::SMALL),
                            )
                            .wrap(),
                        );
                        if ui.button("Copy address").clicked() {
                            ui.output_mut(|o| o.copied_text = recv_addr.clone());
                            did_copy = true;
                        }
                    });
                });
            }

            // ── Send ──
            ui.separator();
            ui.label(egui::RichText::new("Send").strong().size(ty::SECTION));
            // One label-column width shared by every form row in the send flow
            // (transparent AND private), so the To / Amount fields start on the
            // same x even across the auction panel that sits between them.
            const SEND_LABEL_W: f32 = 84.0;
            // Spendable balance of the account we're sending FROM (the effective).
            let spendable: u128 = onchain.map(|a| a.balance.parse().unwrap_or(0)).unwrap_or(0);
            egui::Grid::new("send_to_form")
                .num_columns(2)
                .min_col_width(SEND_LABEL_W)
                .spacing([sp::L, sp::M])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("To").weak());
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.send_to).desired_width(420.0));
                        if ui.button("Shield to my pool").clicked() {
                            self.send_to = shielded.clone();
                            self.receive_kind = ReceiveKind::Shielded;
                        }
                    });
                    ui.end_row();
                });
            // Live route detection + self-send labelling.
            let route = SendRoute::detect(&self.send_to);
            // Owned, not a borrow of `self.send_to`: the auction panel below takes
            // `&mut self` to drive the tip field.
            let to_trim = self.send_to.trim().to_string();
            let to_trim = to_trim.as_str();
            let self_send = !to_trim.is_empty()
                && (to_trim == shielded
                    || to_trim == unified
                    || to_trim == account
                    || to_trim == effective);
            let (route_text, route_color) = route.label();
            if !route_text.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(route_text).small().color(route_color));
                    if self_send {
                        ui.label(
                            egui::RichText::new("· your own address")
                                .small()
                                .color(named_color(true)),
                        );
                    }
                });
            } else {
                ui.label(
                    egui::RichText::new("named account → transparent · xus1…/uxus1… → shielded")
                        .weak(),
                );
            }
            // Amount + Max + live validation. The network fee AND the auction tip are
            // RESERVED: a send must leave room for both (amount + fee + tip ≤ balance),
            // or the tx would fail execution ("cannot afford fee") and clog the mempool
            // while blocks come up empty.
            let base_fee = if route.private() {
                s.fee_shielded_grains
            } else {
                s.fee_transfer_grains
            };
            // ── Blockspace auction: the live floor, and this send's bid ──────────
            // Rendered BEFORE the amount field, because the tip changes what "Max"
            // means and a spender must see the price of blockspace before they
            // decide how much of their balance to commit.
            let tip = self.auction_controls(ui, &s.auction);
            // A tip is an ENVELOPE, and the envelope costs gas of its own — so the
            // fee this send is charged is not the bare route's fee once a tip is
            // attached. Reserving the bare figure would build a send that cannot
            // pay for itself (a hard `CannotAffordFee` reject).
            let fee = auction::route_fee_grains(base_fee, s.gas_price_grains, tip);
            // The most you can send while still covering the fee AND the tip.
            let sendable = auction::max_sendable_grains(spendable, fee, tip);
            let amount_grains = parse_xus(&self.send_amount);
            let amount_resp = egui::Grid::new("send_amount_form")
                .num_columns(2)
                .min_col_width(SEND_LABEL_W)
                .spacing([sp::L, sp::M])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Amount XUS").weak());
                    let r = ui
                        .horizontal(|ui| {
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut self.send_amount)
                                    .desired_width(160.0),
                            );
                            if ui
                                .button("Max")
                                .on_hover_text(
                                    "send the most that still leaves room for the network fee \
                                     and the tip",
                                )
                                .clicked()
                            {
                                self.send_amount = grains_to_xus_plain(sendable);
                            }
                            let note = match (fee, tip) {
                                (0, 0) => format!("balance {} XUS", xus(&spendable.to_string())),
                                (f, 0) => format!(
                                    "balance {} XUS · fee ~{} XUS",
                                    xus(&spendable.to_string()),
                                    xus(&f.to_string())
                                ),
                                (f, t) => format!(
                                    "balance {} XUS · fee ~{} + tip {} XUS",
                                    xus(&spendable.to_string()),
                                    xus(&f.to_string()),
                                    xus(&t.to_string())
                                ),
                            };
                            ui.label(egui::RichText::new(note).weak());
                            r
                        })
                        .inner;
                    ui.end_row();
                    r
                })
                .inner;
            let amount_err: Option<String> = match amount_grains {
                None if !self.send_amount.trim().is_empty() => {
                    Some("amount must be a number (e.g. 1.5)".to_string())
                }
                Some(0) => Some("amount must be greater than zero".to_string()),
                Some(g) if g > spendable => Some("amount exceeds your balance".to_string()),
                Some(g) if g > sendable => Some(format!(
                    "amount + network fee (~{} XUS){} exceeds your balance — lower it, lower the \
                     tip, or use Max",
                    xus(&fee.to_string()),
                    if tip > 0 {
                        format!(" + tip ({} XUS)", xus(&tip.to_string()))
                    } else {
                        String::new()
                    }
                )),
                _ => None,
            };
            // The full cost, once, in one place: what the recipient gets, what
            // consensus charges, what the bid costs, and what is left.
            if let Some(g) = amount_grains.filter(|g| *g > 0) {
                let cost = SendCost {
                    amount_grains: g,
                    fee_grains: fee,
                    tip_grains: tip,
                };
                ui.add_space(sp::XS);
                ui.label(
                    egui::RichText::new(format!(
                        "total {} XUS  ·  balance after {} XUS",
                        xus(&cost.total_grains().to_string()),
                        xus(&cost.balance_after(spendable).to_string())
                    ))
                    .size(ty::SMALL)
                    .color(if cost.affordable(spendable) {
                        palette::text_dim()
                    } else {
                        palette::error()
                    }),
                );
            }
            if let Some(e) = &amount_err {
                ui.label(
                    egui::RichText::new(format!("✗ {e}"))
                        .small()
                        .color(palette::error()),
                );
            }
            let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
            let can_send = route.is_valid()
                && matches!(amount_grains, Some(g) if g > 0 && g <= sendable)
                && !busy;
            // Pressing Enter in the amount field reviews the send (same as the button).
            let submit_enter =
                amount_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let mut review_clicked = false;
            ui.add_space(sp::S);
            // The one step forward, styled as THE primary action — the same filled
            // treatment as the modal's "Confirm & send", so the path reads as two
            // matching green steps: review, then confirm. Nothing is sent here.
            ui.add_enabled_ui(can_send, |ui| {
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("Review send →")
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(palette::accent()),
                    )
                    .clicked()
                {
                    review_clicked = true;
                }
            });
            if (review_clicked || submit_enter) && can_send {
                if let Some(g) = amount_grains {
                    new_pending = Some(PendingSend {
                        from_label: label.clone(),
                        from_account: effective.clone(),
                        to: to_trim.to_string(),
                        amount_grains: g,
                        from_balance_grains: spendable,
                        route_label: route.label().0,
                        self_send,
                        // Any transparent route puts sender, recipient, and amount
                        // on-chain in the clear — the privacy downgrade.
                        links_public: !route.private(),
                        source: SendSource::Transparent,
                        fee_grains: fee,
                        tip_grains: tip,
                    });
                }
            }
            if busy {
                ui.label(egui::RichText::new("working…").weak());
            }

            // Shielded pool: private balance (scanned by trial-decryption) + de-shield.
            ui.add_space(sp::L);
            ui.separator();
            ui.add_space(sp::M);
            // THIS wallet's scanned view, looked up by its own account — never
            // whatever was scanned last. An unscanned wallet yields the default
            // view (scanned_height 0), which renders as UNKNOWN, not zero.
            let sv = self
                .shielded
                .lock()
                .map(|m| m.view_for(&account))
                .unwrap_or_default();
            // Belt AND braces: the lookup already guarantees this entry is this
            // wallet's, and the stored account is re-checked before a single
            // figure is shown. Unscanned leaves it empty ⇒ not "for this wallet"
            // ⇒ nothing is claimed about a balance nobody has scanned.
            let for_this = sv.account == account;
            let snap = self.snapshot.lock().map(|s| s.clone()).unwrap_or_default();

            // BOTH pools, side by side, before any control that acts on either. An
            // operator has to be able to see which pool holds what — and which pool is
            // not live — before touching a button that moves value.
            //
            // `v1_own` is `Some` only when THIS wallet has actually been scanned; a
            // scan that has not run yields `None`, which the view renders as "unknown",
            // never as a zero balance.
            let v1_own = sv.own_figures(&account);
            // Likewise for pool v2: this wallet's own scanned v2 view, retained
            // across wallet switches, or its unscanned default.
            let v2v = self
                .shielded_v2
                .lock()
                .map(|m| m.view_for(&account))
                .unwrap_or_default();
            let v2_own = v2v.own_figures(&account);
            shielded_pools_view(ui, &snap, v1_own, v2_own);
            if sv.scanning {
                ui.add_space(sp::S);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        egui::RichText::new("scanning pool v1 by trial-decryption…")
                            .size(ty::SMALL)
                            .color(palette::text_dim()),
                    );
                });
            }
            // Pool v2 is only scannable when it is actually live; offering the
            // control while dormant would invite the conclusion that a zero
            // balance means "no funds" rather than "no pool yet".
            if matches!(
                PoolState::classify_v2(snap.online, snap.shielded_v2.as_ref()),
                PoolState::Active
            ) {
                ui.add_space(sp::S);
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!v2v.scanning && !busy, |ui| {
                        if ui
                            .button("Scan pool v2")
                            .on_hover_text(
                                "Trial-decapsulate this chain's pool-v2 notes with this \
                                 wallet's ML-KEM key. Slower than a v1 scan by design — a \
                                 post-quantum pool has no ECDH detection shortcut.",
                            )
                            .clicked()
                        {
                            do_scan_v2 = true;
                        }
                    });
                    if v2v.scanning {
                        ui.spinner();
                    }
                    if !v2v.message.is_empty() {
                        ui.label(
                            egui::RichText::new(&v2v.message)
                                .size(ty::SMALL)
                                .color(palette::text_dim()),
                        );
                    }
                });
            }

            ui.add_space(sp::L);
            ui.label(
                egui::RichText::new("Pool v1 — move value")
                    .size(ty::SECTION)
                    .strong(),
            );
            ui.add_space(sp::S);
            // De-shield a VARIABLE amount: move `amount` from the pool to this
            // account's transparent balance; any remainder stays shielded as change.
            // The amount is bounded by the wallet's shielded balance AND the node's
            // live per-window drain budget, both shown so the limit is never a
            // surprise (the de-shield circuit breaker is visible, not silent).
            let budget_now = snap.deshieldable_now;
            // The de-shieldable ceiling: the smaller of the scanned shielded balance
            // and the current window budget (a de-shield over budget would be mined
            // and rejected, so we never offer more than can actually go through now).
            let deshield_cap: u128 = match budget_now {
                Some(b) => (sv.balance as u128).min(b),
                None => sv.balance as u128,
            };
            let ds_grains = parse_xus(&self.deshield_amount);
            ui.horizontal(|ui| {
                if ui.button("Scan pool").clicked() {
                    do_scan = true;
                }
                // Recovery path: wipe this wallet's note-store cache and re-scan the whole
                // chain from its birthday. The cache is a rebuildable index; deleting it is
                // how a contaminated store (e.g. one written before the receipt-status filter)
                // is cleanly rebuilt from the canonical chain. Two-step confirm — destructive.
                ui.add_enabled_ui(!sv.scanning, |ui| {
                    if ui
                        .button("Rescan from scratch")
                        .on_hover_text(
                            "Delete this wallet's local note-store cache and re-scan the entire \
                             chain from its birthday. Safe (the cache is rebuildable) but slow.",
                        )
                        .clicked()
                    {
                        self.rescan_armed = true;
                    }
                });
                ui.label("De-shield XUS");
                ui.add(
                    egui::TextEdit::singleline(&mut self.deshield_amount)
                        .hint_text("amount")
                        .desired_width(140.0),
                );
                ui.add_enabled_ui(deshield_cap > 0, |ui| {
                    if ui
                        .button("Max")
                        .on_hover_text("de-shield the most allowed right now (balance, capped by the window budget)")
                        .clicked()
                    {
                        self.deshield_amount = grains_to_xus_plain(deshield_cap);
                    }
                });
                let ds_ok = for_this
                    && sv.notes > 0
                    && !sv.scanning
                    && !busy
                    && matches!(ds_grains, Some(g) if g > 0 && g <= deshield_cap);
                ui.add_enabled_ui(ds_ok, |ui| {
                    if ui.button("De-shield").clicked() {
                        do_deshield = true;
                    }
                });
            });
            // Confirmation for the destructive "Rescan from scratch": deleting the cache is
            // safe (rebuildable) but a full re-scan is expensive, so require an explicit OK.
            if self.rescan_armed {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        palette::warning(),
                        "Delete this wallet's note-store cache and re-scan the whole chain?",
                    );
                    if ui.button("Confirm rescan").clicked() {
                        self.rescan_armed = false;
                        do_rescan = true;
                    }
                    if ui.button("Cancel").clicked() {
                        self.rescan_armed = false;
                    }
                });
            }
            // Show the live budget so the per-window drain limit is transparent — and,
            // when the window cap (not the balance) is the binding constraint, say so
            // LOUDLY with when it resets, so a limited/0 Max never reads as a broken
            // wallet (this is the de-shield circuit breaker, working as designed).
            if for_this {
                match budget_now {
                    Some(b) => {
                        // Reset as a time estimate (height delta × block time), not a raw height.
                        let reset_str = match (snap.deshield_resets_at, snap.height) {
                            (Some(r), Some(h)) if r > h && snap.target_block_ms > 0 => {
                                let secs = (r - h) * snap.target_block_ms / 1000;
                                if secs >= 60 {
                                    format!(" — resets in ~{} min (block {r})", secs / 60)
                                } else {
                                    format!(" — resets in ~{secs}s (block {r})")
                                }
                            }
                            (Some(r), _) => format!(" — resets at block {r}"),
                            _ => String::new(),
                        };
                        if b < sv.balance as u128 {
                            // The per-window cap, not the balance, is the limit right now.
                            let of_limit = snap
                                .deshield_limit
                                .filter(|l| *l > 0)
                                .map(|l| format!(" of {} XUS/window", grains_to_xus_plain(l)))
                                .unwrap_or_default();
                            ui.label(
                                egui::RichText::new(format!(
                                    "⏳ De-shield rate-limited — up to {} XUS{} de-shieldable now{}. \
                                     Your {} XUS pool balance exceeds the per-window cap, so de-shield \
                                     in batches. (Private shielded → shielded sends are NOT limited.)",
                                    grains_to_xus_plain(deshield_cap),
                                    of_limit,
                                    reset_str,
                                    xus(&sv.balance.to_string()),
                                ))
                                .small()
                                .color(palette::warning()),
                            );
                        } else {
                            let cap_note = snap
                                .deshield_limit
                                .filter(|l| *l > 0)
                                .map(|l| format!("; per-window cap {} XUS", grains_to_xus_plain(l)))
                                .unwrap_or_default();
                            ui.label(
                                egui::RichText::new(format!(
                                    "de-shieldable now: up to {} XUS (balance {} XUS{})",
                                    grains_to_xus_plain(deshield_cap),
                                    xus(&sv.balance.to_string()),
                                    cap_note,
                                ))
                                .small()
                                .weak(),
                            );
                        }
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "de-shield moves a variable amount to this account (transparent); change stays shielded",
                            )
                            .small()
                            .weak(),
                        );
                    }
                }
            }

            // ── Send privately (shielded → shielded): sender, recipient, and
            // amount ALL hidden. Spends this wallet's scanned notes; private change
            // returns to the wallet.
            //
            // The POOL is chosen here, explicitly. It used to be inferred from the
            // recipient's address prefix, which meant the single most consequential
            // property of a private payment — whether its privacy survives a
            // quantum adversary — was decided by whatever string got pasted. The
            // selector makes it a decision. ──
            ui.add_space(sp::L);
            ui.separator();
            ui.add_space(sp::M);
            ui.label(
                egui::RichText::new("Send privately — choose a pool")
                    .size(ty::SECTION)
                    .strong(),
            );
            ui.label(
                egui::RichText::new(
                    "A private send spends notes from ONE shielded pool. The pools are separate \
                     value spaces with different cryptography — choose the pool, then paste an \
                     address from that pool. Sender, recipient, and amount are hidden either way.",
                )
                .weak(),
            );
            ui.add_space(sp::S);

            let v2_state = PoolState::classify_v2(snap.online, snap.shielded_v2.as_ref());
            // ONE guard for every pool-v2 decision on this tab, built once from the
            // observed facts. `pool_active` is the classified state, never a
            // hard-coded `true` — so a selector left on v2 when the pool is not
            // Active is refused by the same pure function that gates shield and
            // de-shield, rather than by a second rule written here.
            let v2_guard = v2v.guard(
                &account,
                v2_state == PoolState::Active,
                busy,
                snap.shielded_v2.as_ref().map(|i| i.deshieldable_now),
            );
            // The operator's choice FOR THIS WALLET. `chosen_for` drops a choice
            // made for a different wallet before a single control is drawn, so a
            // wallet switch can never leave someone else's pool armed.
            let chosen = self.pool_selection.chosen_for(&account);

            // The selector itself. Both options are always VISIBLE — hiding v2
            // while it is dormant would leave an operator unable to learn that a
            // post-quantum pool exists — but v2 is selectable only when consensus
            // will actually accept a v2 spend, and the reason is stated beneath it
            // rather than left to a greyed-out control to imply.
            //
            // NOTHING is pre-selected. `Option<Pool>` rather than `Pool` is the
            // whole mechanism: there is no value the app can supply on the
            // operator's behalf, so a private send cannot be completed by someone
            // who never looked at this control.
            let v2_selectable = v2_state == PoolState::Active;
            let mut pick = chosen;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut pick, Some(Pool::V1), Pool::V1.selector_label())
                    .on_hover_text(
                        "Zcash Orchard / Halo2, live since genesis. Its hiding is discrete-log \
                         based: a future quantum adversary who recorded this chain could break \
                         the privacy of a payment you make today (harvest now, decrypt later).",
                    );
                ui.add_enabled_ui(v2_selectable, |ui| {
                    ui.selectable_value(
                        &mut pick,
                        Some(Pool::V2),
                        format!("{} {}", Pool::V2.selector_label(), v2_state.glyph()),
                    )
                    .on_hover_text(
                        "ML-KEM-768 note carriers with a STARK spend proof — no discrete-log \
                         assumption, so the privacy of a payment made today is not retroactively \
                         breakable. Slower to build (~25 s to prove).",
                    );
                });
            });
            if pick != chosen {
                if let Some(p) = pick {
                    self.pool_selection.choose(p, &account);
                }
            }
            let chosen = pick;
            if !v2_selectable {
                ui.label(
                    egui::RichText::new(format!("{} {V2_DORMANT_REASON}", v2_state.glyph()))
                        .small()
                        .color(palette::warning()),
                );
            }

            // WHAT IS ARMED — the single authority, restated in words and shapes.
            // A v2 choice on a chain where v2 is not Active resolves to "nothing
            // armed", never to a quiet fall-back to v1: handing someone the
            // non-post-quantum pool because the post-quantum one was unavailable
            // would give them the exact property they were trying to avoid.
            let armed = armed_pool(chosen, v2_state);
            ui.add_space(sp::S);
            arm_banner(ui, armed);

            // No pool chosen ⇒ no form at all. An operator must not be able to
            // fill in a recipient and an amount and only then discover which pool
            // it was going to come out of.
            if chosen.is_none() {
                ui.add_space(sp::S);
                empty_hint(
                    ui,
                    "Choose a pool before you can send privately",
                    "The two shielded pools use different cryptography and only Pool v2 is \
                     post-quantum. Nothing is pre-selected, because which pool your payment \
                     leaves decides whether its privacy survives a future quantum adversary — \
                     that is your choice to make, not this app's. Pick one above.",
                );
            }
            if let Some(sel) = chosen {
                // The consequence of the choice, stated before the form: which pool is
                // about to be spent from, what it costs in privacy terms, and how much
                // is actually in it.
                ui.add_space(sp::S);
                let sel_balance: u128 = match sel {
                    Pool::V1 => sv.balance as u128,
                    Pool::V2 => v2v.balance as u128,
                };
                let sel_state = match sel {
                    Pool::V1 => {
                        PoolState::classify_v1(snap.online, for_this && sv.scanned_height > 0)
                    }
                    Pool::V2 => v2_state,
                };
                // A balance is shown ONLY when this wallet's notes in that pool have
                // actually been scanned. An unscanned pool has an UNKNOWN balance, and
                // rendering a bare `0` beside the word "balance" is exactly how an
                // operator concludes their funds are gone — so the state word replaces
                // the figure rather than sitting next to a misleading one.
                let sel_balance_text = match sel_state {
                    PoolState::Active => format!("{} XUS scanned", xus(&sel_balance.to_string())),
                    PoolState::Dormant => format!("{} — no notes can exist yet", sel_state.word()),
                    PoolState::Unavailable => format!("{} — balance unknown", sel_state.word()),
                };
                ui.label(
                    egui::RichText::new(format!(
                        "spending from {} · {} · {} — {} {sel_balance_text}",
                        sel.name(),
                        sel.crypto(),
                        sel.pq_claim(),
                        sel_state.glyph(),
                    ))
                    .small()
                    .color(match sel {
                        Pool::V1 => palette::warning(),
                        Pool::V2 => palette::success(),
                    }),
                );

                // The recipient must belong to the SELECTED pool. A cross-pool paste
                // names the pool it actually belongs to and the one action that fixes
                // it — never a generic "invalid".
                let priv_to_field = match sel {
                    Pool::V1 => &mut self.private_to,
                    Pool::V2 => &mut self.private_v2_to,
                };
                // The same aligned label column as the transparent form above, so
                // the private To / Amount fields sit on the identical x — one form
                // language for the whole send flow.
                egui::Grid::new("priv_send_form")
                    .num_columns(2)
                    .min_col_width(SEND_LABEL_W)
                    .spacing([sp::L, sp::M])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("To").weak());
                        ui.add(
                            egui::TextEdit::singleline(priv_to_field)
                                .hint_text(format!(
                                    "{} (recipient stays private)",
                                    sel.address_hint()
                                ))
                                .desired_width(420.0),
                        );
                        ui.end_row();
                    });
                let priv_to_text = match sel {
                    Pool::V1 => self.private_to.clone(),
                    Pool::V2 => self.private_v2_to.clone(),
                };
                let recipient_check = pool_recipient_check(sel, &priv_to_text);
                if !priv_to_text.trim().is_empty() {
                    if let Err(why) = recipient_check {
                        ui.label(
                            egui::RichText::new(format!("✗ {why}"))
                                .small()
                                .color(palette::error()),
                        );
                    }
                }

                let priv_amount_field = match sel {
                    Pool::V1 => &mut self.private_amount,
                    Pool::V2 => &mut self.private_v2_amount,
                };
                let mut set_max = false;
                egui::Grid::new("priv_amount_form")
                    .num_columns(2)
                    .min_col_width(SEND_LABEL_W)
                    .spacing([sp::L, sp::M])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Amount XUS").weak());
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(priv_amount_field).desired_width(160.0),
                            );
                            if ui
                                .button("Max")
                                .on_hover_text(
                                    "send your full scanned balance in the selected pool",
                                )
                                .clicked()
                            {
                                set_max = true;
                            }
                            // The scanned balance of the ARMED pool, beside the field
                            // that spends it — the figure the decision is made against.
                            ui.label(
                                egui::RichText::new(sel_balance_text.clone())
                                    .size(ty::SMALL)
                                    .color(palette::text_dim()),
                            );
                        });
                        ui.end_row();
                    });
                if set_max {
                    match sel {
                        Pool::V1 => self.private_amount = grains_to_xus_plain(sel_balance),
                        Pool::V2 => self.private_v2_amount = grains_to_xus_plain(sel_balance),
                    }
                }
                let priv_grains = parse_xus(match sel {
                    Pool::V1 => &self.private_amount,
                    Pool::V2 => &self.private_v2_amount,
                });

                // Whether the send may proceed, per pool. v1 keeps its existing
                // conditions; v2 defers ENTIRELY to `v2_allows`, the same pure function
                // that gates shield and de-shield — no second copy of that judgement.
                // Both are then run through `private_send_dispatch`, which is what the
                // submit path re-checks, so render and submit agree by construction.
                let (priv_ok, priv_reason): (bool, String) = match sel {
                    Pool::V1 => {
                        let ok = for_this
                            && recipient_check.is_ok()
                            && matches!(priv_grains, Some(g) if g > 0 && g <= sv.balance as u128)
                            && !sv.scanning
                            && !busy;
                        // Tell the user EXACTLY what's blocking the button. You do NOT
                        // need to de-shield to send privately — a private send spends
                        // your shielded notes directly.
                        let why: String = if w_watch_only {
                            "watch-only wallet — cannot send".into()
                        } else if sv.scanning {
                            "scanning the pool…".into()
                        } else if !for_this || sv.scanned_height == 0 {
                            "loading your shielded balance…".into()
                        } else if sv.balance == 0 {
                            "no pool-v1 funds yet — use “Shield to pool” above to move XUS in (you do \
                         NOT need to de-shield to send privately)"
                            .into()
                        } else if let Err(r) = recipient_check {
                            r.into()
                        } else if !matches!(priv_grains, Some(g) if g > 0) {
                            "enter an amount".into()
                        } else if matches!(priv_grains, Some(g) if g > sv.balance as u128) {
                            "amount exceeds your pool-v1 balance".into()
                        } else {
                            String::new()
                        };
                        (ok, why)
                    }
                    Pool::V2 => {
                        let verdict = v2_allows(
                            &v2_guard,
                            V2Intent::Send {
                                to: &priv_to_text,
                                amount: priv_grains,
                            },
                        );
                        let dispatch = private_send_dispatch(sel, v2_state);
                        let why: String = if w_watch_only {
                            "watch-only wallet — cannot send".into()
                        } else if let Err(r) = dispatch {
                            r.into()
                        } else if let Err(r) = verdict {
                            // The selector-aware cross-pool wording wins over the
                            // generic one when both apply — same refusal, more
                            // actionable sentence.
                            match recipient_check {
                                Err(c) if !priv_to_text.trim().is_empty() => c.into(),
                                _ => r.into(),
                            }
                        } else {
                            String::new()
                        };
                        (verdict.is_ok() && dispatch.is_ok(), why)
                    }
                };
                let priv_ok = priv_ok && armed.is_ok();
                if !priv_ok && !priv_reason.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("→ {priv_reason}"))
                            .small()
                            .color(palette::warning()),
                    );
                }
                // The armed pool restated IMMEDIATELY above the button that acts on
                // it. The statement at the top of the section can be scrolled off; the
                // one adjacent to the control cannot be missed by anyone about to
                // click it. Same sentence, same shapes — one source, rendered twice.
                ui.add_space(sp::S);
                arm_banner(ui, armed);
                ui.add_enabled_ui(priv_ok, |ui| {
                    // Primary-styled like the transparent "Review send →" and the
                    // modal's confirm — one visual language for "the step forward".
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Review private send →")
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(palette::accent()),
                        )
                        .clicked()
                    {
                        // EVERY condition re-decided at click time, not inherited from
                        // paint: what is armed, and whether the recipient belongs to
                        // the armed pool. Both can go stale between the two.
                        let to = priv_to_text.trim().to_string();
                        match (priv_grains, armed_pool(chosen, v2_state)) {
                            (Some(g), Ok(dispatch_pool)) => {
                                if let Err(why) = pool_recipient_check(dispatch_pool, &to) {
                                    self.set_action(why);
                                } else {
                                    let self_send = match dispatch_pool {
                                        Pool::V1 => to == shielded || to == unified,
                                        Pool::V2 => to == v2_addr,
                                    };
                                    new_pending = Some(PendingSend {
                                        from_label: label.clone(),
                                        from_account: effective.clone(),
                                        to,
                                        amount_grains: g,
                                        from_balance_grains: sel_balance,
                                        route_label: format!(
                                            "{} → {} · {} (fully private)",
                                            dispatch_pool.name(),
                                            dispatch_pool.name(),
                                            dispatch_pool.crypto(),
                                        ),
                                        self_send,
                                        links_public: false,
                                        source: SendSource::Pool(dispatch_pool),
                                        // A pool spend pays the fee from the
                                        // transparent account that carries it; tips are
                                        // not wired on this route yet, so the bid is
                                        // honestly zero rather than a number the send
                                        // would not actually carry.
                                        fee_grains: s.fee_shielded_grains,
                                        tip_grains: 0,
                                    });
                                }
                            }
                            (_, Err(why)) => self.set_action(why),
                            _ => {}
                        }
                    }
                });
            }

            // ── Pool v2 (post-quantum) — shield in / de-shield out ────────────
            // Shown only when bit 2 is live. Offering these while dormant would
            // invite a user to spend ~25 s proving a transaction every node will
            // reject; the state chip in the table above already explains why the
            // pool is not usable yet.
            //
            // The pool-v2 PRIVATE SEND is not here — it lives in the pool selector
            // above, alongside its v1 counterpart, because the two are the same
            // operation in different pools and choosing between them is the point.
            if v2_state == PoolState::Active {
                ui.add_space(sp::L);
                ui.label(
                    egui::RichText::new("Pool v2 — shield in / de-shield out (post-quantum)")
                        .size(ty::SECTION)
                        .strong(),
                );
                // The cost of a v2 move, stated IN the panel rather than buried in a
                // hover tooltip: every shield/de-shield builds a real STARK proof, and
                // ~25 s of silence after a click reads as a frozen app to anyone who
                // was not told to expect it.
                ui.label(
                    egui::RichText::new(
                        "⏱ Each move builds a real STARK proof — expect ~25 s of proving \
                         before it broadcasts.",
                    )
                    .size(ty::SMALL)
                    .color(palette::text_dim()),
                );
                ui.add_space(sp::S);
                // Every decision below comes from ONE pure function, through the
                // SAME guard the private-send selector uses. The UI gathers facts
                // and renders; it never decides on its own.
                let guard = v2_guard;

                // Render a control from a guard verdict: enabled ONLY on Ok,
                // and the refusal reason shown verbatim beneath it.
                let mut verdicts: Vec<&'static str> = Vec::new();

                // SHIELD IN — spends no notes, so it needs no scan.
                let shield_v = v2_allows(
                    &guard,
                    V2Intent::Shield {
                        to: &self.shield_v2_to,
                        amount: parse_xus(&self.shield_v2_amount_in),
                    },
                );
                // DE-SHIELD OUT — bounded by balance AND the window budget.
                let deshield_v = v2_allows(
                    &guard,
                    V2Intent::Deshield {
                        amount: parse_xus(&self.deshield_v2_amount_in),
                    },
                );
                let v2_cap = guard.deshield_cap();

                // ONE aligned two-column form — label column, control column — so
                // every input and button lands on a shared x whatever its label says.
                // This replaces a stack of ad-hoc horizontals whose fields drifted
                // with their label widths (one row was literally indented with a
                // "  to" spaces-as-layout label). The balance each row draws on is
                // shown BESIDE its field: the decision is made here, so the fact
                // that informs it lives here too.
                egui::Grid::new("v2_move_form")
                    .num_columns(2)
                    .spacing([sp::L, sp::M])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Shield in").weak());
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.shield_v2_amount_in)
                                    .hint_text("amount")
                                    .desired_width(140.0),
                            );
                            ui.add_enabled_ui(shield_v.is_ok(), |ui| {
                                if ui
                                    .button("Shield →")
                                    .on_hover_text(
                                        "Move transparent value into the post-quantum pool. \
                                         Builds a real STARK proof (~25 s).",
                                    )
                                    .clicked()
                                {
                                    do_shield_v2 = true;
                                }
                            });
                            // What a shield can draw on. No Max here on purpose: the
                            // network fee comes out of the same transparent balance on
                            // top of the amount, so "all of it" is not a buildable
                            // transaction — an honest figure beats a misleading button.
                            ui.label(
                                egui::RichText::new(format!(
                                    "from transparent balance {} XUS",
                                    xus(&spendable.to_string())
                                ))
                                .size(ty::SMALL)
                                .color(palette::text_dim()),
                            );
                        });
                        ui.end_row();

                        ui.label(egui::RichText::new("Recipient").weak());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.shield_v2_to)
                                .hint_text("xusq1… (blank = yourself)")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("De-shield out").weak());
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.deshield_v2_amount_in)
                                    .hint_text("amount")
                                    .desired_width(140.0),
                            );
                            ui.add_enabled_ui(v2_cap > 0, |ui| {
                                if ui
                                    .button("Max")
                                    .on_hover_text(
                                        "the most allowed right now (balance, capped by the window budget)",
                                    )
                                    .clicked()
                                {
                                    self.deshield_v2_amount_in = grains_to_xus_plain(v2_cap);
                                }
                            });
                            ui.add_enabled_ui(deshield_v.is_ok(), |ui| {
                                if ui.button("De-shield").clicked() {
                                    do_deshield_v2 = true;
                                }
                            });
                            // The pool balance this spends — or an honest "unknown"
                            // when this wallet's v2 notes have not been scanned. A
                            // bare zero beside the field is exactly how an operator
                            // concludes their funds are gone.
                            let ctx_text = if guard.scanned {
                                if v2_cap < guard.balance_grains {
                                    format!(
                                        "up to {} XUS now (window cap) of {} XUS in pool",
                                        grains_to_xus_plain(v2_cap),
                                        xus(&guard.balance_grains.to_string())
                                    )
                                } else {
                                    format!(
                                        "pool balance {} XUS",
                                        xus(&guard.balance_grains.to_string())
                                    )
                                }
                            } else {
                                "pool balance unknown — scan pool v2 first".to_string()
                            };
                            ui.label(
                                egui::RichText::new(ctx_text)
                                    .size(ty::SMALL)
                                    .color(palette::text_dim()),
                            );
                        });
                        ui.end_row();
                    });
                if let Err(r) = shield_v {
                    if !self.shield_v2_amount_in.trim().is_empty() {
                        verdicts.push(r);
                    }
                }
                if let Err(r) = deshield_v {
                    verdicts.push(r);
                }

                // The in-progress state, IN the panel: while a proof is being built
                // the spinner and the worker's own message sit beside the buttons
                // that started it, so ~25 s of proving never reads as a hang.
                if guard.busy {
                    let act_msg = self
                        .action
                        .lock()
                        .map(|a| a.message.clone())
                        .unwrap_or_default();
                    ui.add_space(sp::S);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new(if act_msg.is_empty() {
                                "working…".to_string()
                            } else {
                                act_msg
                            })
                            .size(ty::SMALL)
                            .color(palette::text_dim()),
                        );
                    });
                }

                // PRIVATE SEND lives in the pool selector above — see the note at
                // the head of this section.
                ui.add_space(sp::S);
                ui.label(
                    egui::RichText::new(
                        "To send privately WITHIN pool v2, use “Send privately — choose a pool” \
                         above and select Pool v2.",
                    )
                    .small()
                    .weak(),
                );

                // One reason at a time, the most fundamental first — a wall of
                // warnings teaches a user to ignore all of them.
                if let Some(r) = verdicts.first() {
                    ui.label(
                        egui::RichText::new(format!("→ {r}"))
                            .small()
                            .color(palette::warning()),
                    );
                }
            }

            // ── Offline / air-gapped signing (cold reserves) ──────────────────
            ui.add_space(6.0);
            egui::CollapsingHeader::new("🔌 Offline / air-gapped signing").show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Keep keys off the network. Build an UNSIGNED tx here, carry it to the \
                         air-gapped machine to SIGN, then BROADCAST the signed result from an \
                         online node. A watch-only wallet can do step 1 and 3.",
                    )
                    .weak()
                    .small(),
                );
                // 1. Build unsigned (online / watch-only).
                ui.label(egui::RichText::new("1 · Build unsigned transfer").strong());
                ui.horizontal(|ui| {
                    ui.label("To");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ofl_to)
                            .hint_text("recipient account id")
                            .desired_width(360.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Amount XUS");
                    ui.add(egui::TextEdit::singleline(&mut self.ofl_amount).desired_width(120.0));
                    if ui.button("Build unsigned").clicked() {
                        do_build_unsigned = true;
                    }
                });
                if !self.ofl_unsigned.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.ofl_unsigned)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("Copy unsigned").clicked() {
                        ui.output_mut(|o| o.copied_text = self.ofl_unsigned.clone());
                        did_copy = true;
                    }
                }
                ui.separator();
                // 2. Sign (offline machine that holds the seed).
                ui.label(egui::RichText::new("2 · Sign (machine with the seed)").strong());
                ui.add(
                    egui::TextEdit::multiline(&mut self.ofl_sign_in)
                        .hint_text("paste the unsigned tx JSON here")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button("Sign").clicked() {
                    do_sign_offline = true;
                }
                if !self.ofl_signed.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.ofl_signed)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("Copy signed").clicked() {
                        ui.output_mut(|o| o.copied_text = self.ofl_signed.clone());
                        did_copy = true;
                    }
                }
                ui.separator();
                // 3. Broadcast (online node).
                ui.label(egui::RichText::new("3 · Broadcast (online node)").strong());
                ui.add(
                    egui::TextEdit::multiline(&mut self.ofl_broadcast_in)
                        .hint_text("paste the signed tx JSON here")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button("Broadcast").clicked() {
                    do_broadcast = true;
                }
                if !self.ofl_msg.is_empty() {
                    status_label(ui, &self.ofl_msg);
                }
            });
        }

        // A freshly-reviewed send opens the confirmation modal.
        if new_pending.is_some() {
            self.pending_send = new_pending;
        }
        // ── Send confirmation modal (review before broadcast) ──
        if let Some(p) = self.pending_send.clone() {
            let ctx = ui.ctx().clone();
            let network = self.network;
            egui::Window::new(egui::RichText::new("Review transaction").strong())
                .collapsible(false)
                .resizable(false)
                .default_width(450.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.set_max_width(450.0);
                    // Hero amount + privacy state — the two things that matter most.
                    // The amount is the modal's ONE hero figure, on the type ladder.
                    ui.add_space(sp::XS);
                    ui.horizontal(|ui| {
                        ui.label(
                            num(xus(&p.amount_grains.to_string()))
                                .size(ty::HERO)
                                .strong()
                                .color(palette::text()),
                        );
                        ui.label(
                            egui::RichText::new("XUS")
                                .size(ty::SECTION)
                                .color(palette::text_dim()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if p.links_public {
                                pill(ui, "PUBLIC", palette::warning());
                            } else {
                                pill(ui, "PRIVATE", palette::success());
                            }
                            // The post-quantum status as a WORD, beside the
                            // privacy pill. "PRIVATE" alone is the dangerous
                            // half-truth — private against whom, and for how
                            // long, is what the pool decides.
                            if let Some(pool) = p.pool() {
                                pill(
                                    ui,
                                    pool.pq_badge(),
                                    match pool {
                                        Pool::V1 => palette::warning(),
                                        Pool::V2 => palette::success(),
                                    },
                                );
                            }
                        });
                    });
                    // The source, stated where it cannot be missed and in terms
                    // that decide the durability of this payment's privacy. Read
                    // straight off `SendSource`, which is total — every reachable
                    // confirm screen carries this line, pool or transparent.
                    ui.add_space(sp::M);
                    ui.label(
                        egui::RichText::new(p.source.confirm_line())
                            .strong()
                            .monospace()
                            .color(match p.pool() {
                                Some(Pool::V1) => palette::warning(),
                                Some(Pool::V2) => palette::success(),
                                None => palette::warning(),
                            }),
                    );
                    ui.add_space(sp::L);
                    egui::Grid::new("confirm_grid")
                        .num_columns(2)
                        .spacing([16.0, 8.0])
                        .show(ui, |ui| {
                            kv(
                                ui,
                                "From",
                                &format!("{} · {}", p.from_label, short_id(&p.from_account)),
                            );
                            // Recipient, monospace + wrapped so it never overflows. A
                            // pool-v2 xusq1… address carries an ML-KEM key (~1.2 KiB)
                            // and is NEVER rendered raw — head…tail elision, the same
                            // rule as everywhere else it appears.
                            let to_display = if p.to.starts_with("xusq1") {
                                truncate_middle(&p.to, 22, 12)
                            } else {
                                p.to.clone()
                            };
                            ui.label(egui::RichText::new("To").weak());
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(to_display).monospace().size(ty::SMALL),
                                )
                                .wrap(),
                            );
                            ui.end_row();
                            kv(ui, "Route", &p.route_label);
                            // WHICH pool moves, and whether its privacy is
                            // post-quantum, as a named row as well as the banner
                            // below — so it is present both where the eye scans
                            // for facts and where it cannot be skipped.
                            if let Some(pool) = p.pool() {
                                kv(
                                    ui,
                                    "Pool",
                                    &format!(
                                        "{} {} · {} · {}",
                                        pool.glyph(),
                                        pool.name(),
                                        pool.crypto(),
                                        pool.pq_claim()
                                    ),
                                );
                            }
                            kv(
                                ui,
                                "Network",
                                &format!("{} · {}", network.label(), network.pow_algo()),
                            );
                            // The EXACT cost, in the three parts a spender must be
                            // able to tell apart: the network fee consensus charges
                            // (`sov_estimateFee`), the blockspace bid they chose,
                            // and the resulting balance. Both were captured when
                            // Review was clicked, so this modal shows precisely the
                            // numbers about to be signed.
                            let cost = SendCost {
                                amount_grains: p.amount_grains,
                                fee_grains: p.fee_grains,
                                tip_grains: p.tip_grains,
                            };
                            let fee_str = if cost.fee_grains == 0 {
                                "0 XUS  ·  no network fee".to_string()
                            } else {
                                format!("{} XUS", xus(&cost.fee_grains.to_string()))
                            };
                            kv(ui, "Network fee", &fee_str);
                            let tip_str = if cost.tip_grains == 0 {
                                "0 XUS  ·  no bid (blockspace is free right now)".to_string()
                            } else {
                                format!(
                                    "{} XUS  ·  paid to the miner who includes it",
                                    xus(&cost.tip_grains.to_string())
                                )
                            };
                            kv(ui, "Blockspace tip", &tip_str);
                            // The bottom line, WEIGHTED as the bottom line: total
                            // cost and the balance it leaves are the two figures a
                            // spender confirms against, so they carry the emphasis
                            // the per-part rows above them do not.
                            ui.label(egui::RichText::new("Total cost").weak());
                            ui.label(
                                num(format!("{} XUS", xus(&cost.total_grains().to_string())))
                                    .strong(),
                            );
                            ui.end_row();
                            ui.label(egui::RichText::new("Balance after").weak());
                            ui.label(
                                num(format!(
                                    "{} XUS",
                                    xus(&cost.balance_after(p.from_balance_grains).to_string())
                                ))
                                .strong(),
                            );
                            ui.end_row();
                        });
                    ui.add_space(sp::M);
                    // Privacy + self-send context.
                    if p.links_public {
                        ui.colored_label(
                            palette::warning(),
                            "⚠ Public — sender, recipient, and amount are visible on-chain. Send \
                             to a xus1…/uxus1… address to keep it private.",
                        );
                    } else {
                        ui.colored_label(
                            palette::success(),
                            "🛡 Private — recipient and amount are shielded on-chain.",
                        );
                    }
                    if p.self_send {
                        ui.colored_label(
                            palette::text_dim(),
                            "↩ This is one of your own addresses.",
                        );
                    }
                    ui.add_space(sp::L);
                    ui.separator();
                    ui.add_space(sp::S);
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("✓ Confirm & send")
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(palette::accent()),
                            )
                            .clicked()
                        {
                            // A pool spend (sender hidden) goes through the shielded
                            // path OF THE POOL THE OPERATOR SELECTED — the two pools
                            // are different circuits, so the pool travels with the
                            // pending send rather than being re-inferred here. Every
                            // other route goes through the transparent/shield send.
                            match p.source {
                                SendSource::Pool(Pool::V2) => do_send_v2 = true,
                                SendSource::Pool(Pool::V1) => do_private_send = true,
                                SendSource::Transparent => {
                                    do_send = true;
                                    confirmed_tip_grains = p.tip_grains;
                                }
                            }
                            // DISARM. The choice was made for THIS payment; the
                            // next one gets made deliberately too, rather than
                            // inheriting a pool nobody re-examined.
                            if p.is_pool_spend() {
                                self.pool_selection.clear();
                            }
                            self.pending_send = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_send = None;
                        }
                    });
                });
        }

        // This session's sends, each with a BUMP for anything still pooled — the
        // lever that makes "stuck below the floor" a recoverable state instead of
        // an indefinite wait.
        self.pending_sends_view(ui, &ctx, &s.auction);

        // Action status — a spinner while broadcasting, then a green (success) or red
        // (failure) banner so the result of a sent transaction is unmistakable.
        ui.add_space(8.0);
        let (busy, msg) = self
            .action
            .lock()
            .map(|a| (a.busy, a.message.clone()))
            .unwrap_or((false, String::new()));
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                if !msg.is_empty() {
                    ui.label(egui::RichText::new(&msg).color(palette::text_dim()));
                }
            });
        } else {
            status_banner(ui, &msg);
        }

        // Activity feed — a running history of submitted actions, each line timestamped
        // and colored by outcome (green = succeeded, red = failed). Open by default so
        // you can always see what just happened.
        let log = self.activity.lock().map(|l| l.clone()).unwrap_or_default();
        if !log.is_empty() {
            ui.add_space(4.0);
            egui::CollapsingHeader::new(format!("Recent activity ({})", log.len()))
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("activity_log")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            for line in &log {
                                let (time, body) =
                                    line.split_once('\t').unwrap_or(("", line.as_str()));
                                let col = status_color(tx_status(body));
                                ui.horizontal_wrapped(|ui| {
                                    if !time.is_empty() {
                                        ui.label(
                                            egui::RichText::new(time)
                                                .monospace()
                                                .size(11.0)
                                                .color(palette::text_dim()),
                                        );
                                    }
                                    ui.label(
                                        egui::RichText::new(body).monospace().size(11.0).color(col),
                                    );
                                });
                            }
                        });
                    if ui.button("Clear").clicked() {
                        if let Ok(mut l) = self.activity.lock() {
                            l.clear();
                        }
                    }
                });
        }

        // Encrypted keystore — wallets survive restart (Argon2id + ChaCha20-Poly1305).
        ui.separator();
        ui.label(egui::RichText::new("Wallet file (encrypted keystore)").strong());
        ui.label(
            egui::RichText::new(
                "Save persists ALL wallets (keys + recovery phrases) to an encrypted file \
                 (Argon2id + ChaCha20-Poly1305) so they survive restart. Load restores them under \
                 the same passphrase.",
            )
            .weak(),
        );
        if let Ok(path) = keystore_path() {
            ui.label(egui::RichText::new(format!("file: {}", path.display())).weak());
        }
        // `do_save` is declared at the top of STATE 3 (the unsaved banner can set it).
        let mut do_load = false;
        ui.horizontal(|ui| {
            ui.label("Passphrase");
            ui.add(
                egui::TextEdit::singleline(&mut self.keystore_pass)
                    .password(true)
                    .desired_width(180.0),
            );
            if ui.button("Save wallets").clicked() {
                do_save = true;
            }
            if ui.button("Load wallets").clicked() {
                do_load = true;
            }
        });
        if !self.keystore_msg.is_empty() {
            status_label(ui, &self.keystore_msg);
        }

        // Dispatch collected actions (after the UI borrows end).
        if let Some(i) = select {
            if i != self.selected {
                // Switching wallets resets per-wallet UI so an action can never
                // land on the wrong account: clear the rename box, disarm forget,
                // and drop any "operate as" link from the previous wallet's view.
                self.selected = i;
                self.rename_field.clear();
                self.forget_armed = false;
                self.forget_confirm.clear();
                self.reveal_phrase = false;
                self.operate_msg.clear();
            }
        }
        if do_rename {
            self.rename_selected();
        }
        if do_forget {
            self.forget_selected();
        }
        if do_generate {
            self.generate_wallet();
        }
        if do_import {
            self.import_wallet();
        }
        if do_add_watch {
            self.add_watch_only();
        }
        if do_set_operate {
            self.set_operate_as();
        }
        if do_clear_operate {
            self.clear_operate_as();
        }
        if do_register_named {
            self.register_named(&ctx);
        }
        // SNS is foundational: refresh EVERY loaded wallet's names (keyed by the
        // account they resolve to) periodically (~4s), so each wallet's name shows
        // uniformly in the header and switch list, and a freshly-mined name appears
        // within seconds without switching wallets.
        let stale = self
            .names_refreshed_at
            .map(|t| t.elapsed() >= Duration::from_secs(4))
            .unwrap_or(true);
        if stale {
            self.names_refreshed_at = Some(Instant::now());
            let accounts: Vec<String> =
                self.wallets.iter().map(|w| w.effective_account()).collect();
            let rpc = self
                .config
                .lock()
                .map(|c| c.rpc.clone())
                .unwrap_or_default();
            let cache = self.names_by_account.clone();
            let ctxc = ctx.clone();
            std::thread::spawn(move || {
                let mut fresh: HashMap<String, Vec<String>> = HashMap::new();
                for acct in accounts {
                    if let Ok(names) = fetch_names_of(&rpc, &acct) {
                        fresh.insert(acct, names);
                    }
                }
                if let Ok(mut m) = cache.lock() {
                    *m = fresh;
                }
                ctxc.request_repaint();
            });
        }
        // Live availability check for the name being typed, keyed to the active
        // wallet's account (so a registered name resolves to it).
        if let Some(me) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        {
            // Debounced availability check: at most one in flight per typed value.
            let typed = self.name_field.trim().to_string();
            let need = self
                .name_check
                .lock()
                .ok()
                .map(|c| c.name != typed && !c.checking)
                .unwrap_or(false);
            if !typed.is_empty() && need {
                match validate_name_format(&typed) {
                    Err(e) => {
                        if let Ok(mut c) = self.name_check.lock() {
                            *c = NameCheck {
                                name: typed,
                                message: format!("✗ {e}"),
                                ok: false,
                                checking: false,
                            };
                        }
                    }
                    Ok(()) => {
                        if let Ok(mut c) = self.name_check.lock() {
                            *c = NameCheck {
                                name: typed.clone(),
                                message: "checking…".into(),
                                ok: false,
                                checking: true,
                            };
                        }
                        let rpc = self
                            .config
                            .lock()
                            .map(|c| c.rpc.clone())
                            .unwrap_or_default();
                        let cache = self.name_check.clone();
                        let ctxc = ctx.clone();
                        std::thread::spawn(move || {
                            let (ok, msg) = check_name_registrable(&rpc, &typed, &me);
                            if let Ok(mut c) = cache.lock() {
                                if c.name == typed {
                                    c.ok = ok;
                                    c.message = msg;
                                    c.checking = false;
                                }
                            }
                            ctxc.request_repaint();
                        });
                    }
                }
            }
        }
        if do_send {
            self.send(&ctx, confirmed_tip_grains);
        }
        if do_private_send {
            self.send_private(&ctx);
        }
        if do_scan {
            self.scan_shielded(&ctx);
        }
        if do_scan_v2 {
            self.scan_shielded_v2(&ctx);
        }
        if do_shield_v2 {
            self.shield_v2(&ctx);
        }
        if do_deshield_v2 {
            self.deshield_v2(&ctx);
        }
        if do_send_v2 {
            self.send_private_v2(&ctx);
        }
        if do_rescan {
            self.rescan_shielded(&ctx);
        }
        // Auto-scan the shielded pool the first time a (spendable) wallet is shown,
        // so its private balance + notes appear WITHOUT a manual "Scan pool" — this
        // is what lets "Send privately" enable on its own (you never need to
        // de-shield to send). Debounced to once per account; skipped for watch-only
        // (no seed → no viewing key) and while a scan is already running.
        if !do_scan {
            if let Some((acct, key, watch)) = self
                .wallets
                .get(self.selected)
                .map(|w| (w.effective_account(), w.scan_key(), w.watch_only))
            {
                // Busy is per WALLET: another wallet's scan still running must not
                // stop this one from starting, and must not be mistaken for it.
                let scanning = self
                    .shielded
                    .lock()
                    .map(|m| m.view_for(&key).scanning)
                    .unwrap_or(false);
                if !watch && self.shielded_scan_for != acct && !scanning {
                    self.shielded_scan_for = acct;
                    self.scan_shielded(&ctx);
                }
            }
        }
        if do_deshield {
            self.deshield(&ctx);
        }
        if do_build_unsigned {
            self.build_unsigned();
        }
        if do_sign_offline {
            self.sign_offline();
        }
        if do_broadcast {
            self.broadcast_signed(&ctx);
        }
        if do_save {
            self.save_wallets();
        }
        if do_load {
            self.load_wallets();
        }
        if did_copy {
            self.copied_at = Some(now_ms());
        }
    }
}

/// Format a block's wall-clock timestamp (Unix ms) as `HH:MM:SS` (UTC, matching the
/// node log) plus a relative age, for the Blocks tab. `0` (genesis/unknown) shows `—`.
fn block_time(ts_ms: u64) -> String {
    if ts_ms == 0 {
        return "—".to_string();
    }
    let secs = (ts_ms / 1000) % 86_400;
    let hms = format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    let now = now_ms();
    if now < ts_ms {
        return hms;
    }
    let age = (now - ts_ms) / 1000;
    if age < 60 {
        format!("{hms}  ({age}s ago)")
    } else if age < 3_600 {
        format!("{hms}  ({}m ago)", age / 60)
    } else {
        format!("{hms}  ({}h ago)", age / 3_600)
    }
}

fn blocks_panel(ui: &mut egui::Ui, s: &Snapshot, selected: &mut Option<u64>) {
    ui.label(egui::RichText::new("Blocks").size(ty::TITLE).strong());
    ui.label(
        egui::RichText::new(
            "each block's coinbase — newly minted issuance, paid entirely to the miner (no tax)",
        )
        .size(ty::SMALL)
        .color(palette::text_dim()),
    );
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("click a height to inspect the block →")
                .size(ty::SMALL)
                .color(palette::text_dim()),
        );
        ui.hyperlink_to("open explorer ↗", EXPLORER_URL);
    });
    ui.add_space(sp::M);
    if s.blocks.is_empty() {
        // "No blocks yet" is only true if we actually heard from a node. Offline, the
        // recent-block list is UNKNOWN — and telling an operator their chain is empty
        // when the truth is that nothing answered is the same class of mistake as
        // showing a dormant pool as a zero balance.
        if s.online {
            empty_state(
                ui,
                "▦",
                "No blocks yet",
                "Start the local node (Node tab) to begin mining — solved blocks appear here.",
            );
        } else {
            empty_state(
                ui,
                "?",
                "Recent blocks unavailable",
                "No node is answering, so the recent-block list is unknown — not empty. \
                 Connect to a node or start a local one from the Node tab.",
            );
        }
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("blocks")
            .num_columns(4)
            .striped(true)
            .spacing([18.0, 5.0])
            .show(ui, |ui| {
                for h in ["Height", "Time", "Miner", "Coinbase (XUS)"] {
                    ui.label(
                        egui::RichText::new(h.to_uppercase())
                            .size(ty::MICRO)
                            .color(palette::text_dim()),
                    );
                }
                ui.end_row();
                for b in &s.blocks {
                    // Height opens the in-app block-detail view (seal, nonce, hashes).
                    if ui
                        .link(num(group_thousands(b.height as u128)).size(ty::SMALL))
                        .on_hover_text("Inspect this block")
                        .clicked()
                    {
                        *selected = Some(b.height);
                    }
                    ui.label(num(block_time(b.timestamp_ms)).size(ty::SMALL));
                    ui.label(num(short(&b.miner)).size(ty::SMALL));
                    ui.label(num(xus(&b.reward)).size(ty::SMALL));
                    ui.end_row();
                }
            });
    });
    // ── Block-detail view (click a height above) ──
    if let Some(height) = *selected {
        if let Some(b) = s.blocks.iter().find(|b| b.height == height) {
            block_detail_window(ui.ctx(), b, selected);
        } else {
            // The block scrolled out of the recent window — nothing to show.
            *selected = None;
        }
    }
}

/// The block-detail modal: full header identity (hash / prev / state root), the PoW
/// seal (nonce + compact target), timestamp, tx count, and the coinbase split — each
/// hash with a copy affordance, plus a deep link into the explorer.
fn block_detail_window(ctx: &egui::Context, b: &BlockRow, selected: &mut Option<u64>) {
    let mut open = true;
    egui::Window::new(egui::RichText::new(format!("Block #{}", b.height)).strong())
        .collapsible(false)
        .resizable(false)
        .default_width(460.0)
        .open(&mut open)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.add_space(2.0);
            egui::Grid::new("block_detail_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    kv(ui, "Height", &b.height.to_string());
                    kv(ui, "Time", &block_time(b.timestamp_ms));
                    kv_copy(ui, "Hash", &b.hash);
                    kv_copy(ui, "Prev hash", &b.prev_hash);
                    kv_copy(ui, "State root", &b.state_root);
                    // The PoW seal — the nonce that satisfied the compact target.
                    ui.label(egui::RichText::new("Nonce (seal)").weak());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(b.nonce.to_string()).monospace());
                        copy_glyph(ui, &b.nonce.to_string());
                    });
                    ui.end_row();
                    kv(ui, "Target (nBits)", &format!("0x{:08x}", b.bits));
                    kv(ui, "Transactions", &b.tx_count.to_string());
                });
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Coinbase").strong());
            egui::Grid::new("block_detail_coinbase")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    kv(ui, "Reward", &format!("{} XUS", xus(&b.reward)));
                    kv_copy(ui, "Miner", &b.miner);
                    kv(ui, "To miner", &format!("{} XUS", xus(&b.miner_amount)));
                });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Close").clicked() {
                    *selected = None;
                }
                ui.hyperlink_to(
                    "open in explorer ↗",
                    format!("{EXPLORER_URL}/#/block/{}", b.height),
                );
            });
        });
    // The window's [x] close button.
    if !open {
        *selected = None;
    }
}

// ---------------------------------------------------------------------------
// wallet actions (run on worker threads)
// ---------------------------------------------------------------------------

fn begin(action: &Arc<Mutex<ActionState>>, msg: &str) {
    if let Ok(mut a) = action.lock() {
        a.busy = true;
        a.message = msg.to_string();
    }
}

fn finish(action: &Arc<Mutex<ActionState>>, msg: &str) {
    if let Ok(mut a) = action.lock() {
        a.busy = false;
        a.message = msg.to_string();
    }
}

/// Append a line to the activity log (newest first), capped so it stays bounded.
fn record(activity: &Arc<Mutex<Vec<String>>>, msg: &str) {
    if let Ok(mut log) = activity.lock() {
        // `time\tmessage` — the feed renders the time dim and colors the message by
        // outcome (see `tx_status`); the tab keeps the two cleanly separable.
        log.insert(0, format!("{}\t{}", clock_hms(), msg));
        log.truncate(100);
    }
}

/// On-chain control state of a named account, relative to a specific wallet key.
enum Control {
    /// This wallet's key is bound to the account — it can spend.
    Mine,
    /// A different key is bound — this wallet cannot spend it.
    DifferentKey,
    /// Keyless but funded (balance > 0): claimable now via `RotateKey`.
    KeylessFunded,
    /// Keyless and empty, or not on-chain yet: must be funded before it can be
    /// claimed (the claim transaction's fee is paid by the account itself).
    KeylessEmpty,
    /// The node could not be reached / queried.
    Unreachable(String),
}

/// Resolve how the wallet derived from `seed` relates to `account` on-chain by
/// comparing the account's bound key (and balance) to this wallet's key.
fn account_control(rpc: &str, seed: [u8; 32], id: &AccountId) -> Control {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(4));
    let mine = Keypair::hybrid_from_seed(seed).public_key();
    match client.account(id) {
        Ok(Some(a)) => match a.key {
            Some(k) if k == mine => Control::Mine,
            Some(_) => Control::DifferentKey,
            None if a.balance != Balance::ZERO => Control::KeylessFunded,
            None => Control::KeylessEmpty,
        },
        Ok(None) => Control::KeylessEmpty,
        Err(e) => Control::Unreachable(e.to_string()),
    }
}

/// A human-readable one-line status for `account` given its resolved [`Control`].
fn control_message(account: &str, control: &Control) -> String {
    match control {
        Control::Mine => format!("✓ this wallet controls {account} — you can send from it"),
        Control::DifferentKey => {
            format!("✗ {account} is bound to a DIFFERENT key — this wallet cannot spend it")
        }
        Control::KeylessFunded => {
            format!("⚠ {account} is funded but keyless — click “Register name” to claim it")
        }
        Control::KeylessEmpty => {
            format!(
                "⚠ {account} is unclaimed — works once it is funded or genesis-bound to this key"
            )
        }
        Control::Unreachable(e) => format!("could not reach the node to check {account}: {e}"),
    }
}

/// Sign `action` with `seed`'s key as `signer` and submit it. The generic submit
/// path for token + HTLC actions; returns the tx id hex.
fn submit_action(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    action: Action,
) -> Result<String, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let kp = Keypair::hybrid_from_seed(seed);
    let id = AccountId::new(signer).map_err(|e| e.to_string())?;
    // Queue-aware nonce (slice 1) + Phase-2 signing domain: an action issued while an
    // earlier send is still pending gets the next free slot instead of colliding, and
    // its signature binds to {chain_id, genesis} once the tx-domain fork is active
    // (`None` = dormant/legacy, byte-identical).
    let nonce = client.next_nonce(&id).map_err(|e| e.to_string())?;
    let domain = client.signing_domain().map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: id,
        public_key: kp.public_key(),
        nonce,
        action,
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    Ok(txid.to_hex())
}

/// Submit `action`, then BLOCK until its receipt confirms — returning the tx id hex
/// only on a real on-chain SUCCESS, or the failure reason for an included-but-rejected
/// tx (or a pending timeout). This is the "don't report success on mere mempool
/// admission" path for the HTLC swap actions, reusing [`await_receipt`].
fn submit_and_confirm(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    action: Action,
    secs: u64,
) -> Result<String, String> {
    let txid_hex = submit_action(rpc, seed, signer, action)?;
    let txid =
        Hash::from_hex(&txid_hex).map_err(|_| "node returned a malformed tx id".to_string())?;
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    await_receipt(&client, &txid, secs)?;
    Ok(txid_hex)
}

/// The live format + availability check for a name being typed, so the GUI can
/// refuse to register a name that would not resolve (bad shape, already taken, or
/// shadowing an existing account) — the "checksum" guard.
#[derive(Default, Clone)]
struct NameCheck {
    /// The name this result describes (a stale result for an older field value
    /// is ignored by comparing against the current input).
    name: String,
    /// Human-readable status line.
    message: String,
    /// True only when the name is well-formed AND free to register right now.
    ok: bool,
    /// A check is in flight.
    checking: bool,
}

/// Client-side name **format** validation — the same rule consensus enforces, so
/// the GUI never even submits a name the chain would reject. A name must be a
/// valid `*.sov` account id and not a reserved 64-hex implicit id.
fn validate_name_format(name: &str) -> Result<(), String> {
    let id = AccountId::new(name).map_err(|e| e.to_string())?;
    if !id.is_registrable_name() {
        return Err("must end in .sov and use a–z, 0–9, - _ . (not a 64-hex address)".into());
    }
    Ok(())
}

/// Resolve a name to the account it points to via the node, if registered.
fn resolve_name_via_rpc(rpc: &str, name: &str) -> Option<String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    client
        .call("sov_resolveName", json!({ "name": name }))
        .ok()?
        .as_str()
        .map(str::to_string)
}

/// Whether an account already holds state on-chain (a name may not shadow one).
fn account_exists_onchain(rpc: &str, id: &str) -> bool {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    client
        .call("sov_getAccount", json!({ "account": id }))
        .map(|v| !v.is_null())
        .unwrap_or(false)
}

/// Check whether `name` can be registered to resolve to `me`: valid format, not
/// already taken by someone else, and not shadowing an existing account. Returns
/// `(registrable_now, status_message)`. This is the gate behind "won't let you
/// create a name that won't resolve".
fn check_name_registrable(rpc: &str, name: &str, me: &str) -> (bool, String) {
    if let Err(e) = validate_name_format(name) {
        return (false, format!("✗ {e}"));
    }
    if let Some(owner) = resolve_name_via_rpc(rpc, name) {
        return if owner == me {
            (
                false,
                "✓ already registered — this name resolves to you".into(),
            )
        } else {
            (false, format!("✗ already taken by {}", short_id(&owner)))
        };
    }
    if account_exists_onchain(rpc, name) {
        return (
            false,
            "✗ shadows an existing account — choose another".into(),
        );
    }
    (true, "✓ available — will resolve to your account".into())
}

/// Register `name` on-chain as an ENS/SNS alias to `signer`'s account. Re-checks
/// availability immediately before submitting (race-safe), submits `RegisterName`,
/// and returns the transaction id.
fn register_name_onchain(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    name: &str,
) -> Result<String, String> {
    validate_name_format(name)?;
    let (ok, why) = check_name_registrable(rpc, name, signer);
    if !ok {
        return Err(why
            .trim_start_matches("✗ ")
            .trim_start_matches("✓ ")
            .to_string());
    }
    submit_action(
        rpc,
        seed,
        signer,
        Action::RegisterName {
            name: name.to_string(),
        },
    )
}

/// Every name currently resolving to `account` (the reverse lookup), for the
/// wallet's "your names" list.
fn fetch_names_of(rpc: &str, account: &str) -> Result<Vec<String>, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    let v = client
        .call("sov_namesOf", json!({ "account": account }))
        .map_err(|e| e.to_string())?;
    Ok(v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// Resolve a payee for sending: a registered `*.sov` name resolves to the account
/// it points to; shielded/unified addresses, raw ids, and unregistered names pass
/// through unchanged (so genesis named accounts still work literally).
fn resolve_payee(rpc: &str, to: &str) -> String {
    if let Ok(id) = AccountId::new(to) {
        if id.is_registrable_name() {
            if let Some(owner) = resolve_name_via_rpc(rpc, to) {
                return owner;
            }
        }
    }
    to.to_string()
}

/// SHA-256 of `data` (the HTLC hashlock function — consensus checks
/// `sha256(preimage) == hashlock`).
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&sha256_bytes(data))
}

/// The minimum HTLC timeout offset, in blocks past the current tip. A too-short
/// timeout risks the refund window opening before the counterparty can claim (or a
/// swap's other leg confirms), so the lock form enforces this floor on the relative
/// offset the operator enters.
const HTLC_MIN_TIMEOUT_BLOCKS: u64 = 20;

/// A fresh 32-byte HTLC secret from the OS CSPRNG, rendered as lowercase hex. The
/// secret's bytes are the preimage (hashlock = sha256(secret bytes)), so it must be
/// unguessable — 256 bits of OS entropy is, drawn through the health-checked
/// chokepoint (`sov_crypto::fill_secure`, which FAILS CLOSED if the startup RNG
/// self-test flagged a degraded source). Empty on RNG/health failure, so the
/// entropy gate rejects it rather than let a weak secret through.
fn random_secret_hex() -> String {
    let mut buf = [0u8; 32];
    if sov_crypto::fill_secure(&mut buf).is_err() {
        return String::new();
    }
    let s = hex_lower(&buf);
    buf.zeroize();
    s
}

/// Reject a weak HTLC secret. The secret's UTF-8 bytes ARE the preimage, so once the
/// hashlock is on-chain a short/low-entropy secret is brute-forceable by the
/// counterparty. Require at least 16 bytes AND several distinct byte values — this
/// rejects a 1-char secret or a run of one repeated character, while accepting any
/// Generate output (32 random bytes → 64 hex chars) and a real passphrase.
fn htlc_secret_ok(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    let distinct = bytes
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    bytes.len() >= 16 && distinct >= 8
}

/// Set the Tokens view's status line from a worker and repaint.
fn set_token_view_msg(view: &Arc<Mutex<TokensView>>, ctx: &egui::Context, msg: &str) {
    if let Ok(mut v) = view.lock() {
        v.loading = false;
        v.message = msg.to_string();
    }
    ctx.request_repaint();
}

/// Set the Swaps view's status line from a worker and repaint.
fn set_swap_view_msg(view: &Arc<Mutex<SwapsView>>, ctx: &egui::Context, msg: &str) {
    if let Ok(mut v) = view.lock() {
        v.looking = false;
        v.message = msg.to_string();
    }
    ctx.request_repaint();
}

/// What a send asks for beyond its recipient: the amount, the blockspace bid, and
/// — for a replace-by-fee — the nonce slot to reuse.
#[derive(Clone, Copy, Debug)]
struct SendTerms {
    /// What the recipient receives, in grains.
    amount_grains: u128,
    /// The auction bid. `0` produces the BARE action (`Transfer` / `Shielded`),
    /// byte for byte what Station submitted before this feature and the only
    /// legal form on a chain where the `fee-auction` deployment is dormant: a tip
    /// is an envelope that is ADDED, never a field that is zeroed.
    tip_grains: u128,
    /// `Some(n)` ⇒ REPLACE the pooled transaction in slot `n` instead of taking a
    /// fresh nonce. That is precisely what makes the result a replacement rather
    /// than a second payment: same signer, same nonce, higher bid, so the node
    /// swaps one for the other atomically and exactly one can ever confirm.
    replace_nonce: Option<u64>,
}

/// Build, sign, and submit one send. `to` may be a named account (transparent), a
/// `xus1…` shielded address, or a `uxus1…` unified address; a shielded route
/// builds (and caches) the Halo2 prover first.
///
/// This mirrors `RpcClient::pay` transaction-for-transaction, and is built here
/// rather than delegated for two reasons the client cannot serve: the tip
/// envelope, and the NONCE. A wallet that cannot name the slot its transaction
/// occupies cannot replace it, so it cannot unstick it — and `pay` returns only
/// a txid.
fn send_payment(
    rpc: &str,
    seed: [u8; 32],
    from: &str,
    to: &str,
    terms: SendTerms,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<SentTx, String> {
    let SendTerms {
        amount_grains: grains,
        tip_grains,
        replace_nonce,
    } = terms;
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(90));
    let kp = Keypair::hybrid_from_seed(seed);
    let from_id = AccountId::new(from).map_err(|e| e.to_string())?;
    let amount = Balance::from_grains(grains);
    // Resolve an ENS/SNS name to the account it points to (a registered `.sov`
    // name → its owner). Shielded/unified addresses, raw ids, and unregistered
    // names pass through unchanged, so genesis named accounts still work literally.
    let resolved = resolve_payee(rpc, to);
    let to = resolved.as_str();
    let address = AnyAddress::parse(to).map_err(|e| format!("invalid recipient: {e}"))?;
    // The route's action. Privacy-first, exactly as `RpcClient::pay` routes it: a
    // unified address carrying a shielded receiver is paid into the pool, and a
    // pool-v2 receiver is REFUSED rather than silently downgraded to the
    // address's transparent receiver (which would pay a different party).
    let (inner, shielded_route) = match address.receiver() {
        Receiver::Transparent(account) => (
            Action::Transfer {
                to: account,
                amount,
            },
            false,
        ),
        Receiver::Shielded(recipient) => {
            let params = {
                let cached = params_cache.lock().ok().and_then(|p| p.clone());
                match cached {
                    Some(p) => p,
                    None => {
                        begin(action, "building the shielded prover (one-time, ~seconds)…");
                        let p = Arc::new(ShieldedParams::build());
                        if let Ok(mut slot) = params_cache.lock() {
                            *slot = Some(p.clone());
                        }
                        p
                    }
                }
            };
            begin(action, "proving the shielded transfer (real Halo2)…");
            let units = u64::try_from(amount.grains())
                .map_err(|_| "amount exceeds u64 grains".to_string())?;
            let bundle = mint_to_shielded(&params, &recipient, units)
                .map_err(|e| format!("shield bundle build failed: {e}"))?;
            (
                Action::Shielded {
                    bundle: bundle.to_bytes(),
                },
                true,
            )
        }
        Receiver::ShieldedV2(_) => {
            return Err(
                "recipient routes to the post-quantum shielded pool (v2), which is not \
                        active on any chain yet — refusing to send. Paying the address's \
                        transparent receiver instead would pay a different recipient and \
                        downgrade privacy without your consent."
                    .to_string(),
            )
        }
    };
    // Queue-aware nonce (a send issued while an earlier one is still pending gets
    // the next free slot instead of colliding) — unless this IS a replacement, in
    // which case the whole point is to reuse the occupied slot.
    let nonce = match replace_nonce {
        Some(n) => n,
        None => client.next_nonce(&from_id).map_err(|e| e.to_string())?,
    };
    // Phase-2 signing domain: binds the signature to {chain_id, genesis} once the
    // tx-domain fork is active (`None` = dormant/legacy, byte-identical).
    let domain = client.signing_domain().map_err(|e| e.to_string())?;
    let tx_action = if tip_grains == 0 {
        inner
    } else {
        Action::Tipped {
            tip: Balance::from_grains(tip_grains),
            inner: Box::new(inner),
        }
    };
    let tx = Transaction {
        signer: from_id,
        public_key: kp.public_key(),
        nonce,
        action: tx_action,
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    Ok(SentTx {
        txid: txid.to_hex(),
        from_account: from.to_string(),
        // The RESOLVED recipient, so a bump can never pay a different party than
        // the original if a `.sov` name is re-pointed in between.
        to: to.to_string(),
        amount_grains: grains,
        nonce,
        tip_grains,
        shielded_route,
        submitted_ms: now_ms(),
        state: SendState::Pending,
        note: String::new(),
    })
}

/// Path to a wallet's encrypted incremental note cache, keyed by its stable
/// implicit id (per seed). `<home>/.sov-station/notes/<id>.store`.
fn note_store_path(store_id: &str) -> Result<PathBuf, String> {
    Ok(station_dir()?
        .join("notes")
        .join(format!("{store_id}.store")))
}

/// As [`note_store_path`], for the POOL-V2 note cache. A distinct suffix, because
/// the two pools are separate value spaces with different note formats — loading
/// one as the other must be impossible, not merely unlikely.
fn note_store_v2_path(store_id: &str) -> Result<PathBuf, String> {
    Ok(station_dir()?
        .join("notes")
        .join(format!("{store_id}.v2.store")))
}

/// Encrypt `plaintext` with the 32-byte device `key` (ChaCha20-Poly1305, random
/// 12-byte nonce prepended) — the note cache holds note secrets, so it is never
/// written in the clear.
fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    sov_crypto::fill_secure(&mut nonce).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob written by [`encrypt_blob`]. `None` on a wrong key or tamper.
fn decrypt_blob(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    if data.len() < 12 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .ok()
}

/// Sum the coinbase paid to any of `accounts` across the whole chain, by reading
/// each block's coinbase recipients. Returns `(total_grains, tip, rows)` where
/// rows are per-account earnings (label, role, blocks credited, grains). Real
/// on-chain data only — every grain is a coinbase the chain actually paid.
#[allow(clippy::type_complexity)]
fn scan_earnings(
    rpc: &str,
    accounts: &HashMap<String, String>,
) -> Result<(u128, u64, Vec<EarningRow>), String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let head = client.height().map_err(|e| e.to_string())?;
    // account -> (label, role, blocks, grains)
    let mut tally: HashMap<String, (String, String, u64, u128)> = HashMap::new();
    let mut total: u128 = 0;
    for h in 1..=head {
        let Ok(d) = client.call("sov_getBlockDigest", json!({ "height": h })) else {
            continue;
        };
        let Some(cb) = d.get("coinbase").filter(|c| !c.is_null()) else {
            continue;
        };
        let Some(Value::Array(recips)) = cb.get("recipients") else {
            continue;
        };
        for r in recips {
            let acct = field(r, "account");
            let Some(label) = accounts.get(&acct) else {
                continue;
            };
            let role = field(r, "role");
            let amt: u128 = field(r, "amount").parse().unwrap_or(0);
            total += amt;
            let e = tally
                .entry(acct.clone())
                .or_insert((label.clone(), role, 0, 0));
            e.2 += 1;
            e.3 += amt;
        }
    }
    let mut rows: Vec<EarningRow> = tally
        .into_iter()
        .map(|(account, (label, role, blocks, grains))| EarningRow {
            label,
            account,
            role,
            blocks,
            grains,
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.grains));
    Ok((total, head, rows))
}

/// The canonical block hash at `height` (the header hash, matching what
/// [`NoteStore::ingest_block`] records), or `None` if the node has no block there
/// (e.g. the chain is now shorter). Used to detect a reorg before folding.
fn canonical_hash(client: &RpcClient, height: u64) -> Result<Option<[u8; 32]>, String> {
    Ok(client
        .block_by_height(height)
        .map_err(|e| e.to_string())?
        .map(|b| *b.hash().as_bytes()))
}

/// Incrementally scan for `seed`'s shielded notes, persisting an encrypted
/// [`NoteStore`] so each call only fetches + decrypts the **new** blocks since
/// last time (not the whole chain). Loads the cached store (decrypting with the
/// device key), folds in blocks `scanned_height+1..=tip`, persists, and returns
/// the up-to-date store. A `tip` below the cached height (a chain reset/reorg)
/// rebuilds from genesis.
fn scan_store(rpc: &str, seed: [u8; 32]) -> Result<NoteStore, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    // The cache is keyed by this wallet's stable implicit id (one seed → one
    // shielded key → one note set). Encrypted at rest under a key derived from the
    // wallet's OWN seed (the secret we're already scanning with) — so there is no
    // device key on disk, and the cache is meaningless without the seed. It is a
    // rebuildable cache anyway: an unreadable file just forces a fresh scan.
    let store_id = Keypair::hybrid_from_seed(seed)
        .public_key()
        .implicit_account_id()
        .to_string();
    let path = note_store_path(&store_id)?;
    let dkey = notes_cache_key(&seed);

    let mut store = std::fs::read(&path)
        .ok()
        .and_then(|enc| decrypt_blob(&dkey, &enc))
        .and_then(|bytes| NoteStore::from_bytes(&bytes))
        .unwrap_or_else(|| NoteStore::new(0));

    let tip = client.height().map_err(|e| e.to_string())?;

    // Reconcile the cache with the canonical chain before folding forward. If the
    // chain reorged out from under us — the node's hash at our cached tip no
    // longer matches — walk our checkpoints newest→oldest to find the deepest
    // height that still agrees (the fork point) and roll back to it, so we never
    // extend an orphaned branch. A reorg deeper than the cached horizon rebuilds.
    if let Some((tip_h, cached_hash)) = store.tip_checkpoint() {
        if canonical_hash(&client, tip_h)? != Some(cached_hash) {
            let mut fork = None;
            for (h, our_hash) in store.checkpoints().into_iter().rev() {
                if canonical_hash(&client, h)? == Some(our_hash) {
                    fork = Some(h);
                    break;
                }
            }
            match fork {
                Some(f) if store.rollback_to(f) => {}
                // Fork is below our retained horizon (or not checkpointed) —
                // rebuild from the birthday; correctness over a faster path.
                _ => store = NoteStore::new(store.birthday()),
            }
        }
    }

    for h in (store.scanned_height() + 1)..=tip {
        let block = client
            .block_by_height(h)
            .map_err(|e| e.to_string())?
            // A missing block at h<=tip is a transient RPC gap; stop here and
            // resume next scan rather than desync the contiguous height.
            .ok_or_else(|| format!("block {h} unavailable; will resume"))?;
        // Fetch this block's receipts (transaction order, 1:1 with `block.transactions`)
        // so we ingest ONLY shielded bundles whose transaction actually APPLIED. A
        // shielded tx can be mined but rejected during execution (a Failed receipt);
        // ingesting its bundle would credit the wallet notes the chain never accepted,
        // corrupting the store. A missing/short receipt list ⇒ that tx is treated as
        // unconfirmed and skipped (fail-closed), never ingested unverified.
        let receipts = client
            .call("sov_getBlockReceipts", json!({ "height": h }))
            .map_err(|e| e.to_string())?;
        let receipts = receipts.as_array();
        let bundles: Vec<ShieldedBundle> = block
            .transactions
            .iter()
            .enumerate()
            .filter_map(|(i, stx)| match &stx.transaction.action {
                Action::Shielded { bundle }
                    if receipts
                        .and_then(|rs| rs.get(i))
                        .map(receipt_succeeded)
                        .unwrap_or(false) =>
                {
                    ShieldedBundle::from_bytes(bundle).ok()
                }
                _ => None,
            })
            .collect();
        let refs: Vec<&ShieldedBundle> = bundles.iter().collect();
        store.ingest_block(&zkey, h, *block.hash().as_bytes(), &refs);
    }

    // Persist the updated cache (encrypted, owner-only).
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let enc = encrypt_blob(&dkey, &store.to_bytes())?;
    std::fs::write(&path, &enc).map_err(|e| e.to_string())?;
    restrict_to_owner(&path);
    Ok(store)
}

/// Scan the chain for this wallet's POOL-V2 (post-quantum) notes, mirroring
/// [`scan_store`] one-for-one — same cache discipline, same reorg reconciliation,
/// same fail-closed receipt filter — over `Action::ShieldedV2` bundles.
///
/// Pool v2 detection cannot use pool v1's ECDH trick: ML-KEM has no shared
/// secret until a decapsulation happens, so every v2 ciphertext must be
/// trial-decapsulated. That cost is why the cache matters here even more than
/// it does for v1.
fn scan_store_v2(rpc: &str, seed: [u8; 32]) -> Result<PqNoteStore, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let key = PqShieldedKey::from_leaf_seed(&seed);
    let store_id = Keypair::hybrid_from_seed(seed)
        .public_key()
        .implicit_account_id()
        .to_string();
    let path = note_store_v2_path(&store_id)?;
    let dkey = notes_cache_key(&seed);

    let mut store = std::fs::read(&path)
        .ok()
        .and_then(|enc| decrypt_blob(&dkey, &enc))
        .and_then(|bytes| PqNoteStore::from_bytes(&bytes))
        .unwrap_or_else(|| PqNoteStore::new(0));

    let tip = client.height().map_err(|e| e.to_string())?;

    // Same reorg reconciliation as v1: never extend an orphaned branch.
    if let Some((tip_h, cached_hash)) = store.tip_checkpoint() {
        if canonical_hash(&client, tip_h)? != Some(cached_hash) {
            let mut fork = None;
            for (h, our_hash) in store.checkpoints().into_iter().rev() {
                if canonical_hash(&client, h)? == Some(our_hash) {
                    fork = Some(h);
                    break;
                }
            }
            match fork {
                Some(f) if store.rollback_to(f) => {}
                _ => store = PqNoteStore::new(store.birthday()),
            }
        }
    }

    for h in (store.scanned_height() + 1)..=tip {
        let block = client
            .block_by_height(h)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("block {h} unavailable; will resume"))?;
        // Fail-closed on receipts exactly as v1 does: a v2 bundle whose
        // transaction did not APPLY must never credit the wallet.
        let receipts = client
            .call("sov_getBlockReceipts", json!({ "height": h }))
            .map_err(|e| e.to_string())?;
        let receipts = receipts.as_array();
        let bundles: Vec<SpendBundle> = block
            .transactions
            .iter()
            .enumerate()
            .filter_map(|(i, stx)| match &stx.transaction.action {
                Action::ShieldedV2 { bundle }
                    if receipts
                        .and_then(|rs| rs.get(i))
                        .map(receipt_succeeded)
                        .unwrap_or(false) =>
                {
                    decode_bundle(bundle).ok()
                }
                _ => None,
            })
            .collect();
        let refs: Vec<&SpendBundle> = bundles.iter().collect();
        store.ingest_block(&key, h, *block.hash().as_bytes(), &refs);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let enc = encrypt_blob(&dkey, &store.to_bytes())?;
    std::fs::write(&path, &enc).map_err(|e| e.to_string())?;
    restrict_to_owner(&path);
    Ok(store)
}

/// De-shield the wallet's largest unspent note back to its transparent account
/// (a real Halo2 spend, witnessed against a held anchor).
/// Whether a receipt JSON value (as returned by `sov_getReceipt` /
/// `sov_getBlockReceipts`) records a SUCCESSFUL execution. The execution status is a
/// tagged object nested under `status`: `{"status":"success"}` on success, or
/// `{"status":"failed","reason":…}` on a rejected-but-included transaction. Anything
/// else (unmined, malformed) is treated as not-yet-successful.
fn receipt_succeeded(v: &Value) -> bool {
    v.get("status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        == Some("success")
}

/// Poll the node for transaction `txid`'s receipt until it is mined, returning
/// `Ok(())` only when it actually **applied**, or `Err(reason)` if it was included
/// but rejected (e.g. the de-shield drain limit). This is what stops the GUI from
/// reporting "confirmed" for a transaction that silently failed on-chain — the
/// exact failure mode that made de-shielded funds look stuck.
/// Where a submitted transaction stands, as the CHAIN reports it — with the one
/// distinction the old `Result` collapsed and must never collapse again:
/// "not yet mined" is **not** a failure.
///
/// A transaction that reached the mempool is on the network. It may still be mined
/// minutes later (a pool-v2 bundle is ~11 KiB and blocks stall). Reporting that as
/// "FAILED" invites the operator to send it again — burning a second nonce, or
/// worse, believing value vanished. Only a receipt may declare failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiptStatus {
    /// A receipt says mined and applied.
    Confirmed,
    /// Accepted, no receipt yet. In the mempool, outcome still open. NOT a failure.
    Pending,
    /// A receipt says mined and REJECTED — terminal, carrying the chain's reason.
    Rejected(String),
}

/// Poll for `txid`'s receipt up to `secs`, returning what the chain actually says.
/// Unlike [`await_receipt`], a timeout yields [`ReceiptStatus::Pending`] rather than
/// an error, so a caller cannot accidentally render "still pending" as "failed".
fn await_receipt_status(client: &RpcClient, txid: &Hash, secs: u64) -> ReceiptStatus {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(v) = client.call("sov_getReceipt", json!({ "txId": txid.to_hex() })) {
            let status = v.get("status");
            match status.and_then(|s| s.get("status")).and_then(Value::as_str) {
                Some("success") => return ReceiptStatus::Confirmed,
                Some("failed") => {
                    let reason = status
                        .and_then(|s| s.get("reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("rejected on-chain")
                        .to_string();
                    return ReceiptStatus::Rejected(reason);
                }
                _ => {} // not mined yet
            }
        }
        if Instant::now() >= deadline {
            return ReceiptStatus::Pending;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn await_receipt(client: &RpcClient, txid: &Hash, secs: u64) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(v) = client.call("sov_getReceipt", json!({ "txId": txid.to_hex() })) {
            let status = v.get("status");
            match status.and_then(|s| s.get("status")).and_then(Value::as_str) {
                Some("success") => return Ok(()),
                Some("failed") => {
                    let reason = status
                        .and_then(|s| s.get("reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("rejected on-chain");
                    return Err(reason.to_string());
                }
                _ => {} // not mined yet
            }
        }
        if Instant::now() >= deadline {
            return Err("still pending (not yet mined) — check the receipt shortly".into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// How much value can be de-shielded from the pool right now, per the node's live
/// drain-limiter state (`sov_getShieldedInfo`). `None` if the node does not report
/// it (older node) — callers then skip the pre-check rather than block.
fn deshieldable_now(client: &RpcClient) -> Option<u128> {
    let v = client.call("sov_getShieldedInfo", json!({})).ok()?;
    v.get("deshieldableNowGrains")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u128>().ok())
}

fn deshield_amount(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    amount_grains: u128,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<String, String> {
    let amount = u64::try_from(amount_grains).map_err(|_| "amount too large".to_string())?;
    let store = scan_store(rpc, seed)?;
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    let unspent = store.unspent();
    if unspent.is_empty() {
        return Err("no unspent shielded notes to de-shield".to_string());
    }
    // The node's live per-window drain budget: a de-shield over it would be mined
    // and REJECTED, leaving value in the pool looking "stuck". Pre-check and fail
    // fast with an actionable message instead of submitting a doomed transaction.
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(60));
    if let Some(budget) = deshieldable_now(&client) {
        if amount_grains > budget {
            return Err(format!(
                "only {} XUS can be de-shielded in the current window (per-window drain limit) — \
                 reduce the amount or wait for the window to reset",
                grains_to_xus_plain(budget),
            ));
        }
    }
    // Coin selection: accumulate notes LARGEST-first until they cover `amount`, then
    // spend them all in ONE bundle — this is what lets a de-shield exceed any single
    // note's value. Capped at MAX_DESHIELD_NOTES to bound proof time + tx size; if the
    // request needs more, de-shield the largest cap-many this round (the most possible
    // in one tx) and leave the rest shielded for a follow-up — value is never trapped,
    // just paced. All notes are witnessed against the same tree root (a shared anchor).
    const MAX_DESHIELD_NOTES: usize = 32;
    let mut ranked: Vec<_> = unspent.iter().collect();
    ranked.sort_by_key(|it| std::cmp::Reverse(it.0.value()));
    let mut selected = Vec::new();
    let mut acc: u64 = 0;
    let mut anchor_opt = None;
    for (n, pos) in ranked.into_iter().take(MAX_DESHIELD_NOTES) {
        let (path, anchor) = store.witness(*pos).ok_or("could not witness a note")?;
        anchor_opt = Some(anchor);
        acc = acc.saturating_add(n.value());
        selected.push((n.clone(), path));
        if acc >= amount {
            break;
        }
    }
    let anchor = anchor_opt.ok_or("no unspent shielded notes to de-shield")?;
    // If the largest MAX_DESHIELD_NOTES notes still don't cover the request, de-shield
    // everything they hold this round (the most achievable in one transaction).
    let effective = amount.min(acc);
    let note_count = selected.len();
    let params = {
        let cached = params_cache.lock().ok().and_then(|p| p.clone());
        match cached {
            Some(p) => p,
            None => {
                begin(action, "building the shielded prover (one-time, ~seconds)…");
                let p = Arc::new(ShieldedParams::build());
                if let Ok(mut slot) = params_cache.lock() {
                    *slot = Some(p.clone());
                }
                p
            }
        }
    };
    begin(
        action,
        &format!("proving the de-shield of {note_count} note(s) (real Halo2)…"),
    );
    let bundle = unshield_amount_multi(&params, &zkey, &selected, anchor, effective)
        .map_err(|e| e.to_string())?;
    // Wrap the de-shield bundle in a tx signed by the transparent account that
    // receives the funds and pays the fee.
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(account).map_err(|e| e.to_string())?;
    // Queue-aware next nonce (slice 1) + Phase-2 signing domain: queues behind a
    // pending send, and binds the signature to {chain_id, genesis} when active
    // (`None` = dormant/legacy).
    let nonce = client.next_nonce(&from).map_err(|e| e.to_string())?;
    let domain = client.signing_domain().map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: from,
        public_key: kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    // Wait for the receipt: only report success once the transaction actually
    // applied on-chain. A rejection (e.g. the drain limit) surfaces its reason
    // instead of being mistaken for a confirmed de-shield.
    begin(action, "submitted — waiting for on-chain confirmation…");
    await_receipt(&client, &txid, 90)?;
    Ok(txid.to_hex())
}

/// Submit a pool-v2 bundle inside a carrier transaction signed by `account`.
///
/// The carrier binding is the step that makes a bundle admissible at all:
/// consensus verifies the bundle's ML-DSA authorization over
/// `carrier_sighash(digest, {signer, nonce})`, so the bundle must be bound to
/// the exact `{signer, nonce}` this transaction uses — and can therefore never
/// be lifted onto another transaction. It happens here because the nonce is
/// only known now, after proving.
fn submit_v2_bundle(
    client: &RpcClient,
    seed: [u8; 32],
    account: &str,
    mut bundle: SpendBundle,
    action: &Arc<Mutex<ActionState>>,
) -> Result<V2Submitted, String> {
    let key = PqShieldedKey::from_leaf_seed(&seed);
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(account).map_err(|e| e.to_string())?;
    let nonce = client.next_nonce(&from).map_err(|e| e.to_string())?;
    let domain = client.signing_domain().map_err(|e| e.to_string())?;
    // The bundle's ML-DSA carrier authorization binds this chain's {chain_id,
    // genesis} (PQV2-06 cross-network replay protection) in addition to the
    // carrier {signer, nonce}. The domain is the chain's own identity, sourced
    // from the node (not the tx-domain deployment state), so the binding holds
    // regardless of activation ordering.
    let chain_domain = client.chain_domain().map_err(|e| e.to_string())?;
    authorize_for_carrier(
        &mut bundle,
        &key,
        chain_domain.chain_id(),
        chain_domain.genesis().as_bytes(),
        account,
        nonce,
    )
    .map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: from,
        public_key: kp.public_key(),
        nonce,
        action: Action::ShieldedV2 {
            bundle: encode_bundle(&bundle),
        },
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
    // PAST THIS LINE THE TRANSACTION IS ON THE NETWORK. Everything above can fail
    // safely (nothing was broadcast, the nonce is untouched, a retry is correct);
    // everything below must never be reported as a failure, because a retry would
    // then be a SECOND transaction for one intended action.
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    begin(action, "submitted — in the mempool, waiting to be mined…");
    // A short opportunistic wait so the common fast case still confirms inline;
    // on timeout this reports PENDING, never failure, and the outbox poller keeps
    // tracking the receipt to a real terminal state.
    let status = await_receipt_status(client, &txid, V2_INLINE_WAIT_SECS);
    Ok(V2Submitted {
        txid: txid.to_hex(),
        nonce,
        status,
    })
}

/// How long a pool-v2 submit waits inline for a receipt before handing the
/// transaction off to the outbox poller. Short on purpose: the poller tracks it to a
/// real terminal state either way, so blocking longer only delays honest feedback.
const V2_INLINE_WAIT_SECS: u64 = 45;

/// The sentence shown for a pool-v2 transaction that IS ON THE NETWORK, given what
/// the chain says about it. Pure, so the one rule that matters can be tested rather
/// than trusted: **a pending transaction is never described as a failure.**
///
/// The bug this replaces read "shield failed: still pending (not yet mined)" — an
/// outright contradiction that told an operator their value had not moved when it
/// was sitting in the mempool, inviting a resend of an action already in flight.
fn v2_status_line(what: V2Action, status: &ReceiptStatus, short_tx: &str) -> String {
    match status {
        ReceiptStatus::Confirmed => {
            format!("{} CONFIRMED on-chain (tx {short_tx})", what.noun())
        }
        ReceiptStatus::Pending => format!(
            "{} SUBMITTED — in the mempool, not yet mined (tx {short_tx}) · do NOT \
             resend; Station is tracking it to confirmation",
            what.noun()
        ),
        ReceiptStatus::Rejected(why) => {
            format!("{} REJECTED on-chain: {why} (tx {short_tx})", what.noun())
        }
    }
}

/// The sentence shown when a pool-v2 action NEVER REACHED the network. Separated
/// from [`v2_status_line`] because the operator's next move differs entirely: here,
/// and only here, retrying is correct.
fn v2_not_broadcast_line(what: V2Action, err: &str) -> String {
    format!(
        "{} could not be sent — nothing was broadcast, no nonce used, safe to \
         retry: {err}",
        what.noun()
    )
}

/// A pool-v2 bundle that REACHED THE NETWORK, and where it stands. Returned only
/// once `submit_transaction` succeeded — so holding one of these means a retry
/// would double-submit. An `Err` from [`submit_v2_bundle`] means the opposite:
/// nothing was broadcast and retrying is safe.
struct V2Submitted {
    txid: String,
    /// The nonce slot it occupies, so the outbox can resolve supersession.
    nonce: u64,
    status: ReceiptStatus,
}

/// Refuse before spending ~25 s proving if pool v2 is not live on this chain.
fn require_v2_live(client: &RpcClient) -> Result<(), String> {
    let info = client
        .call("sov_getShieldedV2Info", json!({}))
        .map_err(|e| e.to_string())?;
    if info.get("active").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    Err(
        "pool v2 is not active on this chain (consensus signal bit 2 is unarmed), \
         so every v2 spend would be rejected. This is the deployment being dormant, \
         not a problem with this wallet."
            .to_string(),
    )
}

/// Shield transparent value INTO pool v2 (a real STARK, no input notes).
fn shield_v2_amount(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    to: &str,
    amount_grains: u128,
    action: &Arc<Mutex<ActionState>>,
) -> Result<V2Submitted, String> {
    let amount = u64::try_from(amount_grains).map_err(|_| "amount too large".to_string())?;
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(180));
    require_v2_live(&client)?;
    let key = PqShieldedKey::from_leaf_seed(&seed);
    // Blank means "to myself"; otherwise shield into the named pool-v2
    // address. Re-checked here, not just in the UI, so no caller can bypass it.
    let dest = if to.trim().is_empty() {
        key.address()
    } else {
        decode_shielded_v2(to.trim())
            .map_err(|e| format!("the shield recipient is not a pool-v2 (xusq1…) address: {e}"))?
    };
    begin(action, "proving the pool-v2 shield (STARK, ~25s)…");
    let bundle = build_shield(&key, &dest, amount, 0).map_err(|e| e.to_string())?;
    submit_v2_bundle(&client, seed, account, bundle, action)
}

/// De-shield value OUT of pool v2 back to `account`; change returns shielded.
fn deshield_v2_amount(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    amount_grains: u128,
    action: &Arc<Mutex<ActionState>>,
) -> Result<V2Submitted, String> {
    let amount = u64::try_from(amount_grains).map_err(|_| "amount too large".to_string())?;
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(180));
    require_v2_live(&client)?;
    // The live per-window drain budget: a de-shield over it would be mined and
    // REJECTED, which reads as value "stuck" in the pool. Fail fast instead.
    if let Some(budget) = deshieldable_v2_now(&client) {
        if amount_grains > budget {
            return Err(format!(
                "only {} XUS can be de-shielded from pool v2 in the current window \
                 (per-window drain limit) — reduce the amount or wait for the window to reset",
                grains_to_xus_plain(budget),
            ));
        }
    }
    let key = PqShieldedKey::from_leaf_seed(&seed);
    begin(action, "scanning pool v2 for spendable notes…");
    let store = scan_store_v2(rpc, seed)?;
    if store.unspent_count() == 0 {
        return Err("no unspent pool-v2 notes to de-shield".to_string());
    }
    begin(action, "proving the pool-v2 de-shield (STARK, ~25s)…");
    let built = build_spend(&key, &store, None, amount, 0).map_err(|e| e.to_string())?;
    submit_v2_bundle(&client, seed, account, built.bundle, action)
}

/// Fully-private pool-v2 transfer to another `xusq1…` address.
fn zsend_v2_amount(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    to: &str,
    amount_grains: u128,
    action: &Arc<Mutex<ActionState>>,
) -> Result<V2Submitted, String> {
    let amount = u64::try_from(amount_grains).map_err(|_| "amount too large".to_string())?;
    // A pool-v1 address here would pay the wrong recipient in the wrong value
    // space, so it is REFUSED rather than coerced.
    let to_addr = decode_shielded_v2(to.trim()).map_err(|e| {
        format!("not a pool-v2 (xusq1…) address: {e}. Pool v1 addresses (xus1…) cannot receive here — the pools are separate value spaces.")
    })?;
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(180));
    require_v2_live(&client)?;
    let key = PqShieldedKey::from_leaf_seed(&seed);
    begin(action, "scanning pool v2 for spendable notes…");
    let store = scan_store_v2(rpc, seed)?;
    if store.unspent_count() == 0 {
        return Err("no unspent pool-v2 notes to send".to_string());
    }
    begin(
        action,
        "proving the private pool-v2 transfer (STARK, ~25s)…",
    );
    let built = build_spend(&key, &store, Some(&to_addr), amount, 0).map_err(|e| e.to_string())?;
    submit_v2_bundle(&client, seed, account, built.bundle, action)
}

/// The node's live pool-v2 de-shield budget for this window, in grains.
fn deshieldable_v2_now(client: &RpcClient) -> Option<u128> {
    let info = client.call("sov_getShieldedV2Info", json!({})).ok()?;
    info.get("deshieldableNowGrains").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64().map(u128::from))
    })
}

/// After a shielded action is submitted, re-scan the pool as new blocks arrive so
/// the shielded view reflects the spend (the spent note drops, change appears) —
/// no stale "note stayed behind". Polls for ~30s (a spend confirms within a block
/// or two); each rescan updates the shared view and repaints.
///
/// `scan_key` is the WALLET the re-scan belongs to (its own implicit id) — the
/// entry updated here — so a spend that confirms after the operator switched
/// wallets updates that wallet's view and never the one on screen.
fn refresh_shielded_view(
    rpc: &str,
    seed: [u8; 32],
    scan_key: &str,
    shielded: &Arc<Mutex<ScannedPools<ShieldedView>>>,
    ctx: &egui::Context,
) {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(5));
    let start_tip = client.height().unwrap_or(0);
    for _ in 0..15 {
        std::thread::sleep(Duration::from_secs(2));
        let Ok(store) = scan_store(rpc, seed) else {
            continue;
        };
        let scanned = store.scanned_height();
        if let Ok(mut m) = shielded.lock() {
            let v = m.entry_mut(scan_key);
            v.scanning = false;
            v.account = scan_key.to_string();
            v.balance = store.balance();
            v.notes = store.unspent_count();
            v.scanned_height = scanned;
            v.message = format!("re-scanned to height {scanned}");
        }
        ctx.request_repaint();
        // Once a new block (which includes our tx) has been scanned, the view is
        // current — stop polling.
        if scanned > start_tip {
            break;
        }
    }
}

/// Fully-private send (shielded → shielded): spend one of `seed`'s scanned notes
/// to pay `recipient` (`xus1…`/`uxus1…`) `grains`, with private change back to the
/// sender. Sender, recipient, and amount are all hidden; value stays in the pool.
/// `signer` is the transparent account that submits the tx and pays its fee.
fn shielded_send(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    recipient: &str,
    grains: u128,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<String, String> {
    let amount = u64::try_from(grains).map_err(|_| "amount too large".to_string())?;
    // Resolve the recipient to a shielded address (privacy-first for a unified one).
    let recipient_addr = match AnyAddress::parse(recipient)
        .map_err(|e| format!("invalid recipient: {e}"))?
        .receiver()
    {
        Receiver::Shielded(addr) => addr,
        Receiver::Transparent(_) => {
            return Err("recipient must be a shielded (xus1…) or unified address".to_string())
        }
        // Pool v2 (post-quantum): well-formed but unspendable — bit 2 is defined
        // and NOT armed, so `Action::ShieldedV2` is a hard reject everywhere.
        // Refuse rather than fall back to another receiver on the same address,
        // which would pay someone the sender did not choose.
        Receiver::ShieldedV2(_) => {
            return Err(
                "recipient routes to the post-quantum shielded pool (v2), which is not \
                 active yet — refusing to send"
                    .to_string(),
            )
        }
    };

    let store = scan_store(rpc, seed)?;
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    let unspent = store.unspent();
    // A spend consumes ONE note, so pick the smallest unspent note that covers the
    // amount (minimizes change); fail clearly if no single note is large enough.
    let (note, pos) = unspent
        .iter()
        .filter(|(n, _)| n.value() >= amount)
        .min_by_key(|(n, _)| n.value())
        .ok_or_else(|| {
            let largest = unspent.iter().map(|(n, _)| n.value()).max().unwrap_or(0);
            format!(
                "no single shielded note covers {} XUS (largest note is {} XUS) — \
                 de-shield/consolidate first",
                grains_to_xus_plain(grains),
                grains_to_xus_plain(largest as u128),
            )
        })?;
    let (path, anchor) = store.witness(*pos).ok_or("could not witness the note")?;

    let params = {
        let cached = params_cache.lock().ok().and_then(|p| p.clone());
        match cached {
            Some(p) => p,
            None => {
                begin(action, "building the shielded prover (one-time, ~seconds)…");
                let p = Arc::new(ShieldedParams::build());
                if let Ok(mut slot) = params_cache.lock() {
                    *slot = Some(p.clone());
                }
                p
            }
        }
    };
    begin(action, "proving the private transfer (real Halo2)…");
    let bundle =
        shielded_transfer_with_change(&params, &zkey, note, path, anchor, &recipient_addr, amount)
            .map_err(|e| e.to_string())?;

    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(60));
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(signer).map_err(|e| e.to_string())?;
    // Queue-aware next nonce (slice 1) on the private-send path + Phase-2 signing
    // domain: queues behind a pending send, and binds the signature when active
    // (`None` = dormant/legacy).
    let nonce = client.next_nonce(&from).map_err(|e| e.to_string())?;
    let domain = client.signing_domain().map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: from,
        public_key: kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref()).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    // Confirm the spend actually applied on-chain before reporting success, so a
    // rejected private transfer is never mistaken for a confirmed one.
    begin(action, "submitted — waiting for on-chain confirmation…");
    await_receipt(&client, &txid, 90)?;
    Ok(txid.to_hex())
}

// ---------------------------------------------------------------------------
// encrypted wallet keystore (Argon2id + ChaCha20-Poly1305, via sov-rpc)
// ---------------------------------------------------------------------------

/// The user's home directory, cross-platform: `HOME` on Unix/macOS, `USERPROFILE`
/// on Windows (its standard home variable). This is why the wallet file, device
/// key, and auto-save all resolve identically on every OS.
fn home_dir() -> Result<PathBuf, String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| "no home directory (HOME / USERPROFILE unset)".to_string())
}

/// Station's data directory — wallets, keystore, device key, note caches.
///
/// Defaults to `<home>/.sov-station`, and is overridden by `SOV_STATION_DIR`.
///
/// The override exists for a specific safety reason: this path was previously
/// hardcoded, so ANY build of Station — including a development or test build
/// run from a working tree — opened the operator's real wallet, keystore and
/// note caches. Isolating a dev build was impossible, which makes destroying
/// live wallet state a matter of running the wrong binary. Set
/// `SOV_STATION_DIR` to a scratch path for any build that is not the one you
/// actually keep funds in.
///
/// Every path helper below routes through here, so there is one place to
/// isolate rather than five to remember.
fn station_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("SOV_STATION_DIR") {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    Ok(home_dir()?.join(".sov-station"))
}

/// `<home>/.sov-station/wallets.keystore`.
fn keystore_path() -> Result<PathBuf, String> {
    Ok(station_dir()?.join("wallets.keystore"))
}

fn write_keystore(json: &str) -> Result<String, String> {
    let path = keystore_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, format!("{json}\n")).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

fn read_keystore() -> Result<String, String> {
    let path = keystore_path()?;
    std::fs::read_to_string(&path).map_err(|e| format!("{e} (nothing saved yet?)"))
}

/// The auto-persist file: wallets are encrypted to this on every change and
/// reloaded from it on launch (no passphrase). `<home>/.sov-station/wallets.auto`.
fn autosave_path() -> Result<PathBuf, String> {
    Ok(station_dir()?.join("wallets.auto"))
}

/// The device key file (owner-only). Holds the random key the auto-persist file
/// is encrypted under, so auto-load needs no passphrase yet the file is not
/// plaintext. `<home>/.sov-station/device.key`.
fn device_key_path() -> Result<PathBuf, String> {
    Ok(station_dir()?.join("device.key"))
}

/// Restrict a file to owner read/write (0600) on Unix; best-effort elsewhere.
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path; // NTFS ACLs already default to the owning user.
    }
}

/// Read a LEGACY device key (64 hex chars) if one exists — read-only, never
/// created. Wallets used to be auto-encrypted under this on-disk key; the store is
/// now passphrase-encrypted, so this exists only to MIGRATE an old `wallets.auto`
/// on first unlock (decrypt with the device key → re-encrypt under the passphrase →
/// delete the file). Returns an error when there is no legacy key.
fn legacy_device_key_hex() -> Result<String, String> {
    let path = device_key_path()?;
    let s = std::fs::read_to_string(&path)
        .map_err(|_| "no legacy device key".to_string())?
        .trim()
        .to_string();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err("legacy device key is malformed".to_string())
    }
}

/// Delete the legacy device-key file once its `wallets.auto` has been migrated to
/// passphrase encryption — so no decryption key is ever left on disk.
fn remove_legacy_device_key() {
    if let Ok(path) = device_key_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Minimum length for a new master passphrase.
const PASSPHRASE_MIN_LEN: usize = 8;

/// Whether a first-run passphrase is acceptable to COMMIT: non-empty, at least
/// [`PASSPHRASE_MIN_LEN`] characters, and the confirmation matches exactly. The
/// match check is the whole point — it stops a typo from silently becoming the key.
fn passphrase_setup_valid(pw: &str, confirm: &str) -> bool {
    !pw.is_empty() && pw.chars().count() >= PASSPHRASE_MIN_LEN && pw == confirm
}

/// Which button (if any) the create-a-passphrase form reported this frame.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum SetupAction {
    None,
    Set,
    Cancel,
}

/// Render the create-a-passphrase form into `ui`. Returns which button fired and the
/// "Set passphrase" button's rect (exposed so a headless test can click it). The Set
/// button is ENABLED only when [`passphrase_setup_valid`] holds, so a mismatch or a
/// too-short passphrase can never be committed — this is the typo/lockout guard, and
/// the test drives this exact function.
fn render_passphrase_setup(
    ui: &mut egui::Ui,
    pw: &mut String,
    pw2: &mut String,
) -> (SetupAction, egui::Rect) {
    let red = egui::Color32::from_rgb(220, 80, 80);
    let amber = egui::Color32::from_rgb(220, 160, 60);
    let green = egui::Color32::from_rgb(80, 200, 120);
    ui.heading("🔐  Create a passphrase");
    ui.add_space(8.0);
    ui.label(
        "This encrypts your wallets on this device and is required on every launch. \
         There is no reset — if you forget it, the only recovery is re-importing each \
         wallet from its 24-word phrase. Write it down.",
    );
    ui.add_space(16.0);
    ui.add(
        egui::TextEdit::singleline(pw)
            .password(true)
            .hint_text("passphrase")
            .desired_width(280.0),
    );
    ui.add_space(6.0);
    ui.add(
        egui::TextEdit::singleline(pw2)
            .password(true)
            .hint_text("re-enter passphrase")
            .desired_width(280.0),
    );
    ui.add_space(10.0);
    let too_short = pw.chars().count() < PASSPHRASE_MIN_LEN;
    let mismatch = pw.as_str() != pw2.as_str();
    let ok = passphrase_setup_valid(pw, pw2);
    // Live feedback so a mismatch/typo is caught BEFORE it's committed.
    if pw.is_empty() && pw2.is_empty() {
        ui.label(
            egui::RichText::new(format!("at least {PASSPHRASE_MIN_LEN} characters"))
                .small()
                .weak(),
        );
    } else if too_short {
        ui.colored_label(
            amber,
            format!("use at least {PASSPHRASE_MIN_LEN} characters"),
        );
    } else if mismatch {
        ui.colored_label(red, "✗ passphrases don't match");
    } else {
        ui.colored_label(green, "✓ passphrases match");
    }
    ui.add_space(12.0);
    let mut action = SetupAction::None;
    let mut set_rect = egui::Rect::NOTHING;
    ui.horizontal(|ui| {
        let set = ui.add_enabled(ok, egui::Button::new("Set passphrase"));
        set_rect = set.rect;
        if set.clicked() {
            action = SetupAction::Set;
        }
        if ui.button("Cancel").clicked() {
            action = SetupAction::Cancel;
        }
    });
    (action, set_rect)
}

/// The at-rest key for a wallet's shielded-note CACHE, derived from that wallet's
/// own seed (domain-separated). The seed is the secret we already scan with, so the
/// cache needs no separate key on disk and is unreadable without the seed.
fn notes_cache_key(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sov-station/notes-cache/v1");
    h.update(seed);
    h.finalize().into()
}

/// Decode a 64-char hex string into a 32-byte seed.
fn hex_decode32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("seed must be 64 hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Decode an arbitrary-length hex string into bytes (for NFT token ids).
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("token id must be an even-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// local node supervision
// ---------------------------------------------------------------------------

/// One-time node setup, entirely IN-PROCESS: write the embedded genesis spec + a
/// node-config into `node_dir`. NO external helper binary — a shipped app is fully
/// self-contained. Extracted so a test can prove it needs nothing on disk but the
/// app itself (the regression that shipped "sov-testnet not built" on mainnet).
fn setup_node_dir(node_dir: &Path, spec_filename: &str) -> Result<(), String> {
    let spec_text = embedded_spec(spec_filename)?;
    std::fs::create_dir_all(node_dir.join("node-1/data"))
        .map_err(|e| format!("create node dir: {e}"))?;
    std::fs::write(node_dir.join(spec_filename), spec_text)
        .map_err(|e| format!("write spec: {e}"))?;
    let config = NodeConfig {
        // Ask the router to open the P2P port so this desktop node can accept
        // INBOUND peers instead of only dialing out. A home machine behind NAT
        // is exactly the case this exists for — it works either way, but an
        // unreachable node consumes connectivity without contributing any.
        //
        // Best-effort and silent on failure: no IGD router, UPnP disabled, or
        // carrier-grade NAT all leave the node working exactly as before.
        upnp: Some(true),
        rpc_addr: "127.0.0.1:8645".to_string(),
        rpc_workers: 4,
        data_dir: "node-1/data".to_string(),
        block_time_ms: 60_000,
        mempool_capacity: 16_384,
        max_block_txs: 4_096,
        // Node-local transaction-timing observability (`sov_getTxTiming`) at its
        // defaults: ~7.5 days of blocks, capped at 200k rows. Non-consensus —
        // it is this node's own record of how long transactions waited, is
        // committed to no block, receipt, or state root, and can differ freely
        // from any other node's.
        tx_timing_retention_blocks: sov_rpc::daemon::TX_TIMING_DEFAULT_RETENTION_BLOCKS,
        tx_timing_max_entries: sov_rpc::daemon::TX_TIMING_DEFAULT_MAX_ENTRIES,
        // Start in SYNC-ONLY mode: the node connects, serves, and downloads the chain
        // WITHOUT mining, so it never burns CPU on proof-of-work while catching up (the
        // thing that starved sync on slow machines). Mining is an explicit opt-in from
        // the Mining tab, flipped live via `DaemonHandle::set_mining` — no restart.
        mine: false,
        mining_duty_pct: None, // adaptive: ~90% on this multi-core desktop, ~50% single-core
        p2p_addr: Some("0.0.0.0:9645".to_string()),
        bootstrap_peers: Vec::new(),
        checkpoints: Vec::new(),
        noban: Vec::new(),
    };
    std::fs::write(
        node_dir.join("node-1/node-config.json"),
        serde_json::to_string_pretty(&config).map_err(|e| format!("serialize node-config: {e}"))?,
    )
    .map_err(|e| format!("write node-config: {e}"))?;
    Ok(())
}

/// The `SOV_STATION_DIR` override, if one is set and non-empty.
///
/// `station_dir` covers the wallet files AND (since 0.2.7) the chain store. The
/// peer/theme/RPC preferences are still dotfiles directly in `$HOME`, so they escape
/// that helper and are isolated here instead: a dev build silently overwriting the
/// operator's saved peer and theme is reaching into their live install.
///
/// The override is applied ONLY when it is set. With it unset the preference files
/// resolve exactly where they always did, so an existing install keeps its saved peer
/// and theme. (The chain directory is the one thing that deliberately MOVED — out of
/// the purgeable temp dir — and it is migrated rather than abandoned; see
/// [`migrate_node_dir_from_temp`].)
fn dev_override_dir() -> Option<PathBuf> {
    std::env::var("SOV_STATION_DIR")
        .ok()
        .filter(|d| !d.trim().is_empty())
        .map(PathBuf::from)
}

/// The directory the GUI's supervised local node keeps its chain + keystore in.
///
/// **This used to be the OS temp directory** — `$TMPDIR/sov-station-node-<net>` —
/// and that was a data-loss bug, not a style problem. On macOS `$TMPDIR` is a
/// per-user `/var/folders/.../T` that the OS purges on reboot, under disk
/// pressure, and on its periodic cleanup schedule. A mainnet node kept its
/// `blocks.log` there, so the chain was being deleted out from under a running
/// install and re-synced from genesis with no message and no warning. That is the
/// real "syncing is endless / it keeps re-walking fork points" experience: the
/// node was not slow, it was starting over.
///
/// A chain store must live where the OS will not touch it, so it now sits under
/// [`station_dir`] — `<home>/.sov-station/node-<net>` — the same durable directory
/// that already holds the wallet keystore and device key. One convention for
/// everything Station must not lose, and `SOV_STATION_DIR` still isolates a dev
/// build's chain exactly as before (it overrides `station_dir` itself).
///
/// Returns an error rather than falling back to anything purgeable: see
/// [`ensure_durable_node_dir`].
fn local_node_dir(net: &str) -> Result<PathBuf, String> {
    Ok(station_dir()?.join(format!("node-{net}")))
}

/// Where a pre-0.2.7 Station kept this network's chain: the purgeable temp dir.
/// Retained solely so [`migrate_node_dir_from_temp`] can rescue it.
fn legacy_temp_node_dir(net: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sov-station-node-{net}"))
}

/// Resolve the node directory AND guarantee it exists on durable storage.
///
/// Hard-fails instead of degrading. A chain store that quietly lands somewhere the
/// OS can delete is the bug this whole change exists to remove, so "could not
/// create the durable directory" is an error the operator sees, never a silent
/// fallback to `$TMPDIR`.
fn ensure_durable_node_dir(net: &str) -> Result<PathBuf, String> {
    // `local_node_dir` derives strictly from `station_dir`, which ERRORS when there
    // is no home directory rather than substituting anything — so there is no silent
    // fallback path to begin with. The remaining guard is against the specific
    // location this bug came from, so it can never be reintroduced by any future
    // rule change here.
    let dir = local_node_dir(net)?;
    if dir == legacy_temp_node_dir(net) {
        return Err(format!(
            "refusing to start: the chain directory resolved back to the OS temp \
             directory ({}), which the operating system deletes — that is the data-loss \
             bug fixed in 0.2.7. Set SOV_STATION_DIR to a durable path you own.",
            dir.display()
        ));
    }
    std::fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "could not create the chain directory {} ({e}). Station will not store a \
             mainnet chain in a location the OS can purge — fix the permissions on \
             that path, or set SOV_STATION_DIR to a durable directory you own.",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// The outcome of the one-time temp-dir → durable-dir chain migration.
#[derive(Debug, PartialEq, Eq)]
enum NodeDirMigration {
    /// No legacy store to rescue (a fresh install, or already migrated and cleaned).
    Nothing,
    /// The legacy store was moved to the durable location. Carries a human message.
    Moved(String),
    /// BOTH exist. Nothing is touched and nothing is deleted — the durable one is
    /// used and the legacy one is left in place for the operator to inspect.
    BothPresent(String),
}

/// Move a pre-0.2.7 temp-dir chain store to its durable home, ONCE.
///
/// The whole point is that nobody re-syncs. An existing `blocks.log` is the
/// operator's own verified history; it is moved, never re-downloaded and never
/// deleted.
///
/// Rules, all of them chosen so no data can be lost:
///
/// * legacy present, durable absent → move it (atomic `rename` when both are on one
///   filesystem; a copy-then-remove fallback when they are not, which `$TMPDIR` and
///   `$HOME` frequently are on macOS);
/// * both present → touch NEITHER. The durable one wins, the legacy one is left
///   exactly where it is and reported. Guessing which is "newer" and deleting the
///   other is how a migration destroys a chain;
/// * a partially-completed copy is left behind rather than removed, and the legacy
///   source is only removed after the copy fully succeeded.
fn migrate_node_dir_from_temp(net: &str) -> Result<NodeDirMigration, String> {
    let legacy = legacy_temp_node_dir(net);
    let durable = local_node_dir(net)?;
    // A dev build (SOV_STATION_DIR set) never adopts the installed Station's chain.
    if dev_override_dir().is_some() || !legacy.is_dir() {
        return Ok(NodeDirMigration::Nothing);
    }
    let durable_has_content = std::fs::read_dir(&durable)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if durable_has_content {
        return Ok(NodeDirMigration::BothPresent(format!(
            "a legacy chain store still exists at {} — the durable store at {} is in use \
             and NOTHING was deleted. Remove the legacy copy yourself once you are \
             satisfied it is not needed.",
            legacy.display(),
            durable.display()
        )));
    }
    if let Some(parent) = durable.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "could not create {} for the chain store: {e}",
                parent.display()
            )
        })?;
    }
    // Same-filesystem move: atomic, instant, no risk of a half-copy.
    if std::fs::rename(&legacy, &durable).is_ok() {
        return Ok(NodeDirMigration::Moved(format!(
            "moved the chain store out of the OS temp directory ({}) to {} — it is no \
             longer at risk of being purged, and nothing had to be re-synced.",
            legacy.display(),
            durable.display()
        )));
    }
    // Cross-filesystem (the usual macOS $TMPDIR vs $HOME case): copy, verify, then
    // remove the source. The source survives every failure path.
    copy_dir_recursive(&legacy, &durable).map_err(|e| {
        format!(
            "could not move the chain store from {} to {} ({e}). Your chain is UNTOUCHED at \
             the old path; free some space or fix permissions and restart.",
            legacy.display(),
            durable.display()
        )
    })?;
    let _ = std::fs::remove_dir_all(&legacy);
    Ok(NodeDirMigration::Moved(format!(
        "moved the chain store out of the OS temp directory ({}) to {} — it is no longer at \
         risk of being purged, and nothing had to be re-synced.",
        legacy.display(),
        durable.display()
    )))
}

/// Recursively copy `from` into `to`, creating directories as needed.
fn copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// Base directory for network-scoped seed/bootstrap choices. These live outside the
/// node data dir so a testnet reset does not forget its peer, but MAINNET and TESTNET
/// must never share one address again. Falls back to the temp dir without a home.
fn peer_config_base() -> PathBuf {
    if let Some(d) = dev_override_dir() {
        return d;
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn peer_config_path(network: Network) -> PathBuf {
    peer_config_base().join(format!(".sov-station-peer-{}", network.data_subdir()))
}

fn legacy_peer_config_path() -> PathBuf {
    peer_config_base().join(".sov-station-peer")
}

/// The seed/bootstrap peer configured for exactly one network. A legacy unscoped file
/// migrates to Testnet only because that was the only screen where it could be entered.
fn read_saved_peer(network: Network) -> String {
    match std::fs::read_to_string(peer_config_path(network)) {
        Ok(peer) => peer.trim().to_string(),
        // The legacy field was only exposed on the Testnet screen. Migrate it there;
        // never carry a testnet address into mainnet again.
        Err(_) if network == Network::Testnet => std::fs::read_to_string(legacy_peer_config_path())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Persist one network's operator peer outside the data dir. The per-launch node config
/// gets only this network's value via `build_and_run_node`.
fn save_peer(network: Network, peer: &str) {
    let _ = std::fs::write(peer_config_path(network), peer.trim());
}

/// Where the UI theme choice is persisted (next to the peer file, outside the data dir).
fn theme_config_path() -> PathBuf {
    // Via `peer_config_base` so the dev override reaches this too — otherwise a
    // scratch build rewrites the operator's saved light/dark choice.
    peer_config_base().join(".sov-station-theme")
}

/// The saved theme mode — dark unless the operator chose light last time.
fn read_saved_theme() -> bool {
    match std::fs::read_to_string(theme_config_path()) {
        Ok(s) => s.trim() != "light",
        Err(_) => true,
    }
}

/// Persist the theme choice so it survives restarts.
fn save_theme(dark: bool) {
    let _ = std::fs::write(theme_config_path(), if dark { "dark" } else { "light" });
}

/// Where the "expose node RPC on LAN" opt-in is persisted (next to the peer/theme files).
fn expose_rpc_config_path() -> PathBuf {
    peer_config_base().join(".sov-station-rpc-lan")
}

/// The saved RPC-bind posture. Loopback (false) unless the operator explicitly opted the
/// node's unauthenticated RPC onto the LAN last time. Absent file ⇒ loopback (safe default).
fn read_expose_rpc_lan() -> bool {
    matches!(
        std::fs::read_to_string(expose_rpc_config_path()).map(|s| s.trim().to_string()),
        Ok(s) if s == "lan"
    )
}

/// Persist the RPC-bind choice so it survives restarts.
fn save_expose_rpc_lan(expose: bool) {
    let _ = std::fs::write(
        expose_rpc_config_path(),
        if expose { "lan" } else { "loopback" },
    );
}

/// Add an inbound Windows Defender Firewall allow-rule for this executable, so LAN
/// peers can reach the P2P (9645/TCP) + discovery (9646/UDP) ports. Unsigned apps
/// are inbound-blocked by default on Windows, which silently prevents peering; this
/// requests the exception (one UAC prompt). Best-effort; a no-op off Windows.
#[cfg(windows)]
fn add_firewall_rule() {
    if let Ok(exe) = std::env::current_exe() {
        // Elevate via UAC and add a program-scoped inbound allow rule (covers both
        // the P2P and the multicast discovery ports).
        let ps = format!(
            "Start-Process netsh -Verb RunAs -WindowStyle Hidden -ArgumentList \
             'advfirewall firewall add rule name=\"SOV Station\" dir=in action=allow \
             program=\"{}\" enable=yes profile=any'",
            exe.display()
        );
        // Fire-and-forget (`spawn`, not `status`): the elevated `Start-Process -Verb
        // RunAs` raises a UAC prompt, and waiting on it would BLOCK node startup until
        // the user clicks (or indefinitely if they ignore it). Spawning lets the node
        // come up immediately while the rule is added in the background.
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps])
            .spawn();
    }
}
#[cfg(not(windows))]
fn add_firewall_rule() {}

/// Ensure the firewall exception exists, ONCE per machine (marker-gated), so a
/// fresh Windows install auto-allows itself on first node start — keeping LAN
/// discovery zero-config (no manual firewall navigation, no IP entry). No-op off
/// Windows and after the first successful attempt.
fn ensure_firewall(logs: &Arc<Mutex<Vec<String>>>) {
    #[cfg(windows)]
    {
        let marker = match station_dir() {
            Ok(d) => d.join("firewall.ok"),
            Err(_) => return,
        };
        if marker.exists() {
            return;
        }
        add_firewall_rule();
        if let Some(d) = marker.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&marker, "1");
        push_log(
            logs,
            "requested Windows Firewall inbound allow for LAN peers (one-time)",
        );
    }
    #[cfg(not(windows))]
    {
        let _ = logs;
    }
}

/// This machine's LAN IPv4 address, for telling the operator what to seed the
/// OTHER machine to (e.g. `192.168.0.244`). Best-effort; `None` if offline.
fn lan_ipv4() -> Option<String> {
    // Open a UDP socket "to" a public address (no packets are sent for UDP connect)
    // and read back the local address the OS would route from — the standard
    // dependency-free way to discover the primary LAN IP.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4.to_string()),
        _ => None,
    }
}

/// File holding the running local node's PID, so it can be stopped even across a
/// GUI restart (otherwise an orphaned node keeps mining with no way to halt it).
fn node_pid_path() -> PathBuf {
    // PER DATA DIRECTORY, not a machine-wide fixed path.
    //
    // This was `/tmp/sov-station-node.pid`, shared by every Station on the
    // machine — and `stop_tracked_node()` KILLS whatever pid it finds there, on
    // startup. So launching any second Station (a dev build, a release
    // candidate) terminated the node subprocess belonging to the operator's
    // installed copy. An override that isolates the wallet but leaves a
    // kill-on-startup pointing at a shared file is not isolation.
    //
    // Falls back to the old location only if the data directory is
    // unresolvable, so the legacy reap still works on a broken environment.
    match station_dir() {
        Ok(d) => {
            let _ = std::fs::create_dir_all(&d);
            d.join("node.pid")
        }
        Err(_) => std::env::temp_dir().join("sov-station-node.pid"),
    }
}

/// The PID recorded in the pidfile, if any.
fn read_node_pid() -> Option<u32> {
    std::fs::read_to_string(node_pid_path())
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Run `cmd` but never let it wedge the caller: spawn it, wait up to `timeout` for it
/// to exit, and force-kill + abandon it if it overruns. This runs on the NODE-STARTUP
/// path, where any indefinite block shows up to the operator as "the app never gets
/// past Starting…". Windows `taskkill` against a process stuck in an uninterruptible
/// kernel wait (e.g. a wedged prior node mid ~2 GiB RandomX dataset allocation, or a
/// blocked socket syscall) can otherwise hang forever — the exact "sync hangs on
/// startup, macOS is fine" symptom, since macOS reaps via `pgrep`/`kill -9` and never
/// spawns `taskkill`. Best-effort by design: the single-instance guard and pid-kill are
/// advisory, so a timeout just means we proceed — a genuinely-leftover ghost surfaces
/// later as a clear "address already in use" bind error, never a silent hang.
fn run_bounded(mut cmd: Command, timeout: Duration) {
    let mut child = match cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => return, // the tool isn't present / couldn't launch — nothing to wait on
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return, // exited cleanly
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill(); // overran the budget — abandon it and move on
                let _ = child.wait();
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return,
        }
    }
}

/// Whether process `pid` is alive. Unix: `kill -0` (a no-signal liveness probe).
/// Windows: `tasklist` filtered by PID (its output names the image only if the
/// process exists). Both are real probes, so adopt-on-launch behaves the same.
/// Force-stop process `pid`. The block log is append-only and crash-recovers, so
/// a hard kill is safe for the node. Bounded so a stuck target can't wedge startup.
fn kill_pid(pid: u32) {
    #[cfg(unix)]
    let mut cmd = Command::new("kill");
    #[cfg(unix)]
    cmd.arg("-9").arg(pid.to_string());
    #[cfg(windows)]
    let mut cmd = Command::new("taskkill");
    #[cfg(windows)]
    cmd.args(["/PID", &pid.to_string(), "/F"]);
    run_bounded(cmd, Duration::from_secs(4));
}

/// Stop the local node recorded in the pidfile (if any) and clear the pidfile.
fn stop_tracked_node() {
    if let Some(pid) = read_node_pid() {
        kill_pid(pid);
    }
    let _ = std::fs::remove_file(node_pid_path());
}

/// SINGLE INSTANCE: terminate any OTHER running copy of this app before we start a node,
/// so a stale ghost (a previous launch that didn't fully exit and release its sockets)
/// cannot hold the P2P/RPC port and fail the start with "address already in use"
/// (os error 10048 on Windows, 48 on macOS). Best-effort; never kills THIS process. This
/// is the "I want exactly ONE node, no ghosts" guarantee enforced at the OS level.
fn kill_other_instances() {
    let self_pid = std::process::id();
    let Some(name) = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    else {
        return;
    };
    #[cfg(windows)]
    {
        // Bounded: a wedged prior instance (stuck in a kernel wait) must not let
        // `taskkill` hang node startup — that is the "app never gets past Starting…"
        // Windows symptom. If it overruns we proceed; any real port conflict then
        // surfaces as a clear bind error, not a silent hang.
        let mut cmd = Command::new("taskkill");
        cmd.args(["/F", "/IM", &name, "/FI", &format!("PID ne {self_pid}")]);
        run_bounded(cmd, Duration::from_secs(4));
    }
    #[cfg(unix)]
    {
        // SCOPED BY DATA DIRECTORY, not by process name.
        //
        // This used to `pgrep -x sov-station` and kill EVERY match, so starting
        // any second Station — a development build from a working tree, a
        // release candidate being smoke-tested — killed the operator's running
        // wallet. The guard exists to stop two instances fighting over ONE data
        // directory and one set of ports; it was never meant to stop two
        // isolated instances coexisting.
        //
        // Now only an instance recorded in THIS data directory's `station.pid`
        // is a conflict. Two Stations with different `SOV_STATION_DIR` values
        // share nothing and leave each other alone.
        let Ok(dir) = station_dir() else { return };
        let pidfile = dir.join("station.pid");
        if let Ok(text) = std::fs::read_to_string(&pidfile) {
            if let Ok(prev) = text.trim().parse::<u32>() {
                // Only kill it if it is (a) not us and (b) still a live process
                // of the same name — a stale pid file after a crash must never
                // let us kill whatever unrelated process later reused the id.
                if prev != self_pid && pid_is_named(prev, &name) {
                    kill_pid(prev);
                }
            }
        }
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&pidfile, self_pid.to_string());
    }
}

/// Whether `pid` is live AND its executable name is `name`.
///
/// A pid file can outlive a crash, and the operating system reuses process ids.
/// Killing on the recorded number alone would eventually kill an unrelated
/// process, so identity is confirmed before any signal is sent.
#[cfg(unix)]
fn pid_is_named(pid: u32, name: &str) -> bool {
    Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                == name
        })
        .unwrap_or(false)
}

/// The testnet-1 genesis spec, COMPILED INTO the binary so a shipped app is fully
/// self-contained — no source checkout, no reliance on the build-machine path in
/// `CARGO_MANIFEST_DIR` (which does not exist on a user's machine). This is the same
/// frozen spec the dev tree ships in `chain/specs/testnet-1.json`.
const TESTNET_1_SPEC: &str = include_str!("../../chain/specs/testnet-1.json");
const MAINNET_SPEC: &str = include_str!("../../chain/specs/mainnet.json");

/// The genesis spec text for `spec_filename`, from the embedded copy — both the
/// frozen testnet-1 and the mainnet (RandomX, 21M cap, zero pre-mine) genesis are
/// bundled, so a shipped app can run either network self-contained.
fn embedded_spec(spec_filename: &str) -> Result<&'static str, String> {
    match spec_filename {
        "testnet-1.json" => Ok(TESTNET_1_SPEC),
        "mainnet.json" => Ok(MAINNET_SPEC),
        other => Err(format!(
            "no genesis spec bundled for this network ({other})"
        )),
    }
}

/// Set up (if needed) and start a local node **in-process**, returning a handle
/// whose lifetime is the app's. The one-time chain setup (`sov-testnet join`, which
/// writes the genesis spec + config) is a transient helper that runs and exits; the
/// long-running node itself is embedded here via the [`sov_rpc`] library — no
/// `sov-rpcd` subprocess, so nothing can outlive the GUI.
// This is the node-startup wiring seam: it legitimately takes the full launch config
// (spec, network, coinbase account, seed, bootstrap peer, keystore passphrase, the
// LAN-RPC opt-in, and the shared log sink). Bundling these into a struct would only move
// the argument list, not remove it, and adds churn to a mainnet start path — so allow it.
#[allow(clippy::too_many_arguments)]
fn build_and_run_node(
    spec_filename: &str,
    net: &str,
    account: &str,
    seed: [u8; 32],
    peer: &str,
    passphrase: &str,
    expose_lan: bool,
    logs: &Arc<Mutex<Vec<String>>>,
) -> Result<EmbeddedNode, String> {
    // Breadcrumb the PRE-INDEXING startup so a hang here is never a silent black box:
    // every heavy/blocking step below logs before it runs, so the operator's Node-tab
    // log pinpoints exactly which call wedged (this is how the Windows "never reaches
    // 'indexing'" hang gets diagnosed instead of guessed at).
    push_log(logs, "startup: clearing any stale instance…");
    // SINGLE INSTANCE: kill any ghost copy of this app first, so a leftover process from
    // a previous launch can't still hold the P2P/RPC ports and fail our bind with
    // "address already in use" (os error 10048/48) — the real cause of "node start
    // FAILED: p2p bind". One node, no ghosts. Bounded so a wedged ghost can't hang us.
    kill_other_instances();
    // On Windows, make sure we're allowed inbound through the firewall (once), so LAN
    // peers can actually reach this node — otherwise discovery silently never connects.
    ensure_firewall(logs);
    // DURABLE CHAIN STORE + one-time rescue of a pre-0.2.7 temp-dir chain. Both run
    // before anything touches the directory, so a store the OS was about to delete is
    // moved to safety rather than re-downloaded. See `local_node_dir`.
    match migrate_node_dir_from_temp(net) {
        Ok(NodeDirMigration::Nothing) => {}
        Ok(NodeDirMigration::Moved(msg)) => push_log(logs, format!("startup: {msg}")),
        Ok(NodeDirMigration::BothPresent(msg)) => push_log(logs, format!("startup: ⚠ {msg}")),
        // A failed migration must NOT start a node on a fresh empty chain next to a
        // perfectly good one the operator cannot see. Stop and say why.
        Err(e) => return Err(e),
    }
    let node_dir = ensure_durable_node_dir(net)?;

    // Safety: never silently destroy a chain. If this chain was mined to a DIFFERENT
    // wallet, refuse rather than wiping it — the user selects that wallet, or uses
    // "Reset local chain" to wipe deliberately. (A real chain is never silently
    // erased from under you.)
    let marker = node_dir.join("miner.txt");
    let prev = std::fs::read_to_string(&marker).unwrap_or_default();
    if !prev.trim().is_empty() && prev.trim() != account {
        return Err(format!(
            "this local chain was mined to a different wallet ({}…); starting as {}… would wipe \
             it. Select that wallet, or use “Reset local chain” to start fresh deliberately.",
            &prev.trim()[..prev.trim().len().min(12)],
            &account[..account.len().min(12)],
        ));
    }

    // One-time setup, entirely IN-PROCESS — no external helper binary, so a shipped
    // app is TRULY self-contained. (This is exactly what broke: the app used to shell
    // out to `sov-testnet join` for setup, but that helper was dropped from the desktop
    // bundle, so a fresh install failed with "sov-testnet not built" — worse, on
    // mainnet.) The genesis spec is EMBEDDED in the binary (`embedded_spec`); here we
    // write it (the "already set up" marker), create the data dir, and write the
    // node-config the in-process daemon reads back below. The node starts in SYNC-ONLY
    // mode (`mine: false`); mining to this wallet's coinbase is an opt-in toggle in the
    // Mining tab. The miner keystore is still written next (so mining CAN be enabled);
    // peers are filled in
    // afterward. `block_time_ms` is unused by the continuous miner (the difficulty
    // retarget regulates cadence), so its value here is immaterial.
    if !node_dir.join(spec_filename).exists() {
        setup_node_dir(&node_dir, spec_filename)?;
    }

    // Point the node's keystore at this wallet's account+seed, so the coinbase funds a
    // wallet the GUI controls. The miner seed is a SPENDING KEY — it must never touch
    // disk in the clear (this is a mainnet key). Seal it under the master passphrase
    // (Argon2id + ChaCha20-Poly1305, same envelope as the wallet store) and lock the
    // file to the owner. Refuse to start rather than write a plaintext seed.
    if passphrase.is_empty() {
        return Err(
            "unlock your wallet first — the miner seed is encrypted at rest and \
                    needs your passphrase, so a spending key is never written in the clear"
                .to_string(),
        );
    }
    push_log(logs, "startup: sealing miner keystore (encrypting)…");
    let keystore_json = Keystore {
        miners: vec![KeystoreEntry {
            account: account.to_string(),
            seed_hex: hex_lower(&seed),
            scheme: Some("hybrid65".to_string()),
            mnemonic: None,
            public_key: None,
        }],
    }
    .to_encrypted_json(passphrase)
    .map_err(|e| format!("encrypt miner keystore: {e}"))?;
    let ks_path = node_dir.join("node-1/keystore.json");
    std::fs::write(&ks_path, keystore_json)
        .map_err(|e| format!("could not set miner keystore: {e}"))?;
    restrict_to_owner(&ks_path);
    let _ = std::fs::write(&marker, account);

    // ── Run the node IN-PROCESS via the library (mirrors `sov-rpcd`'s `run`). ──
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("read {p:?}: {e}"));
    let mut config: NodeConfig =
        serde_json::from_str(&read(&node_dir.join("node-1/node-config.json"))?)
            .map_err(|e| format!("node-config: {e}"))?;
    // The config's data_dir is relative to the node dir (the old subprocess set its
    // cwd there); resolve it to an absolute path for the in-process daemon.
    config.data_dir = node_dir
        .join(&config.data_dir)
        .to_string_lossy()
        .into_owned();
    // RPC bind posture. The JSON-RPC surface is key-free (reads + submit of an ALREADY-signed
    // tx; it never signs or holds wallet keys) but it is UNAUTHENTICATED, so it binds LOOPBACK
    // (127.0.0.1) by default — reachable only from this machine. The operator can opt in to a
    // LAN bind (0.0.0.0) for the OTHER machine / the conformance dashboard / a remote explorer
    // via the Node-tab "Expose node RPC on LAN" checkbox; that choice is persisted and threaded
    // in as `expose_lan`. We NORMALIZE on every start (not migrate-once) so a legacy install
    // that was force-migrated to 0.0.0.0 is pulled back to loopback unless the operator opted
    // in. The per-IP RPC rate limiter applies in either posture.
    let rpc_port = config
        .rpc_addr
        .rsplit(':')
        .next()
        .filter(|p| !p.is_empty())
        .unwrap_or("8645")
        .to_string();
    config.rpc_addr = if expose_lan {
        format!("0.0.0.0:{rpc_port}")
    } else {
        format!("127.0.0.1:{rpc_port}")
    };
    // Seed/bootstrap peer (Bitcoin `addnode` style), scoped to THIS network. Replace
    // the persisted operator list on every start—even when empty—so a legacy testnet
    // peer can never survive in the mainnet node config. Stable spec seeds are merged
    // into the in-memory list below.
    let peer = peer.trim();
    config.bootstrap_peers = if peer.is_empty() {
        Vec::new()
    } else {
        vec![peer.to_string()]
    };
    let cfg_path = node_dir.join("node-1/node-config.json");
    let mut persisted: Value = serde_json::from_str(&read(&cfg_path)?)
        .map_err(|e| format!("node-config persistence: {e}"))?;
    persisted["bootstrap_peers"] = json!(config.bootstrap_peers.clone());
    std::fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&persisted)
            .map_err(|e| format!("serialize node-config: {e}"))?,
    )
    .map_err(|e| format!("persist network-scoped peers: {e}"))?;
    // Always refresh chain-spec.json from the EMBEDDED spec, so a new build's spec
    // changes take effect on an EXISTING chain instead of being frozen at first-run.
    // testnet-1's genesis is frozen (hash 5e9f3cc5…) and the de-shield limiter params
    // are NOT genesis-header fields, so this never alters the genesis ⇒ the persisted
    // chain still resumes, no reset. (`sov-testnet join` writes chain-spec.json as a
    // verbatim passthrough of the spec, so the embedded spec IS the on-disk content —
    // this just keeps the two consistent across upgrades.)
    let spec_text = embedded_spec(spec_filename)?;
    std::fs::write(node_dir.join("chain-spec.json"), spec_text)
        .map_err(|e| format!("refresh chain-spec: {e}"))?;
    let spec = ChainSpec::from_json(&read(&node_dir.join("chain-spec.json"))?)
        .map_err(|e| format!("chain-spec: {e}"))?;
    // Merge the spec's baked-in seed peers into the bootstrap set (dedup, after any
    // operator-typed peer), so a fresh node can find the network off its LAN even with
    // no peer typed in. mDNS still covers same-LAN discovery.
    for s in &spec.seeds {
        if !config.bootstrap_peers.contains(s) {
            config.bootstrap_peers.push(s.clone());
        }
    }
    push_log(logs, "startup: unlocking keystore + verifying genesis…");
    let keystore = Keystore::from_encrypted_or_plain(
        &read(&node_dir.join("node-1/keystore.json"))?,
        Some(passphrase),
    )
    .map_err(|e| format!("keystore: {e}"))?;
    // Verify the built genesis matches the spec's pinned hash before starting, so a
    // corrupt/drifted embedded spec fails loudly instead of forking off the real chain.
    let genesis = spec
        .to_genesis_config_verified()
        .map_err(|e| format!("genesis: {e}"))?;
    let miner_keys = keystore.keys().map_err(|e| format!("keys: {e}"))?;

    // Build + replay the persisted block log to resume state. This is the bulk of
    // startup time on a long chain — so STREAM live "indexing N/total" progress to the
    // node log (instead of appearing to hang), and log how long it took at the end.
    push_log(logs, "indexing local chain — replaying block log…");
    let t0 = std::time::Instant::now();
    let mut last_pct = u64::MAX;
    let mut daemon = Daemon::new_with_progress(
        &genesis,
        &config.data_dir,
        config.mempool_capacity,
        config.max_block_txs,
        miner_keys,
        &mut |done, total| {
            // One line per ~percent so it streams visibly without flooding.
            let pct = (done * 100).checked_div(total).unwrap_or(100);
            if pct != last_pct {
                last_pct = pct;
                push_log(logs, format!("  indexing… {done}/{total} blocks ({pct}%)"));
            }
        },
    )
    .map_err(|e| format!("daemon: {e}"))?;
    push_log(
        logs,
        format!(
            "✓ indexed {} block(s) in {:.1}s — chain head at height {}",
            daemon.resumed_blocks(),
            t0.elapsed().as_secs_f64(),
            daemon.height()
        ),
    );
    // Set when the router accepts a mapping; released when the node stops.
    let mut port_mapper: Option<(Arc<sov_network::PortMapper>, u16)> = None;
    let checkpoints = config
        .checkpoints
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("checkpoints: {e}"))?;
    if !checkpoints.is_empty() {
        daemon = daemon.with_checkpoints(checkpoints);
    }

    // Shared sync telemetry: the P2P engine writes it, the mining loop reads it to GATE
    // production (a joining node downloads the existing chain BEFORE it mines, instead of
    // forking), and the UI reads it for the live peer/sync status. One handle, cloned to
    // every party — this is what makes bootstrapping a new node deterministic.
    let sync = Arc::new(SyncShared::new());

    // P2P is ALWAYS on (the node discovers + peers with other machines); solo
    // mining works regardless, since a node produces blocks with zero peers. Bound
    // to the same shared node so blocks/txs flow both ways.
    let p2p = match config.p2p_addr.as_deref() {
        Some(p2p_addr) => {
            let (acct, keypair) = keystore
                .keys()
                .map_err(|e| format!("keys: {e}"))?
                .into_iter()
                .next()
                .ok_or("p2p_addr set but no miner key")?;
            let p2p = P2p::bind(
                daemon.node(),
                P2pConfig {
                    chain_id: genesis.chain_id.clone(),
                    genesis_hash: daemon.genesis_hash(),
                    account: acct,
                    keypair,
                },
                p2p_addr,
            )
            .map_err(|e| format!("p2p bind: {e}"))?
            .with_block_log(daemon.block_log())
            .with_bootstrap(config.bootstrap_peers.clone())
            .with_noban(config.noban.clone())
            .with_sync_status(Arc::clone(&sync))
            .with_log_sink(logs.clone());
            // Surface transport-level dial/handshake diagnostics in the Node tab too,
            // so peering is never a silent black box (dialing → tcp connected → link up,
            // or the exact failure).
            p2p.tcp().set_log_sink(logs.clone());
            // Kick an immediate, NON-BLOCKING dial of each saved seed peer and report
            // the resolved target (or a clear error) right away — no 5s startup stall on
            // a peer that is still down; the engine's reconnect loop keeps retrying.
            for peer in &config.bootstrap_peers {
                match p2p.tcp().request_reconnect(peer) {
                    Ok(addrs) => {
                        let list = addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        push_log(logs, format!("seed peer {peer} → dialing {list}"));
                    }
                    Err(e) => push_log(
                        logs,
                        format!("seed peer '{peer}' is not a valid address: {e}"),
                    ),
                }
            }
            let bound = p2p.local_addr();
            // mDNS-style LAN auto-discovery: find + dial same-chain peers on the
            // local network with zero configuration. Report the real socket/join
            // result; never print "on" when the OS/firewall prevented activation.
            match p2p.tcp().enable_lan_discovery(&genesis.chain_id) {
                Ok(()) => push_log(
                    logs,
                    "LAN discovery active on 239.255.90.45:9646 (same-chain peers only)",
                ),
                Err(e) => push_log(
                    logs,
                    format!(
                        "⚠ LAN discovery unavailable ({e}) — relay/manual peering remains active"
                    ),
                ),
            }
            daemon = daemon.with_gossip(p2p.tcp());
            push_log(logs, format!("P2P listening on {bound} (peers welcome)"));

            // UPnP: ask the router to let peers IN.
            //
            // Station runs the node IN-PROCESS, so it does not inherit the
            // mapping sov-rpcd sets up — this is the wiring for the desktop
            // case, which is precisely the machine sitting behind a home router.
            //
            // A `PortMapper` rather than a one-shot: a UPnP mapping is a LEASE,
            // and mapping once then forgetting means going quietly unreachable
            // an hour later. It renews at half the lease, rediscovers the router
            // if a renewal fails, and backs off when refused.
            //
            // Best-effort throughout: no IGD router, UPnP disabled, or
            // carrier-grade NAT all leave the node working exactly as before —
            // able to dial out, just not to be dialled.
            if config.upnp.unwrap_or(true) {
                let logs_for_map = logs.clone();
                port_mapper = Some((
                    Arc::new(sov_network::PortMapper::start(
                        bound,
                        "SOV Station",
                        move |msg| push_log(&logs_for_map, msg),
                    )),
                    bound.port(),
                ));
            } else {
                push_log(logs, "UPnP disabled in config");
            }
            Some(p2p.start())
        }
        None => {
            push_log(logs, "P2P disabled in config (no p2p_addr)");
            None
        }
    };

    // Gate mining on the SAME telemetry the P2P engine writes: while behind a heavier
    // peer chain, the production loop does not mine (it would only fork). A solo node is
    // never behind, so it still bootstraps the network.
    let handle = daemon
        .with_sync_status(Arc::clone(&sync))
        .with_log_sink(logs.clone())
        .run(
            &config.rpc_addr,
            config.rpc_workers,
            config.block_time_ms,
            config.mine,
            config.resolved_mining_duty(),
        )
        .map_err(|e| format!("run: {e}"))?;
    push_log(
        logs,
        format!(
            "node up — RPC on http://{} — mining every {}ms (paused while syncing a heavier peer)",
            handle.rpc_addr(),
            config.block_time_ms
        ),
    );
    Ok(EmbeddedNode {
        daemon: handle,
        p2p,
        account: account.to_string(),
        sync,
        port_mapper,
    })
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// Open the SOV Station window, polling `rpc` for live node state.
pub fn run(rpc: String) -> Result<(), String> {
    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let config = Arc::new(Mutex::new(Config {
        rpc,
        accounts: DEFAULT_ACCOUNTS.iter().map(|s| s.to_string()).collect(),
        // Empty until a wallet is loaded or an operate-as name is verified as ours: the
        // default watch accounts are genesis-bound addresses, not necessarily the user's.
        mining_accounts: Vec::new(),
    }));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("SOV Station"),
        ..Default::default()
    };

    // Sends this session, shared with the poller so their pending/confirmed state
    // stays live without the UI thread ever making an RPC call.
    let outbox: Arc<Mutex<Vec<SentTx>>> = Arc::new(Mutex::new(Vec::new()));

    let poll_snap = snapshot.clone();
    let poll_cfg = config.clone();
    let poll_outbox = outbox.clone();
    eframe::run_native(
        "SOV Station",
        options,
        Box::new(move |cc| {
            install_theme(&cc.egui_ctx, read_saved_theme());
            spawn_poller(poll_snap, poll_cfg, poll_outbox, cc.egui_ctx.clone());
            Ok(Box::new(Station::new(snapshot, config, outbox)))
        }),
    )
    .map_err(|e| format!("GUI failed: {e}"))
}

/// Background poller: every second, read the node into the shared snapshot and
/// nudge the UI to repaint. Honors the (UI-editable) RPC endpoint and accounts.
/// Refresh every still-pending entry in the outbox against the node.
///
/// The node exposes no "list my pooled transactions" query, so Station tracks
/// what it submitted itself. Two signals settle an entry: a receipt for its id
/// (mined — applied or rejected), or the signer's on-chain nonce moving past its
/// slot (evicted, or beaten to the slot by something else). Without the second
/// signal a displaced transaction would read PENDING forever and Station would
/// keep offering a bump the node could only refuse.
///
/// Runs on the poller thread, never the UI thread, and holds the outbox lock only
/// to read the work list and to write results back — never across an RPC call.
fn refresh_outbox(client: &RpcClient, outbox: &Arc<Mutex<Vec<SentTx>>>) {
    let pending: Vec<(String, String, u64)> = match outbox.lock() {
        Ok(o) => o
            .iter()
            .filter(|t| t.state.is_pending())
            .map(|t| (t.txid.clone(), t.from_account.clone(), t.nonce))
            .collect(),
        Err(_) => return,
    };
    if pending.is_empty() {
        return;
    }
    let mut settled: Vec<(String, SendState, String)> = Vec::new();
    for (txid, account, nonce) in pending {
        let receipt = client.call("sov_getReceipt", json!({ "txId": &txid })).ok();
        let onchain_nonce = AccountId::new(&account)
            .ok()
            .and_then(|id| client.nonce(&id).ok());
        let state = auction::resolve_state(receipt.as_ref(), onchain_nonce, nonce);
        if state.is_pending() {
            continue;
        }
        let note = receipt
            .as_ref()
            .and_then(auction::receipt_failure_reason)
            .unwrap_or_default();
        settled.push((txid, state, note));
    }
    if settled.is_empty() {
        return;
    }
    if let Ok(mut o) = outbox.lock() {
        for entry in o.iter_mut() {
            if let Some((_, state, note)) = settled.iter().find(|(id, ..)| *id == entry.txid) {
                // Only ever settle something still pending: a bump may have moved
                // this entry to REPLACED while the RPCs above were in flight, and
                // that user-known truth must not be overwritten by a stale read.
                if entry.state.is_pending() {
                    entry.state = *state;
                    entry.note = note.clone();
                }
            }
        }
    }
}

fn spawn_poller(
    snapshot: Arc<Mutex<Snapshot>>,
    config: Arc<Mutex<Config>>,
    outbox: Arc<Mutex<Vec<SentTx>>>,
    ctx: egui::Context,
) {
    thread::spawn(move || {
        // Count consecutive failed polls so a TRANSIENT timeout — e.g. while the
        // node is busy importing a batch during catch-up — does not flicker the UI
        // to "offline/transport error". We keep showing the last good snapshot and
        // only surface offline after several misses in a row.
        let mut consecutive_fail = 0u32;
        // The previous poll's `account → blocksMined`, so we can spot a NEW win (the
        // definitive "mining now" signal). Updated only on ONLINE polls, so an offline
        // blip cannot zero the baseline and make the next win look like a first sighting.
        let mut prev_miner_blocks: HashMap<String, u64> = HashMap::new();
        // The set that read as actively mining last poll — the hysteresis state, so an
        // active miner stays lit across the gaps between its wins instead of strobing.
        let mut prev_active_miners: HashSet<String> = HashSet::new();
        loop {
            let cfg = match config.lock() {
                Ok(c) => c.clone(),
                Err(_) => break,
            };
            // A generous timeout: RPC shares the node lock with block import, which
            // can briefly hold it during a sync burst.
            let client = RpcClient::new(cfg.rpc.clone()).with_timeout(Duration::from_secs(6));
            let mut snap = poll(&client, &cfg);
            if snap.online {
                // Cross-reference the on-chain miner registry against the accounts the
                // operator PROVABLY controls (`mining_accounts` — non-watch wallets and
                // operate-as names verified as `Control::Mine`, NEVER a merely-watched or
                // foreign-key account), so an EXTERNAL miner mining to one of their own
                // addresses is seen even though it never touches this node's in-process
                // sync engine — and foreign hashrate can never light the chip. Absent on
                // an older node ⇒ `miners` is empty ⇒ `None`, never a false "mining".
                let owner: HashSet<String> = cfg.mining_accounts.iter().cloned().collect();
                let assessment = assess_external_mining(
                    &snap.miners,
                    &owner,
                    snap.height,
                    &prev_miner_blocks,
                    &prev_active_miners,
                );
                snap.external_miner = assessment.facts;
                prev_active_miners = assessment.active_accounts;
                prev_miner_blocks = snap
                    .miners
                    .iter()
                    .map(|m| (m.account.clone(), m.blocks))
                    .collect();
                refresh_outbox(&client, &outbox);
                consecutive_fail = 0;
                if let Ok(mut s) = snapshot.lock() {
                    *s = snap;
                }
            } else {
                consecutive_fail += 1;
                // Only commit the offline/error snapshot after 3 straight misses, so
                // a single busy/slow poll doesn't replace good live data.
                if consecutive_fail >= 3 {
                    if let Ok(mut s) = snapshot.lock() {
                        *s = snap;
                    }
                }
            }
            ctx.request_repaint();
            thread::sleep(Duration::from_millis(1000));
        }
    });
}

#[cfg(test)]
mod tests {
    /// Operational logs must survive the process.
    ///
    /// This buffer was memory-only, so the sync that stalled and the error
    /// before a close both died with the app — and a close is precisely when
    /// the log matters. Pins that `push_log` reaches disk, that the file names
    /// its build, and that old sessions are pruned so a wallet cannot fill the
    /// disk.
    #[test]
    fn operational_logs_persist_to_disk_and_are_pruned() {
        // Takes the same lock as every other test that mutates `SOV_STATION_DIR`.
        // Without it this raced the chain-dir guards: those resolve the DEFAULT
        // station dir, so a concurrent override here made them read this scratch
        // path and fail intermittently in the release gate.
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("sov-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let prev = std::env::var("SOV_STATION_DIR").ok();
        std::env::set_var("SOV_STATION_DIR", &dir);

        let logs = Arc::new(Mutex::new(Vec::new()));
        push_log(&logs, "sync stalled at height 12345");

        let path = session_log_path().expect("a session log path");
        let body = std::fs::read_to_string(path).expect("the log exists on disk");
        assert!(
            body.contains(env!("CARGO_PKG_VERSION")),
            "the log must name the build that wrote it"
        );
        assert!(
            body.contains("sync stalled at height 12345"),
            "the logged line must actually be on disk"
        );

        // Pruning: 25 fabricated logs must fall back to the 20 newest.
        let logdir = dir.join("logs");
        for i in 0..25u32 {
            let _ = std::fs::write(logdir.join(format!("station-{i:010}.log")), "x");
        }
        prune_old_session_logs(&logdir);
        let remaining = std::fs::read_dir(&logdir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("station-"))
            .count();
        assert!(
            remaining <= 20,
            "old session logs must be pruned; {remaining} remain"
        );

        match prev {
            Some(v) => std::env::set_var("SOV_STATION_DIR", v),
            None => std::env::remove_var("SOV_STATION_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serialises the tests that mutate `SOV_STATION_DIR`.
    ///
    /// Rust runs tests in parallel threads of ONE process, so the environment is
    /// shared mutable state. Without this lock a test asserting the DEFAULT path can
    /// observe another test's override and fail intermittently — and an intermittent
    /// failure in the check that keeps dev builds off the live wallet is worse than
    /// no check, because it trains people to re-run until green.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poisoning: a panic in one env test must not cascade
    /// into unrelated failures in the others.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// **A mainnet chain must NEVER live where the OS can delete it.**
    ///
    /// Station stored `blocks.log` in `$TMPDIR/sov-station-node-mainnet`. On macOS
    /// that is a `/var/folders/.../T` directory the OS purges on reboot, under disk
    /// pressure, and periodically — so the operator's chain was silently deleted and
    /// re-synced from genesis, over and over. This is the regression guard: whatever
    /// the resolution rules become, the answer may not be inside the temp directory.
    #[test]
    fn the_chain_directory_is_never_inside_the_os_temp_directory() {
        let _g = env_guard();
        let prev = std::env::var("SOV_STATION_DIR").ok();
        std::env::remove_var("SOV_STATION_DIR");

        for net in ["mainnet", "testnet", "devnet"] {
            let dir = local_node_dir(net).expect("a durable chain dir resolves");
            assert!(
                !dir.starts_with(std::env::temp_dir()),
                "the {net} chain dir resolved inside the purgeable temp dir: {dir:?}"
            );
            assert!(
                dir.starts_with(station_dir().unwrap()),
                "the {net} chain dir must live beside the keystore in the station dir, \
                 got {dir:?}"
            );
        }

        // The belt-and-braces guard, exercised against a THROWAWAY home so the test
        // never creates a directory in the operator's real install.
        let prev_home = std::env::var("HOME").ok();
        let scratch = std::env::temp_dir().join(format!("sov-durable-test-{}", std::process::id()));
        std::env::set_var("HOME", &scratch);
        let made = ensure_durable_node_dir("mainnet").expect("a durable dir is created");
        assert!(
            !made.starts_with(std::env::temp_dir().join("sov-station-node-mainnet")),
            "ensure_durable_node_dir must never hand back the old purgeable path"
        );
        assert!(made.is_dir(), "and it creates the directory it promises");
        let _ = std::fs::remove_dir_all(&scratch);
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        match prev {
            Some(v) => std::env::set_var("SOV_STATION_DIR", v),
            None => std::env::remove_var("SOV_STATION_DIR"),
        }
    }

    /// The one-time rescue of a chain already sitting in the temp dir: it MOVES,
    /// it never re-syncs, and it never destroys anything.
    #[test]
    fn a_temp_dir_chain_is_migrated_once_and_never_destroyed() {
        let _g = env_guard();
        let prev = std::env::var("SOV_STATION_DIR").ok();
        let scratch = std::env::temp_dir().join(format!(
            "sov-migrate-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        // A unique network name so this test never touches a real store.
        let net = format!("migtest{}", std::process::id());
        let legacy = legacy_temp_node_dir(&net);
        let _ = std::fs::remove_dir_all(&legacy);

        // Home points at the scratch dir, so `station_dir()` (and therefore the
        // durable node dir) is a throwaway path — the override is deliberately NOT
        // used, because migration is skipped for dev builds.
        let prev_home = std::env::var("HOME").ok();
        std::env::remove_var("SOV_STATION_DIR");
        std::env::set_var("HOME", &scratch);

        // 1. Nothing to migrate is a clean no-op.
        assert_eq!(
            migrate_node_dir_from_temp(&net).unwrap(),
            NodeDirMigration::Nothing,
            "a fresh install has nothing to rescue"
        );

        // 2. A legacy store MOVES, contents intact — no re-sync.
        std::fs::create_dir_all(legacy.join("node-1/data")).unwrap();
        std::fs::write(legacy.join("node-1/data/blocks.log"), b"CHAIN-BYTES").unwrap();
        std::fs::write(legacy.join("miner.txt"), b"acct").unwrap();
        let moved = migrate_node_dir_from_temp(&net).unwrap();
        assert!(
            matches!(moved, NodeDirMigration::Moved(_)),
            "an existing temp-dir chain must be rescued, got {moved:?}"
        );
        let durable = local_node_dir(&net).unwrap();
        assert_eq!(
            std::fs::read(durable.join("node-1/data/blocks.log")).unwrap(),
            b"CHAIN-BYTES",
            "the chain itself survived the move byte-for-byte"
        );
        assert!(durable.join("miner.txt").exists(), "siblings moved too");
        assert!(
            !legacy.exists(),
            "the purgeable copy is gone after a clean move"
        );

        // 3. Already migrated is a no-op — it must not run again on every start.
        assert_eq!(
            migrate_node_dir_from_temp(&net).unwrap(),
            NodeDirMigration::Nothing
        );

        // 4. BOTH present destroys NOTHING. This is the case where guessing wrong
        //    costs someone their chain, so neither side is touched.
        std::fs::create_dir_all(legacy.join("node-1/data")).unwrap();
        std::fs::write(legacy.join("node-1/data/blocks.log"), b"OLD-CHAIN").unwrap();
        let both = migrate_node_dir_from_temp(&net).unwrap();
        assert!(
            matches!(both, NodeDirMigration::BothPresent(_)),
            "with both stores present the migration must stand down, got {both:?}"
        );
        assert_eq!(
            std::fs::read(legacy.join("node-1/data/blocks.log")).unwrap(),
            b"OLD-CHAIN",
            "the legacy store is left exactly as it was — never deleted"
        );
        assert_eq!(
            std::fs::read(durable.join("node-1/data/blocks.log")).unwrap(),
            b"CHAIN-BYTES",
            "and the durable store is untouched"
        );

        let _ = std::fs::remove_dir_all(&legacy);
        let _ = std::fs::remove_dir_all(&scratch);
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev {
            Some(v) => std::env::set_var("SOV_STATION_DIR", v),
            None => std::env::remove_var("SOV_STATION_DIR"),
        }
    }

    /// `SOV_STATION_DIR` must actually redirect the data directory.
    ///
    /// This path was hardcoded, so any build run from a working tree opened the
    /// operator's REAL wallet, keystore and note caches — isolating a dev build
    /// was impossible. If this override ever silently stops working, a test
    /// build touches live funds again, so the behaviour is pinned here.
    #[test]
    fn station_dir_is_overridable_for_isolation() {
        // Serialised against the other env-mutating test: the environment is shared
        // across test threads, so overlapping set/remove is a flake source.
        let _g = env_guard();
        let prev = std::env::var("SOV_STATION_DIR").ok();

        std::env::set_var("SOV_STATION_DIR", "/tmp/sov-station-isolated");
        assert_eq!(
            station_dir().unwrap(),
            PathBuf::from("/tmp/sov-station-isolated"),
            "the override must redirect the data directory"
        );

        // An empty override is ignored rather than resolving to the filesystem
        // root, which would be a spectacular way to lose a wallet.
        std::env::set_var("SOV_STATION_DIR", "");
        assert!(
            station_dir().unwrap().ends_with(".sov-station"),
            "an empty override falls back to the default, never to an empty path"
        );

        match prev {
            Some(v) => std::env::set_var("SOV_STATION_DIR", v),
            None => std::env::remove_var("SOV_STATION_DIR"),
        }
    }

    /// The override must isolate the CHAIN DIRECTORY and the preference dotfiles too,
    /// not only the wallet files.
    ///
    /// The chain directory is the sharpest of these: it is keyed by network name, so
    /// without the override a dev build and the installed Station open the same
    /// database. Two processes on one chain database is how a dev build takes the
    /// operator's node down with it.
    ///
    /// Equally important is the other direction: with the override UNSET, the
    /// preference dotfiles must resolve exactly where they always did, or an existing
    /// install silently loses its saved peer and theme on upgrade. (The CHAIN dir is
    /// the one deliberate exception — it moved OUT of the purgeable temp dir in 0.2.7
    /// and is migrated, not abandoned; see the tests below.)
    #[test]
    fn the_override_isolates_the_chain_dir_and_preferences_without_migrating_anyone() {
        let _g = env_guard();
        let prev = std::env::var("SOV_STATION_DIR").ok();
        let scratch = "/tmp/sov-station-scratch-xyz";

        std::env::set_var("SOV_STATION_DIR", scratch);
        let node = local_node_dir("mainnet").unwrap();
        assert!(
            node.starts_with(scratch),
            "the chain dir must move under the override, got {node:?}"
        );
        assert!(
            !node.starts_with(std::env::temp_dir().join("sov-station-node-mainnet")),
            "and must NOT be the shared temp-dir chain the installed Station uses"
        );
        for p in [
            peer_config_path(Network::Mainnet),
            theme_config_path(),
            // The pid file matters most of all: `stop_tracked_node()` KILLS
            // whatever pid it finds here, on every startup. Shared, launching a
            // dev build terminates a process belonging to the operator's
            // install — so an override that misses this one is not isolation.
            node_pid_path(),
            expose_rpc_config_path(),
        ] {
            assert!(
                p.starts_with(scratch),
                "preference file escaped the override: {p:?}"
            );
        }

        // Unset ⇒ historical locations, unchanged. This is the "do not break what
        // works" half: an operator upgrading must keep their peer, theme and chain.
        std::env::remove_var("SOV_STATION_DIR");
        assert_eq!(
            local_node_dir("mainnet").unwrap(),
            station_dir().unwrap().join("node-mainnet"),
            "the chain dir lives under the durable station dir, beside the keystore"
        );
        assert!(theme_config_path().ends_with(".sov-station-theme"));
        assert!(peer_config_path(Network::Mainnet).ends_with(".sov-station-peer-mainnet"));

        match prev {
            Some(v) => std::env::set_var("SOV_STATION_DIR", v),
            None => std::env::remove_var("SOV_STATION_DIR"),
        }
    }

    /// EVERY path under the data directory must be derived from `station_dir`.
    ///
    /// The override is only worth as much as its coverage: one function that still
    /// builds its own `home_dir().join(".sov-station")` re-opens the live wallet
    /// directory for a dev build, and it would do so silently. This is a source-level
    /// check because the failure is a path that is never constructed at test time —
    /// the pool-v2 address export was exactly such a site, added after the override
    /// landed and missed by it.
    #[test]
    fn no_path_bypasses_the_station_dir_override() {
        let src = include_str!("gui.rs");
        // Scan the SHIPPING code only — this test module necessarily mentions the
        // pattern it is looking for, and would otherwise flag itself.
        let shipping = src.split("#[cfg(test)]").next().unwrap_or(src);
        let offenders: Vec<&str> = shipping
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            // The one legitimate construction lives inside `station_dir` itself.
            .filter(|l| l.contains(".sov-station") && l.contains("home_dir"))
            .collect();
        assert_eq!(
            offenders.len(),
            1,
            "exactly one site may join home_dir with .sov-station (station_dir's own \
             fallback); every other path must go through station_dir(). Found:\n{}",
            offenders.join("\n")
        );
    }

    use super::*;

    /// The receipt-status filter that gates shielded-note ingestion: only a
    /// `{"status":"success"}` receipt may credit notes. A Failed receipt (a mined but
    /// rejected shielded tx) must NOT ingest — that is the wallet-corruption class this
    /// filter closes. Malformed/absent status is treated as not-yet-successful.
    #[test]
    fn receipt_succeeded_only_on_success() {
        assert!(receipt_succeeded(
            &json!({ "status": { "status": "success" }, "gas_used": 0 })
        ));
        assert!(!receipt_succeeded(&json!({
            "status": { "status": "failed", "reason": "de-shield rate limit exceeded" }
        })));
        assert!(!receipt_succeeded(&json!({ "status": {} })));
        assert!(!receipt_succeeded(&json!({})));
        assert!(!receipt_succeeded(&Value::Null));
    }

    /// The HTLC secret-entropy gate: reject short or low-entropy secrets (the preimage
    /// is brute-forceable once the hashlock is on-chain), accept a real passphrase and
    /// any `Generate` output.
    #[test]
    fn htlc_secret_entropy_gate() {
        assert!(!htlc_secret_ok(""), "empty rejected");
        assert!(!htlc_secret_ok("x"), "1-char rejected");
        assert!(
            !htlc_secret_ok("aaaaaaaaaaaaaaaa"),
            "16 identical bytes rejected"
        );
        assert!(!htlc_secret_ok("short"), "under 16 bytes rejected");
        assert!(
            htlc_secret_ok("correct horse battery staple"),
            "a real passphrase passes"
        );
        // Generate produces 32 random bytes → 64 hex chars; always passes the gate.
        let g = random_secret_hex();
        assert_eq!(g.len(), 64, "generated secret is 32 bytes of hex");
        assert!(htlc_secret_ok(&g), "generated secret passes the gate");
    }

    /// The relative-timeout floor: a lock's timeout resolves to `tip + offset`, and the
    /// enforced floor keeps it comfortably in the future (never <= tip). This mirrors the
    /// `htlc_lock` computation so the floor can't silently regress.
    #[test]
    fn htlc_timeout_floor_is_future() {
        let tip = 6_800u64;
        let timeout = tip.saturating_add(HTLC_MIN_TIMEOUT_BLOCKS);
        assert!(timeout > tip, "the minimum offset still lands past the tip");
        const { assert!(HTLC_MIN_TIMEOUT_BLOCKS >= 20, "floor is at least 20 blocks") };
    }

    /// REGRESSION GUARD (v0.1.78): the desktop app's node setup must be fully
    /// SELF-CONTAINED — needing NO external helper binary — and the EMBEDDED spec
    /// must build the FROZEN genesis, for BOTH networks. v0.1.77 shipped a mainnet
    /// app that shelled out to a `sov-testnet` binary which had been dropped from the
    /// bundle → "sov-testnet not built" on start. This test makes that class of bug
    /// impossible to ship again (and it runs where no such binary exists).
    #[test]
    fn node_setup_is_self_contained_and_builds_frozen_genesis() {
        for (spec, pinned) in [
            (
                "mainnet.json",
                "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d",
            ),
            (
                "testnet-1.json",
                "4d7d9123a489f4fd29486da3d66a6c20b04953cb886dee847662e11af293da15",
            ),
        ] {
            let dir =
                std::env::temp_dir().join(format!("sov-setup-test-{spec}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            // Runs entirely in-process — no external binary is consulted.
            setup_node_dir(&dir, spec)
                .expect("in-process node setup must not require an external binary");
            let cfg: NodeConfig = serde_json::from_str(
                &std::fs::read_to_string(dir.join("node-1/node-config.json")).unwrap(),
            )
            .expect("node-config parses");
            assert!(
                !cfg.mine,
                "the GUI node starts in sync-only mode; mining is an opt-in Mining-tab toggle"
            );
            assert!(dir.join("node-1/data").is_dir(), "data dir created");
            // The embedded spec builds + verifies the FROZEN genesis, byte-for-byte.
            let spec_obj =
                ChainSpec::from_json(&std::fs::read_to_string(dir.join(spec)).unwrap()).unwrap();
            let genesis = spec_obj
                .to_genesis_config_verified()
                .expect("embedded spec builds + verifies its pinned genesis")
                .build()
                .expect("genesis builds");
            assert_eq!(
                genesis.block.hash().to_hex(),
                pinned,
                "{spec} must build the frozen genesis"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn mainnet_embeds_both_independent_relay_seeds() {
        let spec = ChainSpec::from_json(MAINNET_SPEC).expect("mainnet spec parses");
        assert_eq!(
            spec.seeds,
            vec!["137.184.83.91:9645", "164.92.141.24:9645"],
            "every updated mainnet node must bootstrap through the live relay hosts \
             (SFO relay-2 + Frankfurt; the retired NYC relay-1 64.225.10.34 was removed)"
        );
        let genesis = spec
            .to_genesis_config_verified()
            .expect("non-consensus seed changes preserve the frozen genesis")
            .build()
            .expect("genesis builds");
        assert_eq!(
            genesis.block.hash().to_hex(),
            ChainSpec::MAINNET_GENESIS_HASH
        );
    }

    #[test]
    fn operator_peer_storage_is_scoped_per_network() {
        let mainnet = peer_config_path(Network::Mainnet);
        let testnet = peer_config_path(Network::Testnet);
        assert_ne!(mainnet, testnet);
        assert!(mainnet.ends_with(".sov-station-peer-mainnet"));
        assert!(testnet.ends_with(".sov-station-peer-testnet"));
    }

    // A tiny keystore for the crypto round-trip tests below.
    fn one_wallet_keystore() -> Keystore {
        Keystore {
            miners: vec![KeystoreEntry {
                account: "test.wallet".to_string(),
                seed_hex: hex_lower(&[7u8; 32]),
                scheme: Some("hybrid65".to_string()),
                mnemonic: Some("abandon ability able".to_string()),
                public_key: None,
            }],
        }
    }

    #[test]
    fn passphrase_store_round_trips() {
        // What auto_save → try_unlock (current format) relies on: encrypt under a
        // passphrase, decrypt under the SAME passphrase, recover the entry.
        let json = one_wallet_keystore()
            .to_encrypted_json("correct horse battery staple")
            .expect("encrypt");
        let back = Keystore::from_encrypted_or_plain(&json, Some("correct horse battery staple"))
            .expect("decrypt");
        assert_eq!(back.miners.len(), 1);
        assert_eq!(back.miners[0].seed_hex, hex_lower(&[7u8; 32]));
        assert_eq!(
            back.miners[0].mnemonic.as_deref(),
            Some("abandon ability able")
        );
    }

    #[test]
    fn migration_invariant_device_key_then_passphrase() {
        // The safety property behind try_unlock's two-step: a store sealed under the
        // legacy DEVICE KEY does NOT decrypt under a (different) passphrase — so the
        // passphrase attempt cleanly fails and we fall through to the device-key
        // branch — yet decrypts under the device key, and re-encrypting under the
        // passphrase then decrypts under the passphrase. No wallet is ever orphaned.
        let device_key = "a".repeat(64); // shape of a legacy device key
        let passphrase = "my new passphrase";
        let legacy = one_wallet_keystore()
            .to_encrypted_json(&device_key)
            .expect("seal under device key");

        // passphrase-first attempt fails (wrong key) → migration branch taken
        assert!(Keystore::from_encrypted_or_plain(&legacy, Some(passphrase)).is_err());
        // device-key attempt succeeds → wallets recovered for migration
        let recovered = Keystore::from_encrypted_or_plain(&legacy, Some(&device_key))
            .expect("device-key decrypt");
        assert_eq!(recovered.miners[0].seed_hex, hex_lower(&[7u8; 32]));
        // re-seal under the passphrase → now opens with the passphrase
        let migrated = recovered.to_encrypted_json(passphrase).expect("re-seal");
        let after = Keystore::from_encrypted_or_plain(&migrated, Some(passphrase)).expect("open");
        assert_eq!(after.miners[0].seed_hex, hex_lower(&[7u8; 32]));
    }

    #[test]
    fn passphrase_setup_requires_match_and_length() {
        // The check that prevents a typo'd passphrase from becoming the key.
        assert!(!passphrase_setup_valid("", ""), "empty rejected");
        assert!(
            !passphrase_setup_valid("short", "short"),
            "too short rejected"
        );
        assert!(
            !passphrase_setup_valid("longenough", "longenuogh"),
            "mismatch rejected (typo in confirm)"
        );
        assert!(
            !passphrase_setup_valid("longenough", ""),
            "empty confirm rejected"
        );
        assert!(
            passphrase_setup_valid("correct horse", "correct horse"),
            "matching + long enough accepted"
        );
    }

    /// A real headless CLICK-TEST: render the actual create-a-passphrase screen and
    /// inject a genuine pointer press+release on the rendered "Set passphrase" button.
    /// It must fire ONLY when the two inputs match (and meet the length floor) — i.e.
    /// the disabled-button guard against a typo'd, unconfirmed passphrase actually
    /// works at the widget level, not just in the validity helper.
    #[test]
    fn setup_screen_set_button_clicks_only_when_inputs_match() {
        use egui::{Event, Modifiers, PointerButton, RawInput};

        // Run ONE headless frame; returns which button fired + the Set button's rect.
        fn frame(
            ctx: &egui::Context,
            p: &mut String,
            p2: &mut String,
            input: RawInput,
        ) -> (SetupAction, egui::Rect) {
            let mut action = SetupAction::None;
            let mut rect = egui::Rect::NOTHING;
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let (a, r) = render_passphrase_setup(ui, p, p2);
                    action = a;
                    rect = r;
                });
            });
            (action, rect)
        }

        fn click_set(pw: &str, pw2: &str) -> SetupAction {
            let ctx = egui::Context::default();
            let mut p = pw.to_string();
            let mut p2 = pw2.to_string();
            let btn = PointerButton::Primary;
            let m = Modifiers::default();
            // Frame 1: lay out the screen and capture the Set button's rect.
            let (_, rect) = frame(&ctx, &mut p, &mut p2, RawInput::default());
            let c = rect.center();
            // Frame 2: press on the button.
            frame(
                &ctx,
                &mut p,
                &mut p2,
                RawInput {
                    events: vec![
                        Event::PointerMoved(c),
                        Event::PointerButton {
                            pos: c,
                            button: btn,
                            pressed: true,
                            modifiers: m,
                        },
                    ],
                    ..Default::default()
                },
            );
            // Frame 3: release on the button → a click registers (if it's enabled).
            let (action, _) = frame(
                &ctx,
                &mut p,
                &mut p2,
                RawInput {
                    events: vec![
                        Event::PointerMoved(c),
                        Event::PointerButton {
                            pos: c,
                            button: btn,
                            pressed: false,
                            modifiers: m,
                        },
                    ],
                    ..Default::default()
                },
            );
            action
        }

        // Matching + long enough → the button is live, the click commits.
        assert_eq!(
            click_set("correct horse", "correct horse"),
            SetupAction::Set,
            "matching passphrases: Set should fire on click"
        );
        // A typo in the confirm → button disabled → clicking does nothing.
        assert_eq!(
            click_set("correct horse", "correct hoarse"),
            SetupAction::None,
            "mismatch: Set must NOT fire (no silent typo lockout)"
        );
        // Too short → button disabled.
        assert_eq!(
            click_set("short", "short"),
            SetupAction::None,
            "too short: Set must NOT fire"
        );
    }

    #[test]
    fn notes_cache_key_is_deterministic_and_seed_bound() {
        let a = notes_cache_key(&[1u8; 32]);
        let b = notes_cache_key(&[1u8; 32]);
        let c = notes_cache_key(&[2u8; 32]);
        assert_eq!(a, b, "same seed → same cache key");
        assert_ne!(a, c, "different seed → different cache key");
        assert_ne!(a, [1u8; 32], "not the raw seed (domain-separated)");
    }

    #[test]
    fn xus_groups_thousands_and_trims_fraction() {
        assert_eq!(xus("0"), "0");
        assert_eq!(xus("100000000"), "1");
        assert_eq!(xus("1250000000000"), "12,500"); // 12.5k XUS
        assert_eq!(xus("150000000"), "1.5");
        assert_eq!(xus("100000000000000000"), "1,000,000,000");
    }

    #[test]
    fn grains_to_xus_plain_has_no_separators_and_round_trips() {
        // The Max button writes this back into the input, so it must re-parse.
        for g in [
            0u128,
            1,
            100_000_000,
            150_000_000,
            1_250_000_000_000,
            999_999_999,
        ] {
            let s = grains_to_xus_plain(g);
            assert!(!s.contains(','), "{s} must be parseable by parse_xus");
            assert_eq!(parse_xus(&s), Some(g), "round-trip {g}");
        }
    }

    #[test]
    fn tx_status_colors_success_green_and_any_failure_red() {
        // Success: the ✓ convention.
        assert!(matches!(
            tx_status("✓ sent 5 XUS to alice.sov (tx ab12cd34)"),
            TxStatus::Ok
        ));
        assert!(matches!(
            tx_status("✓ HTLC opened — id = ff00"),
            TxStatus::Ok
        ));
        // Failure with the ✗ marker.
        assert!(matches!(
            tx_status("✗ send failed: insufficient balance"),
            TxStatus::Err
        ));
        // Failure WITHOUT a marker still goes red — the "for any reason" guarantee.
        assert!(matches!(
            tx_status("send failed: node unreachable"),
            TxStatus::Err
        ));
        assert!(matches!(
            tx_status("issue failed: bad symbol"),
            TxStatus::Err
        ));
        assert!(matches!(
            tx_status("insufficient balance for shielded value"),
            TxStatus::Err
        ));
        assert!(matches!(tx_status("invalid recipient: …"), TxStatus::Err));
        // Neutral / in-progress stays dim (not green, not red).
        assert!(matches!(
            tx_status("broadcasting signed tx…"),
            TxStatus::Info
        ));
        assert!(matches!(
            tx_status("scanning the shielded pool…"),
            TxStatus::Info
        ));
    }

    #[test]
    fn toast_chip_text_strips_the_glyph_and_caps_length() {
        // The leading status glyph (added by the action layer) is stripped — the
        // bottom-bar toast supplies its own colored glyph.
        assert_eq!(
            toast_chip_text("✓ sent 5 XUS to alice.sov", 96),
            "sent 5 XUS to alice.sov"
        );
        assert_eq!(
            toast_chip_text("✗ send failed: insufficient balance", 96),
            "send failed: insufficient balance"
        );
        assert_eq!(toast_chip_text("• broadcasting…", 96), "broadcasting…");
        // A short message is returned verbatim (no ellipsis).
        assert_eq!(toast_chip_text("ok", 96), "ok");
        // An over-long message is capped to exactly `max_chars` with a trailing ellipsis
        // so it can never blow out the single-line status bar.
        let long = "x".repeat(200);
        let capped = toast_chip_text(&long, 96);
        assert_eq!(capped.chars().count(), 96);
        assert!(capped.ends_with('…'));
        assert!(capped.starts_with(&"x".repeat(95)));
        // Char-safe truncation: a multi-byte boundary must never panic or split a glyph.
        let wide = "✓ ".to_string() + &"é".repeat(200);
        let capped = toast_chip_text(&wide, 10);
        assert_eq!(capped.chars().count(), 10);
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn send_route_detects_each_tier() {
        assert!(matches!(SendRoute::detect(""), SendRoute::Empty));
        assert!(matches!(
            SendRoute::detect("treasury.sov"),
            SendRoute::Transparent(_)
        ));
        assert!(matches!(SendRoute::detect("!!bad!!"), SendRoute::Invalid));
        // A transparent route is public; the others are private.
        assert!(!SendRoute::detect("treasury.sov").private());
        assert!(SendRoute::detect("treasury.sov").is_valid());
    }

    #[test]
    fn is_named_account_distinguishes_implicit_from_human_names() {
        assert!(is_named_account("alice.sov"));
        assert!(!is_named_account(&"a".repeat(64))); // 64-hex-ish implicit id
        assert!(!is_named_account("")); // invalid id
    }

    #[test]
    fn note_cache_blob_round_trips_and_rejects_wrong_key_or_tamper() {
        let key = [7u8; 32];
        let plaintext = b"shielded note cache: secrets must never sit in the clear";
        let blob = encrypt_blob(&key, plaintext).expect("encrypt");
        // Ciphertext is not the plaintext, and a fresh nonce is prepended.
        assert_ne!(&blob[12..], &plaintext[..]);
        // Correct key recovers exactly.
        assert_eq!(decrypt_blob(&key, &blob).as_deref(), Some(&plaintext[..]));
        // A two-different-encryptions check: random nonce ⇒ different ciphertext.
        let blob2 = encrypt_blob(&key, plaintext).expect("encrypt");
        assert_ne!(blob, blob2, "nonce must be random per write");
        // Wrong key fails closed (no panic, no plaintext).
        assert_eq!(decrypt_blob(&[8u8; 32], &blob), None);
        // Tampered ciphertext fails the AEAD tag.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(decrypt_blob(&key, &bad), None);
        // Truncated/short input is rejected, not panicked on.
        assert_eq!(decrypt_blob(&key, &blob[..8]), None);
    }

    #[test]
    fn block_row_parses_header_identity_seal_and_coinbase() {
        // A digest as `sov_getBlockDigest` returns it (incl. the new prevHash /
        // stateRoot fields the block-detail view shows).
        let digest = serde_json::json!({
            "hash": "aa".repeat(32),
            "prevHash": "bb".repeat(32),
            "stateRoot": "cc".repeat(32),
            "timestampMs": 1_700_000_000_000u64,
            "nonce": 42u64,
            "bits": 0x1d00ffffu64,
            "txIds": ["dd".repeat(32), "ee".repeat(32)],
            "coinbase": {
                "reward": "1250000000000",
                "recipients": [
                    { "role": "miner", "account": "miner.acct", "amount": "1250000000000" },
                ],
            },
        });
        let row = block_row(7, &digest);
        assert_eq!(row.height, 7);
        assert_eq!(row.hash, "aa".repeat(32));
        assert_eq!(row.prev_hash, "bb".repeat(32));
        assert_eq!(row.state_root, "cc".repeat(32));
        assert_eq!(row.nonce, 42);
        assert_eq!(row.bits, 0x1d00ffff);
        assert_eq!(row.tx_count, 2);
        assert_eq!(row.miner, "miner.acct");
        assert_eq!(row.reward, "1250000000000");
        // The entire coinbase goes to the miner — no tax.
        assert_eq!(row.miner_amount, "1250000000000");
        // Missing optional fields degrade gracefully (no panic, sensible defaults).
        let bare = block_row(0, &serde_json::json!({}));
        assert_eq!(bare.height, 0);
        assert_eq!(bare.tx_count, 0);
        assert!(bare.hash.is_empty());
    }

    #[test]
    fn palette_modes_differ_and_toggle() {
        // The light/dark accessor must actually return different values per mode, so
        // the toggle re-skins custom surfaces (not just egui's base visuals).
        palette::set_dark(true);
        assert!(palette::is_dark());
        let dark_bg = palette::bg();
        let dark_text = palette::text();
        // The SEMANTIC colors are mode-aware too — every status color, banner and
        // card tint now flows through these (no hardcoded dark RGBs left as "islands"
        // on a light background), so each must shift between modes.
        let (ds, de, dw, dl) = (
            palette::success(),
            palette::error(),
            palette::warning(),
            palette::link(),
        );
        palette::set_dark(false);
        assert!(!palette::is_dark());
        assert_ne!(dark_bg, palette::bg(), "bg differs by mode");
        assert_ne!(dark_text, palette::text(), "text differs by mode");
        assert_ne!(ds, palette::success(), "success differs by mode");
        assert_ne!(de, palette::error(), "error differs by mode");
        assert_ne!(dw, palette::warning(), "warning differs by mode");
        assert_ne!(dl, palette::link(), "link differs by mode");
        // Restore the process-wide default so nothing else observes light mode.
        palette::set_dark(true);
    }

    // ── Pool v1 / v2 surfaces ────────────────────────────────────────────────
    //
    // These cover the pure logic behind every pool-v2 pathway: the wire→struct
    // mapping, the THREE-WAY state selection that keeps "not active yet" from ever
    // reading as "empty", and the display maths for a ~1.8 KB address.

    /// The reply the live mainnet node CANNOT give (it predates the method), used to
    /// exercise the dormant path. Field names mirror `sov_getShieldedV2Info`.
    fn v2_reply(active: bool) -> serde_json::Value {
        serde_json::json!({
            "active": active,
            "poolValue": "0",
            "noteCount": 0,
            "nullifierCount": 0,
            "anchor": "00".repeat(32),
            "deshieldableNowGrains": "0",
            "deshieldLimitGrains": "2100000000000000",
            "deshieldWindowBlocks": 576,
            "windowResetsAtHeight": 12086,
            "height": 12570,
        })
    }

    #[test]
    fn shielded_v2_info_requires_the_activation_flag() {
        // `active` is the ONLY thing separating Dormant from Active, so a reply we
        // cannot read it from must not parse at all — otherwise the UI would render a
        // confident "NOT ACTIVE YET, 0 XUS" it never actually learned from a node.
        assert!(shielded_v2_info(&serde_json::Value::Null).is_none());
        assert!(shielded_v2_info(&serde_json::json!({})).is_none());
        assert!(
            shielded_v2_info(&serde_json::json!({ "active": "false" })).is_none(),
            "a STRING is not the boolean flag; refuse rather than coerce"
        );
        // A well-formed reply parses every field through.
        let got = shielded_v2_info(&v2_reply(false)).expect("well-formed reply parses");
        assert!(!got.active);
        assert_eq!(got.deshield_window_blocks, 576);
        assert_eq!(got.deshield_limit, 2_100_000_000_000_000);
        assert_eq!(got.height, 12570);
        assert_eq!(got.anchor.len(), 64);
    }

    #[test]
    fn pool_v2_state_keeps_all_three_cases_apart() {
        let dormant = shielded_v2_info(&v2_reply(false)).unwrap();
        let live = shielded_v2_info(&v2_reply(true)).unwrap();

        // 1. Node too old / unreachable → UNAVAILABLE. This is the case the live
        //    mainnet node at 127.0.0.1:8645 actually produces today: it answers
        //    `-32601 method not found`, the poller stores None, and we must NOT
        //    conclude the pool is dormant-and-empty from a question nobody answered.
        assert_eq!(
            PoolState::classify_v2(true, None),
            PoolState::Unavailable,
            "an unanswered query is UNKNOWN, never an empty pool"
        );
        // 2. Offline outranks any stale reading we may still be holding.
        assert_eq!(
            PoolState::classify_v2(false, Some(&live)),
            PoolState::Unavailable,
            "a figure we can no longer confirm is not a figure we may present"
        );
        // 3. Answered + bit 2 unarmed → DORMANT (zero is a consensus proof).
        assert_eq!(
            PoolState::classify_v2(true, Some(&dormant)),
            PoolState::Dormant
        );
        // 4. Answered + armed → ACTIVE (zero would be a real balance).
        assert_eq!(PoolState::classify_v2(true, Some(&live)), PoolState::Active);

        // The three must be DISTINGUISHABLE without colour: distinct words AND
        // distinct shapes. Colour is the third, redundant channel.
        let all = [
            PoolState::Unavailable,
            PoolState::Dormant,
            PoolState::Active,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.word(), b.word(), "states must differ in WORDS");
                assert_ne!(a.glyph(), b.glyph(), "states must differ in SHAPE");
                assert_ne!(a.color(), b.color(), "and in colour too");
                assert_ne!(
                    a.explanation(Pool::V2),
                    b.explanation(Pool::V2),
                    "each state needs its own sentence"
                );
            }
        }

        // Only UNAVAILABLE forbids printing digits. Dormant DOES print — its zero is
        // a real reading, and suppressing it would hide the very fact we want shown.
        assert!(!PoolState::Unavailable.figures_are_real());
        assert!(PoolState::Dormant.figures_are_real());
        assert!(PoolState::Active.figures_are_real());
    }

    #[test]
    fn pool_v1_is_never_dormant_and_never_fakes_a_zero() {
        // v1 has been live since genesis: the only question is whether the node told
        // us anything, so "dormant" is not one of its possible states.
        assert_eq!(PoolState::classify_v1(true, true), PoolState::Active);
        assert_eq!(
            PoolState::classify_v1(true, false),
            PoolState::Unavailable,
            "a node that does not serve sov_getShieldedInfo leaves v1 UNKNOWN, not 0"
        );
        assert_eq!(PoolState::classify_v1(false, true), PoolState::Unavailable);
        assert_ne!(PoolState::classify_v1(true, true), PoolState::Dormant);
        assert_ne!(PoolState::classify_v1(true, false), PoolState::Dormant);
    }

    #[test]
    fn pool_v1_is_never_described_as_post_quantum() {
        // The single most damaging thing this UI could claim. v1 is Orchard/Halo2 and
        // its privacy is discrete-log based; only v2 is post-quantum.
        assert_eq!(Pool::V1.pq_claim(), "NOT post-quantum");
        assert_eq!(Pool::V2.pq_claim(), "post-quantum");
        assert!(
            !Pool::V1.crypto().to_lowercase().contains("kem"),
            "v1 must not name post-quantum primitives"
        );
        assert!(Pool::V2.crypto().contains("ML-KEM-768"));
        // And the v1 "active" sentence must itself carry the disclaimer, because it is
        // the one an operator reads in the normal, everyday case.
        assert!(PoolState::Active
            .explanation(Pool::V1)
            .contains("NOT post-quantum"));
    }

    #[test]
    fn a_v2_send_is_never_offered() {
        // Pool v2 is a hard consensus reject while dormant. The refusal lives in
        // `SendRoute`: the v2 route deliberately fails `is_valid()`, which is what
        // keeps the Send button disabled. This pins that so no future edit can make
        // a v2 send appear possible by "fixing" the route.
        assert!(
            !SendRoute::ShieldedV2Unsupported.is_valid(),
            "a v2 recipient must never enable Send"
        );
    }

    #[test]
    fn truncate_middle_is_char_safe_and_only_elides_when_needed() {
        // A no-op below the threshold: a short address is shown whole, not pointlessly
        // ellipsised.
        assert_eq!(truncate_middle("abc", 2, 2), "abc");
        assert_eq!(truncate_middle("", 4, 4), "");
        // Elision keeps exactly `head` and `tail` characters around one ellipsis.
        let s: String = std::iter::repeat_n('x', 200).collect();
        let t = truncate_middle(&s, 22, 12);
        assert_eq!(t.chars().count(), 22 + 1 + 12);
        assert!(t.contains('…'));
        assert!(t.starts_with(&"x".repeat(22)));
        // MULTI-BYTE safety: slicing by bytes here would panic mid-sequence. The real
        // input is bech32m ASCII, but a panic in a wallet is never acceptable, so the
        // char-boundary guarantee is pinned rather than assumed.
        let wide: String = std::iter::repeat_n('é', 100).collect();
        let tw = truncate_middle(&wide, 5, 5);
        assert_eq!(tw.chars().count(), 11);
        assert!(tw.starts_with("ééééé") && tw.ends_with("ééééé"));
    }

    #[test]
    fn v2_address_export_filename_is_bound_to_the_owner_and_path_safe() {
        // The tag is hex from the chain, but it reaches a filesystem path, so anything
        // that is not a hex digit is dropped rather than trusted.
        assert_eq!(
            v2_address_filename("00ff00ff00ff00ff00ff"),
            "sov-pool-v2-address-00ff00ff00ff00ff.txt"
        );
        for bad in ["../../etc/passwd", "a/b", "..", "", "zzz"] {
            let f = v2_address_filename(bad);
            assert!(
                !f.contains('/') && !f.contains(".."),
                "unsafe name from {bad:?}: {f}"
            );
            assert!(f.ends_with(".txt"));
        }
        // Two different wallets never collide on one file.
        assert_ne!(v2_address_filename("aaaa"), v2_address_filename("bbbb"));
        // A tag with no hex at all still yields a usable, generic name.
        assert_eq!(v2_address_filename("zzz"), "sov-pool-v2-address.txt");
    }

    #[test]
    fn difficulty_formats_without_inventing_a_value() {
        assert_eq!(fmt_difficulty("1234567.8901"), "1,234,567");
        assert_eq!(fmt_difficulty("42"), "42");
        // Absent stays absent — `kv` turns "" into an em-dash. A value the node did
        // not send must never become "0".
        assert_eq!(fmt_difficulty(""), "");
        assert_eq!(fmt_difficulty("   "), "");
        // Unparseable is passed through verbatim rather than prettified into a lie.
        assert_eq!(fmt_difficulty("NaN"), "NaN");
    }

    #[test]
    fn hashrate_units_are_consistent_and_scale_at_the_right_boundaries() {
        assert_eq!(fmt_hashrate(0.0), "0 H/s");
        assert_eq!(fmt_hashrate(999.0), "999 H/s");
        assert_eq!(fmt_hashrate(1_000.0), "1.00 kH/s");
        assert_eq!(fmt_hashrate(1_500_000.0), "1.50 MH/s");
        assert_eq!(fmt_hashrate(2_000_000_000.0), "2.00 GH/s");
    }

    #[test]
    fn link_state_keeps_offline_isolated_and_synced_apart_by_shape() {
        let snap = |online, syncing, peers: Option<usize>| Snapshot {
            online,
            syncing,
            peers,
            ..Default::default()
        };
        assert_eq!(LinkState::of(&snap(false, false, None)), LinkState::Offline);
        assert_eq!(
            LinkState::of(&snap(true, true, Some(3))),
            LinkState::Syncing
        );
        assert_eq!(
            LinkState::of(&snap(true, false, Some(3))),
            LinkState::Connected
        );
        assert_eq!(
            LinkState::of(&snap(true, false, Some(0))),
            LinkState::Isolated,
            "up but peerless is its own state, not 'connected'"
        );
        // Previously OFFLINE, NOT CONNECTED and CONNECTED were all drawn as a filled
        // dot separated only by hue. Shapes must now be distinct.
        let all = [
            LinkState::Offline,
            LinkState::Syncing,
            LinkState::Connected,
            LinkState::Isolated,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.glyph(), b.glyph(), "link states must differ in SHAPE");
                assert_ne!(a.word(), b.word());
            }
        }
    }

    /// Render `add` in a headless egui frame and return every string that was actually
    /// PAINTED, in paint order.
    ///
    /// This is the difference between testing what the code intends and testing what an
    /// operator sees. The claims that matter here — "no zero without its state beside
    /// it", "v1 is never called post-quantum", "unavailable prints a dash, not a digit"
    /// — are claims about pixels, so they are asserted against the text that reached the
    /// painter rather than against the helpers that were supposed to produce it.
    fn painted_text(add: impl Fn(&mut egui::Ui)) -> String {
        let ctx = egui::Context::default();
        // Wide enough to take the two-column branch of the layout.
        let input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 1200.0),
            )),
            ..Default::default()
        };
        let run = |i| {
            ctx.run(i, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| add(ui));
            })
        };
        // Frame 1 establishes layout (egui sizes many widgets from the previous
        // frame's measurements); frame 2 is the one that paints a settled screen.
        let _ = run(input());
        let out = run(input());
        fn walk(shapes: &[egui::Shape], into: &mut String) {
            for s in shapes {
                match s {
                    egui::Shape::Text(t) => {
                        into.push_str(t.galley.text());
                        into.push('\n');
                    }
                    egui::Shape::Vec(v) => walk(v, into),
                    _ => {}
                }
            }
        }
        let mut text = String::new();
        for cs in &out.shapes {
            walk(std::slice::from_ref(&cs.shape), &mut text);
        }
        text
    }

    /// A snapshot shaped like the LIVE mainnet node this was developed against:
    /// online, height 12,570, serving v1 with a real pool value, and NOT serving
    /// `sov_getShieldedV2Info`.
    fn live_like_snapshot() -> Snapshot {
        Snapshot {
            online: true,
            height: Some(12_570),
            shielded_v1_available: true,
            shielded_pool: "11055753450464".to_string(),
            deshieldable_now: Some(11_055_753_450_464),
            deshield_limit: Some(2_100_000_000_000_000),
            deshield_resets_at: Some(12_086),
            shielded_v2: None,
            ..Default::default()
        }
    }

    #[test]
    fn the_two_pool_view_never_prints_a_bare_zero_for_an_unavailable_pool() {
        // THE case the live node produces today: v1 answers, v2 does not exist.
        let snap = live_like_snapshot();
        let out =
            painted_text(|ui| shielded_pools_view(ui, &snap, Some((500_000_000, 3, 12_500)), None));

        // Both pools are present and each carries its state IN WORDS.
        assert!(out.contains("Pool v1"), "v1 column missing:\n{out}");
        assert!(out.contains("Pool v2"), "v2 column missing:\n{out}");
        assert!(out.contains("ACTIVE"), "v1 state word missing:\n{out}");
        assert!(
            out.contains("UNAVAILABLE"),
            "v2 must say UNAVAILABLE when the node does not serve the RPC:\n{out}"
        );
        // ...and the word that would be WRONG here is absent: the node being too old
        // is NOT the same fact as the deployment being dormant.
        assert!(
            !out.contains("NOT ACTIVE YET"),
            "an unanswered query must not be reported as dormancy:\n{out}"
        );
        // The v2 figures are dashes, not digits. This is the honesty invariant: an
        // unavailable pool cannot render a number that looks like a measurement.
        assert!(
            out.contains('—'),
            "unavailable figures must render as the explicit unknown dash:\n{out}"
        );
        assert!(
            out.contains("is UNKNOWN from here"),
            "the unavailable sentence must say the value is unknown, not zero:\n{out}"
        );
        // v1's real figures DID come through, so "unavailable" is not suppressing
        // everything indiscriminately.
        // Grouped thousands, matching every other amount in the app. Rendering this
        // through the input-field formatter produced an ungrouped `110557.53450464`,
        // which only showed up by reading the painted output.
        assert!(
            out.contains("110,557.53450464"),
            "v1's real pool value should render with grouped thousands:\n{out}"
        );
        assert!(
            out.contains("21,000,000"),
            "the de-shield window cap should be grouped too:\n{out}"
        );
        // And the post-quantum labelling is correct in both directions, on screen.
        assert!(
            out.contains("NOT post-quantum"),
            "v1 must be labelled NOT post-quantum on screen:\n{out}"
        );
        assert!(out.contains("Orchard / Halo2"), "v1 crypto named:\n{out}");
        assert!(
            out.contains("ML-KEM-768 / STARK"),
            "v2 crypto named:\n{out}"
        );
    }

    #[test]
    fn a_dormant_pool_v2_says_dormant_and_explains_the_zero() {
        // A node that DOES serve the RPC while bit 2 is unarmed.
        let mut snap = live_like_snapshot();
        snap.shielded_v2 = shielded_v2_info(&v2_reply(false));
        let out = painted_text(|ui| shielded_pools_view(ui, &snap, Some((0, 0, 12_500)), None));

        assert!(
            out.contains("NOT ACTIVE YET"),
            "a dormant pool must say so:\n{out}"
        );
        assert!(
            !out.contains("UNAVAILABLE"),
            "an ANSWERED query is not unavailable:\n{out}"
        );
        // The zero is present AND explained — this is the sentence that stops an
        // operator concluding their funds vanished.
        assert!(
            out.contains("bit 2") && out.contains("NOT a balance that went missing"),
            "a dormant zero must be explained beside it:\n{out}"
        );
        assert!(
            out.contains("No v2 note can exist yet"),
            "the 'your balance' line must explain WHY it is not a number:\n{out}"
        );
        // Nothing on this surface may suggest a v2 send is possible.
        let lower = out.to_lowercase();
        assert!(
            !lower.contains("send to pool v2") && !lower.contains("shield to v2"),
            "no v2 send may be offered while dormant:\n{out}"
        );
    }

    #[test]
    fn an_unscanned_v1_wallet_shows_unknown_rather_than_a_zero_balance() {
        // The trap: a wallet that has not been scanned has an UNKNOWN balance. Showing
        // "0 XUS" there is how a user with real shielded funds concludes they are gone.
        let snap = live_like_snapshot();
        let out = painted_text(|ui| shielded_pools_view(ui, &snap, None, None));
        assert!(
            out.contains("Not scanned yet"),
            "an unscanned wallet must say so:\n{out}"
        );
        assert!(
            out.contains("which is not the same as zero"),
            "and must say plainly that unknown is not zero:\n{out}"
        );
    }

    #[test]
    fn a_real_v2_address_is_the_size_the_ui_claims_and_matches_the_cli() {
        // Every design decision in the receive view rests on the address being ~1.8 KB
        // of bech32m. That number is asserted here against a REAL derivation rather
        // than trusted from a comment — if the encoding ever changes, the reasoning
        // ("no QR code, elide the middle, export to a file") has to be revisited, and
        // this test is what forces that.
        let seed = [7u8; 32];
        let key = PqShieldedKey::from_leaf_seed(&seed);
        let addr = encode_shielded_v2(&key.address());

        assert!(addr.starts_with("xusq1"), "unexpected HRP: {}", &addr[..16]);
        let n = addr.chars().count();
        assert_eq!(
            n, 1957,
            "the v2 address is {n} chars; the receive view's design assumes 1,957"
        );
        // Far past anything a QR code can carry legibly, which is the documented
        // reason there is no QR: even alphanumeric mode tops out well below this.
        assert!(n > 1_500);

        // Same seed ⇒ same address, every time. This is what lets an operator record
        // the address today and trust it after the pool activates.
        let again = encode_shielded_v2(&PqShieldedKey::from_leaf_seed(&seed).address());
        assert_eq!(addr, again, "derivation must be deterministic");
        // A different seed must give a different address.
        let other = encode_shielded_v2(&PqShieldedKey::from_leaf_seed(&[8u8; 32]).address());
        assert_ne!(addr, other);

        // The owner tag is the short fingerprint the UI asks a human to compare, so it
        // must actually be comparable: 32 bytes as 64 hex characters.
        let tag = hex_lower(&key.owner_tag().to_bytes());
        assert_eq!(tag.len(), 64, "owner tag must be 32 bytes of hex");
        // The elided form the view shows keeps both ends of the real address.
        let shown = truncate_middle(&addr, 22, 12);
        assert!(shown.starts_with("xusq1"));
        assert!(addr.ends_with(shown.rsplit('…').next().unwrap()));
    }

    // ── Blockspace auction (v0.1.98) ────────────────────────────────────────

    /// A live, CONTESTED auction — the state every auction UI test below runs
    /// against, so none of them can pass merely because the feature declined to
    /// engage (a panel that renders nothing renders no mistakes either).
    fn contested_auction() -> Auction {
        let a = Auction::from_rpc(
            Some(&json!({
                "txCount": 5u64,
                "maxBlockTxs": 4u64,
                "floorGrains": "5000",
                "poolFloorGrains": "0",
                "buckets": [
                    {"feeRateGrains": "900000", "txCount": 2u64, "totalBytes": 500u64},
                    {"feeRateGrains": "5000",   "txCount": 3u64, "totalBytes": 750u64},
                ],
            })),
            Some(&json!({
                "txCount": 5u64,
                "queuedCount": 2u64,
                "maxBlockTxs": 4u64,
                "nextBlockFloorGrains": "5000",
                "poolFloorGrains": "0",
                "oldestPendingAgeMs": 96_000u64,
            })),
            true,
        );
        assert!(
            a.available && a.fee_auction_active && a.next_block_floor_grains == 5_000,
            "the fixture must be LIVE and CONTESTED, or these tests prove nothing"
        );
        a
    }

    /// "Blockspace is free" and "we could not ask what blockspace costs" are
    /// opposite advice. They must never paint the same.
    #[test]
    fn the_auction_readout_never_renders_unknown_as_free() {
        // An old / unreachable node: the floor is UNKNOWN.
        let blind = Auction::from_rpc(None, None, true);
        let out = painted_at_width(900.0, |ui| auction_readout(ui, &blind));
        assert!(out.contains("UNKNOWN"), "no pressure word:\n{out}");
        assert!(
            out.contains("the floor is unknown, not zero"),
            "the unknown case must say so in words:\n{out}"
        );
        assert!(
            !out.contains("CLEAR"),
            "unknown must never read as clear:\n{out}"
        );
        assert!(
            out.contains('—'),
            "unknown figures render as em-dashes:\n{out}"
        );

        // A node that ANSWERS with a zero floor really is clear — and says a
        // different word, with a different figure.
        let clear = Auction::from_rpc(
            None,
            Some(&json!({"txCount": 0u64, "queuedCount": 0u64, "nextBlockFloorGrains": "0"})),
            true,
        );
        let out = painted_at_width(900.0, |ui| auction_readout(ui, &clear));
        assert!(out.contains("CLEAR"), "{out}");
        assert!(!out.contains("the floor is unknown"), "{out}");

        // And a contested one names its price and flags the pressure.
        let out = painted_at_width(900.0, |ui| auction_readout(ui, &contested_auction()));
        assert!(out.contains("CONTESTED"), "{out}");
        assert!(out.contains("NEXT-BLOCK FLOOR"), "{out}");
        assert!(
            out.contains("0.00005"),
            "the floor in XUS, not grains:\n{out}"
        );
        assert!(out.contains("96"), "oldest wait in seconds:\n{out}");

        // A chain where tips are not legal must SAY so, not silently offer one.
        let dormant = Auction::from_rpc(
            None,
            Some(&json!({"txCount": 9u64, "nextBlockFloorGrains": "5000"})),
            false,
        );
        let out = painted_at_width(900.0, |ui| auction_readout(ui, &dormant));
        assert!(out.contains("TIPS DORMANT"), "{out}");
    }

    /// Every suggested tip accounts for itself, in XUS, naming the reading it came
    /// from. A default the spender cannot audit is a default spending their money
    /// on their behalf.
    #[test]
    fn the_suggested_tip_always_explains_itself() {
        let a = contested_auction();
        let why = tip_rationale(&a);
        assert!(why.contains("0.00006"), "names the bid it suggests: {why}");
        assert!(
            why.contains("0.00005"),
            "and the floor it derives from: {why}"
        );
        assert!(
            !why.contains("grains"),
            "figures are XUS, not raw grains: {why}"
        );

        let clear = Auction::from_rpc(None, Some(&json!({"nextBlockFloorGrains": "0"})), true);
        assert!(
            tip_rationale(&clear).contains("the next block still has room"),
            "a zero suggestion must say WHY it is zero"
        );
        let blind = Auction::from_rpc(None, None, true);
        assert!(
            tip_rationale(&blind).contains("no bid is invented"),
            "an unknown pool must not be dressed up as a priced one"
        );
    }

    /// The outlook and the histogram must show an OUTBID send as outbid — this is
    /// the readout that turns "my payment vanished" into "my bid is too low".
    #[test]
    fn an_outbid_send_is_shown_as_outbid_and_a_winning_one_as_winning() {
        let a = contested_auction();

        // A zero bid on a contested pool: outbid, with the competition drawn.
        let out = painted_at_width(900.0, |ui| bid_outlook_view(ui, &a, 0));
        assert!(out.contains("outbid"), "{out}");
        assert!(out.contains("ahead of this one"), "{out}");
        assert!(out.contains("WHAT YOU ARE BIDDING AGAINST"), "{out}");
        assert!(
            out.contains("ahead of you"),
            "the dearer bucket is marked:\n{out}"
        );

        // The suggested bid clears the floor, and the histogram reclassifies the
        // bucket it now outbids.
        let tip = a.suggested_tip_grains();
        let out = painted_at_width(900.0, |ui| bid_outlook_view(ui, &a, tip));
        assert!(out.contains("clears the floor"), "{out}");
        assert!(!out.contains("outbid"), "{out}");
        assert!(out.contains("below your bid"), "{out}");
        // The 0.009 XUS bucket is still above the suggestion, so it stays ahead.
        assert!(out.contains("ahead of you"), "{out}");
    }

    /// The bump modal must make "did I just pay twice?" impossible to believe.
    ///
    /// This is the single most dangerous misunderstanding the whole feature makes
    /// available, so the words that rule it out are pinned here rather than left
    /// to survive the next edit by luck.
    #[test]
    fn the_bump_modal_makes_double_spend_anxiety_impossible() {
        let a = contested_auction();
        let sent = SentTx {
            txid: "ab".repeat(32),
            from_account: "usa.reserve.sov".to_string(),
            to: "ecb.reserve.sov".to_string(),
            amount_grains: 250_000_000, // 2.5 XUS
            nonce: 41,
            tip_grains: 1_000,
            shielded_route: false,
            submitted_ms: 0,
            state: SendState::Pending,
            note: String::new(),
        };
        let new_tip = auction::bump_tip_grains(sent.tip_grains, &a);
        let out = painted_at_width(700.0, |ui| bump_explainer(ui, &sent, new_tip));

        for needle in [
            "NOT A SECOND SEND",
            "THE SAME PAYMENT",
            "THE SAME nonce slot",
            "can only ever apply one of them",
            "paid ONCE, either way",
            "41 (unchanged)",
            "only the tip increase; the amount is not spent twice",
            "receives the amount exactly once",
            "can no longer confirm",
        ] {
            assert!(out.contains(needle), "missing {needle:?} from:\n{out}");
        }
        // The EXTRA cost shown is the tip delta — not the amount again.
        assert!(
            out.contains(&xus(&new_tip.saturating_sub(sent.tip_grains).to_string())),
            "the extra cost must be the tip increase:\n{out}"
        );
        // And the replacement really is admissible under the pool's own rule.
        assert!(new_tip >= sent.tip_grains + auction::MIN_RBF_BUMP_GRAINS);

        // A shielded route re-proves its bundle — say so, and still say ONE payment.
        let out = painted_at_width(700.0, |ui| {
            bump_explainer(
                ui,
                &SentTx {
                    shielded_route: true,
                    ..sent.clone()
                },
                new_tip,
            )
        });
        assert!(out.contains("re-proves the bundle"), "{out}");
        assert!(out.contains("Still one payment"), "{out}");
    }

    /// Render at an explicit width and return the painted text.
    fn painted_at_width(w: f32, add: impl Fn(&mut egui::Ui)) -> String {
        let ctx = egui::Context::default();
        let input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(w, 2400.0),
            )),
            ..Default::default()
        };
        let run = |i| {
            ctx.run(i, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| add(ui));
                });
            })
        };
        let _ = run(input());
        let out = run(input());
        let mut text = String::new();
        fn walk(shapes: &[egui::Shape], into: &mut String) {
            for s in shapes {
                match s {
                    egui::Shape::Text(t) => {
                        into.push_str(t.galley.text());
                        into.push('\n');
                    }
                    egui::Shape::Vec(v) => walk(v, into),
                    _ => {}
                }
            }
        }
        for cs in &out.shapes {
            walk(std::slice::from_ref(&cs.shape), &mut text);
        }
        text
    }

    #[test]
    fn the_two_pool_view_reflows_across_the_whole_window_range() {
        // The owner's report was that the pool areas "seemed off" and were not
        // resizable. The table must survive the entire range the window can take —
        // from the 720x480 minimum through a maximised display — never losing a pool,
        // a state word, or the post-quantum disclaimer.
        let snap = live_like_snapshot();
        let mut counts = Vec::new();
        for w in [560.0, 700.0, 900.0, 1200.0, 1800.0, 2560.0] {
            let out = painted_at_width(w, |ui| {
                shielded_pools_view(ui, &snap, Some((500_000_000, 3, 12_500)), None)
            });
            for needle in [
                "Pool v1",
                "Pool v2",
                "ACTIVE",
                "UNAVAILABLE",
                "NOT post-quantum",
                "POOL TOTAL",
                "NULLIFIERS SPENT",
                "ANCHOR",
                "110,557.53450464",
            ] {
                assert!(
                    out.contains(needle),
                    "at width {w}, {needle:?} was not painted:\n{out}"
                );
            }
            counts.push((
                w,
                out.matches("Pool v1").count(),
                out.matches("Pool v2").count(),
                out.matches("POOL TOTAL").count(),
            ));
        }
        // Reflowing must not duplicate or drop anything: whatever the layout, each
        // pool is named the same number of times and each metric row appears once per
        // pool. Collapsing to stacked is a change of ARRANGEMENT, not of content.
        let first = counts[0];
        for c in &counts {
            assert_eq!(
                (c.1, c.2, c.3),
                (first.1, first.2, first.3),
                "content changed when reflowing: {counts:?}"
            );
        }
    }

    #[test]
    fn the_four_kinds_of_absence_stay_distinct_in_the_table() {
        // Four different reasons a cell has no number, which must not collapse into
        // one ambiguous blank:
        //   —                 the node did not answer (unknown)
        //   not reported      the node answered; this RPC does not carry the figure
        //   cannot exist yet  consensus forbids it (dormant v2)
        //   a real figure     an actual reading
        let mut snap = live_like_snapshot();

        // v1 live, v2 absent: v1's anchor is "not reported" (its RPC lacks it), while
        // v2's is a bare dash (nobody answered). Conflating these would tell an
        // operator their live v1 pool is degraded.
        let out = painted_at_width(1400.0, |ui| {
            shielded_pools_view(ui, &snap, Some((500_000_000, 3, 12_500)), None)
        });
        assert!(
            out.contains("not reported"),
            "v1's un-exposed figures must say 'not reported':\n{out}"
        );
        assert!(
            out.contains('—'),
            "v2's unanswered figures must be the unknown dash:\n{out}"
        );
        assert!(
            !out.contains("cannot exist yet"),
            "nothing is provably impossible when v2 is merely UNAVAILABLE:\n{out}"
        );

        // Now v2 answers and is dormant: its figures become provably impossible,
        // which is a stronger and more reassuring statement than "unknown".
        snap.shielded_v2 = shielded_v2_info(&v2_reply(false));
        let out = painted_at_width(1400.0, |ui| {
            shielded_pools_view(ui, &snap, Some((500_000_000, 3, 12_500)), None)
        });
        assert!(
            out.contains("cannot exist yet"),
            "a dormant v2 pool's figures cannot exist, not merely unknown:\n{out}"
        );
        assert!(
            out.contains("NOT ACTIVE YET"),
            "and the state word must be present:\n{out}"
        );
    }

    #[test]
    fn the_two_pool_view_survives_a_narrow_window() {
        // The minimum window is 720x480. Below ~720 px of content width the view
        // stacks to one column rather than squeezing two unreadable ones — and, more
        // importantly, every state word and every explanation must still be painted.
        let snap = live_like_snapshot();
        let ctx = egui::Context::default();
        let input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680.0, 900.0),
            )),
            ..Default::default()
        };
        let run = |i| {
            ctx.run(i, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        shielded_pools_view(ui, &snap, None, None);
                    });
                });
            })
        };
        let _ = run(input());
        let out = run(input());
        let mut text = String::new();
        fn walk(shapes: &[egui::Shape], into: &mut String) {
            for s in shapes {
                match s {
                    egui::Shape::Text(t) => {
                        into.push_str(t.galley.text());
                        into.push('\n');
                    }
                    egui::Shape::Vec(v) => walk(v, into),
                    _ => {}
                }
            }
        }
        for cs in &out.shapes {
            walk(std::slice::from_ref(&cs.shape), &mut text);
        }
        assert!(text.contains("Pool v1"), "v1 lost when narrow:\n{text}");
        assert!(text.contains("Pool v2"), "v2 lost when narrow:\n{text}");
        assert!(
            text.contains("UNAVAILABLE"),
            "the state word must survive a narrow window:\n{text}"
        );
        assert!(
            text.contains("NOT post-quantum"),
            "the v1 disclaimer must survive a narrow window:\n{text}"
        );
    }

    #[test]
    fn the_v2_receive_block_discloses_dormancy_before_the_address() {
        // The address is derivable today and payable never (while dormant), so the
        // disclosure has to come FIRST — an operator must not read an address, copy
        // it, hand it out, and only then learn nothing can be sent to it.
        let addr = format!("xusq1{}", "q".repeat(1_952));
        let tag = "ab".repeat(32);
        for state in [PoolState::Dormant, PoolState::Unavailable] {
            let mut copied = false;
            let out = painted_text(|ui| {
                let mut c = false;
                v2_address_block(ui, &addr, &tag, state, &mut c);
            });
            let _ = &mut copied;

            let state_at = out.find(state.word()).unwrap_or(usize::MAX);
            let addr_at = out.find("ADDRESS").unwrap_or(0);
            assert!(
                state_at < addr_at,
                "{:?}: the state must be painted before the address:\n{out}",
                state
            );
            // The address's LENGTH is stated, so the operator understands why it is
            // elided and why there is no QR code.
            assert!(
                out.contains("1,957 characters"),
                "{:?}: the address length must be stated:\n{out}",
                state
            );
            assert!(
                out.contains("No QR code is shown"),
                "{:?}: the missing QR must be explained, not silently absent:\n{out}",
                state
            );
            // The elided form is shown, never the full 1,957 characters inline.
            assert!(out.contains('…'), "{:?}: elision missing:\n{out}", state);
            // The owner tag is the eye-checkable fingerprint.
            assert!(
                out.contains("OWNER TAG") && out.contains(&tag),
                "{:?}: the owner tag must be shown in full:\n{out}",
                state
            );
            // And the non-active states say the address is not payable yet.
            assert!(
                out.contains("no one can pay it until the pool activates"),
                "{:?}: unpayability must be stated:\n{out}",
                state
            );
        }
    }

    #[test]
    fn the_node_status_band_states_the_link_in_words_when_offline() {
        // The degraded screen an operator actually hits. Nothing may render as a
        // confident number when no node answered.
        let out = painted_text(|ui| node_panel(ui, &Snapshot::default()));
        assert!(out.contains("OFFLINE"), "offline must be stated:\n{out}");
        assert!(
            out.contains("No node is answering"),
            "and explained:\n{out}"
        );
        assert!(
            out.contains('—'),
            "height/peers/mempool must be dashes, not zeros:\n{out}"
        );
        // A zero here would read as "the chain is at height 0" / "no transactions".
        assert!(
            !out.contains("CONNECTED"),
            "offline must not also claim connectivity:\n{out}"
        );
    }

    #[test]
    fn the_pool_state_palette_works_in_both_themes() {
        // Light mode was historically an afterthought; the two new signal colours must
        // be real light-mode values, not the dark ones reused.
        for dark in [true, false] {
            palette::set_dark(dark);
            let (d, u) = (palette::dormant(), palette::unknown());
            assert_ne!(d, u, "dormant and unknown must not collide (dark={dark})");
            assert_ne!(d, palette::warning(), "dormant is not a warning");
            assert_ne!(d, palette::error(), "dormant is not an error");
            assert_ne!(u, palette::text(), "unknown must be dimmer than body text");
        }
        palette::set_dark(true);
        let dark_pair = (palette::dormant(), palette::unknown());
        palette::set_dark(false);
        assert_ne!(dark_pair.0, palette::dormant(), "dormant differs by mode");
        assert_ne!(dark_pair.1, palette::unknown(), "unknown differs by mode");
        palette::set_dark(true);
    }

    // ── External-miner telemetry ─────────────────────────────────────────────────
    //
    // The bug these pin: Station read mining only from `local_hashrate` (its OWN
    // in-process miner), so an operator running the standalone XUS Miner saw "SYNCED"
    // while actively mining. Station now sees the external miner through the on-chain
    // registry (`sov_getMiners`), cross-referenced against the operator's accounts.

    fn miner(account: &str, blocks: u64, last: u64) -> MinerRow {
        MinerRow {
            account: account.to_string(),
            blocks,
            first: 0,
            last,
        }
    }

    fn owner_set(accounts: &[&str]) -> HashSet<String> {
        accounts.iter().map(|a| a.to_string()).collect()
    }

    /// A first-poll assessment (no prior baseline, no prior active state). The common
    /// shape for the single-signal tests below.
    fn assess_fresh(
        miners: &[MinerRow],
        owner: &HashSet<String>,
        head: u64,
        prev_blocks: &HashMap<String, u64>,
    ) -> MiningAssessment {
        assess_external_mining(miners, owner, Some(head), prev_blocks, &HashSet::new())
    }

    fn facts_of(a: &MiningAssessment) -> &ExternalMinerFacts {
        a.facts.as_ref().expect("owner has a registry row")
    }

    #[test]
    fn a_new_block_since_the_last_poll_is_the_definitive_mining_signal() {
        // Head is far ahead of `last` (would fail the recency window on its own), but
        // blocksMined ROSE since the previous poll — that is proof of mining now.
        let owner = owner_set(&["myminer"]);
        let miners = vec![miner("myminer", 51, 9_000)];
        let mut prev = HashMap::new();
        prev.insert("myminer".to_string(), 50u64);

        let a = assess_fresh(&miners, &owner, 20_000, &prev);
        assert!(
            a.facts.as_ref().unwrap().active,
            "a NEW block since the last poll must read as actively mining, even far behind the head"
        );
        assert!(a.active_accounts.contains("myminer"));
        assert_eq!(facts_of(&a).blocks_won, 51);
        assert_eq!(facts_of(&a).account, "myminer");
    }

    #[test]
    fn a_stale_registry_row_reads_as_not_mining() {
        // Mined once at 5,531; head is 13,264 and blocksMined has NOT moved. Idle now.
        // A LONE registry row is 100% share ⇒ the window is the 30-block floor.
        let owner = owner_set(&["myminer"]);
        let miners = vec![miner("myminer", 3, 5_531)];
        let mut prev = HashMap::new();
        prev.insert("myminer".to_string(), 3u64); // unchanged since last poll

        let a = assess_fresh(&miners, &owner, 13_264, &prev);
        assert!(
            !facts_of(&a).active,
            "a miner last seen thousands of blocks ago with no new win is NOT mining"
        );
        assert!(a.active_accounts.is_empty());
        // The facts are still surfaced so the tab can show "idle, last won #5,531".
        assert_eq!(facts_of(&a).last_seen, 5_531);
    }

    #[test]
    fn the_min_window_floor_holds_an_already_active_high_share_miner() {
        // The HOLD window only applies to an account ALREADY lit by a witnessed win, so we
        // pass `prev_active = {myminer}` (the hysteresis state). A lone (100%-share) miner
        // uses the 30-block floor. Inclusive at the edge; one past it (no new win) drops out.
        let owner = owner_set(&["myminer"]);
        let head = 13_264u64;
        let mut prev = HashMap::new();
        prev.insert("myminer".to_string(), 40u64); // no delta this poll — pure hold path
        let active_prev = owner_set(&["myminer"]); // was mining last poll

        let at_edge = vec![miner("myminer", 40, head - EXTERNAL_MINING_MIN_WINDOW)];
        assert!(
            facts_of(&assess_external_mining(
                &at_edge,
                &owner,
                Some(head),
                &prev,
                &active_prev
            ))
            .active,
            "an already-active miner's hold window is inclusive at its edge"
        );
        let past_edge = vec![miner("myminer", 40, head - EXTERNAL_MINING_MIN_WINDOW - 1)];
        assert!(
            !facts_of(&assess_external_mining(
                &past_edge,
                &owner,
                Some(head),
                &prev,
                &active_prev
            ))
            .active,
            "one block past the hold window (and no new win) goes idle"
        );
        // And WITHOUT the prior-active state, the same at-edge row is NOT lit from cold —
        // recency alone never enters MINING.
        assert!(
            !facts_of(&assess_fresh(&at_edge, &owner, head, &prev)).active,
            "recency at the window edge must NOT enter MINING with no witnessed win"
        );
    }

    #[test]
    fn cold_start_recent_win_but_no_witnessed_delta_is_never_mining() {
        // THE load-bearing test — the exact bug shipped in v0.2.4. At a COLD START both
        // `prev_blocks` and `prev_active` are empty, so NOTHING has been witnessed yet. An
        // owner account that won a block shortly before launch still has a `lastSeen`
        // comfortably inside every recency window — but a recent `lastSeen` proves only a
        // PAST win, never present activity. Recency ALONE must NEVER assert MINING.
        //
        // This mirrors the reported `a35755d3…` case: it won ~30 blocks (~75 min) before
        // Station launched and then STOPPED, yet Station showed gold MINING at cold start.
        // On the pre-fix code this asserted `active == true`; the fix makes it impossible.
        let owner = owner_set(&["a35755d3"]);
        let head = 11_260u64;
        // A LONE row is 100% share ⇒ the 30-block floor window; last win 30 blocks back is
        // INSIDE it, so the old recency path would (wrongly) have fired.
        let miners = vec![miner("a35755d3", 8, head - 30)];
        let empty_blocks: HashMap<String, u64> = HashMap::new();
        let empty_active: HashSet<String> = HashSet::new();

        let a = assess_external_mining(&miners, &owner, Some(head), &empty_blocks, &empty_active);

        // Liveness FIRST: the feature actually RAN — the owner row was found and assessed,
        // so a NOT-mining verdict is a real decision, not the code silently declining.
        assert!(
            a.facts.is_some(),
            "the owner's registry row must be present and assessed (feature ran)"
        );
        assert_eq!(
            facts_of(&a).last_seen,
            head - 30,
            "the last-won fact is captured"
        );
        assert!(
            facts_of(&a).network_blocks > 0,
            "a real share denominator was computed"
        );

        // The fix: no witnessed win ⇒ NOT mining, even though `lastSeen` is inside the window.
        assert!(
            !facts_of(&a).active,
            "a recently-won-then-stopped miner at COLD START must read NOT mining — \
             recency may never ENTER the MINING state; only a witnessed win can"
        );
        assert!(
            a.active_accounts.is_empty(),
            "nothing is attributed as active at cold start"
        );
    }

    #[test]
    fn a_stale_miner_is_idle_on_the_first_poll_too() {
        // A far-behind row with no witnessed delta is idle on the first poll — this was
        // already true before the fix, and remains true (recency cannot save it either).
        let owner = owner_set(&["myminer"]);
        let head = 13_264u64;
        let empty = HashMap::new();
        let a = assess_fresh(&[miner("myminer", 40, head - 500)], &owner, head, &empty);
        assert!(
            a.facts.is_some(),
            "the owner row is present and assessed (feature ran)"
        );
        assert!(
            !facts_of(&a).active,
            "a stale miner is idle on the first poll — no false positive from an absent baseline"
        );
    }

    #[test]
    fn cold_start_surfaces_the_last_won_fact_without_asserting_mining() {
        // The honest cold-start DISPLAY: an owner row exists but no win is witnessed yet, so
        // Station shows the FACT — "last won N blocks ago" — under a neutral SYNCED/SOLO
        // headline, never the gold MINING claim. Here we verify the FACTS that feed that
        // display: not-active, and a correct "blocks ago" distance the UI renders verbatim.
        let owner = owner_set(&["home"]);
        let head = 11_260u64;
        let last_won = head - 42;
        let miners = vec![miner("home", 8, last_won), miner("rest", 92, head)];
        let a = assess_external_mining(
            &miners,
            &owner,
            Some(head),
            &HashMap::new(),
            &HashSet::new(),
        );
        let f = facts_of(&a);
        // Liveness: the row was assessed, so the facts below are a real reading.
        assert!(
            !f.active,
            "cold start with no witnessed win is NOT the MINING assertion"
        );
        assert_eq!(f.last_seen, last_won);
        assert_eq!(f.head, head);
        // This is exactly the "N blocks ago" the Mining tab and heartbeat chip render.
        assert_eq!(
            f.head.saturating_sub(f.last_seen),
            42,
            "\"last won 42 blocks ago\""
        );

        // And the whole-Snapshot verdict the heartbeat reads is neutral, not MINING.
        let snap = Snapshot {
            online: true,
            syncing: false,
            peers: Some(3),
            local_hashrate: 0,
            external_miner: Some(f.clone()),
            ..Default::default()
        };
        assert!(
            !snap.is_mining(),
            "an unwitnessed owner row must not read as mining"
        );
        assert_eq!(
            BeatState::of(&snap),
            BeatState::Synced,
            "the headline is the neutral SYNCED, never gold MINING, at cold start"
        );
    }

    #[test]
    fn a_station_restart_reverts_to_last_won_until_the_next_witnessed_win() {
        // Session A witnesses a win and lights MINING; the miner then STOPS. Session B is a
        // fresh Station (empty prior state) watching the SAME registry: it must revert to
        // "last won N ago" (not mining), because a restart has witnessed nothing yet. This
        // is the honest behavior, not a regression — the light returns only on a new win.
        let owner = owner_set(&["home"]);
        let won_at = 5_000u64;

        // Session A, poll that witnesses the win (19 → 20): MINING on.
        let prev_a: HashMap<String, u64> =
            [("home".to_string(), 19u64), ("rest".to_string(), 80u64)]
                .into_iter()
                .collect();
        let miners_a = vec![miner("home", 20, won_at), miner("rest", 80, won_at)];
        let a = assess_external_mining(&miners_a, &owner, Some(won_at), &prev_a, &HashSet::new());
        assert!(facts_of(&a).active, "session A witnessed the win ⇒ MINING");

        // Session B: fresh process, empty prior state, head has moved on with NO new home win.
        let head_b = won_at + 5;
        let miners_b = vec![miner("home", 20, won_at), miner("rest", 85, head_b)];
        let b = assess_external_mining(
            &miners_b,
            &owner,
            Some(head_b),
            &HashMap::new(), // cold: no witnessed baseline
            &HashSet::new(), // cold: no prior active state
        );
        assert!(
            !facts_of(&b).active,
            "after a restart the account reverts to NOT mining until the next witnessed win"
        );
        assert_eq!(
            facts_of(&b).head.saturating_sub(facts_of(&b).last_seen),
            5,
            "and it truthfully reads \"last won 5 blocks ago\""
        );
    }

    // ── The core fix: a SMALL-SHARE miner reads MINING STEADILY between wins ──────────
    //
    // A ~2%-share home miner wins on average only every ~50 blocks (~2 h at the 2.5-min
    // cadence). A flat 30-block window would drop it to "not mining" for most of that gap
    // — the exact reported symptom. The share-aware window + hysteresis must hold it lit
    // continuously across the whole gap, then let a truly STOPPED miner go idle.

    #[test]
    fn a_small_share_miner_reads_mining_steadily_across_the_gap_between_wins() {
        // 20 of 1000 registry blocks ⇒ 2% share ⇒ expected gap ≈ 50 blocks. The other 980
        // belong to a stranger (not in the owner set), so the network denominator is real.
        let owner = owner_set(&["home"]);
        let won_at = 5_000u64;
        let miners = |head: u64| vec![miner("home", 20, won_at), miner("rest", 980, head)];

        // Poll 1: a WITNESSED win turns MINING on — home's blocksMined rises 19 → 20 versus
        // the previous poll's baseline (recency alone never enters). From here the head
        // walks forward with NO further win, exercising the pure HOLD path.
        let mut prev_blocks: HashMap<String, u64> =
            [("home".to_string(), 19u64), ("rest".to_string(), 980u64)]
                .into_iter()
                .collect();
        let mut prev_active: HashSet<String> = HashSet::new();
        let mut lit_every_block = true;
        // Walk the head forward across ~2.4 expected gaps (120 blocks) with NO new win —
        // a perfectly ordinary dry spell for a 2% miner — carrying the hysteresis state
        // exactly as the poller does.
        for head in won_at..=(won_at + 120) {
            let a = assess_external_mining(
                &miners(head),
                &owner,
                Some(head),
                &prev_blocks,
                &prev_active,
            );
            if !a.facts.as_ref().unwrap().active {
                lit_every_block = false;
            }
            prev_active = a.active_accounts;
            prev_blocks = miners(head)
                .iter()
                .map(|m| (m.account.clone(), m.blocks))
                .collect();
        }
        assert!(
            lit_every_block,
            "a 2%-share miner must stay MINING for the WHOLE ~120-block gap between wins, \
             never flickering off — this is the bug being fixed"
        );

        // Now it truly STOPS: no more wins ever. Keep walking the head far past the idle
        // window (6 gaps ≈ 300 blocks) and it must eventually read idle.
        let mut idle_seen = false;
        for head in (won_at + 121)..=(won_at + 900) {
            let a = assess_external_mining(
                &miners(head),
                &owner,
                Some(head),
                &prev_blocks,
                &prev_active,
            );
            if !a.facts.as_ref().unwrap().active {
                idle_seen = true;
                break;
            }
            prev_active = a.active_accounts;
            prev_blocks = miners(head)
                .iter()
                .map(|m| (m.account.clone(), m.blocks))
                .collect();
        }
        assert!(
            idle_seen,
            "a stopped miner must eventually go idle once its last win is many expected \
             gaps behind the head"
        );
    }

    #[test]
    fn a_fresh_win_relights_a_small_share_miner_instantly() {
        // Between the recency window and hysteresis, the delta path is the instant confirm:
        // the moment blocksMined ticks up, the miner is MINING regardless of the window.
        let owner = owner_set(&["home"]);
        let head = 9_000u64;
        // Was idle (last win 400 blocks back, well past any window), but just won again.
        let miners = vec![miner("home", 21, head), miner("rest", 979, head)];
        let mut prev = HashMap::new();
        prev.insert("home".to_string(), 20u64); // it had 20 last poll; now 21
        prev.insert("rest".to_string(), 979u64);
        let a = assess_external_mining(&miners, &owner, Some(head), &prev, &HashSet::new());
        assert!(
            facts_of(&a).active,
            "a brand-new win relights the miner immediately, no window required"
        );
    }

    #[test]
    fn mining_is_attributed_only_to_the_operators_own_accounts() {
        let head = 13_264u64;
        // A WITNESSED win for our account (39 → 40) so it legitimately reads MINING; the
        // stranger's baseline is unchanged. Entry is a witnessed delta, never recency.
        let prev: HashMap<String, u64> = [
            ("myminer".to_string(), 39u64),
            ("stranger".to_string(), 900u64),
        ]
        .into_iter()
        .collect();
        // Two miners at the head: one is ours, one is a stranger's.
        let miners = vec![miner("stranger", 900, head), miner("myminer", 40, head - 3)];

        // A stranger mining to their OWN account is invisible to us.
        assert!(
            assess_fresh(&miners, &owner_set(&["notme"]), head, &prev)
                .facts
                .is_none(),
            "no owner row ⇒ Station reports nothing, never a false mining"
        );

        // With our account in the set, we detect OUR miner — not the stranger's.
        let a = assess_fresh(&miners, &owner_set(&["myminer"]), head, &prev);
        assert!(facts_of(&a).active, "our miner just won a block ⇒ mining");
        assert_eq!(
            facts_of(&a).account,
            "myminer",
            "the attributed miner is ours, not the stranger's"
        );
        assert_eq!(
            facts_of(&a).blocks_won,
            40,
            "only OUR blocks are counted as won"
        );
        assert_eq!(
            facts_of(&a).network_blocks,
            940,
            "the share denominator is the whole registry (900 + 40)"
        );
    }

    #[test]
    fn a_linked_but_foreign_account_never_lights_the_chip() {
        // Defect 2: `set_operate_as` links a name for DISPLAY even when it is bound to a
        // DIFFERENT key — but such a name is NOT added to `mining_accounts`, so the owner
        // set passed here excludes it. Model exactly that: a foreign account ("boss") is
        // busily mining at the head, while our verified account ("mine") is idle. The chip
        // must NOT light off the boss's hashrate.
        let head = 20_000u64;
        let prev = HashMap::new();
        let miners = vec![
            miner("boss", 5_000, head),      // foreign, actively winning
            miner("mine", 1, head - 10_000), // ours, long idle
        ];
        // The owner set is the VERIFIED-control set (mining_accounts), which excludes the
        // foreign linked name entirely.
        let owner = owner_set(&["mine"]);
        let a = assess_fresh(&miners, &owner, head, &prev);
        assert!(
            !facts_of(&a).active,
            "foreign hashrate on a linked-but-not-controlled account must never read MINING"
        );
        assert!(
            !a.active_accounts.contains("boss"),
            "a foreign account is never even considered for attribution"
        );
    }

    #[test]
    fn multiple_owner_accounts_are_summed_and_the_main_miner_is_named() {
        let head = 100u64;
        // `small` just WON (1 → 2) so it reads MINING; `big` (last win 40 blocks back, no
        // delta, not previously active) does not — but it has won the most blocks, so it is
        // still named the main miner. Entry is the witnessed win, never recency.
        let prev: HashMap<String, u64> = [("small".to_string(), 1u64), ("big".to_string(), 30u64)]
            .into_iter()
            .collect();
        let miners = vec![miner("small", 2, head - 1), miner("big", 30, head - 40)];
        let owner = owner_set(&["small", "big"]);
        let a = assess_fresh(&miners, &owner, head, &prev);
        assert_eq!(
            facts_of(&a).blocks_won,
            32,
            "both owner rows contribute to blocks won"
        );
        assert_eq!(
            facts_of(&a).account,
            "big",
            "the account with the most blocks is the main miner"
        );
        assert!(
            facts_of(&a).active,
            "one owner row (small) just won a block ⇒ mining"
        );
        assert!(a.active_accounts.contains("small") && !a.active_accounts.contains("big"));
    }

    /// A snapshot whose fields the heartbeat's state machine reads.
    fn beat_snap(
        online: bool,
        syncing: bool,
        peers: usize,
        local_hashrate: u64,
        external: Option<bool>,
    ) -> Snapshot {
        Snapshot {
            online,
            syncing,
            peers: Some(peers),
            local_hashrate,
            external_miner: external.map(|active| ExternalMinerFacts {
                account: "myminer".to_string(),
                blocks_won: 10,
                last_seen: 100,
                head: 100,
                network_blocks: 100,
                active,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_heartbeat_makes_mining_its_own_state_but_offline_and_syncing_dominate() {
        // Offline dominates even if a (now-stale) registry row still says active.
        assert_eq!(
            BeatState::of(&beat_snap(false, false, 3, 0, Some(true))),
            BeatState::Offline,
            "a node that is offline is never 'mining'"
        );
        // Syncing dominates over mining — you join the chain before extending it.
        assert_eq!(
            BeatState::of(&beat_snap(true, true, 3, 0, Some(true))),
            BeatState::Syncing,
            "a node still catching up is 'syncing', not 'mining'"
        );
        // External mining, synced, with peers ⇒ its own MINING state.
        assert_eq!(
            BeatState::of(&beat_snap(true, false, 3, 0, Some(true))),
            BeatState::Mining,
            "an external miner at the tip must promote the chip to MINING"
        );
        // In-process mining still works (local_hashrate path), no registry row needed.
        assert_eq!(
            BeatState::of(&beat_snap(true, false, 3, 42, None)),
            BeatState::Mining,
            "in-process mining must still light the MINING state"
        );
        // An IDLE registry row (active=false) must NOT show mining — it falls through.
        assert_eq!(
            BeatState::of(&beat_snap(true, false, 3, 0, Some(false))),
            BeatState::Synced,
            "a stale/idle registry row must not fake a MINING state"
        );
        // Non-mining, synced, peerless ⇒ SOLO; with peers ⇒ SYNCED.
        assert_eq!(
            BeatState::of(&beat_snap(true, false, 0, 0, None)),
            BeatState::Solo
        );
        assert_eq!(
            BeatState::of(&beat_snap(true, false, 3, 0, None)),
            BeatState::Synced
        );
        // The states are visually distinct in WORD and COLOUR, and MINING is not the
        // same amber as SYNCING (or it would read as "still catching up").
        assert_ne!(BeatState::Mining.word(), BeatState::Synced.word());
        assert_ne!(BeatState::Mining.color(), BeatState::Syncing.color());
        assert_ne!(BeatState::Mining.color(), BeatState::Synced.color());
    }

    #[test]
    fn the_mining_tab_shows_external_miner_facts_instead_of_an_empty_hashrate() {
        // The live symptom: an external miner ⇒ local_hashrate 0 ⇒ "your hashpower"
        // empty. The tab must instead describe the miner from the registry.
        let mut snap = live_like_snapshot();
        snap.height = Some(100);
        snap.difficulty = "1000".to_string();
        snap.target_block_ms = 150_000; // 2.5-min cadence
        snap.local_hashrate = 0;
        snap.external_miner = Some(ExternalMinerFacts {
            account: "myminer".to_string(),
            blocks_won: 25,
            last_seen: 98,
            head: 100,
            network_blocks: 100,
            active: true,
        });

        let out = painted_text(|ui| mining_panel(ui, &snap));
        assert!(
            out.contains("YOUR EXTERNAL MINER"),
            "the external-miner card must render:\n{out}"
        );
        assert!(
            out.contains("MINING"),
            "an active external miner is labelled MINING:\n{out}"
        );
        assert!(
            out.contains("myminer"),
            "the operator's miner account is shown:\n{out}"
        );
        assert!(
            out.contains("Blocks won"),
            "blocks won is a fact we show:\n{out}"
        );
        assert!(
            out.contains("25 of 100") || out.contains("25.0%"),
            "the recent/lifetime share is shown honestly:\n{out}"
        );
        // The honesty invariant: with an active external miner, the tab must NOT tell the
        // operator they are "not mining".
        assert!(
            !out.contains("not mining"),
            "an actively-mining operator must never see 'not mining':\n{out}"
        );
    }

    #[test]
    fn is_mining_combines_external_and_in_process_but_never_a_stale_row() {
        let with_external = |active: bool| ExternalMinerFacts {
            active,
            ..Default::default()
        };
        // In-process only.
        assert!(Snapshot {
            local_hashrate: 5,
            ..Default::default()
        }
        .is_mining());
        // External active only.
        assert!(Snapshot {
            external_miner: Some(with_external(true)),
            ..Default::default()
        }
        .is_mining());
        // A registry row that is NOT active must never count as mining.
        assert!(
            !Snapshot {
                external_miner: Some(with_external(false)),
                ..Default::default()
            }
            .is_mining(),
            "an idle registry row is not mining"
        );
    }
}

/// Exhaustive verification of the pool-v2 money-moving guards.
///
/// The Station moves reserve-grade value, so "we reviewed the UI code" is not
/// an acceptable standard for when a spend button lights up. Every decision is
/// made by [`v2_allows`], a pure function — so here the ENTIRE input space is
/// enumerated and every reachable state is asserted, rather than sampled.
///
/// The organising principle is that a wrong `Ok` is the only truly dangerous
/// outcome: a spurious refusal annoys a user, a spurious permission moves
/// money. So the sweeps below are written as "no state outside the permitted
/// set may return Ok", not as a list of examples.
#[cfg(test)]
mod v2_guard_tests {

    use super::{v2_not_broadcast_line, v2_status_line, ReceiptStatus, V2Action};

    /// THE REGRESSION. A pool-v2 shield/de-shield that is sitting in the mempool
    /// used to be reported as "shield failed: still pending (not yet mined)" —
    /// a sentence that is both self-contradictory and dangerous: it tells an
    /// operator their value did not move while the transaction is live on the
    /// network, and the obvious response (send it again) spends a second nonce on
    /// an action already in flight.
    ///
    /// A pending transaction must never be describable as a failure.
    #[test]
    fn a_pending_pool_v2_transaction_is_never_reported_as_a_failure() {
        for what in [V2Action::Shield, V2Action::Deshield, V2Action::Send] {
            let line = v2_status_line(what, &ReceiptStatus::Pending, "abc123def456");
            let lower = line.to_lowercase();
            assert!(
                !lower.contains("fail"),
                "a pending {what:?} must never read as a failure, got: {line}"
            );
            assert!(
                !lower.contains("reject"),
                "a pending {what:?} must never read as rejected, got: {line}"
            );
            // It must say the thing that stops a double-send.
            assert!(
                lower.contains("mempool") && lower.contains("not yet mined"),
                "a pending {what:?} must say where it actually is, got: {line}"
            );
            assert!(
                lower.contains("do not resend"),
                "a pending {what:?} must warn against resending, got: {line}"
            );
            assert!(line.contains("abc123def456"), "must carry the txid: {line}");
        }
    }

    /// Only a receipt may declare failure — and when it does, it carries the
    /// chain's own reason rather than a generic message.
    #[test]
    fn only_a_receipt_declares_a_pool_v2_failure_and_it_names_the_reason() {
        let line = v2_status_line(
            V2Action::Deshield,
            &ReceiptStatus::Rejected("de-shield rate limit exceeded".into()),
            "deadbeef1234",
        );
        assert!(line.contains("REJECTED on-chain"), "{line}");
        assert!(line.contains("de-shield rate limit exceeded"), "{line}");
        assert!(line.contains("deadbeef1234"), "{line}");
    }

    /// A confirmation must be a REAL one — stated only for a receipt that says
    /// the transaction was mined and applied.
    #[test]
    fn a_pool_v2_confirmation_is_stated_only_for_a_real_receipt() {
        let line = v2_status_line(V2Action::Shield, &ReceiptStatus::Confirmed, "feedface0001");
        assert!(line.contains("CONFIRMED on-chain"), "{line}");
        assert!(line.contains("feedface0001"), "{line}");
        // The three outcomes must be mutually unmistakable.
        let pending = v2_status_line(V2Action::Shield, &ReceiptStatus::Pending, "feedface0001");
        let rejected = v2_status_line(
            V2Action::Shield,
            &ReceiptStatus::Rejected("bad proof".into()),
            "feedface0001",
        );
        assert_ne!(line, pending);
        assert_ne!(line, rejected);
        assert_ne!(pending, rejected);
    }

    /// The one case where retrying is CORRECT is the one case that says so: the
    /// transaction never reached the network, so no nonce was consumed.
    #[test]
    fn a_never_broadcast_pool_v2_action_says_it_is_safe_to_retry() {
        let line = v2_not_broadcast_line(V2Action::Shield, "node unreachable");
        let lower = line.to_lowercase();
        assert!(lower.contains("nothing was broadcast"), "{line}");
        assert!(lower.contains("safe to retry"), "{line}");
        assert!(lower.contains("no nonce used"), "{line}");
        assert!(line.contains("node unreachable"), "{line}");
        // And it must NOT be confusable with an on-network pending state.
        assert!(!lower.contains("mempool"), "{line}");
    }
    use super::*;

    /// A real, checksum-valid pool-v2 address (derived, never hardcoded, so it
    /// cannot drift from the encoder).
    fn v2_addr() -> String {
        encode_shielded_v2(&PqShieldedKey::from_leaf_seed(&[3u8; 32]).address())
    }

    /// A real pool-v1 address — the cross-pool confusion vector.
    fn v1_addr() -> String {
        encode_shielded(&ShieldedKey::from_seed([3u8; 32]).unwrap().address())
    }

    /// Every guard field in its permissive setting; tests turn ONE knob at a
    /// time so a failure names exactly the condition that broke.
    fn permissive() -> V2Guard {
        V2Guard {
            pool_active: true,
            for_this_wallet: true,
            scanned: true,
            notes: 3,
            busy: false,
            balance_grains: 1_000_000_000,
            window_budget: None,
        }
    }

    fn all_intents(to: &str) -> Vec<V2Intent<'_>> {
        vec![
            V2Intent::Shield {
                to: "",
                amount: Some(1_000),
            },
            V2Intent::Deshield {
                amount: Some(1_000),
            },
            V2Intent::Send {
                to,
                amount: Some(1_000),
            },
        ]
    }

    /// THE headline invariant: a dormant pool permits NOTHING. Every v2 spend
    /// is rejected by every node while bit 2 is unarmed, so a button that lit
    /// up here would cost the user ~25 s of proving to earn a certain
    /// rejection — and would imply the pool works when it does not.
    #[test]
    fn a_dormant_pool_permits_absolutely_nothing() {
        let addr = v2_addr();
        for balance in [0u128, 1, u128::MAX] {
            for notes in [0usize, 1, 100] {
                for scanned in [false, true] {
                    for busy in [false, true] {
                        let g = V2Guard {
                            pool_active: false,
                            for_this_wallet: true,
                            scanned,
                            notes,
                            busy,
                            balance_grains: balance,
                            window_budget: None,
                        };
                        for intent in all_intents(&addr) {
                            assert!(
                                v2_allows(&g, intent).is_err(),
                                "DORMANT pool permitted {intent:?} under {g:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A busy Station permits nothing. Two concurrent spends off one note set
    /// would build a doomed double-spend from the same scan.
    #[test]
    fn a_busy_station_permits_absolutely_nothing() {
        let addr = v2_addr();
        let g = V2Guard {
            busy: true,
            ..permissive()
        };
        for intent in all_intents(&addr) {
            assert!(
                v2_allows(&g, intent).is_err(),
                "a BUSY station permitted {intent:?}"
            );
        }
    }

    /// A view belonging to another wallet permits nothing — otherwise one
    /// wallet's balance could authorise another wallet's spend.
    #[test]
    fn another_wallets_view_permits_absolutely_nothing() {
        let addr = v2_addr();
        let g = V2Guard {
            for_this_wallet: false,
            ..permissive()
        };
        for intent in all_intents(&addr) {
            assert!(
                v2_allows(&g, intent).is_err(),
                "another wallet's view permitted {intent:?}"
            );
        }
    }

    /// Spending requires a scan; shielding does not. An unscanned balance is
    /// UNKNOWN, and building a spend against notes we cannot witness would
    /// fail after the proving cost — or, worse, spend the wrong ones.
    #[test]
    fn spending_requires_a_scan_but_shielding_does_not() {
        let addr = v2_addr();
        let g = V2Guard {
            scanned: false,
            notes: 0,
            ..permissive()
        };
        assert!(
            v2_allows(
                &g,
                V2Intent::Shield {
                    to: "",
                    amount: Some(1)
                }
            )
            .is_ok(),
            "a shield spends no notes, so it must not require a scan"
        );
        assert!(v2_allows(&g, V2Intent::Deshield { amount: Some(1) }).is_err());
        assert!(v2_allows(
            &g,
            V2Intent::Send {
                to: &addr,
                amount: Some(1)
            }
        )
        .is_err());
    }

    /// Having scanned and found NOTHING still permits no spend.
    #[test]
    fn a_scanned_but_empty_wallet_cannot_spend() {
        let addr = v2_addr();
        let g = V2Guard {
            notes: 0,
            balance_grains: 0,
            ..permissive()
        };
        assert!(v2_allows(&g, V2Intent::Deshield { amount: Some(1) }).is_err());
        assert!(v2_allows(
            &g,
            V2Intent::Send {
                to: &addr,
                amount: Some(1)
            }
        )
        .is_err());
    }

    /// No amount at, or beyond, the balance may ever be spent — swept across
    /// the boundary rather than spot-checked.
    #[test]
    fn no_spend_may_ever_exceed_the_scanned_balance() {
        let addr = v2_addr();
        let balance = 1_000u128;
        let g = V2Guard {
            balance_grains: balance,
            ..permissive()
        };
        for a in 0..=(balance * 2) {
            let ok_deshield = v2_allows(&g, V2Intent::Deshield { amount: Some(a) }).is_ok();
            let ok_send = v2_allows(
                &g,
                V2Intent::Send {
                    to: &addr,
                    amount: Some(a),
                },
            )
            .is_ok();
            let should = a > 0 && a <= balance;
            assert_eq!(ok_deshield, should, "de-shield of {a} against {balance}");
            assert_eq!(ok_send, should, "send of {a} against {balance}");
        }
        // And the extreme: never permit a saturating amount.
        assert!(v2_allows(
            &g,
            V2Intent::Deshield {
                amount: Some(u128::MAX)
            }
        )
        .is_err());
    }

    /// The per-window drain limiter binds de-shields and NOT private sends —
    /// a private transfer never leaves the pool, so it is not a drain.
    #[test]
    fn the_window_budget_binds_deshields_only() {
        let addr = v2_addr();
        let g = V2Guard {
            balance_grains: 1_000,
            window_budget: Some(100),
            ..permissive()
        };
        assert_eq!(g.deshield_cap(), 100, "the cap is the tighter of the two");
        for a in 1..=1_000u128 {
            let de = v2_allows(&g, V2Intent::Deshield { amount: Some(a) }).is_ok();
            assert_eq!(de, a <= 100, "de-shield of {a} under a 100 budget");
            let send = v2_allows(
                &g,
                V2Intent::Send {
                    to: &addr,
                    amount: Some(a),
                },
            )
            .is_ok();
            assert_eq!(send, a <= 1_000, "a private send of {a} is not a drain");
        }
        // A zero budget stops de-shielding entirely, but not private sends.
        let g0 = V2Guard {
            window_budget: Some(0),
            ..g
        };
        assert_eq!(g0.deshield_cap(), 0);
        assert!(v2_allows(&g0, V2Intent::Deshield { amount: Some(1) }).is_err());
        assert!(v2_allows(
            &g0,
            V2Intent::Send {
                to: &addr,
                amount: Some(1)
            }
        )
        .is_ok());
    }

    /// A zero or unparseable amount never spends.
    #[test]
    fn zero_and_missing_amounts_never_spend() {
        let addr = v2_addr();
        let g = permissive();
        for amount in [None, Some(0u128)] {
            assert!(v2_allows(&g, V2Intent::Shield { to: "", amount }).is_err());
            assert!(v2_allows(&g, V2Intent::Deshield { amount }).is_err());
            assert!(v2_allows(&g, V2Intent::Send { to: &addr, amount }).is_err());
        }
    }

    /// A shield may target a third party, but only a REAL pool-v2 address.
    /// Blank means "to myself". A pool-v1 address here would move value into a
    /// pool the named recipient cannot spend from — value they can see and
    /// never touch — so it is refused.
    #[test]
    fn a_shield_may_only_target_a_real_pool_v2_address_or_yourself() {
        let g = permissive();
        let good = v2_addr();
        let v1 = v1_addr();

        assert!(
            v2_allows(
                &g,
                V2Intent::Shield {
                    to: "",
                    amount: Some(1)
                }
            )
            .is_ok(),
            "blank must mean shield-to-self"
        );
        assert!(
            v2_allows(
                &g,
                V2Intent::Shield {
                    to: "   ",
                    amount: Some(1)
                }
            )
            .is_ok(),
            "whitespace-only must also mean shield-to-self"
        );
        assert!(
            v2_allows(
                &g,
                V2Intent::Shield {
                    to: &good,
                    amount: Some(1)
                }
            )
            .is_ok(),
            "a real pool-v2 recipient must be allowed"
        );
        for bad in [v1.as_str(), "garbage", "xusq1", "usa.reserve.sov"] {
            assert!(
                v2_allows(
                    &g,
                    V2Intent::Shield {
                        to: bad,
                        amount: Some(1)
                    }
                )
                .is_err(),
                "a shield was allowed to target {bad:?}"
            );
        }
        // Every single-character corruption of a valid recipient must fail.
        for i in 0..good.len() {
            let mut b = good.clone();
            let ch = if b.as_bytes()[i] == b'q' { 'p' } else { 'q' };
            b.replace_range(i..i + 1, &ch.to_string());
            if b != good {
                assert!(
                    v2_allows(
                        &g,
                        V2Intent::Shield {
                            to: &b,
                            amount: Some(1)
                        }
                    )
                    .is_err(),
                    "a corrupted shield recipient was accepted: {b}"
                );
            }
        }
    }

    /// THE cross-pool guard. A pool-v1 address in the pool-v2 send box would
    /// pay a different recipient in a different value space. It must be
    /// refused — never coerced, never "helpfully" converted.
    #[test]
    fn a_pool_v1_address_can_never_receive_a_pool_v2_send() {
        let g = permissive();
        let v1 = v1_addr();
        assert!(
            v1.starts_with("xus1"),
            "fixture must really be a v1 address, got {v1}"
        );
        let out = v2_allows(
            &g,
            V2Intent::Send {
                to: &v1,
                amount: Some(1),
            },
        );
        assert!(out.is_err(), "a pool-v1 address was accepted for a v2 send");
        assert!(
            out.unwrap_err().contains("POOL-V2"),
            "the refusal must explain the pool mismatch"
        );
    }

    /// No malformed, lookalike, or hostile recipient string may ever be
    /// accepted — and none may panic. Only a real, checksum-valid `xusq1…`
    /// address passes.
    #[test]
    fn no_malformed_recipient_is_ever_accepted_and_none_panics() {
        let g = permissive();
        let good = v2_addr();
        let mut hostile: Vec<String> = vec![
            String::new(),
            " ".repeat(64),
            "xusq1".to_string(),
            "xusq".to_string(),
            "XUSQ1ABC".to_string(),
            "xus1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            "uxus1qqqqqqqqqqqqqqqqqq".to_string(),
            "0x0000000000000000000000000000000000000000".to_string(),
            "usa.reserve.sov".to_string(),
            "xusq1\0\0nul".to_string(),
            "xusq1\n\ttab".to_string(),
            "xusq1💥💥💥".to_string(),
            "xusq1".to_string() + &"q".repeat(4096),
        ];
        // NOTE: whitespace-padded copies of a VALID address are deliberately
        // NOT hostile — a pasted address commonly carries them, and trimming is
        // safe because the trimmed string must still pass the bech32m
        // checksum. That behaviour is asserted at the end of this test.
        // Case-folding is likewise a bech32m property, not a defect.
        // Every single-character corruption of a VALID address must fail the
        // checksum. This is what makes a typo unable to pay a stranger.
        for i in 0..good.len() {
            let mut bad = good.clone();
            let ch = if bad.as_bytes()[i] == b'q' { 'p' } else { 'q' };
            bad.replace_range(i..i + 1, &ch.to_string());
            if bad != good {
                hostile.push(bad);
            }
        }
        // ...and every truncation.
        for i in 0..good.len() {
            hostile.push(good[..i].to_string());
        }

        for s in hostile {
            let out = v2_allows(
                &g,
                V2Intent::Send {
                    to: &s,
                    amount: Some(1),
                },
            );
            assert!(out.is_err(), "a malformed recipient was ACCEPTED: {s:?}");
        }

        // The genuine article, and only it, is permitted — including with the
        // surrounding whitespace a paste commonly carries.
        assert!(v2_allows(
            &g,
            V2Intent::Send {
                to: &good,
                amount: Some(1)
            }
        )
        .is_ok());
        assert!(v2_allows(
            &g,
            V2Intent::Send {
                to: &format!("  {good}  "),
                amount: Some(1)
            }
        )
        .is_ok());
    }

    /// The exhaustive sweep. Enumerate the whole guard space and assert the
    /// verdict matches an INDEPENDENTLY written specification — so a bug would
    /// have to be made identically twice, in two different forms, to survive.
    #[test]
    fn the_entire_guard_space_matches_an_independent_specification() {
        let good = v2_addr();
        let v1 = v1_addr();
        let recipients = [good.as_str(), v1.as_str(), "", "garbage"];
        let amounts = [
            None,
            Some(0u128),
            Some(1),
            Some(500),
            Some(1_000),
            Some(5_000),
        ];
        let budgets = [None, Some(0u128), Some(500), Some(10_000)];
        let mut checked = 0usize;

        for pool_active in [false, true] {
            for for_this_wallet in [false, true] {
                for scanned in [false, true] {
                    for notes in [0usize, 2] {
                        for busy in [false, true] {
                            for balance in [0u128, 1_000] {
                                for budget in budgets {
                                    let g = V2Guard {
                                        pool_active,
                                        for_this_wallet,
                                        scanned,
                                        notes,
                                        busy,
                                        balance_grains: balance,
                                        window_budget: budget,
                                    };
                                    // Independent spec of the common preconditions.
                                    let base = pool_active && for_this_wallet && !busy;
                                    let can_spend = base && scanned && notes > 0;
                                    let cap = match budget {
                                        Some(b) => balance.min(b),
                                        None => balance,
                                    };
                                    for amount in amounts {
                                        let a = amount.unwrap_or(0);
                                        let positive = amount.is_some() && a > 0;

                                        // A shield spends no notes, so it needs
                                        // no scan — but a NAMED recipient must
                                        // still be a real pool-v2 address.
                                        for sto in recipients {
                                            let sto_ok = sto.trim().is_empty()
                                                || (sto.trim().starts_with("xusq1")
                                                    && decode_shielded_v2(sto.trim()).is_ok());
                                            let want_shield = base && positive && sto_ok;
                                            assert_eq!(
                                                v2_allows(&g, V2Intent::Shield { to: sto, amount })
                                                    .is_ok(),
                                                want_shield,
                                                "shield {amount:?} to {sto:?} under {g:?}"
                                            );
                                            checked += 1;
                                        }

                                        let want_deshield =
                                            can_spend && positive && a <= balance && a <= cap;
                                        assert_eq!(
                                            v2_allows(&g, V2Intent::Deshield { amount }).is_ok(),
                                            want_deshield,
                                            "deshield {amount:?} under {g:?}"
                                        );

                                        for to in recipients {
                                            let addr_ok = to.trim().starts_with("xusq1")
                                                && decode_shielded_v2(to.trim()).is_ok();
                                            let want_send =
                                                can_spend && addr_ok && positive && a <= balance;
                                            assert_eq!(
                                                v2_allows(&g, V2Intent::Send { to, amount })
                                                    .is_ok(),
                                                want_send,
                                                "send {amount:?} to {to:?} under {g:?}"
                                            );
                                            checked += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(
            checked >= 4_000,
            "the sweep must actually be exhaustive, only checked {checked}"
        );
    }

    /// Whenever an action is refused, the user is told why — an empty reason
    /// would render as a dead button with no explanation.
    #[test]
    fn every_refusal_carries_an_actionable_reason() {
        let good = v2_addr();
        for pool_active in [false, true] {
            for scanned in [false, true] {
                for notes in [0usize, 1] {
                    for busy in [false, true] {
                        let g = V2Guard {
                            pool_active,
                            for_this_wallet: true,
                            scanned,
                            notes,
                            busy,
                            balance_grains: 10,
                            window_budget: Some(5),
                        };
                        for intent in [
                            V2Intent::Shield {
                                to: "",
                                amount: Some(50),
                            },
                            V2Intent::Deshield { amount: Some(50) },
                            V2Intent::Send {
                                to: &good,
                                amount: Some(50),
                            },
                        ] {
                            if let Err(reason) = v2_allows(&g, intent) {
                                assert!(
                                    reason.len() > 12 && reason.chars().any(char::is_alphabetic),
                                    "refusal reason is not actionable: {reason:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The pool SELECTOR: proving that choosing a pool actually chooses the pool.
///
/// Two failures are possible here and only one of them is survivable. Refusing a
/// send the operator was entitled to make is an annoyance. Sending from a pool
/// they did NOT choose — in particular, sending from the non-post-quantum pool
/// when they asked for the post-quantum one, or building a v2 spend the chain
/// will hard-reject — is a loss. So the tests below assert the ACTIVE, permitted
/// path works as well as the refusing one: a guard that only ever says "no" is
/// trivially safe and completely useless, and this suite would not notice.
#[cfg(test)]
mod pool_selector_tests {
    use super::*;

    /// A real, checksum-valid pool-v2 address (derived, never hardcoded).
    fn v2_addr() -> String {
        encode_shielded_v2(&PqShieldedKey::from_leaf_seed(&[7u8; 32]).address())
    }

    /// A real pool-v1 address — the cross-pool confusion vector.
    fn v1_addr() -> String {
        encode_shielded(&ShieldedKey::from_seed([7u8; 32]).unwrap().address())
    }

    /// A real unified address, which routes to pool v1.
    fn unified_addr() -> String {
        let zkey = ShieldedKey::from_seed([7u8; 32]).unwrap();
        let id = AccountId::new("treasury.sov").unwrap();
        UnifiedAddress::new(Some(id), Some(zkey.address()))
            .unwrap()
            .encode()
    }

    fn permissive_v2_guard() -> V2Guard {
        V2Guard {
            pool_active: true,
            for_this_wallet: true,
            scanned: true,
            notes: 3,
            busy: false,
            balance_grains: 1_000_000_000,
            window_budget: None,
        }
    }

    #[test]
    fn a_selector_label_states_the_cryptography_and_the_post_quantum_truth() {
        // The label is the entire basis on which the choice is made, so it may
        // never degrade to a bare "Pool v1 / Pool v2".
        let v1 = Pool::V1.selector_label();
        let v2 = Pool::V2.selector_label();
        assert!(v1.contains("Pool v1"), "{v1}");
        assert!(v1.contains("Orchard / Halo2"), "{v1}");
        assert!(
            v1.contains("NOT post-quantum"),
            "the v1 label must state the limitation, not omit it: {v1}"
        );
        assert!(v2.contains("Pool v2"), "{v2}");
        assert!(v2.contains("ML-KEM-768 / STARK"), "{v2}");
        assert!(v2.contains("post-quantum"), "{v2}");
        assert!(
            !v2.contains("NOT post-quantum"),
            "the v2 label must not inherit v1's disclaimer: {v2}"
        );
        // The two labels must be distinguishable at a glance.
        assert_ne!(v1, v2);
    }

    #[test]
    fn the_selected_pool_decides_which_recipients_are_valid() {
        let v1 = v1_addr();
        let v2 = v2_addr();
        let uni = unified_addr();

        // THE ACTIVE PATH: each pool accepts its own addresses. Asserted first,
        // because a check that only ever refuses would pass every other test here.
        assert!(
            pool_recipient_check(Pool::V1, &v1).is_ok(),
            "pool v1 selected must accept a xus1… address"
        );
        assert!(
            pool_recipient_check(Pool::V1, &uni).is_ok(),
            "pool v1 selected must accept a unified address (it routes to v1)"
        );
        assert!(
            pool_recipient_check(Pool::V2, &v2).is_ok(),
            "pool v2 selected must accept a xusq1… address — this is the whole \
             point of the selector; before it, a xusq1… recipient was always refused"
        );

        // Surrounding whitespace is a paste artefact, not a different address.
        assert!(pool_recipient_check(Pool::V2, &format!("  {v2}  ")).is_ok());

        // And each pool REFUSES the other's.
        assert!(pool_recipient_check(Pool::V1, &v2).is_err());
        assert!(pool_recipient_check(Pool::V2, &v1).is_err());
        assert!(pool_recipient_check(Pool::V2, &uni).is_err());

        // Transparent and garbage are refused by both.
        for pool in [Pool::V1, Pool::V2] {
            assert!(pool_recipient_check(pool, "treasury.sov").is_err());
            assert!(pool_recipient_check(pool, "!!bad!!").is_err());
            assert!(pool_recipient_check(pool, "").is_err());
            assert!(pool_recipient_check(pool, "   ").is_err());
        }
    }

    #[test]
    fn a_cross_pool_paste_names_the_pool_and_the_fix_never_a_generic_invalid() {
        // The address is well-formed. Calling it "invalid" would send an
        // operator hunting for a typo that does not exist.
        let wrong_way = pool_recipient_check(Pool::V1, &v2_addr()).unwrap_err();
        assert!(
            wrong_way.contains("POOL-V2"),
            "must name the pool the address belongs to: {wrong_way}"
        );
        assert!(
            wrong_way.contains("switch the selector to Pool v2"),
            "must name the one action that fixes it: {wrong_way}"
        );
        assert!(
            !wrong_way.contains("unrecognized"),
            "a well-formed address must never be reported as unrecognized: {wrong_way}"
        );

        let other_way = pool_recipient_check(Pool::V2, &v1_addr()).unwrap_err();
        assert!(other_way.contains("POOL-V1"), "{other_way}");
        assert!(
            other_way.contains("switch the selector to Pool v1"),
            "{other_way}"
        );
        assert!(!other_way.contains("unrecognized"), "{other_way}");

        // Genuinely unrecognized input, by contrast, IS allowed to say so — the
        // two cases must stay distinguishable.
        assert!(pool_recipient_check(Pool::V1, "!!bad!!")
            .unwrap_err()
            .contains("unrecognized"));
    }

    #[test]
    fn the_selector_dispatches_to_the_pool_that_was_chosen() {
        // THE ACTIVE PATH: with the pool live, each choice reaches its own path.
        assert_eq!(
            private_send_dispatch(Pool::V1, PoolState::Active),
            Ok(Pool::V1)
        );
        assert_eq!(
            private_send_dispatch(Pool::V2, PoolState::Active),
            Ok(Pool::V2),
            "selecting pool v2 on a live chain must dispatch to the v2 path"
        );
        // v1 is live at every height, so its dispatch never depends on v2's state.
        for st in [
            PoolState::Active,
            PoolState::Dormant,
            PoolState::Unavailable,
        ] {
            assert_eq!(
                private_send_dispatch(Pool::V1, st),
                Ok(Pool::V1),
                "pool v1 must be unaffected by pool v2's state ({st:?})"
            );
        }
    }

    #[test]
    fn a_v2_send_is_refused_with_a_reason_while_the_pool_is_not_active() {
        // The selector may sit on v2 (the state survives a node going offline);
        // it may never make a v2 spend possible on its own.
        for st in [PoolState::Dormant, PoolState::Unavailable] {
            let out = private_send_dispatch(Pool::V2, st);
            let why = out.expect_err("a non-Active pool must refuse a v2 send");
            assert!(
                why.contains("not active"),
                "the refusal must say the pool is not active: {why}"
            );
            assert!(
                why.contains("15,552"),
                "the refusal must give the height an operator can check: {why}"
            );
            assert!(
                why.contains("REJECTS"),
                "the refusal must say consensus rejects the spend, not merely that \
                 the app declines to build it: {why}"
            );
        }
        // Never silently downgraded to v1 — that would move value out of a
        // different pool than the one chosen.
        assert_ne!(
            private_send_dispatch(Pool::V2, PoolState::Dormant),
            Ok(Pool::V1)
        );
    }

    #[test]
    fn the_selector_cannot_bypass_the_v2_guard() {
        let addr = v2_addr();

        // THE ACTIVE PATH: guard permissive + pool Active + a v2 address ⇒ the
        // send is genuinely enabled. Both halves of the button's condition.
        let live = permissive_v2_guard();
        assert!(v2_allows(
            &live,
            V2Intent::Send {
                to: &addr,
                amount: Some(1_000),
            }
        )
        .is_ok());
        assert!(private_send_dispatch(Pool::V2, PoolState::Active).is_ok());

        // Dormant pool ⇒ the guard itself refuses, independently of the
        // selector. The UI builds this guard with `pool_active` set from the
        // classified state, so a selector on v2 cannot reach a permissive guard.
        let dormant = V2Guard {
            pool_active: false,
            ..permissive_v2_guard()
        };
        assert!(v2_allows(
            &dormant,
            V2Intent::Send {
                to: &addr,
                amount: Some(1_000),
            }
        )
        .is_err());

        // Every other pre-existing guard survives the selector: over-balance,
        // unscanned, no notes, busy, wrong wallet.
        let over = v2_allows(
            &live,
            V2Intent::Send {
                to: &addr,
                amount: Some(live.balance_grains + 1),
            },
        );
        assert!(
            over.is_err(),
            "a spend above the scanned balance must refuse"
        );
        for g in [
            V2Guard {
                scanned: false,
                ..permissive_v2_guard()
            },
            V2Guard {
                notes: 0,
                ..permissive_v2_guard()
            },
            V2Guard {
                busy: true,
                ..permissive_v2_guard()
            },
            V2Guard {
                for_this_wallet: false,
                ..permissive_v2_guard()
            },
        ] {
            assert!(
                v2_allows(
                    &g,
                    V2Intent::Send {
                        to: &addr,
                        amount: Some(1_000),
                    }
                )
                .is_err(),
                "the selector must not relax any pre-existing pool-v2 guard: {g:?}"
            );
        }
    }

    #[test]
    fn selecting_a_pool_changes_which_balance_and_path_the_send_uses() {
        // The two pools are separate value spaces: the same amount is spendable
        // in one and not the other. This is what "selecting the pool drives the
        // send" has to mean in practice.
        let v2_rich = V2Guard {
            balance_grains: 500,
            ..permissive_v2_guard()
        };
        let addr = v2_addr();
        assert!(v2_allows(
            &v2_rich,
            V2Intent::Send {
                to: &addr,
                amount: Some(500),
            }
        )
        .is_ok());
        assert!(
            v2_allows(
                &v2_rich,
                V2Intent::Send {
                    to: &addr,
                    amount: Some(501),
                }
            )
            .is_err(),
            "the v2 send must be bounded by the v2 balance, not v1's"
        );
    }
}

/// The selector's **explicitness** guarantees, one test per way it could go
/// wrong.
///
/// The standard here is not "the code looks right". It is: *it must be
/// impossible to move funds through the wrong pool without having deliberately
/// and knowingly chosen it.* Pool v1 is not post-quantum and pool v2 is —
/// confusing them silently costs the operator the privacy property they believe
/// they bought, and they find out years later or never.
///
/// Each test names the failure mode it closes, and each asserts the PERMITTED
/// path as well as the refused one. A selector that never arms anything would
/// satisfy every safety assertion here and be worthless, so "it arms the right
/// pool when it should" is tested first in every case.
#[cfg(test)]
mod pool_selector_explicit_tests {
    use super::*;

    fn v2_addr() -> String {
        encode_shielded_v2(&PqShieldedKey::from_leaf_seed(&[11u8; 32]).address())
    }

    fn v1_addr() -> String {
        encode_shielded(&ShieldedKey::from_seed([11u8; 32]).unwrap().address())
    }

    // ── Failure mode 1: a silently-usable default ────────────────────────────

    #[test]
    fn nothing_is_armed_until_the_operator_actually_chooses() {
        // A fresh selection holds no pool. There is no value the app supplies on
        // the operator's behalf — the type has no default variant to fall into.
        let fresh = PoolSelection::default();
        assert_eq!(fresh.pool, None, "no pool may be pre-selected");

        // …and with nothing chosen, NOTHING is armed, on a fully live chain.
        // The chain being healthy is exactly the case where a default would be
        // invisible, so it is the case asserted.
        let idle = armed_pool(None, PoolState::Active);
        let why = idle.expect_err("an unchosen pool must arm nothing even on a live chain");
        assert_eq!(why, NO_POOL_CHOSEN);
        assert!(why.contains("choose Pool v1 or Pool v2"), "{why}");

        // THE ACTIVE PATH: one deliberate choice arms exactly that pool.
        let mut sel = PoolSelection::default();
        sel.choose(Pool::V1, "alice");
        assert_eq!(armed_pool(sel.pool, PoolState::Active), Ok(Pool::V1));
        sel.choose(Pool::V2, "alice");
        assert_eq!(
            armed_pool(sel.pool, PoolState::Active),
            Ok(Pool::V2),
            "choosing v2 on a live chain must arm v2 — the selector has to actually work"
        );
    }

    #[test]
    fn the_armed_statement_is_present_and_unambiguous_in_every_state() {
        // Rendered twice in the UI (section head and immediately above the Send
        // button) from this ONE function, so the two can never disagree.
        for pool in [Pool::V1, Pool::V2] {
            let st = arm_statement(Ok(pool));
            assert!(st.contains("ARMED"), "{st}");
            assert!(st.contains(pool.name()), "{st}");
            assert!(st.contains(pool.crypto()), "{st}");
            assert!(st.contains(pool.pq_claim()), "{st}");
            assert!(st.contains(pool.glyph()), "{st}");
        }
        // Nothing chosen, and a dormant v2 choice, both read as NOTHING ARMED —
        // never as a pool.
        for st in [
            arm_statement(armed_pool(None, PoolState::Active)),
            arm_statement(armed_pool(Some(Pool::V2), PoolState::Dormant)),
        ] {
            assert!(st.contains("NOTHING IS ARMED"), "{st}");
            assert!(
                !st.contains("ARMED ·"),
                "must not read as an armed pool: {st}"
            );
        }
    }

    // ── Failure mode 2: a confirm screen that omits the pool ─────────────────

    #[test]
    fn every_reachable_confirm_screen_states_the_pool_and_the_pq_truth() {
        // `SendSource` is the ONLY way a pending send records where value comes
        // from, and `confirm_line` is total over it — so this loop is the entire
        // reachable space, not a sample. There is no variant that can omit the
        // statement, and none that can carry a pool without naming it.
        for src in [
            SendSource::Transparent,
            SendSource::Pool(Pool::V1),
            SendSource::Pool(Pool::V2),
        ] {
            let line = src.confirm_line();
            assert!(!line.trim().is_empty(), "{src:?} produced no statement");
            match src.pool() {
                Some(pool) => {
                    assert!(line.contains(pool.name()), "{line}");
                    assert!(line.contains(pool.crypto()), "{line}");
                    assert!(
                        line.contains(pool.pq_claim()),
                        "the confirm screen must state the post-quantum truth in plain words: \
                         {line}"
                    );
                    assert!(line.contains(pool.glyph()), "{line}");
                    assert!(line.contains("SPENDING FROM"), "{line}");
                }
                None => assert!(line.contains("PUBLIC"), "{line}"),
            }
        }

        // The two pool statements must not be confusable with each other.
        let v1 = SendSource::Pool(Pool::V1).confirm_line();
        let v2 = SendSource::Pool(Pool::V2).confirm_line();
        assert_ne!(v1, v2);
        assert!(v1.contains("NOT post-quantum"), "{v1}");
        assert!(!v2.contains("NOT post-quantum"), "{v2}");

        // And a pool send necessarily reports a pool — `is_pool_spend` and `pool`
        // cannot disagree, because both read the same enum.
        assert!(SendSource::Pool(Pool::V2).is_pool_spend());
        assert_eq!(SendSource::Pool(Pool::V2).pool(), Some(Pool::V2));
        assert!(!SendSource::Transparent.is_pool_spend());
        assert_eq!(SendSource::Transparent.pool(), None);
    }

    // ── Failure mode 3: sticky selection carried where it wasn't chosen ──────

    #[test]
    fn a_choice_never_survives_into_a_context_where_it_was_not_made() {
        let mut sel = PoolSelection::default();

        // THE ACTIVE PATH first: within one wallet the choice PERSISTS. Leaving
        // and returning to the tab re-reads it and finds the same pool — an
        // operator must never come back to a different pool than they last saw.
        sel.choose(Pool::V2, "alice");
        assert_eq!(sel.chosen_for("alice"), Some(Pool::V2));
        assert_eq!(
            sel.chosen_for("alice"),
            Some(Pool::V2),
            "re-entering the tab must show the SAME pool, not a different one"
        );

        // Switching wallets disarms. The choice was about alice's notes in a
        // pool; it says nothing about bob's.
        assert_eq!(
            sel.chosen_for("bob"),
            None,
            "a choice made for one wallet must never arm a pool for another"
        );
        // …and it stays disarmed on returning to alice: the choice is gone, not
        // merely hidden.
        assert_eq!(sel.chosen_for("alice"), None);

        // Completing a send disarms, so the next payment is chosen deliberately
        // rather than inheriting an unexamined pool.
        sel.choose(Pool::V1, "alice");
        assert_eq!(sel.chosen_for("alice"), Some(Pool::V1));
        sel.clear();
        assert_eq!(sel.chosen_for("alice"), None);
        assert!(
            sel.for_account.is_empty(),
            "clearing must drop the account binding too, or a later choice could \
             inherit a stale pairing"
        );

        // The pool going non-Active does not rewrite the choice — it changes
        // what is ARMED. The distinction matters: the operator's v2 choice is
        // still theirs, it simply cannot fire.
        sel.choose(Pool::V2, "alice");
        assert_eq!(sel.chosen_for("alice"), Some(Pool::V2));
        assert!(armed_pool(sel.pool, PoolState::Dormant).is_err());
        assert_eq!(armed_pool(sel.pool, PoolState::Active), Ok(Pool::V2));
    }

    // ── Failure mode 4: an ambiguous record of what happened ─────────────────

    #[test]
    fn a_completed_send_reports_which_pool_moved() {
        for pool in [Pool::V1, Pool::V2] {
            let line = pool_send_receipt(pool, 250_000_000, "abcdef0123456789deadbeef");
            assert!(line.contains(pool.name()), "{line}");
            assert!(line.contains(pool.crypto()), "{line}");
            assert!(
                line.contains(pool.pq_claim()),
                "the record must state the post-quantum status, not just the pool: {line}"
            );
            assert!(line.contains("2.5"), "the amount must survive: {line}");
            assert!(line.contains("abcdef"), "the txid must survive: {line}");
        }
    }

    #[test]
    fn a_completed_v2_send_reports_v2_and_could_not_be_mistaken_for_v1() {
        let v2 = pool_send_receipt(Pool::V2, 1, "0011223344556677");
        assert!(v2.contains("Pool v2"), "{v2}");
        assert!(v2.contains("ML-KEM-768 / STARK"), "{v2}");
        assert!(v2.contains("post-quantum"), "{v2}");
        assert!(
            !v2.contains("NOT post-quantum"),
            "a v2 send must never be recorded as non-post-quantum: {v2}"
        );
        assert!(
            !v2.contains("Orchard"),
            "a v2 send must never name v1's cryptography: {v2}"
        );
        assert_ne!(v2, pool_send_receipt(Pool::V1, 1, "0011223344556677"));
    }

    // ── Failure mode 5: a cross-pool recipient reaching submit ───────────────

    #[test]
    fn a_recipient_from_the_other_pool_can_never_be_coerced_through() {
        let v1 = v1_addr();
        let v2 = v2_addr();

        // THE ACTIVE PATH: the matching address is accepted by the very check
        // both submit paths run — `send_private` for v1, `run_v2_action` for v2.
        assert!(pool_recipient_check(Pool::V1, &v1).is_ok());
        assert!(pool_recipient_check(Pool::V2, &v2).is_ok());

        // No surface form of the wrong address gets through: padded, upper-cased,
        // newline-wrapped from a paste. None may become Ok, and none may panic.
        for raw in [
            v2.clone(),
            format!(" {v2} "),
            format!("\n{v2}\n"),
            format!("\t{v2}"),
            v2.to_uppercase(),
        ] {
            assert!(
                pool_recipient_check(Pool::V1, &raw).is_err(),
                "a pool-v2 address must never be accepted by the pool-v1 path"
            );
        }
        for raw in [
            v1.clone(),
            format!(" {v1} "),
            format!("\n{v1}\n"),
            v1.to_uppercase(),
        ] {
            assert!(
                pool_recipient_check(Pool::V2, &raw).is_err(),
                "a pool-v1 address must never be accepted by the pool-v2 path"
            );
        }

        // The refusal is specific enough to act on, in both directions.
        assert!(pool_recipient_check(Pool::V1, &v2)
            .unwrap_err()
            .contains("switch the selector to Pool v2"));
        assert!(pool_recipient_check(Pool::V2, &v1)
            .unwrap_err()
            .contains("switch the selector to Pool v1"));
    }

    // ── Failure mode 6: a distinction that needs colour to read ──────────────

    #[test]
    fn the_post_quantum_distinction_is_legible_without_colour() {
        // Shapes differ.
        assert_ne!(Pool::V1.glyph(), Pool::V2.glyph());
        // Words differ, and say the thing outright.
        assert_eq!(Pool::V1.pq_badge(), "NOT PQ");
        assert_eq!(Pool::V2.pq_badge(), "PQ");
        assert_ne!(Pool::V1.pq_badge(), Pool::V2.pq_badge());

        // Every surface an operator reads carries BOTH a shape and the words —
        // strip all colour and the meaning is still fully present.
        for pool in [Pool::V1, Pool::V2] {
            for surface in [
                pool.selector_label(),
                arm_statement(Ok(pool)),
                SendSource::Pool(pool).confirm_line(),
            ] {
                assert!(
                    surface.contains(pool.glyph()),
                    "surface lacks the pool's shape: {surface}"
                );
                assert!(
                    surface.contains(pool.pq_claim()),
                    "surface lacks the post-quantum words: {surface}"
                );
            }
        }
        // The two selector labels are distinguishable as plain text.
        assert_ne!(Pool::V1.selector_label(), Pool::V2.selector_label());
    }

    // ── Failure mode 7: dormant v2 quietly leaving v1 armed ──────────────────

    #[test]
    fn choosing_a_dormant_v2_arms_nothing_and_never_falls_back_to_v1() {
        for st in [PoolState::Dormant, PoolState::Unavailable] {
            let armed = armed_pool(Some(Pool::V2), st);
            assert!(armed.is_err(), "a non-Active v2 must arm nothing ({st:?})");
            assert_ne!(
                armed,
                Ok(Pool::V1),
                "falling back to the NON-post-quantum pool because the post-quantum one \
                 is unavailable would hand the operator exactly the property they were \
                 avoiding ({st:?})"
            );
            let statement = arm_statement(armed);
            assert!(statement.contains("NOTHING IS ARMED"), "{statement}");
            assert!(
                !statement.contains(Pool::V1.name()),
                "the disarmed statement must not name v1 — nothing about v1 was chosen: \
                 {statement}"
            );
            assert!(statement.contains("15,552"), "{statement}");
        }

        // THE ACTIVE PATH: the same choice, on a chain where v2 is live, arms v2.
        assert_eq!(
            armed_pool(Some(Pool::V2), PoolState::Active),
            Ok(Pool::V2),
            "the dormancy guard must not be a blanket refusal — v2 has to work when live"
        );
        // And an explicit v1 choice is unaffected by v2's state throughout.
        for st in [
            PoolState::Active,
            PoolState::Dormant,
            PoolState::Unavailable,
        ] {
            assert_eq!(armed_pool(Some(Pool::V1), st), Ok(Pool::V1));
        }
    }

    // ── The whole space, swept ───────────────────────────────────────────────

    #[test]
    fn the_entire_choice_by_state_matrix_arms_only_what_was_chosen() {
        // Every reachable (choice, chain state) pair. The invariant asserted is
        // the one that matters: `armed_pool` NEVER returns a pool other than the
        // one chosen. It may refuse; it may not substitute.
        for chosen in [None, Some(Pool::V1), Some(Pool::V2)] {
            for st in [
                PoolState::Active,
                PoolState::Dormant,
                PoolState::Unavailable,
            ] {
                match armed_pool(chosen, st) {
                    Ok(armed) => {
                        assert_eq!(
                            Some(armed),
                            chosen,
                            "armed {armed:?} but the operator chose {chosen:?} ({st:?})"
                        );
                        // Anything armed must be genuinely spendable now.
                        if armed == Pool::V2 {
                            assert_eq!(st, PoolState::Active);
                        }
                    }
                    Err(why) => assert!(!why.is_empty(), "a refusal must carry a reason"),
                }
            }
        }
        // Exactly four of the nine pairs may arm anything.
        let armable = [None, Some(Pool::V1), Some(Pool::V2)]
            .iter()
            .flat_map(|c| {
                [
                    PoolState::Active,
                    PoolState::Dormant,
                    PoolState::Unavailable,
                ]
                .iter()
                .map(move |s| armed_pool(*c, *s))
            })
            .filter(|r| r.is_ok())
            .count();
        assert_eq!(
            armable, 4,
            "v1 arms in all three chain states, v2 only when Active — and an unchosen \
             pool never arms"
        );
    }
}

/// PER-WALLET scanned pool views.
///
/// The failure this closes: one global slot per pool meant scanning wallet B
/// destroyed wallet A's scanned view — "I can only view one wallet's v2 pool at a
/// time" — and left A's figures sitting in the slot where only a hand-written
/// equality check kept them off B's screen.
///
/// Every assertion below is on pure functions ([`ScannedPools`],
/// [`ShieldedV2View::own_figures`], [`ShieldedV2View::guard`]) — the same ones the
/// paint code calls — so the guarantees are proven rather than read off UI code.
#[cfg(test)]
mod scanned_pools_tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// Record a completed v2 scan for `account`, exactly as the worker thread does.
    fn record_v2(pools: &mut ScannedPools<ShieldedV2View>, account: &str, bal: u64, notes: usize) {
        let v = pools.entry_mut(account);
        v.scanning = false;
        v.account = account.to_string();
        v.balance = bal;
        v.notes = notes;
        v.scanned_height = 900 + bal;
        v.message = format!("scanned to height {}", 900 + bal);
    }

    /// (a) RETENTION. Scan A, then scan B, then look at A again: A's own figures
    /// come back exactly — no re-scan, no "unknown". This is the reported bug.
    #[test]
    fn each_wallets_scanned_view_survives_scanning_another_wallet() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        record_v2(&mut pools, A, 700, 3);
        record_v2(&mut pools, B, 42, 1);

        let a = pools.view_for(A);
        assert_eq!(
            a.own_figures(A),
            Some((700, 3, 1600)),
            "wallet A's scanned figures must survive a scan of wallet B"
        );
        let b = pools.view_for(B);
        assert_eq!(b.own_figures(B), Some((42, 1, 942)));
        assert_eq!(pools.by_account.len(), 2, "one entry per scanned wallet");
    }

    /// (b) ISOLATION. While B is selected, NOTHING of A's is reachable: not the
    /// balance, not the note count, not the height, not the guard.
    #[test]
    fn a_selected_wallet_can_never_see_another_wallets_figures() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        // A is rich and scanned; B has never been scanned.
        record_v2(&mut pools, A, 700, 3);
        // B's view is its OWN, empty one.
        let b = pools.view_for(B);
        assert_eq!(b.account, "", "B has no scanned view of its own");
        assert_eq!(b.balance, 0);
        assert_eq!(b.own_figures(B), None, "B is UNKNOWN, not 700, not 0");

        // Defence in depth: even if A's view were handed to B's paint (it cannot
        // be — the lookup is by account), it claims nothing for B.
        let a = pools.view_for(A);
        assert_eq!(a.own_figures(B), None, "A's view may claim nothing for B");

        // And the guard built for B out of A's view refuses every spend.
        let g = a.guard(B, true, false, None);
        assert!(!g.for_this_wallet, "a foreign view is not this wallet's");
        assert_eq!(g.balance_grains, 0, "no foreign balance may leak in");
        assert_eq!(g.notes, 0);
        for intent in [
            V2Intent::Shield {
                to: "",
                amount: Some(1),
            },
            V2Intent::Deshield { amount: Some(1) },
            V2Intent::Send {
                to: "",
                amount: Some(1),
            },
        ] {
            assert_eq!(
                v2_allows(&g, intent),
                Err("this pool-v2 view belongs to a different wallet"),
                "a foreign view must authorise nothing"
            );
        }
    }

    /// (c) UNSCANNED IS UNKNOWN, NOT ZERO. An unscanned wallet reports no figures
    /// at all; a wallet actually scanned and found empty reports a real zero. The
    /// two must stay distinguishable — that is the whole point.
    #[test]
    fn unscanned_is_unknown_and_a_scanned_zero_is_a_real_zero() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        assert_eq!(
            pools.view_for(C).own_figures(C),
            None,
            "never scanned ⇒ UNKNOWN"
        );

        record_v2(&mut pools, C, 0, 0); // scanned; genuinely empty
        assert_eq!(
            pools.view_for(C).own_figures(C),
            Some((0, 0, 900)),
            "a completed scan that found nothing is a KNOWN zero"
        );

        // An unscanned wallet may not spend, and is told why in those words.
        let unscanned = ShieldedV2View::default();
        let g = unscanned.guard(A, true, false, None);
        assert!(
            g.for_this_wallet,
            "an untouched view belongs to nobody, so it is not a foreign one"
        );
        assert!(!g.scanned, "…but it is not scanned");
        assert_eq!(
            v2_allows(&g, V2Intent::Deshield { amount: Some(1) }),
            Err("scan pool v2 first — its balance is unknown until then")
        );
    }

    /// (d) A BACKGROUND SCAN THAT FINISHES FOR A NON-SELECTED WALLET lands in its
    /// own entry and cannot touch the selected wallet's view — the concurrency
    /// case the single slot got wrong.
    #[test]
    fn a_scan_completing_for_a_hidden_wallet_updates_only_that_wallet() {
        let pools: Arc<Mutex<ScannedPools<ShieldedV2View>>> =
            Arc::new(Mutex::new(ScannedPools::default()));
        // B is on screen and already scanned.
        record_v2(&mut pools.lock().unwrap(), B, 42, 1);

        // A's scan (started before the switch) completes now, off-thread.
        let bg = pools.clone();
        std::thread::spawn(move || record_v2(&mut bg.lock().unwrap(), A, 700, 3))
            .join()
            .expect("scan thread");

        let m = pools.lock().unwrap();
        assert_eq!(
            m.view_for(B).own_figures(B),
            Some((42, 1, 942)),
            "the selected wallet's view is untouched by another wallet's scan"
        );
        assert_eq!(
            m.view_for(A).own_figures(A),
            Some((700, 3, 1600)),
            "…and the completed scan is retained for the wallet it was run for"
        );
    }

    /// Two scans running at once, for different wallets, do not corrupt each
    /// other: each writes only its own entry, and both survive intact.
    #[test]
    fn concurrent_scans_for_different_wallets_do_not_corrupt_each_other() {
        let pools: Arc<Mutex<ScannedPools<ShieldedV2View>>> =
            Arc::new(Mutex::new(ScannedPools::default()));
        let mut threads = Vec::new();
        for (acct, bal, notes) in [(A, 700u64, 3usize), (B, 42, 1), (C, 5, 9)] {
            let p = pools.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    record_v2(&mut p.lock().unwrap(), acct, bal, notes);
                }
            }));
        }
        for t in threads {
            t.join().expect("scan thread");
        }
        let m = pools.lock().unwrap();
        assert_eq!(m.view_for(A).own_figures(A), Some((700, 3, 1600)));
        assert_eq!(m.view_for(B).own_figures(B), Some((42, 1, 942)));
        assert_eq!(m.view_for(C).own_figures(C), Some((5, 9, 905)));
        assert_eq!(m.by_account.len(), 3);
    }

    /// Busy is PER WALLET: a scan running for A must not read as A's spinner on
    /// B's screen, nor stop B from scanning.
    #[test]
    fn scanning_is_tracked_per_wallet() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        {
            let a = pools.entry_mut(A);
            a.scanning = true;
            a.account = A.to_string();
        }
        assert!(pools.view_for(A).scanning, "A is scanning");
        assert!(
            !pools.view_for(B).scanning,
            "B is not scanning just because A is"
        );
    }

    /// Forgetting a wallet drops its scanned view: no figures for a wallet that no
    /// longer exists, and no unbounded growth from stale keys.
    #[test]
    fn forgetting_a_wallet_drops_its_scanned_view() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        record_v2(&mut pools, A, 700, 3);
        record_v2(&mut pools, B, 42, 1);
        pools.forget(A);
        assert_eq!(
            pools.by_account.len(),
            1,
            "the forgotten wallet's entry is gone"
        );
        assert_eq!(
            pools.view_for(A).own_figures(A),
            None,
            "a forgotten wallet is UNKNOWN again"
        );
        assert_eq!(
            pools.view_for(B).own_figures(B),
            Some((42, 1, 942)),
            "…and the wallets that remain are untouched"
        );
    }

    /// POOL V1 gets the identical treatment — the same single-slot defect existed
    /// there, and a v1 balance belonging to another wallet is exactly as wrong as
    /// a v2 one.
    #[test]
    fn pool_v1_views_are_per_wallet_too() {
        let mut pools: ScannedPools<ShieldedView> = ScannedPools::default();
        {
            let v = pools.entry_mut(A);
            v.account = A.to_string();
            v.balance = 1234;
            v.notes = 2;
            v.scanned_height = 77;
        }
        {
            let v = pools.entry_mut(B);
            v.account = B.to_string();
            v.balance = 1;
            v.notes = 1;
            v.scanned_height = 78;
        }
        assert_eq!(pools.view_for(A).own_figures(A), Some((1234, 2, 77)));
        assert_eq!(pools.view_for(B).own_figures(B), Some((1, 1, 78)));
        assert_eq!(
            pools.view_for(A).own_figures(B),
            None,
            "A's v1 view may claim nothing for B"
        );
        assert_eq!(
            pools.view_for(C).own_figures(C),
            None,
            "an unscanned v1 wallet is UNKNOWN, not zero"
        );
    }

    /// The guard built from a wallet's OWN scanned view still authorises what it
    /// should — the fix must not turn every wallet into a permanently refused one.
    #[test]
    fn a_wallets_own_scanned_view_still_authorises_its_own_spends() {
        let mut pools: ScannedPools<ShieldedV2View> = ScannedPools::default();
        record_v2(&mut pools, A, 700, 3);
        let g = pools.view_for(A).guard(A, true, false, None);
        assert!(g.for_this_wallet && g.scanned);
        assert_eq!(g.balance_grains, 700);
        assert_eq!(g.notes, 3);
        assert_eq!(g.deshield_cap(), 700);
        assert_eq!(
            v2_allows(&g, V2Intent::Deshield { amount: Some(700) }),
            Ok(())
        );
        // …and the window budget still binds.
        let capped = pools.view_for(A).guard(A, true, false, Some(100));
        assert_eq!(capped.deshield_cap(), 100);
        assert!(v2_allows(&capped, V2Intent::Deshield { amount: Some(700) }).is_err());
    }
}
