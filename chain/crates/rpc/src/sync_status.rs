//! Live peer/sync telemetry shared across a node's threads (Phase 8).
//!
//! [`SyncShared`] is a small, lock-free snapshot of "where are we relative to the
//! network" that three parties touch:
//!
//! * the **P2P engine** ([`crate::p2p::P2p`]) is the sole *writer* — each tick it
//!   records HOW MANY BLOCKS behind the best authenticated peer we are, the highest
//!   peer height it has seen, and how many peers are authenticated;
//! * the **block-production loop** ([`crate::Daemon::run`]) *reads* it to GATE mining
//!   ONLY during a real initial download (far behind), via [`should_gate_mining`];
//! * a co-located **UI** (the desktop app) *reads* it for a rolling status display
//!   ("syncing 1208/8400" → "synced").
//!
//! Every field is an atomic, so a reader never blocks the node — the UI can poll it
//! every frame and the miner can check it between blocks at zero contention.
//!
//! ## Why a *threshold*, not "behind at all"
//!
//! An earlier version gated mining whenever we were behind by ANY amount. With two
//! miners that is fatal: the instant one wins a block the other is "1 behind", so it
//! stops mining and only syncs — by the time it catches up the leader has mined again,
//! so the follower NEVER gets to mine and the leader wins every block. A node that is a
//! block or two behind is in a normal Nakamoto *race*, not an initial download; it must
//! keep mining (fork choice + the deterministic tie-break converge the race). Only a
//! node that is genuinely far behind (a fresh/rejoining node) should pause and download.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// How many blocks behind the best peer we tolerate before *pausing* mining to download.
///
/// This is **1**, and the value is load-bearing for fair multi-miner rewards. A node
/// mines a block at `its_tip + 1`. For that block to COMPETE (and so have a ~50% chance
/// to win via the fork-choice tie-break) it must land at the network tip height — i.e.
/// the miner must be at most ONE block behind the tip when it mines. A node 2+ blocks
/// behind would mine *below* the tip, on a shorter fork that is always orphaned, so it
/// would burn work and never earn — exactly "fell behind almost instantly and never
/// mines again". So: 0–1 behind ⇒ keep racing (blocks compete at the tip); 2+ behind ⇒
/// pause and download until back within one. (The OLD rule "mine only when exactly level"
/// was unreachable on a real network with any latency, which is why the follower never
/// mined; "within one" is reachable as long as block time exceeds gossip propagation.)
pub const MINING_GATE_LAG: u64 = 1;

/// A lock-free view of this node's sync position relative to its authenticated peers.
/// Cloneable behind an [`Arc`](std::sync::Arc); construct one, hand a clone to the
/// [`Daemon`](crate::Daemon) (via [`with_sync_status`](crate::Daemon::with_sync_status))
/// and to the [`P2p`](crate::p2p::P2p) engine (via
/// [`with_sync_status`](crate::p2p::P2p::with_sync_status)), and read it anywhere.
#[derive(Debug, Default)]
pub struct SyncShared {
    /// How many blocks behind the best authenticated peer we are (0 if at/ahead of the
    /// tip). Block production pauses only when this exceeds [`MINING_GATE_LAG`].
    behind_blocks: AtomicU64,
    /// Highest block height advertised by any authenticated peer (0 if none).
    best_peer_height: AtomicU64,
    /// Number of peers that have completed the authenticated handshake.
    authed_peers: AtomicUsize,
    /// This node's most recently measured proof-of-work rate, in hashes per second
    /// (0 while not actively mining / gated). Published by the production loop and read
    /// by the UI so an operator can compare machines — block rewards track THIS
    /// (hashpower), not the number of machines, so a 10×-faster node earns ~10× the blocks.
    local_hashrate: AtomicU64,
}

impl SyncShared {
    /// A fresh telemetry handle: at the tip, no peers known yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// **(writer — P2P engine.)** Publish the latest peer view in one shot.
    pub fn update(&self, behind_blocks: u64, best_peer_height: u64, authed_peers: usize) {
        self.behind_blocks.store(behind_blocks, Ordering::Relaxed);
        self.best_peer_height
            .store(best_peer_height, Ordering::Relaxed);
        self.authed_peers.store(authed_peers, Ordering::Relaxed);
    }

    /// How many blocks behind the best authenticated peer we are (0 = at/ahead of tip).
    pub fn behind_blocks(&self) -> u64 {
        self.behind_blocks.load(Ordering::Relaxed)
    }

    /// Whether block production should PAUSE to download (a real initial sync), i.e. we
    /// are more than [`MINING_GATE_LAG`] blocks behind the tip. A node racing at the tip
    /// (0–`LAG` behind) keeps mining, so two miners share blocks instead of one lapping
    /// the other; a far-behind joiner pauses and catches up instead of forking.
    pub fn should_gate_mining(&self) -> bool {
        self.behind_blocks() > MINING_GATE_LAG
    }

    /// Whether we are strictly behind the tip at all (any amount). For UI nuance only —
    /// the *gate* uses [`should_gate_mining`].
    pub fn is_behind(&self) -> bool {
        self.behind_blocks() > 0
    }

    /// Highest block height advertised by any authenticated peer (0 if none).
    pub fn best_peer_height(&self) -> u64 {
        self.best_peer_height.load(Ordering::Relaxed)
    }

    /// Number of authenticated (handshake-complete) peers.
    pub fn authed_peers(&self) -> usize {
        self.authed_peers.load(Ordering::Relaxed)
    }

    /// **(writer — production loop.)** Publish the latest measured local hashrate (H/s).
    pub fn set_local_hashrate(&self, hps: u64) {
        self.local_hashrate.store(hps, Ordering::Relaxed);
    }

    /// This node's most recent measured proof-of-work rate (H/s); 0 when not mining.
    pub fn local_hashrate(&self) -> u64 {
        self.local_hashrate.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_at_tip_with_no_peers() {
        // A node with no peers (a fresh seed) must be free to mine — never gated.
        let s = SyncShared::new();
        assert!(!s.should_gate_mining());
        assert!(!s.is_behind());
        assert_eq!(s.best_peer_height(), 0);
        assert_eq!(s.authed_peers(), 0);
    }

    #[test]
    fn a_one_block_race_does_not_pause_mining() {
        // THE fairness guarantee: a node a block or two behind is racing, not doing an
        // initial download — it must keep mining so two miners share blocks instead of
        // the leader lapping the follower.
        let s = SyncShared::new();
        s.update(1, 100, 1);
        assert!(s.is_behind(), "it is strictly behind by one");
        assert!(
            !s.should_gate_mining(),
            "but a 1-block deficit is a race, not an initial download — keep mining"
        );
        s.update(MINING_GATE_LAG, 100, 1);
        assert!(
            !s.should_gate_mining(),
            "exactly at the lag is still racing"
        );
    }

    #[test]
    fn a_far_behind_joiner_pauses_to_download() {
        let s = SyncShared::new();
        s.update(MINING_GATE_LAG + 1, 5_000, 1);
        assert!(
            s.should_gate_mining(),
            "more than the lag behind = initial download, pause mining"
        );
        // Caught up to within the race window: mining resumes.
        s.update(0, 5_000, 1);
        assert!(!s.should_gate_mining());
    }
}
