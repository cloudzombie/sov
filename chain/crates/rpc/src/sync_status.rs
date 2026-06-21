//! Live peer/sync telemetry shared across a node's threads (Phase 8).
//!
//! [`SyncShared`] is a small, lock-free snapshot of "where are we relative to the
//! network" that three parties touch:
//!
//! * the **P2P engine** ([`crate::p2p::P2p`]) is the sole *writer* — each tick it
//!   records whether any authenticated peer advertises a heavier chain than ours,
//!   the highest peer height it has seen, and how many peers are authenticated;
//! * the **block-production loop** ([`crate::Daemon::run`]) *reads* it to GATE
//!   mining: a node must not extend its own chain while it is still catching up to
//!   a heavier peer chain — otherwise a freshly-joined node mines a competing fork
//!   instead of joining the existing one, and only converges after a deep reorg.
//!   This is the Nakamoto "don't mine during initial block download" rule;
//! * a co-located **UI** (the desktop app) *reads* it for a rolling status display
//!   ("syncing 1208/8400" → "synced").
//!
//! Every field is an atomic, so a reader never blocks the node — the UI can poll it
//! every frame and the miner can check it between blocks at zero contention.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// A lock-free view of this node's sync position relative to its authenticated peers.
/// Cloneable behind an [`Arc`](std::sync::Arc); construct one, hand a clone to the
/// [`Daemon`](crate::Daemon) (via [`with_sync_status`](crate::Daemon::with_sync_status))
/// and to the [`P2p`](crate::p2p::P2p) engine (via
/// [`with_sync_status`](crate::p2p::P2p::with_sync_status)), and read it anywhere.
#[derive(Debug, Default)]
pub struct SyncShared {
    /// Some authenticated peer advertises strictly more cumulative work than our
    /// local chain — i.e. we are still catching up and must NOT mine yet.
    behind: AtomicBool,
    /// Highest block height advertised by any authenticated peer (0 if none).
    best_peer_height: AtomicU64,
    /// Number of peers that have completed the authenticated handshake.
    authed_peers: AtomicUsize,
}

impl SyncShared {
    /// A fresh telemetry handle: not behind, no peers known yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// **(writer — P2P engine.)** Publish the latest peer view in one shot.
    pub fn update(&self, behind: bool, best_peer_height: u64, authed_peers: usize) {
        self.behind.store(behind, Ordering::Relaxed);
        self.best_peer_height
            .store(best_peer_height, Ordering::Relaxed);
        self.authed_peers.store(authed_peers, Ordering::Relaxed);
    }

    /// Whether we are still catching up to a heavier peer chain. Block production is
    /// gated on this being `false`, so a node syncs the existing chain before it
    /// mines instead of extending a competing fork. A solo node (no heavier peer)
    /// is never "behind", so it mines normally and bootstraps the network.
    pub fn is_behind(&self) -> bool {
        self.behind.load(Ordering::Relaxed)
    }

    /// Highest block height advertised by any authenticated peer (0 if none).
    pub fn best_peer_height(&self) -> u64 {
        self.best_peer_height.load(Ordering::Relaxed)
    }

    /// Number of authenticated (handshake-complete) peers.
    pub fn authed_peers(&self) -> usize {
        self.authed_peers.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_not_behind_with_no_peers() {
        // A node with no peers (a fresh seed) must be free to mine — `is_behind`
        // is false by default, so block production is never gated on having peers.
        let s = SyncShared::new();
        assert!(!s.is_behind());
        assert_eq!(s.best_peer_height(), 0);
        assert_eq!(s.authed_peers(), 0);
    }

    #[test]
    fn update_is_readable() {
        let s = SyncShared::new();
        s.update(true, 8_400, 2);
        assert!(s.is_behind());
        assert_eq!(s.best_peer_height(), 8_400);
        assert_eq!(s.authed_peers(), 2);
        // Catching up clears the gate.
        s.update(false, 8_405, 2);
        assert!(!s.is_behind());
    }
}
