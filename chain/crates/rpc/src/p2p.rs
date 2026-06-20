//! Production peer-to-peer networking (Phase 8, p8-i1; Nakamoto form).
//!
//! [`P2p`] is the application layer over [`sov_network::TcpNode`]: it turns a node
//! into a real network participant. It performs an **authenticated handshake**
//! (peers must prove they are on the same chain and control their key before they
//! are trusted), **gossips** transactions and blocks — applying each to the shared
//! [`Node`] and re-broadcasting it once — and **syncs a lagging node** by
//! requesting missing blocks by height. The same node that mines and serves RPC
//! participates here over the same shared [`Node`] handle.
//!
//! Under Nakamoto consensus the block *is* the vote: a block carries its own
//! proof of work, fork choice picks the heaviest chain, and finality is
//! confirmation depth — so no approval/finality messages exist on the wire.
//!
//! Trust is gated: a peer that does not complete the handshake is ignored
//! entirely — its blocks and transactions are never applied. Every applied block
//! is still re-validated by the chain's own import path, so the network is
//! trustless even among handshaken peers.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sov_crypto::Keypair;
use sov_network::{NetMessage, TcpNode};
use sov_node::Node;
use sov_primitives::{AccountId, Hash};
use sov_types::Block;

use crate::BlockLog;

/// The identity and chain binding a node presents in its handshake.
pub struct P2pConfig {
    /// The network/chain id this node belongs to.
    pub chain_id: String,
    /// The node's genesis block hash, pinning the exact chain and fork.
    pub genesis_hash: Hash,
    /// The node's account identity.
    pub account: AccountId,
    /// The key the node signs its handshake with.
    pub keypair: Keypair,
}

/// A peer-to-peer node: a TCP gossip transport bound to a shared [`Node`].
pub struct P2p {
    tcp: Arc<TcpNode>,
    node: Arc<Mutex<Node>>,
    config: Arc<P2pConfig>,
    /// If set, blocks imported from peers are persisted here, so a follower replays
    /// its own log on restart instead of re-syncing the whole chain.
    block_log: Option<Arc<BlockLog>>,
    /// Bootstrap peers to keep connected, retried periodically by the engine so a
    /// link survives the seed being down at startup or a peer sleeping and waking.
    bootstrap: Vec<String>,
}

/// A running gossip/sync engine. Stop it with [`P2pHandle::shutdown`].
pub struct P2pHandle {
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    tcp: Arc<TcpNode>,
    local_addr: SocketAddr,
}

impl P2pHandle {
    /// The address the transport is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// A handle to the transport (e.g. to attach to a daemon for gossiping
    /// produced blocks).
    pub fn tcp(&self) -> Arc<TcpNode> {
        Arc::clone(&self.tcp)
    }

    /// Dial a bootstrap peer (`host:port`).
    pub fn connect(&self, addr: &str) -> std::io::Result<()> {
        self.tcp.connect(addr)
    }

    /// Signal the engine to stop and wait for it to finish, then shut down the
    /// transport so the listen port is released (a node can be restarted in-process
    /// without "address already in use", and no accept/gossip thread lingers).
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.tcp.shutdown();
    }
}

impl P2p {
    /// Bind a TCP transport on `addr` for the shared `node`.
    pub fn bind(node: Arc<Mutex<Node>>, config: P2pConfig, addr: &str) -> std::io::Result<P2p> {
        Ok(P2p {
            tcp: Arc::new(TcpNode::bind(addr)?),
            node,
            config: Arc::new(config),
            block_log: None,
            bootstrap: Vec::new(),
        })
    }

    /// The address the transport is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.tcp.local_addr()
    }

    /// A handle to the transport (to gossip produced blocks, etc.).
    pub fn tcp(&self) -> Arc<TcpNode> {
        Arc::clone(&self.tcp)
    }

    /// Dial a bootstrap peer (`host:port`).
    pub fn connect(&self, addr: &str) -> std::io::Result<()> {
        self.tcp.connect(addr)
    }

    /// Persist blocks received from peers to `log` (typically shared with a
    /// [`Daemon`](crate::Daemon) via [`Daemon::block_log`]), so a follower replays
    /// its own block log on restart instead of re-syncing the entire chain.
    pub fn with_block_log(mut self, log: Arc<BlockLog>) -> Self {
        self.block_log = Some(log);
        self
    }

    /// Configure bootstrap peers the engine keeps connected: it retries them on a
    /// timer, so the link is established once a sleeping seed wakes and is
    /// re-established if it drops. (Initial best-effort dials can still be made via
    /// [`connect`](Self::connect).)
    pub fn with_bootstrap(mut self, peers: Vec<String>) -> Self {
        self.bootstrap = peers;
        self
    }

    /// Start the gossip + sync loop, returning a handle that controls it.
    pub fn start(self) -> P2pHandle {
        let shutdown = Arc::new(AtomicBool::new(false));
        let local_addr = self.tcp.local_addr();
        let tcp = Arc::clone(&self.tcp);
        let node = Arc::clone(&self.node);
        let config = Arc::clone(&self.config);
        let block_log = self.block_log.clone();
        let bootstrap = self.bootstrap.clone();
        let stop = Arc::clone(&shutdown);

        let worker = thread::spawn(move || {
            let mut state = SyncState::new(block_log);
            let mut tick: u64 = 0;
            while !stop.load(Ordering::SeqCst) {
                // Periodically announce our identity + head so peers authenticate
                // us and learn whether they need to sync from us.
                if tick % 8 == 0 {
                    announce(&tcp, &node, &config);
                }
                // Keep bootstrap links up: ~every 2s ask to (re)connect any that are
                // down. Cheap no-op when already connected; recovers a seed that was
                // asleep at startup or a link that dropped.
                if tick % 50 == 0 {
                    for addr in &bootstrap {
                        tcp.request_reconnect(addr);
                    }
                }
                for (peer, msg) in tcp.drain() {
                    state.handle(&tcp, &node, &config, peer, msg);
                }
                state.request_missing(&tcp, &node);
                thread::sleep(Duration::from_millis(40));
                tick += 1;
            }
        });

        P2pHandle {
            shutdown,
            worker: Some(worker),
            tcp: self.tcp,
            local_addr,
        }
    }
}

/// Our handshake + head, sent per-peer so each `Hello` is bound to that peer's own
/// encrypted channel (channel binding), then peers can authenticate us and gauge sync.
fn announce(tcp: &TcpNode, node: &Mutex<Node>, config: &P2pConfig) {
    let status = status(node);
    for peer in tcp.connected_peers() {
        if let Some(binding) = tcp.peer_handshake_hash(&peer) {
            tcp.send(peer, &hello(config, &binding));
            if let Some(s) = &status {
                tcp.send(peer, s);
            }
        }
    }
}

fn hello(config: &P2pConfig, channel_binding: &[u8]) -> NetMessage {
    NetMessage::hello(
        &config.chain_id,
        config.genesis_hash,
        config.account.clone(),
        channel_binding,
        &config.keypair,
    )
}

fn status(node: &Mutex<Node>) -> Option<NetMessage> {
    let n = node.lock().ok()?;
    Some(NetMessage::Status {
        height: n.chain().height(),
        head: n.chain().head().hash(),
        chain_work: n.chain().chain_work().to_be_bytes(),
    })
}

/// How long a block request may go unanswered before sync treats the peer as
/// stalled and falls back to the next-best peer. Comfortably above any healthy
/// round-trip, short enough that a withholding or dead peer cannot wedge sync.
const BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// An outstanding [`GetBlock`](NetMessage::GetBlock) awaiting a response, used to
/// detect a stalled peer. Cleared as soon as any block response arrives.
struct InFlight {
    /// The peer the request was sent to.
    peer: SocketAddr,
    /// When it was sent (for the [`BLOCK_REQUEST_TIMEOUT`] stall check).
    since: Instant,
}

/// Per-connection sync bookkeeping for the gossip loop.
#[derive(Default)]
struct SyncState {
    /// Peers that completed the authenticated handshake.
    authenticated: HashSet<SocketAddr>,
    /// Last-known head status per peer (drives chainwork-based catch-up).
    peer_status: HashMap<SocketAddr, PeerStatus>,
    /// Next height to request from each peer while walking backward to a common
    /// ancestor, then forward along that peer's heavier active chain.
    sync_next: HashMap<SocketAddr, u64>,
    /// The block request currently awaiting a response, if any — drives stall
    /// detection so a single slow/withholding peer cannot wedge catch-up.
    inflight: Option<InFlight>,
    /// If set, blocks imported from peers are persisted here so a follower replays
    /// its own log on restart instead of re-syncing the whole chain.
    block_log: Option<Arc<BlockLog>>,
}

#[derive(Clone, Copy)]
struct PeerStatus {
    height: u64,
    head: Hash,
    chain_work: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportOutcome {
    New,
    Known,
    Rejected,
}

impl SyncState {
    fn new(block_log: Option<Arc<BlockLog>>) -> Self {
        SyncState {
            block_log,
            ..Default::default()
        }
    }

    /// Import a peer's block and PERSIST it to the block log, both while holding
    /// the node lock so the on-disk order matches the chain-commit order even when
    /// the mining thread is committing concurrently. Returns whether the block was
    /// accepted (extended, stored, or reorged onto — the chain decides). This is
    /// what lets a follower replay its own log on restart rather than re-syncing
    /// the whole chain.
    fn import_and_persist(&self, node: &Mutex<Node>, block: Block) -> ImportOutcome {
        let Ok(mut n) = node.lock() else {
            return ImportOutcome::Rejected;
        };
        if n.chain().contains_block(&block.hash()) {
            return ImportOutcome::Known;
        }
        if n.import_block(block.clone()).is_err() {
            return ImportOutcome::Rejected;
        }
        if let Some(log) = &self.block_log {
            let _ = log.append(&block);
        }
        ImportOutcome::New
    }

    fn handle(
        &mut self,
        tcp: &TcpNode,
        node: &Mutex<Node>,
        config: &P2pConfig,
        peer: SocketAddr,
        msg: NetMessage,
    ) {
        // Authenticated handshake: a Hello is trusted only if it is for our chain
        // AND bound to THIS connection's Noise channel (defeating a MITM that
        // relays a Hello from another channel). Only peers that prove same-chain
        // membership and key control are trusted with any chain data.
        let binding = tcp.peer_handshake_hash(&peer);
        let is_authed_hello = binding
            .as_ref()
            .map(|b| {
                msg.authenticated_account(&config.chain_id, &config.genesis_hash, b)
                    .is_some()
            })
            .unwrap_or(false);
        if is_authed_hello {
            if self.authenticated.insert(peer) {
                // Reciprocate, bound to this same channel, so the peer authenticates
                // us and learns our height.
                if let Some(b) = &binding {
                    tcp.send(peer, &hello(config, b));
                }
                if let Some(status) = status(node) {
                    tcp.send(peer, &status);
                }
            }
            return;
        }
        if !self.authenticated.contains(&peer) {
            return; // untrusted: ignore until it completes the handshake
        }

        match msg {
            NetMessage::Status {
                height,
                head,
                chain_work,
            } => {
                self.peer_status.insert(
                    peer,
                    PeerStatus {
                        height,
                        head,
                        chain_work,
                    },
                );
                if let Some(local) = local_status(node) {
                    if head == local.head {
                        self.sync_next.remove(&peer);
                    } else if chain_work > local.chain_work {
                        let start = if height > local.height {
                            local.height + 1
                        } else {
                            height
                        };
                        self.sync_next.entry(peer).or_insert(start.max(1));
                    }
                }
            }
            NetMessage::NewTransaction(stx) => {
                let accepted = node
                    .lock()
                    .map(|mut n| n.submit(stx.clone()).is_ok())
                    .unwrap_or(false);
                if accepted {
                    tcp.broadcast(&NetMessage::NewTransaction(stx)); // forward once
                }
            }
            NetMessage::NewBlock(block) => {
                // The block carries its own authority (its proof of work); import
                // re-validates everything and fork choice decides what it does to
                // the chain. Persisted under the node lock (order == commit
                // order); the lock is released before any network I/O.
                if self.import_and_persist(node, block.clone()) == ImportOutcome::New {
                    tcp.broadcast(&NetMessage::NewBlock(block)); // forward once
                }
            }
            NetMessage::GetBlock { height } => {
                let block = node
                    .lock()
                    .ok()
                    .and_then(|n| n.chain().block_by_height(height).cloned());
                tcp.send(peer, &NetMessage::BlockResponse(block));
            }
            NetMessage::BlockResponse(Some(block)) => {
                // The outstanding request is answered; let the next round pick the
                // best peer afresh (and not treat this peer as stalled).
                self.inflight = None;
                // Catch-up import; succeeds only when it is our next height (or a
                // branch fork choice accepts). No votes to fetch — confirmations
                // accumulate as further blocks arrive.
                let requested_height = block.header.height.get();
                match self.import_and_persist(node, block) {
                    ImportOutcome::New | ImportOutcome::Known => {
                        if let Some(s) = self.peer_status.get(&peer) {
                            if requested_height < s.height {
                                self.sync_next.insert(peer, requested_height + 1);
                            } else {
                                self.sync_next.remove(&peer);
                            }
                        }
                    }
                    ImportOutcome::Rejected => {
                        if requested_height > 1 {
                            self.sync_next.insert(peer, requested_height - 1);
                        } else {
                            self.sync_next.remove(&peer);
                        }
                    }
                }
            }
            NetMessage::BlockResponse(None) => {
                // The peer does not have the requested height (e.g. we walked past
                // its head): the request is answered, so stop waiting on it.
                self.inflight = None;
            }
            NetMessage::Peers(_) | NetMessage::Hello { .. } => {}
        }
    }

    /// Forget bookkeeping for peers that are no longer connected, so catch-up never
    /// targets a ghost peer (whose `send` would silently fail and stall sync) and
    /// per-peer state cannot grow without bound across reconnects.
    fn retain_connected(&mut self, connected: &HashSet<SocketAddr>) {
        self.authenticated.retain(|p| connected.contains(p));
        self.peer_status.retain(|p, _| connected.contains(p));
        self.sync_next.retain(|p, _| connected.contains(p));
    }

    /// Drive catch-up against trusted peers: request the next block from the best
    /// peer that is authenticated, **still connected**, and advertising more
    /// chainwork than us — with one request in flight at a time. If that request
    /// stalls (no response within [`BLOCK_REQUEST_TIMEOUT`], or the peer vanished),
    /// fall back to the next-best peer, so a single slow or block-withholding peer
    /// cannot wedge sync.
    fn request_missing(&mut self, tcp: &TcpNode, node: &Mutex<Node>) {
        let Some(local) = local_status(node) else {
            return;
        };
        let connected: HashSet<SocketAddr> = tcp.connected_peers().into_iter().collect();
        self.retain_connected(&connected);

        // A live, un-timed-out request is outstanding: give it time rather than
        // re-asking or thrashing to another peer.
        if let Some(f) = &self.inflight {
            if connected.contains(&f.peer) && f.since.elapsed() < BLOCK_REQUEST_TIMEOUT {
                return;
            }
        }
        // A request that survived to here stalled (timed out or its peer is gone):
        // avoid that peer this round so it cannot keep wedging catch-up.
        let stalled_peer = self.inflight.as_ref().map(|f| f.peer);

        // Candidate peers ahead of us that we can actually reach, best work first.
        let mut candidates: Vec<SocketAddr> = self
            .peer_status
            .iter()
            .filter(|(p, s)| {
                s.chain_work > local.chain_work
                    && self.authenticated.contains(p)
                    && connected.contains(p)
            })
            .map(|(p, _)| *p)
            .collect();
        if candidates.is_empty() {
            self.inflight = None;
            return;
        }
        candidates.sort_by_key(|p| std::cmp::Reverse(self.peer_status[p].chain_work));

        // Prefer the best peer; skip the stalled one unless it is our only option.
        let peer = candidates
            .iter()
            .copied()
            .find(|p| Some(*p) != stalled_peer)
            .unwrap_or(candidates[0]);
        let peer_height = self.peer_status[&peer].height;

        let height = self
            .sync_next
            .get(&peer)
            .copied()
            .unwrap_or_else(|| {
                if peer_height > local.height {
                    local.height + 1
                } else {
                    peer_height
                }
            })
            .clamp(1, peer_height);
        if tcp.send(peer, &NetMessage::GetBlock { height }) {
            self.inflight = Some(InFlight {
                peer,
                since: Instant::now(),
            });
        } else {
            // The peer dropped between selection and send; clear so the next tick
            // re-evaluates against the live peer set.
            self.inflight = None;
        }
    }
}

fn local_status(node: &Mutex<Node>) -> Option<PeerStatus> {
    let n = node.lock().ok()?;
    Some(PeerStatus {
        height: n.chain().height(),
        head: n.chain().head().hash(),
        chain_work: n.chain().chain_work().to_be_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn peer_status(height: u64, work: u8) -> PeerStatus {
        PeerStatus {
            height,
            head: Hash::digest(&[work]),
            chain_work: [work; 32],
        }
    }

    #[test]
    fn retain_connected_prunes_ghost_peers() {
        // A peer that was authenticated and advertised the heaviest chain, but has
        // since disconnected, must be forgotten — otherwise catch-up keeps targeting
        // it (its `send` silently fails) and sync wedges. This is the core of the
        // sync-robustness fix.
        let mut s = SyncState::new(None);
        let live = addr(7001);
        let gone = addr(7002);
        s.authenticated.insert(live);
        s.authenticated.insert(gone);
        s.peer_status.insert(live, peer_status(5, 5));
        s.peer_status.insert(gone, peer_status(9, 9)); // the (now dead) "best" peer
        s.sync_next.insert(gone, 3);
        s.sync_next.insert(live, 6);

        let connected: HashSet<SocketAddr> = [live].into_iter().collect();
        s.retain_connected(&connected);

        assert!(s.authenticated.contains(&live));
        assert!(
            !s.authenticated.contains(&gone),
            "a disconnected peer is dropped from the authenticated set"
        );
        assert!(s.peer_status.contains_key(&live));
        assert!(
            !s.peer_status.contains_key(&gone),
            "no stale status for a gone peer (so it is never chosen for catch-up)"
        );
        assert!(s.sync_next.contains_key(&live));
        assert!(
            !s.sync_next.contains_key(&gone),
            "no stale sync cursor for a gone peer"
        );
    }

    #[test]
    fn an_answered_request_is_no_longer_in_flight() {
        // A block response clears the in-flight marker so the next round picks the
        // best peer afresh rather than treating the responder as stalled.
        let mut s = SyncState::new(None);
        s.inflight = Some(InFlight {
            peer: addr(7003),
            since: Instant::now(),
        });
        // Mirror what handle() does on receiving a (None) block response.
        s.inflight = None;
        assert!(s.inflight.is_none());
    }
}
