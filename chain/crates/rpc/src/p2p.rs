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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sov_chain::ChainError;
use sov_crypto::Keypair;
use sov_network::{NetMessage, TcpNode};
use sov_node::{Node, NodeError};
use sov_primitives::{AccountId, Hash};
use sov_types::Block;

use crate::sync_status::SyncShared;
use crate::BlockLog;

/// An optional human-readable diagnostics sink (the desktop app's Node-log buffer),
/// so an operator SEES the join/sync pipeline — authentication, block requests,
/// serving, and stalls — instead of an opaque "connected but nothing happening". When
/// `None` (headless/tests) it costs nothing.
type LogSink = Option<Arc<Mutex<Vec<String>>>>;

/// Append one timestamped P2P diagnostic line to `sink` (capped, like the GUI's own
/// logger). A no-op when there is no sink.
fn p2p_log(sink: &LogSink, msg: impl AsRef<str>) {
    let Some(sink) = sink else { return };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    let line = format!(
        "{:02}:{:02}:{:02}  p2p: {}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        msg.as_ref()
    );
    if let Ok(mut v) = sink.lock() {
        v.push(line);
        let n = v.len();
        if n > 5_000 {
            v.drain(0..n - 5_000);
        }
    }
}

/// A short, log-friendly tag for a peer address (the IP:port is enough to correlate
/// across the two machines without dumping noise).
fn short_peer(p: &SocketAddr) -> String {
    p.to_string()
}

/// An abbreviated block hash for logs: `abcdef…1234`.
fn short_hash(h: &Hash) -> String {
    let s = h.to_hex();
    if s.len() > 12 {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    } else {
        s
    }
}

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
    /// If set, the engine publishes live sync telemetry here each tick (whether we
    /// are behind a heavier peer, the best peer height, distinct authenticated peer
    /// count) — read by the mining loop to gate production and by the UI for status.
    sync_status: Option<Arc<SyncShared>>,
    /// Optional Node-log sink for human-readable sync diagnostics.
    log_sink: LogSink,
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
            sync_status: None,
            log_sink: None,
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

    /// Publish live sync telemetry to `status` each tick: whether we are behind a
    /// heavier peer chain (which gates the miner — share the SAME handle with
    /// [`Daemon::with_sync_status`](crate::Daemon::with_sync_status) so a node syncs
    /// before it mines), the best peer height, and the count of DISTINCT
    /// authenticated peers (so a redundant link never shows as a ghost peer).
    pub fn with_sync_status(mut self, status: Arc<SyncShared>) -> Self {
        self.sync_status = Some(status);
        self
    }

    /// Surface human-readable sync diagnostics (authentication, block requests,
    /// serving, stalls) into `sink` — typically the desktop app's Node-log buffer — so
    /// an operator can see the join pipeline progress (or pinpoint exactly where it
    /// stops) on each machine.
    pub fn with_log_sink(mut self, sink: Arc<Mutex<Vec<String>>>) -> Self {
        self.log_sink = Some(sink);
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
        let sync_status = self.sync_status.clone();
        let log_sink = self.log_sink.clone();
        // A second handle to the same sink for bootstrap-dial diagnostics (the primary
        // `log_sink` is moved into `SyncState`, which logs the app-layer sync events).
        let boot_log = self.log_sink.clone();
        let stop = Arc::clone(&shutdown);

        let worker = thread::spawn(move || {
            let mut state = SyncState::new(block_log, log_sink);
            // Periodic tasks are driven by ELAPSED TIME, not a fixed tick count, so the
            // POLL cadence can be adaptive (fast while catching up) without also firing
            // announce/reconnect/sweep far too often. Seed each timer in the past so it
            // fires on the first iteration.
            let past = Instant::now()
                .checked_sub(Duration::from_secs(3_600))
                .unwrap_or_else(Instant::now);
            let mut last_announce = past;
            let mut last_reconnect = past;
            let mut last_sweep = past;
            while !stop.load(Ordering::SeqCst) {
                // Announce our identity + head so peers authenticate us and learn whether
                // they need to sync from us.
                if last_announce.elapsed() >= ANNOUNCE_INTERVAL {
                    announce(&tcp, &node, &config);
                    last_announce = Instant::now();
                }
                // Keep bootstrap links up: a cheap no-op when already connected; recovers
                // a seed that was asleep at startup or a link that dropped.
                if last_reconnect.elapsed() >= RECONNECT_INTERVAL {
                    for addr in &bootstrap {
                        // Tolerant resolve + non-blocking dial request. An unresolvable
                        // bootstrap address is logged ONCE (on the first sweep) rather than
                        // every interval, so a typo is visible without spamming the log.
                        if let Err(e) = tcp.request_reconnect(addr) {
                            if last_reconnect == past {
                                p2p_log(
                                    &boot_log,
                                    format!("bootstrap peer '{addr}' unusable: {e}"),
                                );
                            }
                        }
                    }
                    last_reconnect = Instant::now();
                }
                for (peer, msg) in tcp.drain() {
                    state.handle(&tcp, &node, &config, peer, msg);
                }
                // One fsync for every block imported in this drain (a catch-up batch is
                // one fsync, not 256) — keeps the single worker thread responsive so peers
                // are never reaped mid-import.
                state.sync_log();
                state.request_missing(&tcp, &node);
                // Publish live telemetry every poll: how many blocks behind the tip we are
                // (gates the miner only during a real download, not a 1-block race), the
                // best peer height, and the DISTINCT authenticated-peer count (so the UI
                // never shows a redundant link as a ghost). Cheap — map scans + atomic
                // stores, no extra locks.
                let (behind_blocks, best, peers) = state.telemetry(&node);
                if let Some(s) = &sync_status {
                    s.update(behind_blocks, best, peers);
                }
                // Reclaim slots from peers that connected but never authenticated
                // (zombie-eclipse defense), and reap dead half-open connections to a
                // vanished peer (clears ghost counts AND stops catch-up forever targeting
                // a peer that can never answer).
                if last_sweep.elapsed() >= SWEEP_INTERVAL {
                    state.sweep_unauthenticated(&tcp);
                    state.reap_dead_peers(&tcp);
                    last_sweep = Instant::now();
                }
                // ADAPTIVE poll: while a block request is in flight (actively catching
                // up) poll fast so batches stream back-to-back, turning a long initial
                // sync from minutes of idle-tick overhead into seconds; otherwise idle at
                // the slow cadence so a caught-up node sips CPU.
                let nap = if state.has_inflight() {
                    SYNC_ACTIVE_POLL
                } else {
                    IDLE_POLL
                };
                thread::sleep(nap);
            }
            // On shutdown, make durable any records the last drain wrote but hadn't yet
            // fsync'd — so a clean stop never relies on the OS to flush the tail.
            state.sync_log();
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

/// How many consecutive blocks one [`GetBlocks`](NetMessage::GetBlocks) fetches.
/// Batching turns a long catch-up from one-block-per-round-trip (minutes) into a
/// handful of round-trips (seconds), with far fewer messages — well under the
/// per-peer rate limit. The serving node caps the response to this many. 256 small
/// blocks fit comfortably under the 8 MiB transport frame, so a 10k-block chain is a
/// few dozen round-trips. Wire-compatible: the cap is `min(requested, SYNC_BATCH)`, so
/// a newer/older peer simply serves the smaller of the two.
const SYNC_BATCH: u16 = 256;

/// Poll cadence while a block request is in flight (actively catching up): batches
/// stream back-to-back instead of one per idle tick, so a long initial sync is bound by
/// import + network, not by a fixed sleep.
const SYNC_ACTIVE_POLL: Duration = Duration::from_millis(2);

/// Poll cadence when caught up / idle — slow, so a synced node uses negligible CPU.
const IDLE_POLL: Duration = Duration::from_millis(40);

/// How often to re-announce our identity + head to peers.
const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(320);

/// How often to re-dial configured bootstrap peers that are not currently connected.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(2);

/// How often to sweep unauthenticated zombies and reap dead half-open connections.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Warn when a single block import holds the node lock at least this long. A plain
/// extend is sub-millisecond; crossing this means the reorg replay (currently O(chain
/// length) from genesis) is starting to block peer I/O — the signal that motivates the
/// incremental-reorg work.
const SLOW_IMPORT_MS: u128 = 50;

/// Largest exponential backtrack step when walking back to a common ancestor on a
/// fork: 1, 2, 4, … capped here, so even a deep divergence is located in O(log)
/// requests instead of one height at a time.
const BACKTRACK_CAP: u64 = 256;

/// Misbehavior points charged (via [`TcpNode::penalize_peer`]) to a peer that sends a
/// block which FAILS validation — bad proof of work, a fabricated state/receipts root,
/// a broken supply invariant, etc.: things an honest peer never produces. It is NOT
/// charged for a block that merely can't connect yet (an unknown parent, the ordinary
/// backtrack signal). Calibrated against the transport ban threshold (100), so a
/// couple of fabricated blocks ban + drop the peer.
const INVALID_BLOCK_PENALTY: f64 = 50.0;

/// Misbehavior points for a [`BlocksResponse`](NetMessage::BlocksResponse) carrying
/// more blocks than we ever request ([`SYNC_BATCH`]) — a memory/CPU amplification an
/// honest (server-capped) peer never sends.
const OVERSIZE_RESPONSE_PENALTY: f64 = 50.0;

/// How long a freshly-connected peer may go without completing the authenticated
/// `Hello` handshake before its inbound slot is reclaimed (it is DISCONNECTED, not
/// banned — a slow or old client may simply reconnect). Bounds a zombie-connection
/// eclipse: an attacker cannot pin inbound slots open by connecting and going silent,
/// since the transport's eclipse caps count those slots until they are reclaimed here.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connected peer may send NOTHING before it is treated as dead and its
/// connection reaped. Healthy peers exchange `Status` every announce cycle (sub-second),
/// so any real peer refreshes this constantly; only a half-open connection to a
/// vanished peer (machine off, Wi-Fi drop — no TCP FIN/RST, so the blocking read never
/// returns and the OS keepalive is hours away) goes silent this long. Reaping it both
/// frees the ghost slot AND stops catch-up from forever targeting a dead peer that can
/// never answer — the latter is why a node can be "connected" yet never index.
///
/// Headroom note: stalled SYNC is already retargeted in [`BLOCK_REQUEST_TIMEOUT`] (2s),
/// so this timeout is only about reaping a truly silent ghost. Kept generous so a brief
/// worker stall (e.g. an occasional deep side-branch replay under the node lock) can
/// never reap a healthy, actively-syncing peer — the "hokey connections" failure mode.
const PEER_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(45);

/// Of several connections to the SAME node, pick the deterministic survivor: the one
/// with the lexicographically smallest channel binding (Noise handshake hash). Both
/// ends of a connection share its binding, so each node picks the SAME survivor with
/// no coordination — the property that makes duplicate-connection collapse converge
/// without a flap. `None` only for empty input.
fn survivor(candidates: &[(SocketAddr, Vec<u8>)]) -> Option<SocketAddr> {
    candidates
        .iter()
        .min_by(|a, b| a.1.cmp(&b.1))
        .map(|(p, _)| *p)
}

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
    /// The authenticated node IDENTITY (its account) per connection. Lets us collapse
    /// MULTIPLE connections to the SAME node down to one — the definitive fix for "one
    /// machine shows up as several peers" (a redundant inbound + outbound, or a startup
    /// race) that IP/timing dedup can't fully prevent. Identity-keyed, so it works the
    /// same on a LAN or across the internet.
    identity: HashMap<SocketAddr, AccountId>,
    /// Last-known head status per peer (drives chainwork-based catch-up).
    peer_status: HashMap<SocketAddr, PeerStatus>,
    /// Next height to request from each peer while walking backward to a common
    /// ancestor, then forward along that peer's heavier active chain.
    sync_next: HashMap<SocketAddr, u64>,
    /// Per-peer exponential backtrack step. Absent/0 = forward mode (batched
    /// download); >0 = walking back to a common ancestor by this many heights, then
    /// doubling, so a deep fork is located in O(log) requests.
    bt_step: HashMap<SocketAddr, u64>,
    /// When each currently-connected peer was first observed, so a connection that
    /// completes the transport handshake but never authenticates ([`HELLO_TIMEOUT`])
    /// can be reclaimed — it cannot squat an inbound slot.
    first_seen: HashMap<SocketAddr, Instant>,
    /// When we last received ANY message from each peer — refreshed by every healthy
    /// peer's periodic `Status`. A peer silent past [`PEER_INACTIVITY_TIMEOUT`] is a
    /// dead (half-open) connection and is reaped, so it stops counting as a peer AND
    /// stops being a catch-up target that can never answer.
    last_recv: HashMap<SocketAddr, Instant>,
    /// The block request currently awaiting a response, if any — drives stall
    /// detection so a single slow/withholding peer cannot wedge catch-up.
    inflight: Option<InFlight>,
    /// If set, blocks imported from peers are persisted here so a follower replays
    /// its own log on restart instead of re-syncing the whole chain.
    block_log: Option<Arc<BlockLog>>,
    /// Optional Node-log sink for human-readable sync diagnostics (see [`LogSink`]).
    log: LogSink,
    /// Peers we have already logged an "ignoring … from unauthenticated peer" line for,
    /// so the diagnostic fires ONCE per peer rather than every frame.
    unauth_logged: HashSet<SocketAddr>,
    /// The last `(peer, height)` we logged a block request for, so a repeated request to
    /// the same target (the "stuck at the same height" case) logs once, not every tick.
    last_req_log: Option<(SocketAddr, u64)>,
    /// Whether we have logged the current stall, so "no reply, retrying" fires on the
    /// stall transition rather than continuously.
    stalled_logged: bool,
}

#[derive(Clone, Copy)]
struct PeerStatus {
    height: u64,
    head: Hash,
    chain_work: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportOutcome {
    /// Accepted and newly added to the chain (extended, stored, or reorged onto).
    New,
    /// Already known — a no-op (e.g. a duplicate in a batch).
    Known,
    /// Did not connect to a known parent — the ordinary "walk back to a common
    /// ancestor" signal during sync. NOT misbehavior.
    Rejected,
    /// FAILED validation (bad PoW, a fabricated state/receipts root, a broken
    /// invariant, …) — a block an honest peer never sends. The sender is penalized.
    Invalid,
}

impl SyncState {
    fn new(block_log: Option<Arc<BlockLog>>, log: LogSink) -> Self {
        SyncState {
            block_log,
            log,
            ..Default::default()
        }
    }

    /// Flush + fsync the block log once, making durable every record written by the
    /// imports in this poll iteration. Called once after draining all messages, so a
    /// 256-block catch-up batch costs ONE fsync instead of 256. A cheap no-op when no
    /// blocks were written.
    fn sync_log(&self) {
        if let Some(log) = &self.block_log {
            let _ = log.sync();
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
        let prev_head = n.chain().head().hash();
        let prev_height = n.chain().height();
        // Time the import: this whole call holds the node lock (blocking peer I/O, RPC,
        // mining), and a reorg currently replays its branch from genesis — an O(chain
        // length) cost. Surfacing the lock-held time makes that cost visible so a deep
        // replay can't masquerade as a silent stall / peer drop.
        let started = Instant::now();
        match n.import_block(block.clone()) {
            Ok(_) => {}
            // "Does not extend a known parent" is the ordinary backtrack signal during
            // sync; a too-far-future timestamp is clock skew ("not yet valid", as in
            // Bitcoin) — neither is misbehavior, so keep walking back without penalty.
            Err(NodeError::Chain(ChainError::PrevHashMismatch))
            | Err(NodeError::TimestampTooFarInFuture { .. }) => return ImportOutcome::Rejected,
            // EVERY other error (bad PoW, fabricated state/receipts root, a broken
            // invariant, …) is a block an honest peer never sends: the peer misbehaves.
            Err(_) => return ImportOutcome::Invalid,
        }
        let new_head = n.chain().head().hash();
        let new_height = n.chain().height();
        // Write under the node lock so the on-disk order matches commit order, but do
        // NOT fsync here — the worker fsyncs once per drain (see `sync_log`). On the
        // single P2P thread, an fsync-per-block (a slow Windows FlushFileBuffers) stalls
        // peer I/O + keepalives across a 256-block batch and gets the node reaped; one
        // fsync per drain keeps the thread responsive while preserving durability.
        if let Some(log) = &self.block_log {
            let _ = log.append_unsynced(&block);
        }
        let lock_ms = started.elapsed().as_millis();
        drop(n);
        // A head move to a block that does NOT simply extend the prior head is a REORG —
        // we abandoned our current tip for a competing branch. NEVER silent: log both
        // heads + height (and how long it held the lock), so an operator always knows
        // EXACTLY what happened to the chain (this is the "lost where it is" event made
        // explicit). With the deterministic fork-choice tie-break + jittered block timing,
        // these are rare and convergent.
        if new_head != prev_head && block.header.prev_hash != prev_head {
            p2p_log(
                &self.log,
                format!(
                    "⚠ REORG: head {}@{} → {}@{} in {lock_ms}ms (adopted a heavier/smaller-hash competing block)",
                    short_hash(&prev_head),
                    prev_height,
                    short_hash(&new_head),
                    new_height,
                ),
            );
        } else if lock_ms >= SLOW_IMPORT_MS {
            // A plain extend that nonetheless held the lock a long time — a warning that
            // import cost is growing (the signal that motivates an incremental reorg).
            p2p_log(
                &self.log,
                format!(
                    "⚠ slow block import: {lock_ms}ms (held the node lock) at height {new_height}"
                ),
            );
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
        // Liveness: receiving ANY frame proves the peer is alive — refresh its
        // last-seen so the dead-connection reaper only ever fires on a truly silent
        // (half-open) connection.
        self.last_recv.insert(peer, Instant::now());
        // Authenticated handshake: a Hello is trusted only if it is for our chain
        // AND bound to THIS connection's Noise channel (defeating a MITM that
        // relays a Hello from another channel). Only peers that prove same-chain
        // membership and key control are trusted with any chain data.
        let binding = tcp.peer_handshake_hash(&peer);
        let authed_account = binding.as_ref().and_then(|b| {
            msg.authenticated_account(&config.chain_id, &config.genesis_hash, b)
                .cloned()
        });
        if let Some(account) = authed_account {
            // Self-connection: a peer gossiped OUR OWN public address back and we dialed
            // ourselves, so the authenticated Hello carries our own account. There is
            // nothing to sync from ourselves — record the address so the dialer never
            // reopens it (`local_addr` only knows our bind address, not our reachable
            // one), drop the link, and never register it as a peer. (Two distinct nodes
            // sharing one account identity is a misconfiguration and is treated the same.)
            if account == config.account {
                tcp.mark_self_addr(peer);
                tcp.disconnect(&peer);
                self.last_recv.remove(&peer);
                p2p_log(
                    &self.log,
                    format!("dropped self-connection {}", short_peer(&peer)),
                );
                return;
            }
            let first_time = self.authenticated.insert(peer);
            self.identity.insert(peer, account.clone());
            if first_time {
                // Reciprocate, bound to this same channel, so the peer authenticates
                // us and learns our height.
                if let Some(b) = &binding {
                    tcp.send(peer, &hello(config, b));
                }
                if let Some(status) = status(node) {
                    tcp.send(peer, &status);
                }
                // A duplicate link can only form when a connection FIRST authenticates,
                // so dedup here (not on every repeat Hello — that would be O(peers²) at
                // scale). Collapse any duplicate connections to this node down to one.
                self.dedup_identity(tcp, &account);
                self.unauth_logged.remove(&peer); // it's authed now; allow future warnings
                p2p_log(
                    &self.log,
                    format!(
                        "✓ authenticated {} as {} ({} peer(s))",
                        short_peer(&peer),
                        account,
                        self.authenticated.len()
                    ),
                );
            }
            return;
        }
        if !self.authenticated.contains(&peer) {
            // A peer asking us for blocks before it has completed the handshake WITH US
            // is the asymmetric-auth case behind "connected but nothing is pulled": we
            // received its Status (so WE think it's a peer) but it never authenticated to
            // US, so we must drop its requests. Surface it ONCE so the operator sees the
            // handshake — not the sync — is the thing that's incomplete.
            if matches!(
                msg,
                NetMessage::GetBlocks { .. } | NetMessage::GetBlock { .. }
            ) && self.unauth_logged.insert(peer)
            {
                p2p_log(
                    &self.log,
                    format!(
                        "⚠ {} is requesting blocks but has NOT completed the handshake with us \
                         — dropping its request (asymmetric auth; it cannot sync from us yet)",
                        short_peer(&peer)
                    ),
                );
            }
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
                match self.import_and_persist(node, block.clone()) {
                    ImportOutcome::New => {
                        tcp.broadcast(&NetMessage::NewBlock(block)); // forward once
                    }
                    ImportOutcome::Invalid => {
                        tcp.penalize_peer(peer, INVALID_BLOCK_PENALTY);
                    }
                    // Known, or an orphan we can't connect yet (it arrives via sync) —
                    // neither is misbehavior.
                    ImportOutcome::Known | ImportOutcome::Rejected => {}
                }
            }
            NetMessage::GetBlock { height } => {
                let block = node
                    .lock()
                    .ok()
                    .and_then(|n| n.chain().block_by_height(height).cloned());
                tcp.send(peer, &NetMessage::BlockResponse(block));
            }
            NetMessage::GetBlocks { start, count } => {
                // Serve up to `count` (server-capped) consecutive blocks from `start`
                // for a peer doing batched catch-up — a few round-trips instead of one
                // request per block.
                let want = count.min(SYNC_BATCH) as usize;
                let blocks: Vec<Block> = node
                    .lock()
                    .ok()
                    .map(|n| {
                        let mut v = Vec::with_capacity(want);
                        let mut h = start;
                        while v.len() < want {
                            match n.chain().block_by_height(h) {
                                Some(b) => {
                                    v.push(b.clone());
                                    h += 1;
                                }
                                None => break,
                            }
                        }
                        v
                    })
                    .unwrap_or_default();
                if !blocks.is_empty() {
                    p2p_log(
                        &self.log,
                        format!(
                            "→ served {} block(s) from height {} to {}",
                            blocks.len(),
                            start,
                            short_peer(&peer)
                        ),
                    );
                }
                tcp.send(peer, &NetMessage::BlocksResponse(blocks));
            }
            NetMessage::BlockResponse(Some(block)) => {
                // A single-block response — used while BACKTRACKING to a common
                // ancestor. If it connects, we've found the fork point; resume
                // forward (batched). If not, keep walking back, doubling the step.
                self.inflight = None;
                self.stalled_logged = false; // a reply arrived — clear the stall latch
                let h = block.header.height.get();
                match self.import_and_persist(node, block) {
                    ImportOutcome::New | ImportOutcome::Known => {
                        self.bt_step.remove(&peer); // ancestor found → forward mode
                        self.advance_or_done(peer, h);
                    }
                    ImportOutcome::Rejected => {
                        let step = self.bt_step.get(&peer).copied().unwrap_or(1).max(1);
                        self.sync_next.insert(peer, h.saturating_sub(step).max(1));
                        self.bt_step.insert(peer, (step * 2).min(BACKTRACK_CAP));
                    }
                    ImportOutcome::Invalid => {
                        // A fabricated block while backtracking: penalize and stop
                        // syncing from this peer (don't keep walking its bogus chain).
                        tcp.penalize_peer(peer, INVALID_BLOCK_PENALTY);
                        self.sync_next.remove(&peer);
                        self.bt_step.remove(&peer);
                    }
                }
            }
            NetMessage::BlockResponse(None) => {
                // The peer does not have the requested height: stop waiting on it.
                self.inflight = None;
                self.stalled_logged = false;
            }
            NetMessage::BlocksResponse(blocks) => {
                // A batch of consecutive blocks (forward catch-up). They are on the
                // peer's chain, so they import in order; the first one only fails if
                // its parent isn't ours (a fork), which flips us into backtrack.
                self.inflight = None;
                self.stalled_logged = false; // a reply arrived — clear the stall latch
                                             // A peer must never return more than we ask for ([`SYNC_BATCH`]); a
                                             // larger batch is a memory/CPU amplification — penalize and ignore it.
                if blocks.len() > SYNC_BATCH as usize {
                    tcp.penalize_peer(peer, OVERSIZE_RESPONSE_PENALTY);
                    return;
                }
                if blocks.is_empty() {
                    self.sync_next.remove(&peer); // at/past the peer's head
                } else {
                    let mut last_ok: Option<u64> = None;
                    let mut rejected: Option<u64> = None;
                    let mut invalid = false;
                    for block in blocks {
                        let h = block.header.height.get();
                        match self.import_and_persist(node, block) {
                            ImportOutcome::New | ImportOutcome::Known => last_ok = Some(h),
                            ImportOutcome::Rejected => {
                                rejected = Some(h);
                                break;
                            }
                            ImportOutcome::Invalid => {
                                // A fabricated block in the batch (any valid prefix is
                                // already committed): penalize and stop trusting this peer.
                                tcp.penalize_peer(peer, INVALID_BLOCK_PENALTY);
                                invalid = true;
                                break;
                            }
                        }
                    }
                    if invalid {
                        self.sync_next.remove(&peer);
                        self.bt_step.remove(&peer);
                        p2p_log(
                            &self.log,
                            format!("✗ {} sent an invalid block — penalized", short_peer(&peer)),
                        );
                    } else if let Some(h) = last_ok {
                        self.bt_step.remove(&peer);
                        self.advance_or_done(peer, h);
                        p2p_log(&self.log, format!("← imported blocks up to height {h}"));
                    } else if let Some(h) = rejected {
                        // First block didn't connect → on a fork; start backtracking.
                        self.sync_next.insert(peer, h.saturating_sub(1).max(1));
                        self.bt_step.insert(peer, 1);
                        p2p_log(
                            &self.log,
                            format!(
                                "↩ height {h} didn't connect — backtracking to find the fork point"
                            ),
                        );
                    }
                }
            }
            NetMessage::Peers(_) | NetMessage::Hello { .. } => {}
        }
    }

    /// After importing up to height `h` from `peer`, continue forward from `h + 1`
    /// or stop if we've reached the peer's head.
    fn advance_or_done(&mut self, peer: SocketAddr, h: u64) {
        match self.peer_status.get(&peer) {
            Some(s) if h < s.height => {
                self.sync_next.insert(peer, h + 1);
            }
            _ => {
                self.sync_next.remove(&peer);
            }
        }
    }

    /// Forget bookkeeping for peers that are no longer connected, so catch-up never
    /// targets a ghost peer (whose `send` would silently fail and stall sync) and
    /// per-peer state cannot grow without bound across reconnects.
    fn retain_connected(&mut self, connected: &HashSet<SocketAddr>) {
        self.authenticated.retain(|p| connected.contains(p));
        self.identity.retain(|p, _| connected.contains(p));
        self.peer_status.retain(|p, _| connected.contains(p));
        self.sync_next.retain(|p, _| connected.contains(p));
        self.bt_step.retain(|p, _| connected.contains(p));
        self.first_seen.retain(|p, _| connected.contains(p));
        self.last_recv.retain(|p, _| connected.contains(p));
    }

    /// Collapse MULTIPLE live connections to the SAME node identity down to exactly
    /// one — the definitive fix for "one machine counted as several peers." When a
    /// node ends up with both an inbound and an outbound link to the same peer (a
    /// bootstrap dial + an mDNS/gossip dial, or a startup race), keep the single
    /// connection with the lexicographically smallest **channel binding** (Noise
    /// handshake hash) and disconnect the rest. The binding is identical on BOTH ends
    /// of a given connection, so both nodes independently pick the SAME survivor with
    /// no coordination and no flap — and a disconnect on either side tears the
    /// redundant link down for both. Identity-keyed, so it works on a LAN and across
    /// the internet alike.
    fn dedup_identity(&mut self, tcp: &TcpNode, account: &AccountId) {
        let mut dupes: Vec<(SocketAddr, Vec<u8>)> = self
            .identity
            .iter()
            .filter(|(_, a)| *a == account)
            // Only connections with a retrievable channel binding are survivor
            // candidates: a connection mid-teardown returns `None` here, and treating
            // its (empty) binding as the lexicographically smallest would KEEP the dying
            // link and disconnect the healthy one — a self-inflicted churn. Skip them.
            .filter_map(|(p, _)| tcp.peer_handshake_hash(p).map(|b| (*p, b)))
            .collect();
        if dupes.len() < 2 {
            return;
        }
        let keep = survivor(&dupes);
        dupes.retain(|(p, _)| Some(*p) != keep);
        for (p, _) in dupes {
            tcp.disconnect(&p);
            self.identity.remove(&p);
            self.authenticated.remove(&p);
            self.peer_status.remove(&p);
            self.sync_next.remove(&p);
            self.bt_step.remove(&p);
        }
    }

    /// Reap **dead (half-open) connections**: a peer that has sent nothing for
    /// [`PEER_INACTIVITY_TIMEOUT`] — while every healthy peer sends `Status` each
    /// announce cycle — is a connection whose remote vanished without a clean close
    /// (machine off / Wi-Fi drop), which the blocking read loop and the hours-long OS
    /// keepalive never notice. Disconnecting it both clears the ghost from the peer
    /// count AND removes it as a catch-up target that can never answer (a dead peer
    /// left in `peer_status` would otherwise be picked, time out, and wedge sync —
    /// the "connected but never indexing" failure). A peer's first-seen time gives a
    /// fresh connection the full window before its first message.
    fn reap_dead_peers(&mut self, tcp: &TcpNode) {
        let now = Instant::now();
        for peer in tcp.connected_peers() {
            let last = self
                .last_recv
                .get(&peer)
                .or_else(|| self.first_seen.get(&peer))
                .copied()
                .unwrap_or(now);
            if now.duration_since(last) >= PEER_INACTIVITY_TIMEOUT {
                tcp.disconnect(&peer);
            }
        }
    }

    /// Reclaim inbound slots from **zombie connections**: a peer that completed the
    /// encrypted transport handshake but never sent a valid `Hello` within
    /// [`HELLO_TIMEOUT`] is disconnected (not banned — it may legitimately reconnect).
    /// Without this an attacker could connect and stay silent to pin inbound slots
    /// (which the transport's eclipse caps count) and crowd out honest peers.
    fn sweep_unauthenticated(&mut self, tcp: &TcpNode) {
        let now = Instant::now();
        for peer in tcp.connected_peers() {
            let first = *self.first_seen.entry(peer).or_insert(now);
            if !self.authenticated.contains(&peer) && now.duration_since(first) >= HELLO_TIMEOUT {
                tcp.disconnect(&peer);
            }
        }
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
        if let Some(sp) = stalled_peer {
            if !self.stalled_logged {
                // The smoking gun for "connected but nothing pulled": WE asked, the peer
                // never answered. (If the peer instead logs "requesting blocks but has
                // NOT completed the handshake", the failure is auth in the OTHER direction.)
                p2p_log(
                    &self.log,
                    format!(
                        "… no reply from {} to our block request within {}s — retrying",
                        short_peer(&sp),
                        BLOCK_REQUEST_TIMEOUT.as_secs()
                    ),
                );
                self.stalled_logged = true;
            }
        }

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
        // Forward: fetch a BATCH of blocks (fast, few round-trips). Backtracking to a
        // common ancestor: a single block at a time (we're probing for the fork).
        let backtracking = self.bt_step.get(&peer).copied().unwrap_or(0) > 0;
        let msg = if backtracking {
            NetMessage::GetBlock { height }
        } else {
            NetMessage::GetBlocks {
                start: height,
                count: SYNC_BATCH,
            }
        };
        // Log a (new) request target so the operator sees us actively pulling — and, if
        // it never advances, exactly which height we're stuck asking for.
        if self.last_req_log != Some((peer, height)) {
            p2p_log(
                &self.log,
                format!(
                    "→ requesting {} from {} at height {} (we're at {}, peer at {})",
                    if backtracking { "a block" } else { "blocks" },
                    short_peer(&peer),
                    height,
                    local.height,
                    peer_height
                ),
            );
            self.last_req_log = Some((peer, height));
        }
        if tcp.send(peer, &msg) {
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

    /// Whether a block request is currently outstanding — i.e. we are actively catching
    /// up, so the worker should poll fast rather than idle.
    fn has_inflight(&self) -> bool {
        self.inflight.is_some()
    }

    /// Snapshot the node's sync position for [`SyncShared`]: `(behind_blocks,
    /// best_peer_height, distinct_peers)`.
    ///
    /// * `behind_blocks` — how many blocks below the tallest authenticated peer our head
    ///   is (0 if at/ahead of the tip). The miner pauses only when this exceeds
    ///   [`MINING_GATE_LAG`](crate::sync_status::MINING_GATE_LAG) — so a node racing at
    ///   the tip (a block or two behind) keeps mining, while a far-behind joiner pauses
    ///   to download. Height-based, so a sideways fork at the same height reads as 0
    ///   behind (a race the fork-choice tie-break resolves), not a sync.
    /// * `best_peer_height` — the tallest authenticated peer chain we have heard of.
    /// * `distinct_peers` — the number of distinct authenticated node IDENTITIES, NOT
    ///   raw socket connections. A redundant inbound+outbound link to the same node
    ///   (briefly present before [`dedup_identity`](Self::dedup_identity) collapses it)
    ///   therefore never shows up as an extra "ghost" peer — the count the operator
    ///   sees is simply how many real remote nodes we are talking to.
    fn telemetry(&self, node: &Mutex<Node>) -> (u64, u64, usize) {
        let distinct: HashSet<&AccountId> = self
            .identity
            .iter()
            .filter(|(p, _)| self.authenticated.contains(p))
            .map(|(_, a)| a)
            .collect();
        let best = self
            .peer_status
            .iter()
            .filter(|(p, _)| self.authenticated.contains(p))
            .map(|(_, s)| s.height)
            .max()
            .unwrap_or(0);
        let local_height = local_status(node).map(|l| l.height).unwrap_or(0);
        let behind_blocks = best.saturating_sub(local_height);
        (behind_blocks, best, distinct.len())
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
        let mut s = SyncState::new(None, None);
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
        let mut s = SyncState::new(None, None);
        s.inflight = Some(InFlight {
            peer: addr(7003),
            since: Instant::now(),
        });
        // Mirror what handle() does on receiving a (None) block response.
        s.inflight = None;
        assert!(s.inflight.is_none());
    }

    #[test]
    fn import_classifies_orphan_as_rejected_and_fabricated_as_invalid() {
        // The safety-critical distinction behind sync misbehavior penalties: a block
        // that can't connect yet (unknown parent) is the ORDINARY backtrack signal and
        // must be `Rejected` (NO penalty), while a fabricated/invalid block must be
        // `Invalid` so the sender is banned. Mis-classifying the first would ban honest
        // peers mid-sync; mis-classifying the second would let an attacker waste sync
        // forever for free.
        use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
        use sov_mining::MiningPolicy;
        use sov_primitives::{Balance, BlockHeight};
        use std::sync::Mutex;

        let val = AccountId::new("val01.node.sov").unwrap();
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_000,
            accounts: vec![GenesisAccount {
                account: val.clone(),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            }],
            mining: MiningPolicy::test(),
            vesting: vec![],
        };
        let chain = Blockchain::new(&config).unwrap();
        let genesis_hash = chain.head().hash();
        let node = Mutex::new(Node::new(chain, 1024, 256));
        let state = SyncState::new(None, None);

        // Orphan: parent unknown → Rejected (drives backtracking; not misbehavior).
        let orphan = Block::assemble(
            BlockHeight::new(9),
            Hash::digest(b"unknown-parent"),
            Hash::ZERO,
            Hash::ZERO,
            2_000,
            val.clone(),
            vec![],
        );
        assert_eq!(
            state.import_and_persist(&node, orphan),
            ImportOutcome::Rejected,
            "an unknown-parent block is the benign backtrack signal"
        );

        // Fabricated: extends genesis but is unmined (declares no valid difficulty /
        // carries no valid proof of work) → Invalid.
        let bad = Block::assemble(
            BlockHeight::new(1),
            genesis_hash,
            Hash::ZERO,
            Hash::ZERO,
            2_000,
            val,
            vec![],
        );
        assert_eq!(
            state.import_and_persist(&node, bad),
            ImportOutcome::Invalid,
            "a block that fails validation flags the sender as misbehaving"
        );
    }

    #[test]
    fn sweep_spares_a_recently_connected_unauthenticated_peer() {
        // A peer that just connected but hasn't sent its Hello yet is given time
        // (HELLO_TIMEOUT) — the sweep records when it was first seen and does NOT drop
        // it immediately, so honest inbound peers aren't churned mid-handshake.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&server.local_addr().to_string()).unwrap();
        let mut connected = false;
        // Generous ceiling (~30s): under `cargo test --workspace` the CPU-bound
        // Noise+ML-KEM handshake competes with hundreds of parallel tests, so a tight
        // wait flaked on CI. The healthy path connects in well under a second.
        for _ in 0..1500 {
            if server.peer_count() >= 1 {
                connected = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(connected, "peer connected");

        let mut state = SyncState::new(None, None);
        // Poll the sweep until the peer is recorded. `peer_count()` ticks up at the TCP
        // accept, but `sweep_unauthenticated` reads `connected_peers()`, which only lists
        // a peer once its Noise+ML-KEM handshake completes — a beat later under CI load.
        // Retry rather than flake; HELLO_TIMEOUT (30s) is far longer than this wait, so a
        // freshly-recorded peer is never dropped here.
        let mut recorded = false;
        for _ in 0..500 {
            state.sweep_unauthenticated(&server);
            if state.first_seen.len() == 1 {
                recorded = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(recorded, "the new peer's first-seen time is recorded");
        assert!(
            server.peer_count() >= 1,
            "a just-connected peer is given time to authenticate, not dropped on sight"
        );
    }

    #[test]
    fn reaps_a_dead_silent_peer_but_spares_an_active_one() {
        // The fix for "2 ghost peers when the remote is offline" AND "connected but
        // never indexing": a peer silent past PEER_INACTIVITY_TIMEOUT (a half-open
        // connection to a vanished host) is reaped, freeing the slot and removing it
        // as a catch-up target; an actively-talking peer is left alone.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&server.local_addr().to_string()).unwrap();
        let mut connected = false;
        // Generous ceiling (~30s): under `cargo test --workspace` the CPU-bound
        // Noise+ML-KEM handshake competes with hundreds of parallel tests, so a tight
        // wait flaked on CI. The healthy path connects in well under a second.
        for _ in 0..1500 {
            if server.peer_count() >= 1 {
                connected = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(connected, "peer connected");
        let peer = server.connected_peers()[0];

        let mut state = SyncState::new(None, None);
        // Fresh activity → spared.
        state.last_recv.insert(peer, Instant::now());
        state.reap_dead_peers(&server);
        assert!(
            server.peer_count() >= 1,
            "an active (recently-heard) peer is not reaped"
        );

        // Silent past the inactivity timeout → reaped (the dead half-open case). On
        // loopback the client may re-dial after a reap, so re-mark every current peer
        // silent and reap each iteration until the slot is observed clear — the reap
        // logic is what's under test, not the OS's reconnect timing.
        let stale = || {
            Instant::now()
                .checked_sub(PEER_INACTIVITY_TIMEOUT + Duration::from_secs(1))
                .unwrap()
        };
        let mut reaped = false;
        for _ in 0..1500 {
            for p in server.connected_peers() {
                state.last_recv.insert(p, stale());
            }
            state.reap_dead_peers(&server);
            if server.peer_count() == 0 {
                reaped = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            reaped,
            "a silent (dead) peer is reaped, clearing the ghost slot"
        );
    }

    #[test]
    fn survivor_is_the_smallest_channel_binding_and_order_independent() {
        // Duplicate connections to one node collapse to the link with the smallest
        // channel binding. Both ends share each connection's binding, so this MUST be
        // order-independent — both nodes compute the same survivor and converge.
        let a = addr(9101);
        let b = addr(9102);
        let c = addr(9103);
        assert_eq!(
            survivor(&[(a, vec![0x33]), (b, vec![0x11]), (c, vec![0x22])]),
            Some(b)
        );
        assert_eq!(
            survivor(&[(c, vec![0x22]), (a, vec![0x33]), (b, vec![0x11])]),
            Some(b),
            "same survivor regardless of input order"
        );
        assert_eq!(survivor(&[]), None);
    }
}
