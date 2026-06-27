//! A real, **encrypted** TCP gossip transport with peer discovery.
//!
//! Where [`InMemoryNetwork`](crate::transport::InMemoryNetwork) exists to test
//! propagation logic, [`TcpNode`] is an actual networked node: it binds a TCP
//! listener, dials peers, and gossips [`NetMessage`]s.
//!
//! **Every connection is encrypted — hybrid post-quantum.** Immediately after
//! the TCP connection is established, the two sides run a **Noise XX
//! handshake** (`snow`, an audited Noise implementation — the same protocol
//! family as Bitcoin's BIP-324 and WireGuard), then an **ML-KEM-768 key
//! exchange inside that channel** (see [`crate::pq`]). Application messages
//! are sealed twice: an inner ChaCha20-Poly1305 layer keyed by
//! `Blake3(handshake_hash ‖ KEM secret)`, carried in Noise transport messages
//! — a 4-byte big-endian inner-ciphertext length, then length-prefixed Noise
//! chunks (Noise caps one message at 64 KiB, so larger frames are chunked).
//! Recorded traffic stays confidential unless **both** X25519 and ML-KEM-768
//! fall (no harvest-now-decrypt-later); a peer that cannot complete the KEM
//! exchange is dropped — fail closed, no classical-only fallback. This layers
//! *under* the application-level signed [`Hello`](NetMessage::Hello), which
//! still binds a peer to its chain and node identity.
//!
//! The Noise static key is per-connection (identity is proven by the signed
//! `Hello` at the app layer). Binding the `Hello` signature to the Noise handshake
//! hash — full channel binding — is a documented follow-up.
//!
//! **Peer discovery** is gossip-based. On every new connection a node announces
//! its own listening address plus the peers it already knows
//! ([`NetMessage::Peers`]); a recipient dials any address it has not seen, so
//! knowledge of the network spreads transitively from a single bootstrap link.
//!
//! Reads and writes run on per-connection threads with blocking I/O — no async
//! runtime — which keeps the model simple.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fips203::ml_kem_768;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use snow::{Builder, TransportState};

use crate::message::NetMessage;
use crate::pq::PqChannel;

/// Maximum accepted frame size (8 MiB plaintext), guarding against a malicious
/// length prefix.
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Noise caps one transport message at 65535 bytes; 16 of those are the AEAD tag,
/// leaving this much plaintext per chunk. Larger application frames are split.
const NOISE_MAX_PLAINTEXT: usize = 65535 - 16;

/// The Noise pattern + cipher suite: XX (mutual, no pre-shared static keys) over
/// X25519, ChaCha20-Poly1305, and BLAKE2s.
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// How long the Noise handshake may take before the connection is abandoned.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// An established, encrypted peer connection: the writable socket half, the
/// shared Noise transport cipher (both directions), and the inner hybrid
/// post-quantum channel. The reader half lives on the per-connection reader
/// thread.
struct Peer {
    stream: Mutex<TcpStream>,
    noise: Mutex<TransportState>,
    /// The inner hybrid (X25519 + ML-KEM-768) AEAD layer. Every application
    /// frame is sealed here FIRST, then chunked through the Noise cipher —
    /// so recorded traffic stays confidential unless BOTH key exchanges fall.
    pq: Mutex<PqChannel>,
    /// The Noise handshake hash for this connection — a unique fingerprint of the
    /// encrypted channel, used by the application layer to bind the signed `Hello`
    /// identity to this specific pipe (anti-MITM).
    handshake_hash: Vec<u8>,
}

type PeerWriter = Arc<Peer>;

/// How long a single outbound `connect` may block before being abandoned, so a
/// retry to an unreachable peer (e.g. a seed that is asleep) does not pin the dial
/// thread for the OS default timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default P2P listen/dial port. When an operator enters a bare IP or hostname in
/// the seed-peer box (no `:port`), this is appended — it matches the port the app
/// advertises to the other machine ("enter THIS in the other node's Seed peer:
/// `<ip>:9645`"). Centralised so the listener, the advertised hint, and the
/// tolerant dial resolver can never drift apart.
pub const DEFAULT_P2P_PORT: u16 = 9645;

/// An optional shared, line-buffered log sink — the GUI's Node-tab log. `None` in
/// headless/tests, where transport logging then costs nothing. Lets the transport
/// surface dial attempts and link transitions to the operator, so a failed peering
/// is a visible, actionable line instead of a silent "nothing happens".
type LogSink = Option<Arc<Mutex<Vec<String>>>>;

/// Maximum simultaneous INBOUND connections. Bounds resource use and raises the
/// cost of an eclipse attempt (a flood of inbound peers cannot crowd out the
/// operator-chosen outbound bootstrap links, which are never subject to this cap).
const MAX_INBOUND_PEERS: usize = 64;

/// Eclipse resistance: at most this many inbound slots may be held by a single
/// remote IP. Forces an attacker to source connections from many distinct hosts.
const MAX_INBOUND_PER_IP: usize = 8;

/// Eclipse resistance: at most this many inbound slots may be held by a single
/// network group (the /16 for IPv4, the /32 for IPv6 — the Bitcoin Core "netgroup"
/// notion). Forces an attacker to source connections from many distinct networks,
/// not just many addresses inside one cheap-to-rent block.
const MAX_INBOUND_PER_GROUP: usize = 16;

/// Sustained inbound message rate, in messages per second, that a peer may send
/// before tokens run dry — generous for legitimate sync/gossip, far below a flood.
const MSG_RATE_PER_SEC: f64 = 1_000.0;

/// Token-bucket depth: how large an instantaneous burst is absorbed before the
/// rate limit bites. A short legitimate spike (e.g. a sync catch-up burst) is
/// soaked up here rather than being penalized, which is what makes the limiter
/// robust under load instead of tripping on a window boundary.
const MSG_BURST: f64 = 1_500.0;

/// Misbehavior decays exponentially with this half-life: a peer that briefly
/// misbehaves and then settles is forgiven, while sustained abuse accumulates.
const MISBEHAVIOR_HALFLIFE_SECS: f64 = 30.0;

/// Accumulated misbehavior at or above this score earns a ban. With the penalties
/// below it is reached by a sustained flood or a handful of malformed frames, but
/// not by a brief, bounded burst.
const MISBEHAVIOR_BAN: f64 = 100.0;

/// Misbehavior added per message that arrives with the token bucket empty (i.e.
/// over the sustained rate). ~9 over-budget messages in one decay window ⇒ ban.
const RATE_VIOLATION_PENALTY: f64 = 12.0;

/// Misbehavior added per malformed frame (bad length, AEAD/decrypt failure, or a
/// frame that will not decode). Higher than a rate slip — a post-handshake frame
/// that fails to decrypt is a protocol violation, not mere volume. 4 ⇒ ban.
const MALFORMED_FRAME_PENALTY: f64 = 25.0;

/// How long a misbehaving IP stays banned once its score crosses the threshold.
const BAN_DURATION: Duration = Duration::from_secs(300);

/// LAN auto-discovery (mDNS-style): nodes announce themselves on this
/// administratively-scoped IPv4 multicast group + port, so peers on the SAME LAN
/// find and dial each other with **zero configuration**. The group is site-local
/// (239.0.0.0/8) and never routed off the local network.
const LAN_DISCO_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 90, 45);
/// UDP port the discovery beacon is sent to / listened on (P2P itself is elsewhere).
const LAN_DISCO_PORT: u16 = 9646;
/// How often a node re-announces itself on the LAN. Kept short (1s) so a peer that
/// starts later, or whose first beacon was dropped (UDP multicast is lossy), is
/// discovered within ~a second — one tiny packet per second per node is negligible.
const LAN_DISCO_INTERVAL: Duration = Duration::from_secs(1);
/// Beacon wire format tag (versioned), then `chain_id`, then the P2P listen port.
const LAN_DISCO_TAG: &str = "sov-disco1";

/// Shared state behind a [`TcpNode`], accessible from its background threads.
struct Shared {
    local_addr: SocketAddr,
    /// Active connection writers, keyed by the connection's remote address.
    peers: Mutex<HashMap<SocketAddr, PeerWriter>>,
    /// Received application messages awaiting the caller.
    inbox: Mutex<VecDeque<(SocketAddr, NetMessage)>>,
    /// Listening addresses we know about (for discovery / dedup of dials).
    known: Mutex<HashSet<SocketAddr>>,
    /// Addresses with an outbound dial currently in flight, so concurrent retries
    /// and discovery never open duplicate connections to the same peer.
    dialing: Mutex<HashSet<SocketAddr>>,
    /// Currently-open INBOUND connections, counted against [`MAX_INBOUND_PEERS`]
    /// and the per-IP / per-netgroup eclipse caps.
    inbound: Mutex<HashSet<SocketAddr>>,
    /// Per-IP connection health: a token bucket bounding message rate plus a
    /// decaying misbehavior score and any active ban. Replaces a fixed-window
    /// counter so the rate limiter is robust under load (see [`PeerScore`]).
    scores: Mutex<HashMap<IpAddr, PeerScore>>,
    /// Channel to request the manager thread dial an address (discovery + retry).
    dial_tx: Sender<SocketAddr>,
    /// Optional Node-tab log sink for human-readable transport diagnostics (dial
    /// attempts, connect success/failure, link up/down). `None` until a sink is
    /// attached via [`TcpNode::set_log_sink`]; logging is then a cheap no-op.
    log: Mutex<LogSink>,
    /// Set to stop the background threads and release the listen port, so the node
    /// can be cleanly shut down and its address rebound (e.g. an in-process restart).
    shutdown: AtomicBool,
}

/// Per-IP connection health. Both the rate bucket and the misbehavior score are
/// *continuous* functions of elapsed time — there is no fixed accounting window —
/// so a brief legitimate burst is absorbed by the token bucket while only
/// *sustained* abuse accumulates enough misbehavior to earn a ban. This is what
/// makes the flood/ban path stable under load rather than tripping (or failing to
/// trip) on a one-second boundary.
struct PeerScore {
    /// Available message tokens, refilled at [`MSG_RATE_PER_SEC`] up to [`MSG_BURST`].
    tokens: f64,
    /// Accumulated misbehavior; decays with half-life [`MISBEHAVIOR_HALFLIFE_SECS`].
    misbehavior: f64,
    /// When `tokens` / `misbehavior` were last aged forward.
    updated: Instant,
    /// If set and still in the future, the IP is banned until this instant.
    banned_until: Option<Instant>,
}

impl PeerScore {
    /// A fresh record: a full burst of tokens, no misbehavior, no ban.
    fn fresh(now: Instant) -> PeerScore {
        PeerScore {
            tokens: MSG_BURST,
            misbehavior: 0.0,
            updated: now,
            banned_until: None,
        }
    }

    /// Refill tokens and decay misbehavior for the time elapsed since `updated`.
    fn age(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.updated).as_secs_f64();
        if dt <= 0.0 {
            return;
        }
        self.updated = now;
        self.tokens = (self.tokens + dt * MSG_RATE_PER_SEC).min(MSG_BURST);
        self.misbehavior *= 0.5_f64.powf(dt / MISBEHAVIOR_HALFLIFE_SECS);
    }
}

/// A networked gossip node over TCP.
pub struct TcpNode {
    shared: Arc<Shared>,
}

impl TcpNode {
    /// Bind a listener on `addr` (e.g. `127.0.0.1:0` for an ephemeral port) and
    /// start serving connections.
    pub fn bind(addr: &str) -> std::io::Result<TcpNode> {
        // Retry briefly on "address in use": when the app restarts (or a prior instance
        // is being killed for single-instance), the OS can hold the port for a short
        // release/TIME_WAIT window. Retrying a few times rides through it instead of
        // failing the whole node start with os error 48 / 10048.
        let listener = {
            let mut attempt = TcpListener::bind(addr);
            for _ in 0..20 {
                match attempt {
                    Ok(l) => {
                        attempt = Ok(l);
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                        thread::sleep(Duration::from_millis(150));
                        attempt = TcpListener::bind(addr);
                    }
                    Err(e) => return Err(e),
                }
            }
            attempt?
        };
        let local_addr = listener.local_addr()?;
        let (dial_tx, dial_rx) = channel::<SocketAddr>();

        let shared = Arc::new(Shared {
            local_addr,
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new(VecDeque::new()),
            known: Mutex::new(HashSet::new()),
            dialing: Mutex::new(HashSet::new()),
            inbound: Mutex::new(HashSet::new()),
            scores: Mutex::new(HashMap::new()),
            dial_tx,
            log: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        });

        // Accept inbound connections (we are the Noise *responder*). Non-blocking so
        // the thread can observe shutdown and EXIT — dropping the listener and
        // releasing the port, which is what lets the node be restarted in-process
        // without "address already in use". Accepted streams are set back to blocking
        // for the handshake + steady-state read loop.
        {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let _ = listener.set_nonblocking(true);
                while !shared.shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            let _ = stream.set_nonblocking(false);
                            register(&shared, stream, false);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(50)),
                    }
                }
                // `listener` drops here → the OS releases the bound port.
            });
        }

        // Dial addresses requested via gossip discovery or reconnect, off the
        // caller's thread, so a slow connect never blocks gossip. Wakes periodically
        // to observe shutdown so it exits cleanly too.
        {
            let shared = Arc::clone(&shared);
            thread::spawn(move || loop {
                match dial_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(addr) => {
                        let _ = attempt_dial(&shared, addr);
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if shared.shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            });
        }

        Ok(TcpNode { shared })
    }

    /// Stop the node: signal the background threads to exit and release the listen
    /// port. Idempotent. Live peer sockets are closed so their reader threads
    /// unblock and exit; the accept thread observes the flag, stops, and drops the
    /// listener — freeing the address so a subsequent [`bind`](Self::bind) to it
    /// succeeds (an in-process restart no longer hits "address already in use").
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        if let Ok(peers) = self.shared.peers.lock() {
            for peer in peers.values() {
                if let Ok(stream) = peer.stream.lock() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }

    /// Enable **mDNS-style LAN auto-discovery**: periodically announce this node on
    /// the local network and dial any same-chain peer that announces itself — so two
    /// machines on the same LAN join one network with **zero configuration** (no
    /// seed address needed). Best-effort: if the multicast socket can't bind, it is
    /// silently skipped. The thread stops with the node (shared shutdown flag). The
    /// beacon advertises only the chain id + P2P port; the dial-able IP is the
    /// packet's source address, so no node needs to know its own IP.
    pub fn enable_lan_discovery(&self, chain_id: &str) {
        let shared = Arc::clone(&self.shared);
        let chain_id = chain_id.to_string();
        let p2p_port = self.shared.local_addr.port();
        // A per-node-instance nonce so a node IGNORES its own announcement (some
        // platforms loop multicast back regardless of `multicast_loop`), preventing
        // a node from dialing itself (the "ghost self-peer").
        let nonce = node_nonce();
        thread::spawn(move || {
            // Bind the discovery port and join the multicast group. Reuse is fine —
            // one node per machine; failure just disables discovery (best-effort).
            let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, LAN_DISCO_PORT)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if sock
                .join_multicast_v4(&LAN_DISCO_GROUP, &Ipv4Addr::UNSPECIFIED)
                .is_err()
            {
                return;
            }
            // Don't loop our own announcements back to ourselves (no self-dial).
            let _ = sock.set_multicast_loop_v4(false);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let beacon = format!("{LAN_DISCO_TAG}|{chain_id}|{p2p_port}|{nonce}");
            // Startup burst: UDP multicast is lossy, so fire a few beacons up front
            // (briefly spaced) rather than betting first contact on a single packet —
            // discovery then survives an early dropped datagram and lands in well under
            // a second. Inbound peer beacons arriving meanwhile are buffered by the OS
            // socket and read in the loop right after, so none are missed.
            for _ in 0..3 {
                let _ = sock.send_to(beacon.as_bytes(), (LAN_DISCO_GROUP, LAN_DISCO_PORT));
                thread::sleep(Duration::from_millis(150));
            }
            let mut last = Instant::now();
            let mut buf = [0u8; 256];
            while !shared.shutdown.load(Ordering::SeqCst) {
                if last.elapsed() >= LAN_DISCO_INTERVAL {
                    let _ = sock.send_to(beacon.as_bytes(), (LAN_DISCO_GROUP, LAN_DISCO_PORT));
                    last = Instant::now();
                }
                if let Ok((n, src)) = sock.recv_from(&mut buf) {
                    if let Some(addr) = parse_beacon(&buf[..n], &chain_id, nonce, src.ip()) {
                        // A same-chain peer announced itself — dial it UNLESS that would
                        // just duplicate a link we already have. `dial_would_duplicate`
                        // does all its own locking; we must NOT hold a `peers` lock across
                        // it (that self-deadlocks the non-reentrant Mutex and wedges the node).
                        if !dial_would_duplicate(&shared, addr) {
                            let _ = shared.dial_tx.send(addr);
                        }
                    }
                }
            }
        });
    }

    /// The address this node is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local_addr
    }

    /// Attach a Node-tab log sink so dial attempts and link transitions become
    /// visible to the operator — the cure for "the seed-peer box does nothing":
    /// every dial now logs `dialing X` → `tcp connected to X` / `dial to X failed`,
    /// and each handshake logs `link up` / `handshake failed`. Idempotent; safe to
    /// call after [`bind`](Self::bind) and before [`enable_lan_discovery`].
    pub fn set_log_sink(&self, sink: Arc<Mutex<Vec<String>>>) {
        *self.shared.log.lock().unwrap() = Some(sink);
    }

    /// Dial a peer now (blocking up to [`CONNECT_TIMEOUT`]). Tolerant of how the
    /// address is written — `ip:port`, `host:port`, or a BARE ip / hostname (the
    /// [`DEFAULT_P2P_PORT`] is appended) — and resolves hostnames via DNS, trying
    /// each resolved target until one connects. A no-op if already connected or a
    /// dial is already in flight. Returns an error (never silently nothing) when the
    /// address cannot be parsed/resolved or no target is reachable.
    pub fn connect(&self, addr: &str) -> std::io::Result<()> {
        let targets = resolve_dial_targets(addr)?;
        let mut last_err: Option<std::io::Error> = None;
        for sa in targets {
            match attempt_dial(&self.shared, sa) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no dial targets")))
    }

    /// Ask the background dial thread to (re)connect to `addr` if it is not already
    /// connected — non-blocking, so a slow connect never stalls the gossip loop.
    /// Used to keep bootstrap links up across peer restarts and sleep/wake, and by
    /// the GUI "Connect" button. Tolerant of the address form (`ip:port`,
    /// `host:port`, or a BARE ip / hostname → [`DEFAULT_P2P_PORT`] appended) and
    /// resolves hostnames. Returns the concrete dial target(s) queued — so the
    /// caller can show the operator exactly what it is dialing (with any
    /// appended/resolved port) — or an error for an address it cannot resolve,
    /// instead of silently dropping it (the old bug behind "putting an IP in the
    /// seed-peer window does nothing").
    pub fn request_reconnect(&self, addr: &str) -> std::io::Result<Vec<SocketAddr>> {
        let targets = resolve_dial_targets(addr)?;
        for sa in &targets {
            let _ = self.shared.dial_tx.send(*sa);
        }
        Ok(targets)
    }

    /// Broadcast `message` to every connected peer; returns how many writes
    /// succeeded.
    pub fn broadcast(&self, message: &NetMessage) -> usize {
        let writers: Vec<PeerWriter> = self
            .shared
            .peers
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut sent = 0;
        for w in &writers {
            if write_frame(w, message).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    /// Send `message` to a single connected peer by its connection address;
    /// returns whether the write succeeded. Used for targeted replies such as
    /// catch-up [`BlockResponse`](NetMessage::BlockResponse)s.
    pub fn send(&self, peer: SocketAddr, message: &NetMessage) -> bool {
        let writer = self.shared.peers.lock().unwrap().get(&peer).cloned();
        match writer {
            Some(w) => write_frame(&w, message).is_ok(),
            None => false,
        }
    }

    /// Drain all received application messages.
    pub fn drain(&self) -> Vec<(SocketAddr, NetMessage)> {
        self.shared.inbox.lock().unwrap().drain(..).collect()
    }

    /// Number of pending received messages.
    pub fn pending(&self) -> usize {
        self.shared.inbox.lock().unwrap().len()
    }

    /// Number of active peer connections.
    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().unwrap().len()
    }

    /// The connection addresses of all currently-connected peers.
    pub fn connected_peers(&self) -> Vec<SocketAddr> {
        self.shared.peers.lock().unwrap().keys().copied().collect()
    }

    /// Score `peer` for **application-layer** misbehavior the transport cannot see by
    /// itself — an invalid block during sync, an over-sized response, etc. The points
    /// feed the SAME per-IP decaying misbehavior score and ban machinery as a
    /// transport-level flood or malformed frame (so abuse across layers accumulates
    /// toward one ban), and if this crosses the ban threshold the live connection is
    /// dropped IMMEDIATELY — a proven-bad peer is gone now, not merely barred from
    /// reconnecting. Returns whether the peer's IP is now banned. A brief, bounded
    /// amount is forgiven by the score's exponential decay.
    pub fn penalize_peer(&self, peer: SocketAddr, points: f64) -> bool {
        let banned = penalize(&self.shared, peer.ip(), points);
        if banned {
            self.disconnect(&peer);
        }
        banned
    }

    /// Drop the live connection to `peer` now: remove it from the peer set and shut
    /// its socket down (its reader thread then unblocks and exits). A no-op if not
    /// connected. Unlike a ban, this does not bar reconnection — it is used both by
    /// [`penalize_peer`] (after a ban) and to reclaim a slot from a connection that
    /// never authenticated.
    pub fn disconnect(&self, peer: &SocketAddr) {
        let writer = self.shared.peers.lock().unwrap().remove(peer);
        if let Some(p) = writer {
            if let Ok(stream) = p.stream.lock() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    /// The Noise handshake hash for the connection to `peer` (its channel
    /// fingerprint), or `None` if not connected. Used to bind the signed `Hello`.
    pub fn peer_handshake_hash(&self, peer: &SocketAddr) -> Option<Vec<u8>> {
        self.shared
            .peers
            .lock()
            .unwrap()
            .get(peer)
            .map(|p| p.handshake_hash.clone())
    }

    /// Listening addresses this node has discovered.
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        self.shared.known.lock().unwrap().iter().copied().collect()
    }
}

/// Resolve an operator-entered peer string into concrete dial targets, tolerantly.
/// Accepts every form a human reasonably types:
///   * `ip:port`         — e.g. `192.168.0.244:9645`
///   * `host:port`       — e.g. `seed.example.com:9645` (DNS-resolved, may fan out)
///   * a BARE ip         — e.g. `192.168.0.244` → [`DEFAULT_P2P_PORT`] appended
///   * a BARE hostname   — e.g. `seed.example.com` → default port appended + resolved
///
/// Returns a clear error instead of silently dropping unparseable input — the bug
/// behind "putting an IP in the seed-peer window does absolutely nothing", where a
/// bare IP failed a strict `SocketAddr` parse and was discarded with no feedback.
/// Never returns an empty vector on `Ok`.
fn resolve_dial_targets(addr: &str) -> std::io::Result<Vec<SocketAddr>> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty peer address",
        ));
    }
    // 1) Exactly as entered — handles `ip:port` and `host:port` (with DNS).
    if let Ok(iter) = trimmed.to_socket_addrs() {
        let v: Vec<SocketAddr> = iter.collect();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    // 2) A bare IP (v4 or v6) with no port — pair it with the default port directly
    //    (constructing the `SocketAddr` ourselves so a bare IPv6 like `::1` works
    //    without the operator needing to bracket it).
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, DEFAULT_P2P_PORT)]);
    }
    // 3) A bare hostname with no port — append the default and resolve via DNS.
    if let Ok(iter) = (trimmed, DEFAULT_P2P_PORT).to_socket_addrs() {
        let v: Vec<SocketAddr> = iter.collect();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "could not resolve peer '{trimmed}' — expected host:port, ip:port, or a bare ip/host"
        ),
    ))
}

/// Append one timestamped transport-diagnostic line to the (optional) Node-tab log.
/// A no-op when no sink is attached (headless/tests), so it is free to call on the
/// dial/handshake paths. Mirrors the GUI logger's format and cap.
fn net_log(shared: &Shared, msg: impl AsRef<str>) {
    let sink = match shared.log.lock().unwrap().clone() {
        Some(s) => s,
        None => return,
    };
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
    // Bind the guard to a named local (declared after `sink`) so it drops FIRST, before
    // the cloned `sink` Arc — an `if let` scrutinee would keep the guard alive to the end
    // of the function and conflict with that drop.
    let Ok(mut v) = sink.lock() else { return };
    v.push(line);
    let n = v.len();
    if n > 5_000 {
        v.drain(0..n - 5_000);
    }
}

/// Connect to `addr` and register the resulting stream. Idempotent and
/// retry-safe: skips if already connected or a dial is in flight, and on failure
/// leaves no trace, so a later retry (e.g. once a sleeping seed wakes) succeeds.
fn attempt_dial(shared: &Arc<Shared>, addr: SocketAddr) -> std::io::Result<()> {
    if addr == shared.local_addr {
        return Ok(());
    }
    // Already linked to this host? Skip. This is the AUTHORITATIVE duplicate check that
    // ALL dial sources funnel through (bootstrap/`request_reconnect`, mDNS, gossip,
    // explicit `connect`) — so it must match by IP, not just the exact address: when a
    // pair of nodes dial each other, dedup keeps ONE link, which may be our INBOUND
    // (keyed by the peer's ephemeral port). A bootstrap reconnect dials the peer's
    // fixed LISTEN port, which an exact-address check would miss — re-opening a
    // duplicate that dedup then tears down, every retry, flapping the peer count 1↔0
    // forever (and starving the surviving link of the chance to authenticate + sync).
    // `dial_would_duplicate` matches by IP (loopback-exempt, so single-host tests still
    // run many nodes) and checks the in-flight `inbound` set; it does all its own
    // locking and we hold none across it.
    if dial_would_duplicate(shared, addr) {
        return Ok(());
    }
    // Claim the in-flight slot; if another dial already holds it, defer to that one.
    if !shared.dialing.lock().unwrap().insert(addr) {
        return Ok(());
    }
    shared.known.lock().unwrap().insert(addr);

    // Past the dedup/in-flight guards: this is a genuine new dial, so make it visible
    // (the guarded skips above stay quiet to avoid spamming the log every retry once a
    // link is already up).
    net_log(shared, format!("dialing {addr}…"));
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(stream) => {
            net_log(shared, format!("tcp connected to {addr} — handshaking"));
            // `setup_connection` clears the in-flight slot once the peer is live.
            register(shared, stream, true); // we dialed: we are the Noise initiator
            Ok(())
        }
        Err(e) => {
            net_log(shared, format!("dial to {addr} failed: {e}"));
            // Unreachable: drop the in-flight slot AND forget the address, so a
            // later reconnect request can try again from scratch.
            shared.dialing.lock().unwrap().remove(&addr);
            shared.known.lock().unwrap().remove(&addr);
            Err(e)
        }
    }
}

/// Register a freshly-established connection. The Noise handshake (which blocks)
/// and the subsequent read loop run on a dedicated thread, so neither the accept
/// loop nor the dial thread is held up by a slow or hostile peer.
fn register(shared: &Arc<Shared>, stream: TcpStream, initiator: bool) {
    let shared = Arc::clone(shared);
    thread::spawn(move || {
        if let Err(_e) = setup_connection(&shared, stream, initiator) {
            // A failed handshake / dropped peer is expected churn — just discard.
        }
    });
}

/// Run the Noise handshake, register the encrypted connection, announce our peer
/// set, and then serve the read loop until the connection closes.
fn setup_connection(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    initiator: bool,
) -> io::Result<()> {
    let key = stream.peer_addr()?;

    // Inbound admission control (outbound dials we initiated are always allowed):
    // reject banned IPs and cap concurrent inbound connections — globally, per IP,
    // and per netgroup — so a flood cannot exhaust resources and an attacker cannot
    // eclipse us by filling every inbound slot from one host or one cheap address
    // block. The operator-chosen outbound links are never subject to these caps.
    if !initiator {
        if is_banned(shared, key.ip()) {
            return Ok(());
        }
        let mut inbound = shared.inbound.lock().unwrap();
        if !admit_inbound(&inbound, key.ip()) {
            return Ok(());
        }
        inbound.insert(key);
    }

    // Bound the handshake so a stalled peer cannot pin a thread forever, then
    // clear the timeout for the (blocking) steady-state read loop. Clone the
    // reader half while we're at it. Any failure here clears the in-flight dial
    // slot so the address can be retried.
    let setup = (|| -> io::Result<(TcpStream, TransportState, PqChannel, Vec<u8>)> {
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let (mut transport, handshake_hash) = noise_handshake(&mut stream, initiator)?;
        // Hybrid PQ key exchange, inside the Noise channel. Fail-closed: a
        // peer that cannot complete it never becomes a connection.
        let pq = pq_handshake(&mut stream, &mut transport, initiator, &handshake_hash)?;
        stream.set_read_timeout(None)?;
        let reader = stream.try_clone()?;
        Ok((reader, transport, pq, handshake_hash))
    })();
    let (reader, transport, pq, handshake_hash) = match setup {
        Ok(v) => v,
        Err(e) => {
            net_log(shared, format!("handshake with {key} failed: {e}"));
            shared.dialing.lock().unwrap().remove(&key);
            shared.inbound.lock().unwrap().remove(&key);
            return Err(e);
        }
    };

    let peer: PeerWriter = Arc::new(Peer {
        stream: Mutex::new(stream),
        noise: Mutex::new(transport),
        pq: Mutex::new(pq),
        handshake_hash,
    });
    shared.peers.lock().unwrap().insert(key, Arc::clone(&peer));
    // Connection is live: stop treating this address as an in-flight dial.
    shared.dialing.lock().unwrap().remove(&key);
    // The encrypted transport is up (Noise + ML-KEM). The app-layer signed `Hello`
    // (chain/identity auth) is logged separately by the sync engine; this line is the
    // honest "the pipe exists" milestone an operator watches for after a dial.
    net_log(
        shared,
        format!(
            "link up: {key} ({} · noise+ml-kem encrypted)",
            if initiator { "outbound" } else { "inbound" }
        ),
    );

    // Announce ourselves + everyone we know, so the peer can discover the network.
    let mut addrs = vec![shared.local_addr.to_string()];
    addrs.extend(shared.known.lock().unwrap().iter().map(|a| a.to_string()));
    let _ = write_frame(&peer, &NetMessage::Peers(addrs));

    reader_loop(shared, key, reader, peer);
    shared.inbound.lock().unwrap().remove(&key);
    // The read loop returned → the connection closed (peer gone, reaped, or banned).
    net_log(shared, format!("link down: {key}"));
    Ok(())
}

/// Perform a Noise XX handshake over `stream`, returning the transport-mode cipher
/// and the handshake hash (a unique per-connection channel fingerprint, identical
/// on both ends, used for `Hello` channel binding). The static key is generated per
/// connection; peer identity is authenticated by the application-level signed
/// [`Hello`](NetMessage::Hello) once the channel is up.
fn noise_handshake(
    stream: &mut TcpStream,
    initiator: bool,
) -> io::Result<(TransportState, Vec<u8>)> {
    let params = NOISE_PARAMS
        .parse()
        .map_err(|_| io::Error::other("invalid Noise params"))?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| io::Error::other(format!("noise keygen: {e}")))?;
    let builder = builder.local_private_key(&keypair.private);
    let mut hs = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|e| io::Error::other(format!("noise build: {e}")))?;

    let mut buf = [0u8; 65535];
    // XX is three messages: -> e ; <- e,ee,s,es ; -> s,se. The initiator writes
    // the 1st and 3rd, the responder the 2nd.
    if initiator {
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg1: {e}")))?;
        write_raw(stream, &buf[..n])?;
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg2: {e}")))?;
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg3: {e}")))?;
        write_raw(stream, &buf[..n])?;
    } else {
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg1: {e}")))?;
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg2: {e}")))?;
        write_raw(stream, &buf[..n])?;
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg3: {e}")))?;
    }
    // Capture the handshake hash before consuming the handshake state. Both ends
    // derive the identical value, so it uniquely identifies this channel.
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let transport = hs
        .into_transport_mode()
        .map_err(|e| io::Error::other(format!("noise transport: {e}")))?;
    Ok((transport, handshake_hash))
}

/// Run the hybrid post-quantum key exchange inside the freshly-established
/// Noise channel: the initiator sends an ephemeral ML-KEM-768 encapsulation
/// key; the responder encapsulates and returns the ciphertext; both derive
/// the same 32-byte KEM secret and build the inner [`PqChannel`] bound to
/// this connection's Noise handshake hash. Any failure aborts the connection
/// — there is **no fallback** to a classical-only channel.
fn pq_handshake(
    stream: &mut TcpStream,
    noise: &mut TransportState,
    initiator: bool,
    handshake_hash: &[u8],
) -> io::Result<PqChannel> {
    if initiator {
        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| io::Error::other(format!("ml-kem keygen: {e}")))?;
        noise_send(stream, noise, &ek.into_bytes())?;
        let ct_bytes = noise_recv(stream, noise)?;
        let ct: [u8; ml_kem_768::CT_LEN] = ct_bytes
            .try_into()
            .map_err(|_| io::Error::other("ml-kem ciphertext has the wrong length"))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct)
            .map_err(|e| io::Error::other(format!("ml-kem ciphertext: {e}")))?;
        let secret = dk
            .try_decaps(&ct)
            .map_err(|e| io::Error::other(format!("ml-kem decaps: {e}")))?;
        Ok(PqChannel::new(handshake_hash, &secret.into_bytes(), true))
    } else {
        let ek_bytes = noise_recv(stream, noise)?;
        let ek: [u8; ml_kem_768::EK_LEN] = ek_bytes
            .try_into()
            .map_err(|_| io::Error::other("ml-kem encaps key has the wrong length"))?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek)
            .map_err(|e| io::Error::other(format!("ml-kem encaps key: {e}")))?;
        let (secret, ct) = ek
            .try_encaps()
            .map_err(|e| io::Error::other(format!("ml-kem encaps: {e}")))?;
        noise_send(stream, noise, &ct.into_bytes())?;
        Ok(PqChannel::new(handshake_hash, &secret.into_bytes(), false))
    }
}

/// Send one Noise-encrypted message (single chunk; the KEM material fits well
/// under the 64 KiB Noise cap), framed with a 4-byte length.
fn noise_send(stream: &mut TcpStream, noise: &mut TransportState, data: &[u8]) -> io::Result<()> {
    let mut buf = [0u8; 65535];
    let n = noise
        .write_message(data, &mut buf)
        .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
    write_raw(stream, &buf[..n])
}

/// Receive one Noise-encrypted message framed with a 4-byte length.
fn noise_recv(stream: &mut TcpStream, noise: &mut TransportState) -> io::Result<Vec<u8>> {
    let ct = read_raw(stream)?;
    let mut buf = [0u8; 65535];
    let n = noise
        .read_message(&ct, &mut buf)
        .map_err(|e| io::Error::other(format!("noise decrypt: {e}")))?;
    Ok(buf[..n].to_vec())
}

/// Write a raw, *unencrypted* length-prefixed frame — used only for the Noise
/// handshake messages, before the encrypted channel exists.
fn write_raw(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

/// Read a raw, *unencrypted* length-prefixed handshake frame.
fn read_raw(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 65535 {
        return Err(io::Error::other("invalid handshake frame length"));
    }
    let mut data = vec![0u8; n];
    stream.read_exact(&mut data)?;
    Ok(data)
}

/// A per-node-instance nonce (pid + time), embedded in the discovery beacon so a
/// node can recognize and ignore its OWN announcement looped back to it — different
/// processes/machines get different values; the same node always sends the same one.
fn node_nonce() -> u64 {
    let pid = std::process::id() as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (pid << 40) ^ nanos
}

/// Parse a LAN discovery beacon, returning the announcing peer's dial-able P2P
/// address — the packet's `src` IP plus the advertised port — only if the beacon is
/// well-formed, for the SAME chain, and NOT our own (nonce differs). Nodes on a
/// different chain are never dialed, and a node never dials itself.
fn parse_beacon(
    data: &[u8],
    our_chain_id: &str,
    our_nonce: u64,
    src: IpAddr,
) -> Option<SocketAddr> {
    let text = std::str::from_utf8(data).ok()?;
    let mut parts = text.split('|');
    if parts.next()? != LAN_DISCO_TAG {
        return None;
    }
    if parts.next()? != our_chain_id {
        return None; // a different chain — never dial it
    }
    let port: u16 = parts.next()?.parse().ok()?;
    let nonce: u64 = parts.next()?.parse().ok()?;
    if nonce == our_nonce {
        return None; // our own beacon looped back — never dial ourselves
    }
    Some(SocketAddr::new(src, port))
}

/// The network group an IP belongs to for eclipse accounting: the /16 for IPv4 and
/// the /32 for IPv6. Grouping by network (not by exact address) means renting many
/// addresses inside one block still only counts as a few groups, so spreading a
/// flood across one cheap allocation does not buy extra inbound slots.
fn net_group(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
    }
}

/// Whether `ip` is loopback or on a local/private network. Such peers are exempt
/// from the per-IP and per-netgroup caps: they are not a real eclipse vector, and
/// exempting them keeps single-host operation and loopback testing usable. The
/// global [`MAX_INBOUND_PEERS`] cap still applies to them.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Whether a DISCOVERY dial to `addr` (mDNS / gossip) would just DUPLICATE a link we
/// already have, so it should be skipped. Two cases collapse one machine into "two
/// peers": its inbound link is keyed by an ephemeral source port, while a beacon
/// advertises its fixed *listen* port — so an exact-address check misses it. We match
/// by IP for non-loopback hosts (one node per host is the norm; the inbound per-IP cap
/// still bounds genuine multi-node hosts), AND we check the `inbound` admission set,
/// which is populated at TCP-accept — before the slow Noise+ML-KEM handshake registers
/// the peer in `peers` — closing the startup race that produced the duplicate.
///
/// CRITICAL: this acquires each lock in its OWN statement and releases it before the
/// next, and callers must NOT hold any of these locks across the call — a `peers` lock
/// held by the caller while this re-locks `peers` would self-deadlock the (single,
/// non-reentrant) `Mutex` and wedge the whole node. It is self-contained for exactly
/// that reason.
fn dial_would_duplicate(shared: &Shared, addr: SocketAddr) -> bool {
    // Exact address already connected (this is the only check for loopback).
    if shared.peers.lock().unwrap().contains_key(&addr) {
        return true;
    }
    let loopback = match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if loopback {
        return false; // single-host / loopback tests legitimately run many nodes
    }
    let ip = addr.ip();
    if shared.peers.lock().unwrap().keys().any(|a| a.ip() == ip) {
        return true; // an established link to this host (e.g. its inbound by ephemeral port)
    }
    // A link to this host still completing its handshake (admitted, not yet in `peers`).
    shared.inbound.lock().unwrap().iter().any(|a| a.ip() == ip)
}

/// Decide whether a new INBOUND connection from `candidate` is admissible given the
/// currently-open inbound set, enforcing the global, per-IP, and per-netgroup caps.
/// Pure (no I/O) so the eclipse policy is unit-testable with synthetic addresses.
fn admit_inbound(inbound: &HashSet<SocketAddr>, candidate: IpAddr) -> bool {
    if inbound.len() >= MAX_INBOUND_PEERS {
        return false;
    }
    if is_local(candidate) {
        return true; // exempt from the finer caps (see `is_local`)
    }
    let same_ip = inbound.iter().filter(|a| a.ip() == candidate).count();
    if same_ip >= MAX_INBOUND_PER_IP {
        return false;
    }
    let group = net_group(candidate);
    let same_group = inbound
        .iter()
        .filter(|a| net_group(a.ip()) == group)
        .count();
    same_group < MAX_INBOUND_PER_GROUP
}

/// Whether `ip` is currently banned (expired bans are cleared lazily).
fn is_banned(shared: &Shared, ip: IpAddr) -> bool {
    let mut scores = shared.scores.lock().unwrap();
    match scores.get_mut(&ip) {
        Some(s) => match s.banned_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                s.banned_until = None;
                false
            }
            None => false,
        },
        None => false,
    }
}

/// Account for one inbound message from `ip`: spend a rate token, or accrue a
/// rate-violation penalty if the bucket is empty. Returns `false` (and bans the IP
/// for [`BAN_DURATION`]) once accumulated misbehavior crosses the threshold — the
/// caller then drops the peer.
fn note_message(shared: &Shared, ip: IpAddr) -> bool {
    penalize_inner(shared, ip, |s| {
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
        } else {
            s.misbehavior += RATE_VIOLATION_PENALTY;
        }
    })
}

/// Record protocol misbehavior worth `penalty` points (e.g. a malformed frame).
/// Returns `true` if the IP is now banned.
fn penalize(shared: &Shared, ip: IpAddr, penalty: f64) -> bool {
    !penalize_inner(shared, ip, |s| s.misbehavior += penalty)
}

/// Shared body of [`note_message`] / [`penalize`]: age the per-IP record forward,
/// apply `adjust`, then ban (and zero the score, letting the ban govern) if the
/// misbehavior threshold is reached. Returns `true` while the IP remains in good
/// standing, `false` once it is banned.
fn penalize_inner(shared: &Shared, ip: IpAddr, adjust: impl FnOnce(&mut PeerScore)) -> bool {
    let now = Instant::now();
    let mut scores = shared.scores.lock().unwrap();
    let s = scores.entry(ip).or_insert_with(|| PeerScore::fresh(now));
    s.age(now);
    adjust(s);
    if s.misbehavior >= MISBEHAVIOR_BAN {
        s.banned_until = Some(now + BAN_DURATION);
        s.misbehavior = 0.0;
        false
    } else {
        true
    }
}

/// The outcome of reading one frame: a decoded message, a clean connection close
/// (peer hung up — not misbehavior), or a malformed frame (a protocol violation
/// that both desyncs the encrypted stream and is scored against the peer's IP).
// The `Message` variant is inherently larger than the two unit signals; like
// [`NetMessage`] itself, this value is transient — produced once per read and
// immediately destructured — so boxing would add an allocation on the hot read
// path with no benefit.
#[allow(clippy::large_enum_variant)]
enum FrameRead {
    Message(NetMessage),
    Closed,
    Malformed,
}

/// Read and decrypt framed messages until the connection closes, feeding the
/// per-IP token bucket and misbehavior score: a sustained flood drains the bucket,
/// accrues penalties, and earns a ban; a single malformed frame is penalized and
/// closes the (now-desynced) connection; a clean hang-up is not penalized.
fn reader_loop(shared: &Arc<Shared>, key: SocketAddr, mut reader: TcpStream, peer: PeerWriter) {
    let ip = key.ip();
    loop {
        match read_frame(&mut reader, &peer) {
            FrameRead::Message(message) => {
                // Spend a rate token; over the sustained rate this accrues penalty
                // and, once misbehavior crosses the threshold, bans + drops the peer.
                if !note_message(shared, ip) {
                    break;
                }
                match message {
                    // Discovery messages are handled here, not surfaced to the app.
                    NetMessage::Peers(list) => {
                        for addr in list {
                            if let Ok(sa) = addr.parse::<SocketAddr>() {
                                if sa != shared.local_addr {
                                    // Record it for future dials, but don't open a
                                    // SECOND connection to a host we're already linked to
                                    // (see `dial_would_duplicate`). The `known` lock is
                                    // released at this statement's end, before the call.
                                    let unseen = shared.known.lock().unwrap().insert(sa);
                                    if unseen && !dial_would_duplicate(shared, sa) {
                                        let _ = shared.dial_tx.send(sa);
                                    }
                                }
                            }
                        }
                    }
                    message => shared.inbox.lock().unwrap().push_back((key, message)),
                }
            }
            FrameRead::Malformed => {
                // A post-handshake frame that fails to decrypt/decode is a protocol
                // violation and also desyncs the AEAD stream — penalize and close.
                penalize(shared, ip, MALFORMED_FRAME_PENALTY);
                break;
            }
            FrameRead::Closed => break,
        }
    }
    shared.peers.lock().unwrap().remove(&key);
}

/// Read one encrypted application frame. Wire form: a 4-byte inner-ciphertext
/// length, then Noise ciphertext chunks each prefixed by a 2-byte length, until the
/// decrypted inner ciphertext reaches the declared length; the inner ciphertext is
/// then opened with the hybrid PQ channel and decoded. Distinguishes a clean close
/// (I/O EOF/reset — [`FrameRead::Closed`], not scored) from a protocol violation
/// (bad framing, decrypt or decode failure — [`FrameRead::Malformed`], scored).
fn read_frame(reader: &mut TcpStream, peer: &Peer) -> FrameRead {
    let mut len_bytes = [0u8; 4];
    if reader.read_exact(&mut len_bytes).is_err() {
        return FrameRead::Closed; // peer hung up between frames — expected churn
    }
    let total = u32::from_be_bytes(len_bytes) as usize;
    // +16: the declared length covers the inner AEAD tag over the plaintext.
    if total == 0 || total > MAX_FRAME + 16 {
        return FrameRead::Malformed; // bogus length prefix
    }

    // Cap the initial allocation so a tiny frame declaring a huge length cannot
    // force a multi-megabyte reservation; the buffer grows as real bytes arrive.
    let mut inner = Vec::with_capacity(total.min(64 * 1024));
    let mut buf = [0u8; 65535];
    while inner.len() < total {
        let mut clen = [0u8; 2];
        if reader.read_exact(&mut clen).is_err() {
            return FrameRead::Closed; // truncated mid-frame — treat as a close
        }
        let clen = u16::from_be_bytes(clen) as usize;
        if clen == 0 || clen > buf.len() {
            return FrameRead::Malformed;
        }
        let mut ct = vec![0u8; clen];
        if reader.read_exact(&mut ct).is_err() {
            return FrameRead::Closed;
        }
        let n = match peer.noise.lock().unwrap().read_message(&ct, &mut buf) {
            Ok(n) => n,
            Err(_) => return FrameRead::Malformed, // AEAD/decrypt failure
        };
        if inner.len() + n > total {
            return FrameRead::Malformed; // a chunk decrypted past the declared size
        }
        inner.extend_from_slice(&buf[..n]);
    }
    // Open the inner hybrid layer; any tamper/desync is a malformed frame.
    match peer.pq.lock().unwrap().open(&inner) {
        Some(plaintext) => match NetMessage::decode(&plaintext) {
            Ok(message) => FrameRead::Message(message),
            Err(_) => FrameRead::Malformed,
        },
        None => FrameRead::Malformed,
    }
}

/// Encrypt and write one application frame to a peer: seal with the inner
/// hybrid PQ layer first, then chunk through the Noise cipher. The stream lock
/// is held across encryption *and* the socket write, so concurrent broadcasts
/// cannot interleave and the on-wire order always matches both nonce streams.
fn write_frame(peer: &Peer, message: &NetMessage) -> io::Result<()> {
    let plaintext = message.encode();
    if plaintext.len() > MAX_FRAME {
        return Err(io::Error::other("frame exceeds maximum size"));
    }

    let mut stream = peer.stream.lock().unwrap();
    // Inner hybrid seal (lock order: stream -> pq -> noise, everywhere).
    let inner = peer.pq.lock().unwrap().seal(&plaintext);
    let mut out = Vec::with_capacity(inner.len() + 64);
    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    {
        let mut noise = peer.noise.lock().unwrap();
        let mut buf = [0u8; 65535];
        // An empty payload still needs one chunk so the reader makes progress.
        let chunks = inner.chunks(NOISE_MAX_PLAINTEXT);
        for chunk in chunks {
            let n = noise
                .write_message(chunk, &mut buf)
                .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
            out.extend_from_slice(&(n as u16).to_be_bytes());
            out.extend_from_slice(&buf[..n]);
        }
    }
    stream.write_all(&out)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_primitives::Hash;
    use std::time::{Duration, Instant};

    fn status(h: u64) -> NetMessage {
        NetMessage::Status {
            height: h,
            head: Hash::digest(&h.to_be_bytes()),
            chain_work: {
                let mut w = [0u8; 32];
                w[24..].copy_from_slice(&h.to_be_bytes());
                w
            },
        }
    }

    /// Poll `cond` until true or `secs` elapse.
    fn wait_until(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    #[test]
    fn reconnect_to_listen_port_is_suppressed_when_inbound_link_exists() {
        // THE peer-count-flap regression. When two machines dial each other, dedup keeps
        // ONE link — often our INBOUND, keyed by the peer's ephemeral port. The 2s
        // bootstrap retry then dials the peer's fixed LISTEN port; an exact-address check
        // would miss the existing inbound and re-open a duplicate that dedup tears down,
        // flapping the count 1↔0 forever and starving the survivor of time to sync.
        // `dial_would_duplicate` (the gate ALL dials funnel through in `attempt_dial`)
        // must therefore match by IP for real hosts.
        let node = TcpNode::bind("127.0.0.1:0").unwrap();
        let peer_listen: SocketAddr = "203.0.113.7:9645".parse().unwrap();
        let peer_inbound: SocketAddr = "203.0.113.7:51234".parse().unwrap(); // same host, ephemeral
        node.shared.inbound.lock().unwrap().insert(peer_inbound);
        assert!(
            dial_would_duplicate(&node.shared, peer_listen),
            "a dial to the peer's listen port must be recognized as a duplicate of the \
             existing inbound link from the same host"
        );
        // A genuinely different host is NOT a duplicate — we still dial it.
        let other_host: SocketAddr = "198.51.100.9:9645".parse().unwrap();
        assert!(
            !dial_would_duplicate(&node.shared, other_host),
            "a different host is not a duplicate"
        );
        node.shutdown();
    }

    #[test]
    fn loopback_is_exempt_so_many_nodes_can_run_on_one_host() {
        // The IP-based dedup must NOT collapse distinct loopback nodes (the test/dev
        // single-host topology): only an EXACT loopback address counts as a duplicate.
        let node = TcpNode::bind("127.0.0.1:0").unwrap();
        let a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        node.shared.inbound.lock().unwrap().insert(a);
        assert!(
            !dial_would_duplicate(&node.shared, b),
            "a different loopback port is a distinct node, not a duplicate"
        );
        node.shutdown();
    }

    #[test]
    fn delivers_a_broadcast_over_real_tcp() {
        let a = TcpNode::bind("127.0.0.1:0").unwrap();
        let b = TcpNode::bind("127.0.0.1:0").unwrap();
        a.connect(&b.local_addr().to_string()).unwrap();

        assert!(
            wait_until(15, || a.peer_count() >= 1 && b.peer_count() >= 1),
            "peers connected"
        );

        a.broadcast(&status(7));
        let got = wait_until(15, || {
            b.drain()
                .iter()
                .any(|(_, m)| matches!(m, NetMessage::Status { height: 7, .. }))
        });
        assert!(got, "status message delivered to peer over TCP");
    }

    #[test]
    fn rejects_an_unencrypted_peer() {
        // A peer that skips the Noise handshake and sends a plaintext frame in the
        // old wire format must not be able to inject anything: the transport treats
        // its bytes as a (malformed) handshake, fails, and drops the connection.
        let a = TcpNode::bind("127.0.0.1:0").unwrap();
        let mut raw = TcpStream::connect(a.local_addr()).unwrap();
        let bytes = status(42).encode();
        raw.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
        raw.write_all(&bytes).unwrap();
        raw.flush().unwrap();

        let leaked = wait_until(2, || a.pending() > 0);
        assert!(
            !leaked,
            "a plaintext (non-Noise) peer cannot inject messages"
        );
    }

    #[test]
    fn floods_get_a_peer_dropped_and_banned() {
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().to_string();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&addr).unwrap();
        assert!(
            wait_until(15, || server.peer_count() >= 1),
            "peer connected"
        );

        // Flood HARD and SUSTAINED until the server bans + drops us. A single fixed
        // blast can be paced by TCP flow control to the server's drain rate under
        // `cargo test --workspace` CPU contention — so the token bucket refills about
        // as fast as it drains and never trips, which is what flaked on CI. Sustaining
        // the flood keeps the receive buffer saturated, so a drain burst eventually
        // exceeds the burst budget and accrues enough rate-violation penalty to ban.
        // We poll between rounds and stop the instant we're dropped (healthy path bans
        // in the first round, well under a second); bounded so a real regression (no
        // ban) still FAILS the assert rather than hanging.
        //
        // The rate-scoring math + ban + live-drop are ALSO covered deterministically,
        // without a socket, by `token_bucket_absorbs_a_burst_then_penalizes_sustained_overage`
        // and `penalize_peer_bans_and_drops_for_app_layer_misbehavior` — this test is the
        // end-to-end "a real flood over TCP trips the limiter" integration check.
        let burst = MSG_BURST as usize; // one full token-budget's worth per round
        let mut dropped = false;
        'flood: for _ in 0..60 {
            for _ in 0..burst {
                client.broadcast(&status(1));
            }
            for _ in 0..10 {
                if server.peer_count() == 0 {
                    dropped = true;
                    break 'flood;
                }
                thread::sleep(Duration::from_millis(30));
            }
        }
        assert!(dropped, "a sustained flood gets the peer dropped");
        // ...and its IP is banned, so it cannot immediately reconnect.
        let client2 = TcpNode::bind("127.0.0.1:0").unwrap();
        let _ = client2.connect(&addr);
        let reconnected = wait_until(2, || server.peer_count() >= 1);
        assert!(!reconnected, "a banned IP cannot reconnect");
    }

    /// A lightweight raw Noise-initiator client: completes the handshake so the
    /// server counts it as an inbound peer, but runs no discovery/gossip (so the
    /// test exercises the cap in isolation, with no peer-mesh fan-out).
    fn raw_noise_client(addr: &str) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let params = NOISE_PARAMS
            .parse()
            .map_err(|_| io::Error::other("params"))?;
        let builder = Builder::new(params);
        let kp = builder
            .generate_keypair()
            .map_err(|_| io::Error::other("keygen"))?;
        let mut hs = builder
            .local_private_key(&kp.private)
            .build_initiator()
            .map_err(|_| io::Error::other("init"))?;
        let mut buf = [0u8; 65535];
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|_| io::Error::other("m1"))?;
        write_raw(&mut stream, &buf[..n])?;
        let msg = read_raw(&mut stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|_| io::Error::other("m2"))?;
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|_| io::Error::other("m3"))?;
        write_raw(&mut stream, &buf[..n])?;
        // Complete the hybrid PQ exchange (the server fails closed without it).
        let hh = hs.get_handshake_hash().to_vec();
        let mut transport = hs
            .into_transport_mode()
            .map_err(|_| io::Error::other("transport"))?;
        pq_handshake(&mut stream, &mut transport, true, &hh)?;
        Ok(stream)
    }

    #[test]
    fn a_peer_that_fails_the_kem_exchange_never_becomes_a_connection() {
        // Fail-closed: complete the Noise handshake but send garbage instead
        // of an ML-KEM encapsulation key. The server must drop the
        // connection — there is no classical-only fallback.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let mut stream = TcpStream::connect(server.local_addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let params = NOISE_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let kp = builder.generate_keypair().unwrap();
        let mut hs = builder
            .local_private_key(&kp.private)
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        write_raw(&mut stream, &buf[..n]).unwrap();
        let msg = read_raw(&mut stream).unwrap();
        hs.read_message(&msg, &mut buf).unwrap();
        let n = hs.write_message(&[], &mut buf).unwrap();
        write_raw(&mut stream, &buf[..n]).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        // Noise channel is up — now violate the PQ exchange.
        noise_send(&mut stream, &mut transport, b"not-a-kem-key").unwrap();

        let accepted = wait_until(15, || server.peer_count() > 0);
        assert!(
            !accepted,
            "a connection without a completed ML-KEM exchange must be dropped"
        );
    }

    #[test]
    fn caps_inbound_connections() {
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr();
        // Open more raw clients than the cap allows. The first MAX_INBOUND_PEERS
        // handshake successfully; the excess are refused before the handshake, so
        // their handshake reads fail — we hold the successful streams open.
        let mut held = Vec::new();
        for _ in 0..(MAX_INBOUND_PEERS + 8) {
            if let Ok(s) = raw_noise_client(&addr.to_string()) {
                held.push(s);
            }
        }
        assert!(
            // 64+ Noise+ML-KEM handshakes is the heaviest test here; give it ample
            // headroom under saturated CI parallelism (healthy: a couple of seconds).
            wait_until(40, || server.peer_count() >= MAX_INBOUND_PEERS),
            "cap saturates (got {})",
            server.peer_count()
        );
        assert!(
            server.peer_count() <= MAX_INBOUND_PEERS,
            "inbound never exceeds the cap (got {})",
            server.peer_count()
        );
        drop(held);
    }

    #[test]
    fn discovers_peers_transitively() {
        // A only dials B; B already knows C. A should learn C via gossip and dial it.
        let a = TcpNode::bind("127.0.0.1:0").unwrap();
        let b = TcpNode::bind("127.0.0.1:0").unwrap();
        let c = TcpNode::bind("127.0.0.1:0").unwrap();

        b.connect(&c.local_addr().to_string()).unwrap();
        a.connect(&b.local_addr().to_string()).unwrap();

        let c_addr = c.local_addr();
        let learned = wait_until(15, || a.known_peers().contains(&c_addr));
        assert!(learned, "A discovered C transitively through B");
    }

    #[test]
    fn lan_beacon_parses_same_chain_rejects_others_and_self() {
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 244));
        let me = 42u64; // our nonce
        let peer = 7u64; // a different node's nonce
                         // Well-formed, same chain, different node → dial src_ip:advertised_port.
        let good = format!("{LAN_DISCO_TAG}|sov-testnet-1|9645|{peer}");
        assert_eq!(
            parse_beacon(good.as_bytes(), "sov-testnet-1", me, src),
            Some(SocketAddr::new(src, 9645))
        );
        // OUR OWN beacon looped back (same nonce) → ignored (no self-dial / ghost).
        let mine = format!("{LAN_DISCO_TAG}|sov-testnet-1|9645|{me}");
        assert_eq!(
            parse_beacon(mine.as_bytes(), "sov-testnet-1", me, src),
            None
        );
        // Different chain → ignored.
        let other = format!("{LAN_DISCO_TAG}|sov-mainnet|9645|{peer}");
        assert_eq!(
            parse_beacon(other.as_bytes(), "sov-testnet-1", me, src),
            None
        );
        // Garbage / wrong tag / bad port → ignored.
        assert_eq!(parse_beacon(b"hello world", "sov-testnet-1", me, src), None);
        assert_eq!(
            parse_beacon(
                b"sov-disco1|sov-testnet-1|notaport|7",
                "sov-testnet-1",
                me,
                src
            ),
            None
        );
    }

    #[test]
    fn shutdown_releases_the_listen_port() {
        // The fix for "address already in use" on an in-process restart: shutdown
        // must stop the accept thread and drop the listener so the OS frees the
        // port — a rebind to the SAME address then succeeds.
        let node = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = node.local_addr();
        node.shutdown();
        let freed = wait_until(10, || TcpListener::bind(addr).is_ok());
        assert!(freed, "listen port {addr} must be free after shutdown");
    }

    use std::net::Ipv4Addr;

    /// A synthetic public inbound address in network group `a.b.0.0`.
    fn pub_addr(a: u8, b: u8, host: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(a, b, 100, host), 30000 + host as u16))
    }

    #[test]
    fn eclipse_caps_bound_inbound_per_ip_and_per_group() {
        let mut inbound: HashSet<SocketAddr> = HashSet::new();

        // A single public IP may hold at most MAX_INBOUND_PER_IP slots.
        let one_ip = Ipv4Addr::new(203, 0, 113, 7);
        for port in 0..MAX_INBOUND_PER_IP {
            assert!(
                admit_inbound(&inbound, IpAddr::V4(one_ip)),
                "slot {port} from one IP is admitted up to the cap"
            );
            inbound.insert(SocketAddr::from((one_ip, 40000 + port as u16)));
        }
        assert!(
            !admit_inbound(&inbound, IpAddr::V4(one_ip)),
            "one IP cannot exceed MAX_INBOUND_PER_IP"
        );
        // A different IP in a *different* group is still welcome.
        assert!(
            admit_inbound(&inbound, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            "a fresh netgroup is not blocked by another IP's saturation"
        );
    }

    #[test]
    fn eclipse_cap_bounds_inbound_per_netgroup() {
        // Fill one /16 (group 203.0.x.x here uses a.b=203.0) with distinct IPs;
        // once MAX_INBOUND_PER_GROUP is reached, more from the same group are
        // refused even though each individual IP is under its own cap.
        let mut inbound: HashSet<SocketAddr> = HashSet::new();
        for host in 0..MAX_INBOUND_PER_GROUP as u8 {
            let a = pub_addr(203, 0, host);
            assert!(admit_inbound(&inbound, a.ip()), "host {host} admitted");
            inbound.insert(a);
        }
        let next = pub_addr(203, 0, 200);
        assert!(
            !admit_inbound(&inbound, next.ip()),
            "a saturated netgroup refuses further distinct IPs (anti-eclipse)"
        );
        // A different /16 is unaffected.
        assert!(
            admit_inbound(&inbound, pub_addr(203, 5, 1).ip()),
            "a different netgroup is admitted"
        );
    }

    #[test]
    fn loopback_is_exempt_from_the_finer_eclipse_caps() {
        // Single-host / loopback operation must stay usable: many loopback inbound
        // connections are allowed (up to the GLOBAL cap only), not throttled per-IP.
        let mut inbound: HashSet<SocketAddr> = HashSet::new();
        let lo = Ipv4Addr::LOCALHOST;
        for port in 0..(MAX_INBOUND_PER_IP + 4) {
            assert!(
                admit_inbound(&inbound, IpAddr::V4(lo)),
                "loopback slot {port} admitted past the per-IP cap"
            );
            inbound.insert(SocketAddr::from((lo, 50000 + port as u16)));
        }
    }

    #[test]
    fn global_inbound_cap_is_enforced_even_for_loopback() {
        let mut inbound: HashSet<SocketAddr> = HashSet::new();
        for port in 0..MAX_INBOUND_PEERS {
            inbound.insert(SocketAddr::from((Ipv4Addr::LOCALHOST, 1000 + port as u16)));
        }
        assert!(
            !admit_inbound(&inbound, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "the global cap bounds even exempt (loopback) peers"
        );
    }

    #[test]
    fn token_bucket_absorbs_a_burst_then_penalizes_sustained_overage() {
        // A self-contained Shared just for the scoring helpers (no sockets needed).
        let (tx, _rx) = channel();
        let shared = Shared {
            local_addr: "127.0.0.1:1".parse().unwrap(),
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new(VecDeque::new()),
            known: Mutex::new(HashSet::new()),
            dialing: Mutex::new(HashSet::new()),
            inbound: Mutex::new(HashSet::new()),
            scores: Mutex::new(HashMap::new()),
            dial_tx: tx,
            log: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        // The whole burst budget is absorbed without any ban (tokens cover it).
        for _ in 0..(MSG_BURST as usize) {
            assert!(note_message(&shared, ip), "burst stays in good standing");
        }
        assert!(!is_banned(&shared, ip), "a bounded burst is not banned");

        // Past the burst, each message is over budget; within a single decay
        // window a sustained overage crosses the threshold and bans the IP.
        let mut banned = false;
        for _ in 0..1000 {
            if !note_message(&shared, ip) {
                banned = true;
                break;
            }
        }
        assert!(banned, "sustained overage bans the peer");
        assert!(is_banned(&shared, ip), "the IP is now banned");
    }

    #[test]
    fn a_few_malformed_frames_ban_the_peer() {
        let (tx, _rx) = channel();
        let shared = Shared {
            local_addr: "127.0.0.1:1".parse().unwrap(),
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new(VecDeque::new()),
            known: Mutex::new(HashSet::new()),
            dialing: Mutex::new(HashSet::new()),
            inbound: Mutex::new(HashSet::new()),
            scores: Mutex::new(HashMap::new()),
            dial_tx: tx,
            log: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        // MALFORMED_FRAME_PENALTY is heavy: a small handful of malformed frames is
        // enough to ban, with no flood needed. The +1 is headroom for the tiny
        // continuous decay applied between consecutive calls (so the assertion does
        // not sit exactly on the floating-point threshold boundary).
        let need = (MISBEHAVIOR_BAN / MALFORMED_FRAME_PENALTY).ceil() as usize + 1;
        let mut banned = false;
        for _ in 0..need {
            if penalize(&shared, ip, MALFORMED_FRAME_PENALTY) {
                banned = true;
            }
        }
        assert!(banned, "a handful of malformed frames bans the peer");
        assert!(is_banned(&shared, ip));
    }

    #[test]
    fn penalize_peer_bans_and_drops_for_app_layer_misbehavior() {
        // The sync layer reports application-level misbehavior (e.g. a fabricated
        // block) the transport can't see; a penalty at the ban threshold must drop the
        // live connection AND ban the IP, exactly like a transport-level flood.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().to_string();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&addr).unwrap();
        assert!(
            wait_until(15, || server.peer_count() >= 1),
            "peer connected"
        );
        let peer = server.connected_peers()[0];

        let banned = server.penalize_peer(peer, MISBEHAVIOR_BAN);
        assert!(banned, "a threshold penalty bans");
        // The IP is banned in the authoritative ban state (so it cannot reconnect —
        // that the ban blocks a reconnect is covered by the flood test)...
        assert!(
            is_banned(&server.shared, peer.ip()),
            "the misbehaving peer's IP is banned"
        );
        // ...and the live connection is dropped immediately, not merely barred later.
        assert!(
            wait_until(15, || server.peer_count() == 0),
            "the penalized peer is dropped immediately"
        );
    }

    #[test]
    fn a_sub_threshold_penalty_is_forgiven() {
        // A single, bounded penalty (below the ban threshold) does not drop a peer —
        // an honest peer that trips one check is not punished off the network.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().to_string();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&addr).unwrap();
        assert!(
            wait_until(15, || server.peer_count() >= 1),
            "peer connected"
        );
        let peer = server.connected_peers()[0];

        let banned = server.penalize_peer(peer, MISBEHAVIOR_BAN / 4.0);
        assert!(!banned, "one sub-threshold strike does not ban");
        // The peer stays connected.
        assert!(
            server.peer_count() >= 1,
            "a forgiven peer keeps its connection"
        );
    }

    #[test]
    fn disconnect_drops_a_peer_without_banning_it() {
        // Reclaiming a slot (e.g. a connection that never authenticated) drops the
        // peer but does NOT ban it — a slow/old client may simply reconnect.
        let server = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().to_string();
        let client = TcpNode::bind("127.0.0.1:0").unwrap();
        client.connect(&addr).unwrap();
        assert!(
            wait_until(15, || server.peer_count() >= 1),
            "peer connected"
        );
        let peer = server.connected_peers()[0];

        server.disconnect(&peer);
        assert!(
            wait_until(15, || server.peer_count() == 0),
            "the peer is dropped"
        );
        // NOT banned: a fresh connection from the same host is admitted.
        let client2 = TcpNode::bind("127.0.0.1:0").unwrap();
        client2.connect(&addr).unwrap();
        assert!(
            wait_until(15, || server.peer_count() >= 1),
            "disconnect does not ban — the host can reconnect"
        );
    }

    #[test]
    fn dial_dedup_matches_inflight_inbound_and_exempts_loopback_without_deadlock() {
        // The discovery-dial dedup must (a) treat a LAN host we already have an
        // in-flight inbound from as a duplicate (matched by IP, since the inbound is
        // keyed by an ephemeral port), (b) exempt loopback, and (c) acquire its locks
        // self-contained — if it re-locked `peers` while a guard were still held it
        // would self-deadlock and this test would HANG instead of returning.
        let (tx, _rx) = channel();
        let shared = Shared {
            local_addr: "127.0.0.1:1".parse().unwrap(),
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new(VecDeque::new()),
            known: Mutex::new(HashSet::new()),
            dialing: Mutex::new(HashSet::new()),
            // An inbound from 192.168.1.5 still completing its handshake (ephemeral port).
            inbound: Mutex::new(["192.168.1.5:54321".parse().unwrap()].into_iter().collect()),
            scores: Mutex::new(HashMap::new()),
            dial_tx: tx,
            log: Mutex::new(None),
            shutdown: AtomicBool::new(false),
        };
        // Same host, its advertised LISTEN port → duplicate (matched by IP).
        assert!(dial_would_duplicate(
            &shared,
            "192.168.1.5:9645".parse().unwrap()
        ));
        // A different host → not a duplicate.
        assert!(!dial_would_duplicate(
            &shared,
            "192.168.1.9:9645".parse().unwrap()
        ));
        // Loopback is exempt so single-host / loopback multi-node tests still connect.
        assert!(!dial_would_duplicate(
            &shared,
            "127.0.0.1:9645".parse().unwrap()
        ));
    }

    #[test]
    fn resolve_dial_targets_accepts_every_address_form_an_operator_types() {
        // `ip:port` — the canonical form.
        assert_eq!(
            resolve_dial_targets("192.168.0.244:9645").unwrap(),
            vec!["192.168.0.244:9645".parse::<SocketAddr>().unwrap()]
        );
        // A BARE IPv4 — the exact input the user said "does absolutely nothing". The
        // default P2P port MUST be appended (not silently dropped).
        assert_eq!(
            resolve_dial_targets("192.168.0.244").unwrap(),
            vec![SocketAddr::new(
                "192.168.0.244".parse().unwrap(),
                DEFAULT_P2P_PORT
            )]
        );
        // Surrounding whitespace (a pasted address) is tolerated.
        assert_eq!(
            resolve_dial_targets("  192.168.0.244  ").unwrap(),
            vec![SocketAddr::new(
                "192.168.0.244".parse().unwrap(),
                DEFAULT_P2P_PORT
            )]
        );
        // A BARE IPv6 — paired with the default port without the operator bracketing it.
        assert_eq!(
            resolve_dial_targets("::1").unwrap(),
            vec![SocketAddr::new("::1".parse().unwrap(), DEFAULT_P2P_PORT)]
        );
        // Bracketed IPv6 with an explicit port.
        assert_eq!(
            resolve_dial_targets("[::1]:9645").unwrap(),
            vec!["[::1]:9645".parse::<SocketAddr>().unwrap()]
        );
        // `localhost` resolves (it is in every hosts file) and lands on the default port.
        let local = resolve_dial_targets("localhost").unwrap();
        assert!(
            local.iter().all(|a| a.port() == DEFAULT_P2P_PORT),
            "bare hostname gets the default port: {local:?}"
        );
        // `localhost:port` resolves with the explicit port.
        let local_port = resolve_dial_targets("localhost:9645").unwrap();
        assert!(local_port.iter().all(|a| a.port() == 9645));

        // Genuinely-unusable input is a CLEAR error — never a silent empty success.
        assert!(resolve_dial_targets("").is_err());
        assert!(resolve_dial_targets("   ").is_err());
        assert!(resolve_dial_targets("not a valid address !!!").is_err());
    }

    #[test]
    fn request_reconnect_actually_dials_and_connects_a_bare_address() {
        // The EXACT path the GUI "Connect" button drives (`request_reconnect`), which
        // previously no-op'd on anything that was not strictly `ip:port`. Two real
        // loopback nodes: A asks to reconnect to B by address; the background dial
        // thread must pick it up, open the TCP connection, run the encrypted handshake,
        // and register the peer — proving the seed-peer box does something real.
        let a = TcpNode::bind("127.0.0.1:0").unwrap();
        let b = TcpNode::bind("127.0.0.1:0").unwrap();

        // `request_reconnect` returns the concrete target it queued (no silent drop)...
        let queued = a
            .request_reconnect(&b.local_addr().to_string())
            .expect("a valid loopback address resolves");
        assert!(
            queued.contains(&b.local_addr()),
            "the queued dial target is B's address: {queued:?}"
        );

        // ...and the dial truly lands: A is connected to B within a few seconds.
        assert!(
            wait_until(15, || a.peer_count() >= 1),
            "request_reconnect dialed and the link came up"
        );

        // An unresolvable address is reported as an error here, NOT swallowed.
        assert!(a
            .request_reconnect("definitely not an address !!!")
            .is_err());
    }
}
