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
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
        let listener = TcpListener::bind(addr)?;
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

    /// The address this node is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local_addr
    }

    /// Dial a peer by `host:port` now (blocking up to [`CONNECT_TIMEOUT`]). A
    /// no-op if already connected or a dial to it is already in flight.
    pub fn connect(&self, addr: &str) -> std::io::Result<()> {
        let sa: SocketAddr = addr
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad address"))?;
        attempt_dial(&self.shared, sa)
    }

    /// Ask the background dial thread to (re)connect to `addr` if it is not already
    /// connected — non-blocking. Used to keep bootstrap links up across peer
    /// restarts and sleep/wake, without stalling the gossip loop.
    pub fn request_reconnect(&self, addr: &str) {
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            let _ = self.shared.dial_tx.send(sa);
        }
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

/// Connect to `addr` and register the resulting stream. Idempotent and
/// retry-safe: skips if already connected or a dial is in flight, and on failure
/// leaves no trace, so a later retry (e.g. once a sleeping seed wakes) succeeds.
fn attempt_dial(shared: &Arc<Shared>, addr: SocketAddr) -> std::io::Result<()> {
    if addr == shared.local_addr {
        return Ok(());
    }
    if shared.peers.lock().unwrap().contains_key(&addr) {
        return Ok(()); // already connected
    }
    // Claim the in-flight slot; if another dial already holds it, defer to that one.
    if !shared.dialing.lock().unwrap().insert(addr) {
        return Ok(());
    }
    shared.known.lock().unwrap().insert(addr);

    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(stream) => {
            // `setup_connection` clears the in-flight slot once the peer is live.
            register(shared, stream, true); // we dialed: we are the Noise initiator
            Ok(())
        }
        Err(e) => {
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

    // Announce ourselves + everyone we know, so the peer can discover the network.
    let mut addrs = vec![shared.local_addr.to_string()];
    addrs.extend(shared.known.lock().unwrap().iter().map(|a| a.to_string()));
    let _ = write_frame(&peer, &NetMessage::Peers(addrs));

    reader_loop(shared, key, reader, peer);
    shared.inbound.lock().unwrap().remove(&key);
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
                                    let unseen = shared.known.lock().unwrap().insert(sa);
                                    if unseen {
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
    fn delivers_a_broadcast_over_real_tcp() {
        let a = TcpNode::bind("127.0.0.1:0").unwrap();
        let b = TcpNode::bind("127.0.0.1:0").unwrap();
        a.connect(&b.local_addr().to_string()).unwrap();

        assert!(
            wait_until(3, || a.peer_count() >= 1 && b.peer_count() >= 1),
            "peers connected"
        );

        a.broadcast(&status(7));
        let got = wait_until(3, || {
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
        assert!(wait_until(3, || server.peer_count() >= 1), "peer connected");

        // Blast well past the burst budget as fast as possible: this empties the
        // token bucket, then every further message accrues a rate-violation
        // penalty until the misbehavior score crosses the ban threshold.
        let flood = (MSG_RATE_PER_SEC * 3.0) as usize;
        for _ in 0..flood {
            client.broadcast(&status(1));
        }

        // The flooder is dropped...
        assert!(
            wait_until(5, || server.peer_count() == 0),
            "flooding peer was dropped"
        );
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

        let accepted = wait_until(2, || server.peer_count() > 0);
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
            wait_until(5, || server.peer_count() >= MAX_INBOUND_PEERS),
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
        let learned = wait_until(4, || a.known_peers().contains(&c_addr));
        assert!(learned, "A discovered C transitively through B");
    }

    #[test]
    fn shutdown_releases_the_listen_port() {
        // The fix for "address already in use" on an in-process restart: shutdown
        // must stop the accept thread and drop the listener so the OS frees the
        // port — a rebind to the SAME address then succeeds.
        let node = TcpNode::bind("127.0.0.1:0").unwrap();
        let addr = node.local_addr();
        node.shutdown();
        let freed = wait_until(3, || TcpListener::bind(addr).is_ok());
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
}
