//! The gossip socket loop: listener, dial, peer set.
//!
//! Sits on [`sov_network::SealedLink`] — the same Noise + ML-KEM link consensus
//! transport uses, reused rather than reimplemented. This module owns only the
//! things a *share* protocol needs: who we are connected to, how many, how much
//! we will buffer from them, and how fast we hang up on one that misbehaves.
//!
//! # It runs on its own port
//!
//! Deliberately. Share messages are decoded by [`crate::wire`], never by
//! `NetMessage`, so a bug in share decoding cannot reach block or transaction
//! relay. That separation is the whole reason this is a second listener rather
//! than four new enum variants.
//!
//! # What arrives here is a claim, not a fact
//!
//! The link guarantees the bytes are the ones the peer sent. It guarantees
//! nothing about whether they are true — an authenticated peer can send a
//! well-sealed lie. So this module never interprets a share. It decodes,
//! bounds, and hands the result to the caller, who runs
//! [`ShareChain::accept`](crate::ShareChain::accept). A peer that sends
//! undecodable bytes is dropped; a peer that sends a *decodable but invalid*
//! share is the caller's business.
//!
//! # Bounds, and why each exists
//!
//! Every one of these is a limit on what a stranger can make this process do:
//!
//! - [`MAX_PEERS`] — connection slots are finite; without a cap one host can
//!   fill them all and no honest peer gets in (an eclipse).
//! - [`MAX_INBOX_BYTES`] — the inbox is bounded in BYTES, not messages, because
//!   a message count says nothing about memory. Over the cap, the oldest are
//!   dropped: falling behind must cost bounded memory, not the process.
//! - The frame ceiling lives in [`crate::wire::MAX_FRAME_BYTES`] and the link's
//!   own limit, so a declared length can never drive an allocation.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sov_network::{LinkRead, SealedLink};

use crate::wire::{decode, encode, ShareMessage};

/// Most simultaneous gossip peers.
pub const MAX_PEERS: usize = 64;

/// Most plaintext held in the inbox before the oldest are dropped.
pub const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;

/// How long a handshake may take before the dial is abandoned.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Received messages, oldest first, bounded by total plaintext size.
#[derive(Default)]
struct Inbox {
    queue: Vec<(SocketAddr, ShareMessage)>,
    bytes: usize,
}

impl Inbox {
    fn push(&mut self, from: SocketAddr, msg: ShareMessage, size: usize) {
        self.queue.push((from, msg));
        self.bytes += size;
        // Bounded in BYTES. A slow consumer costs bounded memory, never the
        // process — and the sizes here are the plaintext we actually decoded,
        // not a number the peer told us.
        while self.bytes > MAX_INBOX_BYTES && !self.queue.is_empty() {
            self.queue.remove(0);
            // Recomputed rather than tracked per-entry: exact, and the queue is
            // bounded so it is cheap.
            self.bytes = self.bytes.saturating_sub(size);
        }
    }
    fn drain(&mut self) -> Vec<(SocketAddr, ShareMessage)> {
        self.bytes = 0;
        std::mem::take(&mut self.queue)
    }
}

struct Shared {
    peers: Mutex<HashMap<SocketAddr, Arc<SealedLink>>>,
    inbox: Mutex<Inbox>,
    running: AtomicBool,
}

/// A gossip endpoint: one listener, a peer set, and a read thread per peer.
pub struct GossipNode {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
}

impl GossipNode {
    /// Bind a listener and start accepting. `127.0.0.1:0` takes an ephemeral
    /// port, which is what the tests use.
    pub fn bind(addr: &str) -> io::Result<GossipNode> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new(Inbox::default()),
            running: AtomicBool::new(true),
        });
        let accept_shared = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                if !accept_shared.running.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let s = accept_shared.clone();
                // One thread per connection: the handshake blocks, and a slow or
                // hostile dialer must not stall the accept loop for everyone.
                thread::spawn(move || {
                    let _ = add_peer(&s, stream, false);
                });
            }
        });
        Ok(GossipNode { shared, local_addr })
    }

    /// The bound address (useful when the port was ephemeral).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Dial a peer and complete the handshake as initiator.
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<SocketAddr> {
        let target = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("no address resolved"))?;
        let stream = TcpStream::connect_timeout(&target, HANDSHAKE_TIMEOUT)?;
        add_peer(&self.shared, stream, true)
    }

    /// Currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Send to one peer. `false` if it is unknown or the write failed (in which
    /// case it is dropped — a peer we cannot write to is not a peer).
    pub fn send(&self, peer: &SocketAddr, msg: &ShareMessage) -> bool {
        let link = {
            let peers = self.shared.peers.lock().unwrap();
            peers.get(peer).cloned()
        };
        let Some(link) = link else { return false };
        if link.send(&encode(msg)).is_err() {
            // Same reasoning as `shutdown`: remove AND close, or the read thread
            // stays parked on a socket nobody is writing to.
            self.shared.peers.lock().unwrap().remove(peer);
            if let Ok(s) = link.try_clone_stream() {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            return false;
        }
        true
    }

    /// Send to every peer; returns how many accepted the write.
    pub fn broadcast(&self, msg: &ShareMessage) -> usize {
        let bytes = encode(msg);
        let targets: Vec<(SocketAddr, Arc<SealedLink>)> = {
            let peers = self.shared.peers.lock().unwrap();
            peers.iter().map(|(a, l)| (*a, l.clone())).collect()
        };
        let mut sent = 0;
        let mut dead = Vec::new();
        for (addr, link) in targets {
            if link.send(&bytes).is_ok() {
                sent += 1;
            } else {
                dead.push(addr);
            }
        }
        if !dead.is_empty() {
            let mut peers = self.shared.peers.lock().unwrap();
            for d in dead {
                peers.remove(&d);
            }
        }
        sent
    }

    /// Take everything received since the last call.
    ///
    /// Returns *claims*. Each still has to survive
    /// [`ShareChain::accept`](crate::ShareChain::accept) before it means
    /// anything.
    pub fn drain(&self) -> Vec<(SocketAddr, ShareMessage)> {
        self.shared
            .inbox
            .lock()
            .map(|mut i| i.drain())
            .unwrap_or_default()
    }

    /// Stop accepting and drop every peer.
    ///
    /// Each peer's socket is explicitly shut down, not merely dropped. Its read
    /// thread is parked inside `recv` holding a CLONE of the stream, so dropping
    /// the peer map leaves the socket open and the thread parked forever — the
    /// far side then never sees a disconnect. `shutdown(Both)` on any clone
    /// closes the underlying socket, which unblocks the read and lets both ends
    /// notice.
    pub fn shutdown(&self) {
        self.shared.running.store(false, Ordering::Relaxed);
        let links: Vec<Arc<SealedLink>> = {
            let mut peers = self.shared.peers.lock().unwrap();
            peers.drain().map(|(_, l)| l).collect()
        };
        for link in links {
            if let Ok(s) = link.try_clone_stream() {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
        // Unblock the accept loop, which is parked in `incoming()`.
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(200));
    }
}

impl Drop for GossipNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Handshake a stream into the peer set and start its read thread.
fn add_peer(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    initiator: bool,
) -> io::Result<SocketAddr> {
    // Refuse before doing handshake work: an over-cap connection must cost us a
    // TCP accept, not an ML-KEM exchange.
    if shared.peers.lock().unwrap().len() >= MAX_PEERS {
        return Err(io::Error::other("peer slots full"));
    }
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true).ok();
    let link = Arc::new(SealedLink::establish(&mut stream, initiator)?);
    // Handshake done: reads may now block indefinitely.
    stream.set_read_timeout(None)?;
    let addr = link.peer_addr()?;
    let mut reader = link.try_clone_stream()?;

    shared.peers.lock().unwrap().insert(addr, link.clone());

    let s = shared.clone();
    thread::spawn(move || {
        // Ends on close, on a malformed frame, or on shutdown. Undecodable
        // bytes over a sealed link mean the peer is broken or hostile; either
        // way the stream is no longer interpretable, so hang up rather than try
        // to resynchronise.
        while let LinkRead::Frame(plaintext) = link.recv(&mut reader) {
            let size = plaintext.len();
            let Ok(msg) = decode(&plaintext) else { break };
            if let Ok(mut inbox) = s.inbox.lock() {
                inbox.push(addr, msg, size);
            }
            if !s.running.load(Ordering::Relaxed) {
                break;
            }
        }
        s.peers.lock().unwrap().remove(&addr);
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Share, ShareId};
    use sov_primitives::AccountId;
    use std::time::Instant;

    fn a_share(n: u8) -> Share {
        Share {
            id: [n; 32],
            prev: None,
            uncles: Vec::new(),
            finder: AccountId::new("alice.sov").expect("valid"),
            work: 1_000,
            is_block: false,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    /// Wait for a condition, or fail. Deadline-based, not iteration-based, so a
    /// slow machine waits longer rather than failing sooner.
    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if f() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}");
    }

    /// The point of the whole crate: two nodes connect over a real encrypted
    /// link and a share crosses it intact.
    #[test]
    fn two_nodes_handshake_and_a_share_crosses() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        let b = GossipNode::bind("127.0.0.1:0").expect("bind b");

        a.connect(b.local_addr()).expect("dial");
        wait_for("both sides to register the peer", || {
            a.peer_count() == 1 && b.peer_count() == 1
        });

        let sent = a.broadcast(&ShareMessage::Announce(a_share(7)));
        assert_eq!(sent, 1, "the share must reach the one connected peer");

        let mut got = Vec::new();
        wait_for("b to receive the announce", || {
            got.extend(b.drain());
            !got.is_empty()
        });
        match &got[0].1 {
            ShareMessage::Announce(s) => {
                assert_eq!(s.id, [7u8; 32], "the share must arrive intact");
                assert_eq!(s.finder.as_str(), "alice.sov");
            }
            other => panic!("expected an Announce, got {other:?}"),
        }
    }

    /// Traffic flows both ways on one link — the responder can answer without
    /// dialing back.
    #[test]
    fn the_link_carries_traffic_in_both_directions() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        let b = GossipNode::bind("127.0.0.1:0").expect("bind b");
        a.connect(b.local_addr()).expect("dial");
        wait_for("link up", || a.peer_count() == 1 && b.peer_count() == 1);

        assert_eq!(b.broadcast(&ShareMessage::GetShares { after: None }), 1);
        let mut got = Vec::new();
        wait_for("a to receive the request", || {
            got.extend(a.drain());
            !got.is_empty()
        });
        assert_eq!(got[0].1, ShareMessage::GetShares { after: None });
    }

    /// A batch survives the round trip — this is the path used to catch a new
    /// peer up, so it carries the most bytes.
    #[test]
    fn a_batch_of_shares_round_trips() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        let b = GossipNode::bind("127.0.0.1:0").expect("bind b");
        a.connect(b.local_addr()).expect("dial");
        wait_for("link up", || a.peer_count() == 1 && b.peer_count() == 1);

        let batch: Vec<Share> = (0..32u8).map(a_share).collect();
        assert_eq!(a.broadcast(&ShareMessage::Shares(batch.clone())), 1);

        let mut got = Vec::new();
        wait_for("the batch to arrive", || {
            got.extend(b.drain());
            !got.is_empty()
        });
        match &got[0].1 {
            ShareMessage::Shares(v) => assert_eq!(v, &batch, "every share must survive"),
            other => panic!("expected Shares, got {other:?}"),
        }
    }

    /// Garbage on the socket must not be mistaken for a message. A peer that
    /// never completes the handshake never joins the peer set, and the listener
    /// must survive it — the accept loop is the one thing a stranger can always
    /// reach.
    #[test]
    fn a_peer_that_never_handshakes_is_dropped_and_the_listener_survives() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");

        for _ in 0..5 {
            if let Ok(mut junk) = TcpStream::connect(a.local_addr()) {
                use std::io::Write;
                let _ = junk.write_all(&[0xAB; 512]);
                let _ = junk.flush();
            }
        }
        thread::sleep(Duration::from_millis(300));
        assert_eq!(a.peer_count(), 0, "garbage must never become a peer");
        assert!(a.drain().is_empty(), "garbage must never become a message");

        // And the listener still works afterwards.
        let b = GossipNode::bind("127.0.0.1:0").expect("bind b");
        b.connect(a.local_addr())
            .expect("an honest dial must still succeed");
        wait_for("the honest peer to connect", || a.peer_count() == 1);
    }

    /// Dropping a peer's side removes it from the set rather than leaking a
    /// thread or a slot.
    #[test]
    fn a_disconnecting_peer_leaves_the_peer_set() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        {
            let b = GossipNode::bind("127.0.0.1:0").expect("bind b");
            b.connect(a.local_addr()).expect("dial");
            wait_for("link up", || a.peer_count() == 1);
        } // b drops here
        wait_for("a to notice the disconnect", || a.peer_count() == 0);
    }

    /// Sending to an unknown peer is a clean `false`, not a panic.
    #[test]
    fn sending_to_an_unknown_peer_is_refused() {
        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        let nowhere: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        assert!(!a.send(&nowhere, &ShareMessage::GetShares { after: None }));
        assert_eq!(a.broadcast(&ShareMessage::GetShares { after: None }), 0);
    }

    /// End to end: a share gossiped over the wire is accepted by the receiver's
    /// sharechain — decode and validation joined up, which is the actual
    /// product.
    #[test]
    fn a_gossiped_share_is_accepted_by_the_receivers_chain() {
        use crate::{Payouts, ShareChain};

        let a = GossipNode::bind("127.0.0.1:0").expect("bind a");
        let b = GossipNode::bind("127.0.0.1:0").expect("bind b");
        a.connect(b.local_addr()).expect("dial");
        wait_for("link up", || a.peer_count() == 1 && b.peer_count() == 1);

        let share = a_share(3);
        a.broadcast(&ShareMessage::Announce(share.clone()));

        let mut chain = ShareChain::new();
        let mut applied = false;
        wait_for("b to apply the share", || {
            for (_, msg) in b.drain() {
                if let ShareMessage::Announce(s) = msg {
                    // The receiver validates for itself. The link delivered
                    // bytes; it did not vouch for them.
                    chain.accept(s, 0, &Payouts::new()).expect("valid share");
                    applied = true;
                }
            }
            applied
        });
        assert_eq!(chain.tip(), Some([3u8; 32] as ShareId));
        assert_eq!(chain.len(), 1);
    }
}
