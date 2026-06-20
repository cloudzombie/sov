//! An in-memory transport for the gossip protocol.
//!
//! Real deployments will carry [`NetMessage`]s over an authenticated,
//! libp2p-style transport. That belongs to a later milestone and depends on an
//! async runtime; what matters first is that the *propagation logic* — who
//! receives a broadcast, what a peer does on delivery — is correct and testable
//! deterministically. [`InMemoryNetwork`] provides exactly that: a synchronous
//! message bus where peers register, broadcast, and drain their inboxes with no
//! threads, timers, or sockets.

use std::collections::{HashMap, VecDeque};

use crate::message::{NetMessage, NetworkError};

/// Identifies a peer on the in-memory bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u64);

/// A synchronous, in-process message bus connecting several peers.
#[derive(Default)]
pub struct InMemoryNetwork {
    inboxes: HashMap<PeerId, VecDeque<(PeerId, NetMessage)>>,
}

impl InMemoryNetwork {
    /// Create an empty network.
    pub fn new() -> Self {
        InMemoryNetwork::default()
    }

    /// Register a peer so it can receive messages.
    pub fn register(&mut self, peer: PeerId) {
        self.inboxes.entry(peer).or_default();
    }

    /// The registered peers.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.inboxes.keys().copied()
    }

    /// Deliver `message` to a single peer.
    pub fn send(
        &mut self,
        from: PeerId,
        to: PeerId,
        message: NetMessage,
    ) -> Result<(), NetworkError> {
        let inbox = self.inboxes.get_mut(&to).ok_or(NetworkError::UnknownPeer)?;
        inbox.push_back((from, message));
        Ok(())
    }

    /// Deliver `message` to every registered peer except the sender — the gossip
    /// primitive. Returns how many peers received it.
    pub fn broadcast(&mut self, from: PeerId, message: NetMessage) -> usize {
        let recipients: Vec<PeerId> = self
            .inboxes
            .keys()
            .copied()
            .filter(|p| *p != from)
            .collect();
        for peer in &recipients {
            if let Some(inbox) = self.inboxes.get_mut(peer) {
                inbox.push_back((from, message.clone()));
            }
        }
        recipients.len()
    }

    /// Pop the next pending message for `peer`, if any.
    pub fn recv(&mut self, peer: PeerId) -> Option<(PeerId, NetMessage)> {
        self.inboxes.get_mut(&peer)?.pop_front()
    }

    /// Drain and return all pending messages for `peer` in arrival order.
    pub fn drain(&mut self, peer: PeerId) -> Vec<(PeerId, NetMessage)> {
        match self.inboxes.get_mut(&peer) {
            Some(inbox) => inbox.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Number of pending messages for `peer`.
    pub fn pending(&self, peer: PeerId) -> usize {
        self.inboxes.get(&peer).map_or(0, VecDeque::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_primitives::Hash;

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

    #[test]
    fn broadcast_reaches_others_but_not_sender() {
        let mut net = InMemoryNetwork::new();
        for i in 0..3 {
            net.register(PeerId(i));
        }
        let delivered = net.broadcast(PeerId(0), status(1));
        assert_eq!(delivered, 2);
        assert_eq!(net.pending(PeerId(0)), 0); // sender excluded
        assert_eq!(net.pending(PeerId(1)), 1);
        assert_eq!(net.pending(PeerId(2)), 1);
    }

    #[test]
    fn direct_send_and_recv() {
        let mut net = InMemoryNetwork::new();
        net.register(PeerId(1));
        net.send(PeerId(0), PeerId(1), status(5)).unwrap();
        let (from, msg) = net.recv(PeerId(1)).unwrap();
        assert_eq!(from, PeerId(0));
        assert_eq!(msg, status(5));
        assert!(net.recv(PeerId(1)).is_none());
    }

    #[test]
    fn send_to_unknown_peer_errors() {
        let mut net = InMemoryNetwork::new();
        assert_eq!(
            net.send(PeerId(0), PeerId(9), status(1)),
            Err(NetworkError::UnknownPeer)
        );
    }

    #[test]
    fn drain_returns_all_in_order() {
        let mut net = InMemoryNetwork::new();
        net.register(PeerId(1));
        net.send(PeerId(0), PeerId(1), status(1)).unwrap();
        net.send(PeerId(0), PeerId(1), status(2)).unwrap();
        let msgs = net.drain(PeerId(1));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].1, status(1));
        assert_eq!(msgs[1].1, status(2));
        assert_eq!(net.pending(PeerId(1)), 0);
    }
}
