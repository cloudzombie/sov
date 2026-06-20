//! The peer-to-peer wire protocol: messages nodes exchange to stay in sync.
//!
//! Every message is Borsh-encoded for a compact, deterministic wire form. The
//! set covers the two things that must propagate for a Nakamoto chain to live —
//! transactions (into mempools) and blocks (the proof-of-work itself; finality
//! is confirmation depth, so no votes travel the wire) — plus a minimal
//! request/response for catching a lagging peer up by height.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::{Keypair, PublicKey, Signature};
use sov_primitives::{AccountId, Hash};
use sov_types::{Block, SignedTransaction};

/// A protocol message exchanged between peers.
// The block-carrying variants (`NewBlock`, `BlockResponse`) are inherently larger
// than the control messages; a gossip message is short-lived (one per send), not
// stored in bulk, so the size gap is by design — boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum NetMessage {
    /// Handshake / liveness: a peer's current head height and hash.
    Status {
        /// The peer's head height.
        height: u64,
        /// The peer's head block hash.
        head: Hash,
        /// Cumulative proof-of-work of `head`, encoded as fixed-width big-endian
        /// bytes so lexicographic ordering matches numeric work ordering.
        chain_work: [u8; 32],
    },
    /// Gossip a transaction for inclusion in mempools.
    NewTransaction(SignedTransaction),
    /// Gossip a newly produced block.
    NewBlock(Block),
    /// Request the block at a height (catch-up).
    GetBlock {
        /// The requested height.
        height: u64,
    },
    /// Response to [`NetMessage::GetBlock`]; `None` if the peer lacks it.
    BlockResponse(Option<Block>),
    /// Peer discovery: a list of known peer addresses (`host:port`). On receipt,
    /// a node dials any addresses it does not already know, so knowledge of the
    /// network propagates transitively.
    Peers(Vec<String>),
    /// Authenticated handshake: a peer proves it is on the same chain — matching
    /// `chain_id` and `genesis_hash` — controls `public_key`, AND is speaking over
    /// the specific encrypted channel identified by `channel_binding` (the Noise
    /// handshake hash), by signing all of it. Binding to the channel defeats a
    /// man-in-the-middle: a relayed handshake carries the sender's channel hash,
    /// which will not equal the receiver's hash for its own leg. A peer that fails
    /// this is never trusted with blocks or transactions.
    Hello {
        /// The peer's network/chain id.
        chain_id: String,
        /// The peer's genesis block hash — pins the exact chain and fork.
        genesis_hash: Hash,
        /// The peer's claimed account identity.
        account: AccountId,
        /// The public key that produced `signature`.
        public_key: PublicKey,
        /// The Noise handshake hash of the connection this Hello is sent over —
        /// cryptographically ties the authenticated identity to the encrypted pipe.
        channel_binding: Vec<u8>,
        /// Ed25519 signature over [`handshake_bytes`]`(chain_id, genesis_hash, channel_binding)`.
        signature: Signature,
    },
}

impl NetMessage {
    /// Encode to the canonical Borsh wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialization of a NetMessage is infallible")
    }

    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        borsh::from_slice(bytes).map_err(|_| NetworkError::Decode)
    }

    /// Build a signed [`NetMessage::Hello`] handshake for `account` on the chain
    /// identified by `chain_id` / `genesis_hash`.
    pub fn hello(
        chain_id: impl Into<String>,
        genesis_hash: Hash,
        account: AccountId,
        channel_binding: &[u8],
        keypair: &Keypair,
    ) -> NetMessage {
        let chain_id = chain_id.into();
        let signature = keypair.sign(&handshake_bytes(&chain_id, &genesis_hash, channel_binding));
        NetMessage::Hello {
            chain_id,
            genesis_hash,
            account,
            public_key: keypair.public_key(),
            channel_binding: channel_binding.to_vec(),
            signature,
        }
    }

    /// If this is a valid handshake for the expected chain AND the expected channel
    /// — same `chain_id`, `genesis_hash`, and `channel_binding` (the receiver's own
    /// Noise handshake hash for this connection), with a signature that verifies
    /// against its own `public_key` — return the authenticated account; else `None`.
    pub fn authenticated_account(
        &self,
        expected_chain_id: &str,
        expected_genesis: &Hash,
        expected_binding: &[u8],
    ) -> Option<&AccountId> {
        match self {
            NetMessage::Hello {
                chain_id,
                genesis_hash,
                account,
                public_key,
                channel_binding,
                signature,
            } if chain_id == expected_chain_id
                && genesis_hash == expected_genesis
                && channel_binding.as_slice() == expected_binding
                && public_key.verify(
                    &handshake_bytes(chain_id, genesis_hash, channel_binding),
                    signature,
                ) =>
            {
                Some(account)
            }
            _ => None,
        }
    }
}

/// The canonical bytes a [`NetMessage::Hello`] signs: chain id, genesis hash, and
/// the channel binding (Noise handshake hash). Binding all three means a handshake
/// signed for one chain/fork, or relayed onto a different encrypted channel, cannot
/// be replayed.
pub fn handshake_bytes(chain_id: &str, genesis_hash: &Hash, channel_binding: &[u8]) -> Vec<u8> {
    let mut bytes = chain_id.as_bytes().to_vec();
    bytes.extend_from_slice(genesis_hash.as_bytes());
    bytes.extend_from_slice(channel_binding);
    bytes
}

/// Errors at the network layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkError {
    /// A received message could not be decoded.
    #[error("failed to decode network message")]
    Decode,
    /// A message was addressed to an unknown peer.
    #[error("unknown peer")]
    UnknownPeer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrips() {
        let msg = NetMessage::Status {
            height: 42,
            head: Hash::digest(b"head"),
            chain_work: [0x2a; 32],
        };
        let bytes = msg.encode();
        assert_eq!(NetMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn get_block_roundtrips() {
        let msg = NetMessage::GetBlock { height: 7 };
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn garbage_fails_to_decode() {
        assert_eq!(
            NetMessage::decode(&[0xff, 0xff, 0xff]),
            Err(NetworkError::Decode)
        );
    }

    #[test]
    fn hello_requires_matching_channel_binding() {
        let kp = Keypair::from_seed([1; 32]);
        let genesis = Hash::digest(b"genesis");
        let account = AccountId::new("val01.node.sov").unwrap();
        let binding = b"noise-handshake-hash-A";
        let h = NetMessage::hello("sov", genesis, account, binding, &kp);

        // Correct chain id + genesis + channel binding authenticates.
        assert!(h.authenticated_account("sov", &genesis, binding).is_some());
        // A relayed handshake over a DIFFERENT channel (MITM) is rejected.
        assert!(h
            .authenticated_account("sov", &genesis, b"noise-handshake-hash-B")
            .is_none());
        // Wrong genesis is still rejected.
        assert!(h
            .authenticated_account("sov", &Hash::digest(b"other"), binding)
            .is_none());
    }
}
