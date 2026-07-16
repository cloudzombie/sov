//! # sov-network
//!
//! The peer-to-peer layer that propagates the chain between nodes:
//!
//! - [`NetMessage`] — the Borsh-encoded gossip protocol (transactions, blocks,
//!   chainwork status, and a height-based catch-up request/response).
//! - [`TcpNode`] — the real encrypted transport: Noise XX (X25519) plus an
//!   ML-KEM-768 exchange and an inner hybrid AEAD layer ([`pq`]), so recorded
//!   traffic stays confidential unless both key exchanges fall (Part XIII of
//!   `docs/proofs.md`). Gossip-based peer discovery, inbound caps, flood bans.
//! - [`InMemoryNetwork`] — a synchronous, deterministic transport used to test
//!   propagation logic without sockets or an async runtime.

#![forbid(unsafe_code)]

pub mod message;
pub mod pq;
pub mod tcp;
pub mod transport;

pub use message::{
    handshake_bytes, NetMessage, NetworkError, MIN_SUPPORTED_PROTOCOL, PROTOCOL_VERSION,
};
pub use pq::PqChannel;
pub use tcp::TcpNode;
pub use transport::{InMemoryNetwork, PeerId};
