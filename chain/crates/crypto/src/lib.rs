//! # sov-crypto
//!
//! Authentication primitives for the SOV protocol, layered on
//! [`sov_primitives`]:
//!
//! - [`Keypair`] / [`PublicKey`] / [`Signature`] — Ed25519 signing and
//!   verification. Ed25519 gives small, fast, deterministic signatures suited
//!   to a high-throughput chain.
//! - [`rng`] — the startup-health-checked entropy chokepoint
//!   ([`fill_secure`]): all key/seed generation draws OS entropy through a
//!   NIST SP 800-90B-style startup self-test that FAILS CLOSED (and stays
//!   failed) on a degraded source.
//! - [`merkle_root`] — a domain-separated binary Merkle root over
//!   [`sov_primitives::Hash`] leaves, used to commit to a block's transactions
//!   and receipts — plus [`merkle_proof`] / [`verify_merkle_proof`], the
//!   inclusion proof that lets a verifier holding ONLY the root check a single
//!   leaf without trusting whoever served it.
//!
//! Following best practice, this crate does not implement any cryptographic
//! algorithm itself: signing delegates to the audited `ed25519-dalek`, and
//! hashing delegates to Blake3 via [`sov_primitives::Hash`]. There is no
//! `unsafe` code and no sample/placeholder material.

#![forbid(unsafe_code)]

pub mod keys;
pub mod merkle;
pub mod rng;
pub mod signature;

pub use keys::{KeyError, Keypair, PublicKey, ML_DSA_65_PK_LEN};
pub use merkle::{merkle_proof, merkle_root, verify_merkle_proof, MerkleStep};
pub use rng::{fill_secure, health_check, EntropyError, HealthFailure};
pub use signature::{Signature, ML_DSA_65_SIG_LEN};
