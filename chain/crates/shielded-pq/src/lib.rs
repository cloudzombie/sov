//! # sov-shielded-pq — post-quantum shielded pool core (pool v2, pre-audit)
//!
//! **This crate is NOT wired into consensus, carries no `Action` variant,
//! and nothing here enters the trust path until it has an external audit
//! and parameter review** (the v0.2.0 program ships it DORMANT behind a
//! BIP-9 deployment; see `notes/v0.2.0-program.md`).
//!
//! ## What it is
//!
//! A PQ-trust-path shielded pool core with **no elliptic curves anywhere**:
//!
//! - **Hash-based note commitments** over domain-separated Rescue-Prime
//!   (`Rp64_256`), the STARK-friendly hash the proof system proves natively
//!   ([`hash`], [`note`], [`domains`]).
//! - A **fixed-depth-20 append-only commitment tree** with membership
//!   witnesses ([`tree`]).
//! - **PRF-style nullifiers** `nf = H_NF(nsk, rho)` with ownership bound in
//!   circuit via `owner_tag = H_TAG(nsk, 0)` ([`note`]).
//! - A **consensus-grade 4-in/4-out bundle STARK** (winterfell): per real
//!   input — commitment opening + Merkle membership + nullifier derivation;
//!   per real output — commitment integrity; dummy slots proven zero-valued
//!   with domain-separated dummy nullifiers; 61-bit range checks on every
//!   value; and **in-circuit value conservation with all note values
//!   PRIVATE** — only the transparent legs (`t_in`, `t_out`, `fee`) are
//!   public ([`air`], [`prover`]). No fake proofs: everything the verifier
//!   accepts is either proven in-circuit or checked natively and documented
//!   as transparent.
//! - **ML-KEM-768 + ChaCha20-Poly1305 note encryption** with a 4-byte
//!   detection tag for cheap wallet scanning (D7, [`encrypt`]) and
//!   **ML-DSA-65 carrier spend authorization** over the full public-input
//!   set (D4, [`auth`], [`bundle`]).
//!
//! ## Current limitations (stated plainly)
//!
//! - Spend authorization is a carrier ML-DSA-65 signature, not in-circuit
//!   (pinned trade-off D4; a future proof_version revisits it).
//! - Dummy-slot flags are public: the bundle's real arity (≤ 4 each side)
//!   is visible. Values, owners, and note linkages are not.
//! - The written 128-bit parameter review (S1d) is a separate, still
//!   pending slice. (Deserialization is HARDENED as of S1c: all bundle
//!   and proof decoding is total — [`wire`], [`proof_frame`],
//!   [`prover::decode_proof`] — version-gated per D6 and fuzzed; the
//!   `winterfell::Proof::from_bytes` panic paths of D15 are unreachable
//!   behind the frame pre-validator.)
//! - Proof parameters, the Rescue-Prime instance, and winterfell itself
//!   have not been externally audited for this use.
//!
//! See `chain/docs/pq-shielded-design.md` for the threat model, migration
//! plan, and production-readiness criteria.

pub mod air;
pub mod auth;
pub mod bundle;
pub mod domains;
pub mod encrypt;
pub mod hash;
pub mod note;
pub mod proof_frame;
pub mod prover;
pub mod tree;
pub mod wire;

pub use air::BundlePublicInputs;
pub use auth::AuthKeypair;
pub use bundle::{bundle_digest, verify_bundle, BundleError, SpendBundle};
pub use encrypt::{encrypt_note, EncryptionKeypair, NoteCiphertext};
pub use hash::PqDigest;
pub use note::{Note, SpendingKey, MAX_NOTE_VALUE, VALUE_BITS};
pub use proof_frame::{validate_proof_frame, ProofFrameError, MAX_PROOF_LEN};
pub use prover::{decode_proof, prove_bundle, verify_spend, BundleSpend};
pub use tree::{CommitmentTree, MerklePath};
pub use wire::{decode_bundle, encode_bundle, WireError, PROOF_VERSION_V1};
