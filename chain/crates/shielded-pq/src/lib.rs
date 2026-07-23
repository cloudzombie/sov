//! # sov-shielded-pq — PROTOTYPE post-quantum shielded pool core
//!
//! **This crate is a prototype. It is NOT wired into consensus, carries no
//! `Action` variant, and nothing here enters the trust path until it has an
//! external audit and parameter review.** It exists to move SOV's quantum
//! posture (see `chain/docs/quantum-posture.md`) on the shielded pool from
//! "disclosed gap" to "prototype in tree".
//!
//! ## What it is
//!
//! A working PQ-trust-path shielded pool core with **no elliptic curves
//! anywhere**:
//!
//! - **Hash-based note commitments** over Rescue-Prime (`Rp64_256`), the
//!   STARK-friendly hash the proof system proves natively ([`hash`],
//!   [`note`]).
//! - A **fixed-depth-20 append-only commitment tree** with membership
//!   witnesses, mirroring the Orchard-side `NoteWitnessTree` API ([`tree`]).
//! - **PRF-style nullifiers** `nf = H(nsk, rho)` with ownership bound in
//!   circuit via `owner_tag = H(nsk, 0)` ([`note`]).
//! - A **real STARK spend circuit** (winterfell): commitment opening +
//!   Merkle membership + nullifier derivation proven in one AIR ([`air`],
//!   [`prover`]). No fake proofs: everything the verifier accepts is either
//!   proven in-circuit or checked natively and documented as transparent.
//! - **ML-KEM-768 + ChaCha20-Poly1305 note encryption** ([`encrypt`]) and
//!   **ML-DSA-65 carrier spend authorization** ([`auth`]) — the same FIPS
//!   203/204 crates the transparent layer already ships.
//! - **Bundles** tying it together with native value-conservation checks
//!   ([`bundle`]).
//!
//! ## Prototype limitations (stated plainly)
//!
//! - Spent values are PUBLIC inputs and output notes are carried with their
//!   openings: value conservation is checked transparently, not proven in
//!   zero knowledge. Amount privacy is NOT provided by this increment.
//! - Spend authorization is a carrier ML-DSA-65 signature, not in-circuit.
//! - The commitment/nullifier/tree hash has no per-use domain separation
//!   beyond structure; production would add explicit domain tags.
//! - Proof parameters, the Rescue-Prime instance, and winterfell itself have
//!   not been externally audited for this use.
//!
//! See `chain/docs/pq-shielded-design.md` for the threat model, migration
//! plan, and production-readiness criteria.

pub mod air;
pub mod auth;
pub mod bundle;
pub mod encrypt;
pub mod hash;
pub mod note;
pub mod prover;
pub mod tree;

pub use air::SpendPublicInputs;
pub use auth::AuthKeypair;
pub use bundle::{verify_bundle, SpendBundle, SpendDescription};
pub use encrypt::{encrypt_note, EncryptionKeypair, NoteCiphertext};
pub use hash::PqDigest;
pub use note::{Note, SpendingKey};
pub use prover::{prove_spend, verify_spend};
pub use tree::{CommitmentTree, MerklePath};
