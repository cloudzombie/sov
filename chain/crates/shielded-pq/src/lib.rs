//! # sov-shielded-pq — post-quantum shielded pool core (pool v2, pre-audit)
//!
//! Pool v2 has been armed on mainnet since v0.2.5 and can hold existing notes
//! and supply. Its historical proof suite remains available for deterministic
//! replay. New production writes are quarantined because that suite does not
//! hide its witness and its proof is not bound to the carrier's payout context.
//! The opt-in `zk-suite2` feature implements a versioned hiding replacement;
//! its separate bit-5 schedule is currently limited to isolated rehearsals.
//!
//! ## What it is
//!
//! A PQ-trust-path shielded pool core with **no elliptic curves anywhere**:
//!
//! - **Hash-based note commitments** over domain-separated Rescue-Prime
//!   (`Rp64_256`), the STARK-friendly hash the proof system proves natively
//!   ([`hash`], [`note`], [`domains`]).
//! - A **fixed-depth-32 append-only commitment tree** with membership
//!   witnesses ([`tree`]).
//! - **Position-bound nullifiers** with ownership bound in
//!   circuit via `owner_tag = H_TAG(nsk, 0)` ([`note`]).
//! - A **consensus-grade 4-in/4-out bundle STARK** (winterfell): per real
//!   input — commitment opening + Merkle membership + nullifier derivation;
//!   per real output — commitment integrity; dummy slots proven zero-valued
//!   with domain-separated dummy nullifiers; 61-bit range checks on every
//!   value; and **in-circuit value conservation with all note values
//!   witness registers** — only the transparent legs (`t_in`, `t_out`, `fee`) are
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
//! - Dummy-slot flags reveal real arity (≤ 4 each side). The historical
//!   unmasked suite does not establish privacy for values, owners or linkages.
//!   New masking cannot revoke spending keys already exposed by old proofs.
//! - The written 128-bit parameter review (S1d) is a separate, still
//!   pending slice. The 128 figure is a *classical* FRI soundness bound
//!   (proven Johnson/list-decoding radius); post-quantum (QROM) soundness of
//!   the Fiat-Shamir-transformed proof is a distinct, still-pending analysis
//!   and must not be quoted as "128-bit post-quantum" (PQV2-05; see
//!   `prover::proof_options` and `notes/audit-scope-pq-pool.md` §9).
//!   (Deserialization is HARDENED as of S1c: all bundle
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
pub mod carrier;
pub mod domains;
pub mod encrypt;
pub mod hash;
pub mod hd;
pub mod note;
pub mod proof_frame;
pub mod prover;
pub mod scan;
pub mod state;
pub mod tree;
pub mod wallet;
pub mod wire;
#[cfg(feature = "zk-suite2")]
mod zk_seed;
/// Opt-in replacement proof candidate; independent of the historical verifier.
#[cfg(feature = "zk-suite2")]
pub mod zk_suite2;
#[cfg(feature = "zk-suite2")]
mod zk_suite2_decode;

pub use air::BundlePublicInputs;
pub use auth::AuthKeypair;
pub use bundle::{bundle_digest, check_structure, verify_bundle, BundleError, SpendBundle};
pub use carrier::{
    carrier_sighash, verify_carrier_auth, CarrierContext, SCHEME_DOMAIN_SIGNER_NONCE,
};
pub use encrypt::{encrypt_note, EncryptionKeypair, NoteCiphertext};
pub use hash::PqDigest;
pub use hd::{pq_hd_path, PqAddress, PqShieldedKey, PQ_ADDRESS_LEN, PQ_HD_PATH_TEMPLATE};
pub use note::{Note, SpendingKey, MAX_NOTE_VALUE, VALUE_BITS};
pub use proof_frame::{validate_proof_frame, ProofFrameError, MAX_PROOF_LEN};
pub use prover::{decode_proof, prove_bundle, verify_spend, BundleSpend};
pub use scan::{PqNoteStore, ScanStats, REORG_HORIZON};
pub use state::{ShieldedV2State, ShieldedV2StateError, ANCHOR_RING_LEN, MAX_V2_NOTES};
pub use tree::{CommitmentTree, MerklePath};
pub use wire::{decode_bundle, encode_bundle, WireError, PROOF_VERSION_V1};
