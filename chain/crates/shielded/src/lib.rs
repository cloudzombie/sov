//! # sov-shielded
//!
//! SOV's **Zcash-grade zk-SNARK shielded pool**, built on the audited
//! [Orchard]/[Halo2] stack from the Electric Coin Company — the same protocol
//! and circuits that secure Zcash today, and with **no trusted setup** (Halo2's
//! accumulation scheme replaces the per-circuit ceremony, so there is no
//! "toxic waste" and no counterfeiting risk from a compromised setup).
//!
//! ## Model: dual pool, mint lands shielded
//!
//! SOV keeps its transparent named-account ledger for the mechanisms that need
//! visible state (staking weight, governance, the cross-chain reserve pool), and
//! adds this shielded pool alongside it. Value moves between the two pools
//! through Orchard's signed **value balance** (see [`ShieldedBundle::value_balance`]):
//!
//! - a **mint** (proof-of-work / staking issuance) and a **shield** both create
//!   shielded notes with no shielded inputs — value flows *into* the pool
//!   (negative value balance). [`mint_to_shielded`] is the mint path;
//! - a fully **shielded transfer** spends and creates notes with a zero value
//!   balance — amounts, sender, and recipient are all hidden;
//! - a **de-shield** spends a shielded note and pays a transparent account —
//!   value flows *out* of the pool (positive value balance).
//!
//! Every shielded action carries a Halo2 zero-knowledge proof, a RedPallas spend
//! authorization, and a bundle binding signature. [`ShieldedBundle::verify`]
//! checks all of them, including the binding of the public value balance. A
//! validator must also check that spent nullifiers are unseen and the anchor is
//! a commitment-tree root the chain has held. The explicit proof-only legacy
//! methods exist exclusively to reproduce historical consensus.
//!
//! ## Honest scope
//!
//! The cryptography here is real and delegated to the audited Orchard/Halo2
//! crates, with no trusted setup. **Orchard v1 is not post-quantum:** its proof
//! system and signatures rely on elliptic curves. The current v2 proof suite is
//! quarantined pending confidentiality and quantum soundness remediation.
//! Historical v1 builders sign a fixed zero digest;
//! this does not bind a transparent withdrawal to its intended recipient, even
//! when the outer SOV transaction authenticates its complete action. V1
//! withdrawals after R require the recipient-bound builder and verification
//! APIs; pre-R proof-only behavior is preserved exclusively for history.
//! Tests construct real mint and spend proofs, verify complete authorization,
//! and reject modified signatures and value balances.
//!
//! [Orchard]: https://github.com/zcash/orchard
//! [Halo2]: https://github.com/zcash/halo2

#![forbid(unsafe_code)]

mod codec;
mod keys;
mod pool;
mod state;
mod store;
mod transfer;
mod wallet;

pub use address::{
    decode_shielded, decode_shielded_v2, decode_transparent, encode_shielded, encode_shielded_v2,
    encode_transparent, shielded_v2_looks_truncated, AddressError, AnyAddress, Receiver,
    UnifiedAddress, SHIELDED_V2_ADDRESS_CHARS,
};
pub use keys::{ShieldedAddress, ShieldedKey};
pub use pool::{mint_to_shielded, ShieldedBundle, ShieldedCarrier, ShieldedParams};
pub use state::ShieldedState;
pub use store::NoteStore;
pub use transfer::{
    shielded_transfer, shielded_transfer_with_change, shielded_transfer_with_change_bound,
    unshield, unshield_amount, unshield_amount_multi, unshield_amount_multi_bound,
};
pub mod address;
pub use wallet::{recover_outputs, witness_latest, NoteWitnessTree, ReceivedNote};

/// A note-commitment tree root, against which shielded spends are proven. A
/// spend may reference any anchor the chain has held. Re-exported from Orchard.
pub use orchard::tree::Anchor;
/// A Merkle path proving a note commitment is in the tree at a given anchor.
/// Built wallet-side (see [`witness_latest`]) and consumed by
/// [`shielded_transfer`]. Re-exported from Orchard.
pub use orchard::tree::MerklePath;

/// Errors from shielded-pool operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShieldedError {
    /// Constructing the Orchard bundle failed (e.g. value out of range).
    #[error("shielded bundle construction failed: {0}")]
    Build(String),
    /// Generating the Halo2 zero-knowledge proof failed.
    #[error("shielded proof generation failed: {0}")]
    Prove(String),
    /// No shielded actions were present to build a bundle from.
    #[error("no shielded actions to build")]
    EmptyBundle,
    /// A note commitment could not be appended because the tree is full.
    #[error("note-commitment tree is full")]
    TreeFull,
    /// A nullifier was already spent — a double-spend.
    #[error("nullifier already spent (double-spend)")]
    DoubleSpend,
    /// A serialized shielded bundle was malformed (truncated, invalid component,
    /// or trailing bytes).
    #[error("malformed shielded bundle encoding: {0}")]
    Decode(String),
}
