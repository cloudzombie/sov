//! # sov-state
//!
//! The authenticated world state of the SOV chain:
//!
//! - [`SparseMerkleTree`] — a standard fixed-depth Merkle tree over a 256-bit
//!   key space, with default-hash compression and inclusion/exclusion
//!   [`MerkleProof`]s.
//! - [`Account`] — the per-account state (nonce, liquid balance, staked balance).
//! - [`Ledger`] — all accounts plus their Merkle commitment, exposing a
//!   `state_root` and account proofs.
//!
//! This crate stores and commits to state. *Changing* state (validating and
//! applying transactions) is the job of the execution layer in `sov-runtime`,
//! which sits on top of [`Ledger`].

#![forbid(unsafe_code)]

pub mod account;
pub mod ledger;
pub mod smt;

pub use account::Account;
pub use ledger::{
    nft_class_id, sns_class, token_asset_id, Htlc, Ledger, Multisig, NameRecord, NftClass,
    NftToken, TokenInfo,
};
pub use smt::{MerkleProof, SparseMerkleTree, TREE_HEIGHT};
