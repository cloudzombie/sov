//! # sov-chain
//!
//! The crate that assembles SOV's pieces into a working blockchain:
//!
//! - [`GenesisConfig`] / [`Genesis`] — the trusted initial state and block 0,
//!   where the supply cap is established.
//! - [`Blockchain`] — the validated Nakamoto chain. It produces candidate
//!   blocks, imports blocks through one uncompromising validation path
//!   (re-executing transactions and checking the committed state and receipts
//!   roots), follows the heaviest-work fork, and reports confirmation-depth
//!   finality.
//!
//! This is where state ([`sov_state`]), execution ([`sov_runtime`]), the ledger
//! types ([`sov_types`]), and proof-of-work mining ([`sov_mining`]) meet. Everything it
//! reports is computed from real transactions applied to real state.

#![forbid(unsafe_code)]

pub mod blockchain;
pub mod genesis;

pub use blockchain::{
    Blockchain, ChainError, Imported, MinerStats, MiningCandidate, EDA_ACTIVATION_MS,
    FINALITY_DEPTH,
};
pub use genesis::{Genesis, GenesisAccount, GenesisConfig, GenesisError};
