//! # sov-primitives
//!
//! The foundational value types of the SOV protocol — the vocabulary every
//! other crate is built from. These types are deliberately small, total, and
//! self-validating:
//!
//! - [`Hash`](struct@Hash) — a 32-byte Blake3 digest identifying blocks, transactions, and
//!   state roots.
//! - [`AccountId`] — a validated human-readable account identifier.
//! - [`Balance`] — an exact, checked token amount in grains, aware of the
//!   protocol [`MAX_SUPPLY_GRAINS`] cap.
//! - [`BlockHeight`] — a block's monotonic position in the chain.
//!
//! Two serialization formats are supported on every type:
//! - **Borsh** — the canonical, deterministic binary encoding used for hashing,
//!   signing, and consensus. The same value always encodes to the same bytes.
//! - **Serde/JSON** — the human-readable encoding used by the RPC layer that the
//!   block explorer consumes.
//!
//! There is no `unsafe` code in this crate, and there is no placeholder or
//! sample data: every value is either supplied by a caller or derived from one.

#![forbid(unsafe_code)]

pub mod account;
pub mod amount;
pub mod hash;
pub mod height;
pub mod signing_domain;

pub use account::{AccountId, AccountIdError};
pub use amount::{
    Balance, BalanceError, DECIMALS, GRAINS_PER_SOV, MAX_SUPPLY_GRAINS, MAX_SUPPLY_SOV,
};
pub use hash::{Hash, HashParseError};
pub use height::BlockHeight;
pub use signing_domain::SigningDomain;
