//! # sov-pow
//!
//! SOV's proof-of-work primitives. **Proof of work IS SOV's consensus**
//! (Nakamoto, Bitcoin's model verbatim): [`sha256d`] — Bitcoin's double-SHA-256
//! — seals every block header, the heaviest-work chain wins, and the block
//! coinbase is the only issuance path. There is one algorithm (SHA-256d) and no
//! proof-of-stake of any kind.
//!
//! A 256-bit [`Target`] is the difficulty threshold a header's `sha256d` must
//! not exceed, carried in the header as Bitcoin's compact `nBits`
//! ([`Target::to_compact`]). The emission schedule and difficulty/work
//! accounting live in `sov-mining`; the header grind and fork choice live in
//! `sov-chain`.

#![forbid(unsafe_code)]

pub mod algorithm;
pub mod seal;
pub mod target;

pub use algorithm::sha256d;
pub use seal::{pow_seal, pow_seal_mining, PowAlgo};
pub use target::{mine, pow_hash, verify, Target};
