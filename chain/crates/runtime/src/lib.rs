//! # sov-runtime
//!
//! The SOV execution layer: the protocol's state transition function. Given a
//! [`Ledger`](sov_state::Ledger) and signed transactions, it authenticates and
//! authorizes each one, applies it, meters [`gas`], and emits a
//! [`Receipt`](sov_types::Receipt).
//!
//! The two entry points are [`apply_transaction`] (one transaction) and
//! [`apply_transactions`] (an ordered block body). Both enforce the protocol's
//! safety rules — valid signature, correct controlling key, correct nonce,
//! sufficient balance, conserved supply — with checked arithmetic throughout.

#![forbid(unsafe_code)]

pub mod execution;
pub mod gas;

pub use execution::{
    apply_coinbase, apply_transaction, apply_transactions, BlockContext, BlockExecutionError,
    ExecutionError,
};
pub use gas::{gas_for, INTRINSIC_GAS, SHIELDED_VERIFY_GAS};
