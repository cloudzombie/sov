//! # sov-types
//!
//! The core ledger types of the SOV protocol, built on [`sov_primitives`] and
//! [`sov_crypto`]:
//!
//! - [`Transaction`] / [`SignedTransaction`] — the unit of state change and its
//!   Ed25519 authorization, with stable, non-malleable ids.
//! - [`Block`] / [`BlockHeader`] — ordered batches of transactions, committing
//!   to their contents via Merkle roots and to resulting state via a state root.
//! - [`Receipt`] — the recorded outcome of executing a transaction, committed to
//!   via [`receipts_root`].
//!
//! These types only *describe* the ledger and check their own internal
//! consistency (signatures verify, Merkle roots match their contents). Applying
//! transactions to produce new state is the job of the execution layer in a
//! later phase. Nothing here contains sample or placeholder data.

#![forbid(unsafe_code)]

pub mod block;
pub mod receipt;
pub mod transaction;

pub use block::{compute_tx_root, Block, BlockHeader};
pub use receipt::{receipts_root, Event, ExecutionStatus, Receipt};
pub use transaction::{
    multisig_signing_bytes, rotation_signing_bytes, Action, MultisigApproval, SignedTransaction,
    Transaction, TxError,
};
