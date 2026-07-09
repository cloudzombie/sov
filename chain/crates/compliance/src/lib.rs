//! # sov-compliance
//!
//! Multi-signature custody and institutional compliance tooling for SOV.
//!
//! - [`multisig`] — M-of-N multi-signature authorization. A [`MultisigPolicy`]
//!   names `N` signer keys and a threshold `M`; a [`Proposal`] is authorized once
//!   `M` distinct authorized signers produce a valid [`MultisigApproval`] (an
//!   Ed25519 signature over the proposal), with replay-resistant nonces and an
//!   expiry. The same independently-verifiable, attributable approval model the
//!   chain already uses for finality votes.
//! - [`controls`] — institutional controls an account attaches to itself or has
//!   imposed on it: a regulator [`freeze`](controls::CompliancePolicy), allow- or
//!   deny-list [counterparty control](controls::TransferControl), and a rolling
//!   [spend-velocity limit](controls::SpendLimit). [`CompliancePolicy::check_transfer`]
//!   is a pure decision function returning either a specific
//!   [`ComplianceError`] or the updated spend window.
//!
//! These are authorization/policy primitives: they decide *whether* value may
//! move. Enforcing them inside the runtime's transfer path — and storing each
//! account's policy in the ledger — is the integration follow-on, the same
//! boundary as the account-abstraction layer (`p5-i0`). Together they cover the
//! "multi-sig & institutional compliance" item (`p5-i1`).

#![forbid(unsafe_code)]

pub mod controls;
pub mod multisig;

pub use controls::{ComplianceError, CompliancePolicy, SpendLimit, SpendWindow, TransferControl};
pub use multisig::{MultisigApproval, MultisigError, MultisigPolicy, Proposal};
