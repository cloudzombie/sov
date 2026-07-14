//! # sov-verify
//!
//! Verification & validity assurance for SOV (Phase 7). A reserve asset for
//! nations cannot have "probably correct" rules, so this crate states the
//! protocol's invariants as **exact integer mathematics** and re-checks them
//! against real chain state — independently of the code that produced that state.
//!
//! - [`check_ledger`] — the invariants that hold for any single ledger state:
//!   total supply within the cap, and each emission source within its budget.
//! - [`check_transition`] — the invariant relating a `before -> after` pair (e.g.
//!   importing one block): every grain of new supply is accounted for by the
//!   mining and staking emission counters, so value is conserved and there is no
//!   unauthorized mint.
//!
//! Everything here is `u128`-grain arithmetic — no floating point, no
//! approximation. Deterministic replay and cross-node state-root agreement
//! (Phase 7 p7-i4) build on these same checks over real block production.

#![forbid(unsafe_code)]

pub mod invariants;

pub use invariants::{
    check_ledger, check_transition, check_transition_pre, InvariantViolation, TransitionPre,
};
