//! Provenance: the crate's central honesty mechanism.
//!
//! Every figure this crate reports is wrapped in a [`Sourced`] value that records
//! *where the figure came from* via a [`Source`] tag. A consumer therefore can
//! never mistake a caller's assumption for a protocol fact or a real chain-state
//! reading — the distinction is carried in the type, not left to documentation or
//! convention.
//!
//! The three sources are deliberately exhaustive and ordered by trust:
//!
//! - [`Source::Protocol`] — fixed protocol constants and the deterministic output
//!   of the real protocol policies (the supply cap, the mining emission schedule).
//!   These are facts about SOV itself.
//! - [`Source::ChainState`] — a value read from live chain or pool state (a pooled
//!   reserve balance, a consensus oracle price). A fact about the running chain at
//!   the moment it was read.
//! - [`Source::Assumption`] — a caller-supplied scenario input (a participation
//!   rate, an assumed price used where no oracle exists). Explicitly *not* a fact;
//!   it is what the caller chose to model.
//!
//! There is intentionally no fourth "default" or "estimated" source: a figure is
//! a protocol fact, a chain reading, or a stated assumption, with nothing in
//! between for invented data to hide in.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Where a reported figure came from.
///
/// See the [module docs](self) for the trust ordering and the rationale for the
/// set being exactly these three.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A fixed protocol constant or the deterministic output of a real protocol
    /// policy. A fact about the SOV protocol.
    Protocol,
    /// A value read from live chain or pool state. A fact about the running chain.
    ChainState,
    /// A caller-supplied scenario input. Explicitly an assumption, not a fact.
    Assumption,
}

impl Source {
    /// Whether the figure is a fact (protocol or chain state) rather than a
    /// caller assumption. Useful for a consumer that wants to flag or exclude
    /// everything that is *not* grounded in reality.
    pub const fn is_fact(self) -> bool {
        matches!(self, Source::Protocol | Source::ChainState)
    }

    /// A short, stable, human-readable label for the source.
    pub const fn label(self) -> &'static str {
        match self {
            Source::Protocol => "protocol",
            Source::ChainState => "chain-state",
            Source::Assumption => "assumption",
        }
    }
}

/// A reported figure tagged with its [`Source`].
///
/// This is the unit of every report in this crate. The value travels with its
/// provenance so the distinction between *what the protocol guarantees*, *what
/// the chain currently shows*, and *what the caller assumed* is never lost.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Sourced<T> {
    /// The figure itself.
    pub value: T,
    /// Where the figure came from.
    pub source: Source,
}

impl<T> Sourced<T> {
    /// Tag `value` as a protocol fact.
    pub const fn protocol(value: T) -> Self {
        Sourced {
            value,
            source: Source::Protocol,
        }
    }

    /// Tag `value` as a live chain/pool-state reading.
    pub const fn chain_state(value: T) -> Self {
        Sourced {
            value,
            source: Source::ChainState,
        }
    }

    /// Tag `value` as a caller-supplied assumption.
    pub const fn assumption(value: T) -> Self {
        Sourced {
            value,
            source: Source::Assumption,
        }
    }

    /// Whether this figure is a fact rather than an assumption (see
    /// [`Source::is_fact`]).
    pub const fn is_fact(&self) -> bool {
        self.source.is_fact()
    }

    /// Map the inner value while preserving the source tag. The provenance is
    /// invariant under transformation: deriving a figure from a fact keeps it a
    /// fact; deriving from an assumption keeps it an assumption.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Sourced<U> {
        Sourced {
            value: f(self.value),
            source: self.source,
        }
    }

    /// Borrow the inner value together with its (copied) source tag.
    pub fn as_ref(&self) -> Sourced<&T> {
        Sourced {
            value: &self.value,
            source: self.source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fact_vs_assumption() {
        assert!(Source::Protocol.is_fact());
        assert!(Source::ChainState.is_fact());
        assert!(!Source::Assumption.is_fact());
        assert!(Sourced::protocol(1u32).is_fact());
        assert!(Sourced::chain_state(1u32).is_fact());
        assert!(!Sourced::assumption(1u32).is_fact());
    }

    #[test]
    fn map_preserves_source() {
        let a = Sourced::assumption(10u64).map(|v| v * 2);
        assert_eq!(a, Sourced::assumption(20u64));
        let p = Sourced::protocol(3u64).map(|v| v + 1);
        assert_eq!(p.source, Source::Protocol);
        assert_eq!(p.value, 4);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(Source::Protocol.label(), "protocol");
        assert_eq!(Source::ChainState.label(), "chain-state");
        assert_eq!(Source::Assumption.label(), "assumption");
    }
}
