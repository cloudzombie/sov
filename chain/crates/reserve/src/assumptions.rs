//! Assumptions: the explicit, caller-supplied scenario.
//!
//! Everything in this module is an *assumption*, never a fact. These are the
//! knobs a modeler turns to ask "what if": how much of the supply is locked, for
//! how long, which holders lock what, and — only where the chain has no oracle
//! price — what price to assume for a reserve asset.
//!
//! The contract this crate enforces:
//!
//! - Every field is documented as a caller assumption.
//! - [`Assumptions::neutral`] is the *empty* scenario: zero participation, no
//!   holders, no assumed prices. It models *nothing*, so it can never be mistaken
//!   for "the default real-world state". Running the model on it reproduces pure
//!   protocol mechanics (see the crate-level base-projection contract).
//! - There are no built-in non-zero defaults anywhere, because any non-zero
//!   default would be invented data dressed up as a starting point.
//!
//! Basis points (`bps`) are integer hundredths of a percent: `10_000` bps =
//! 100%. Using integer bps keeps every fraction exact, with no floating point.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::BlockHeight;

use crate::error::ReserveError;

/// One basis point denominator: `10_000` bps = 100%.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// A modeled holder that keeps part of the supply off-market until some height.
///
/// This is entirely an assumption: the `label`, the locked fraction, and the
/// unlock height are all chosen by the caller to describe a scenario. The crate
/// attaches no real-world identity, balance, or schedule to it — a holder named
/// `"sovereign-A"` is a placeholder label for a hypothetical, nothing more.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SovereignHolder {
    /// A caller-chosen label for the modeled holder (e.g. `"sovereign-A"`). Has
    /// no protocol meaning; purely for reading the resulting report.
    pub label: String,
    /// **Assumption:** the fraction of total supply this holder keeps locked,
    /// in basis points of total supply (`10_000` = 100%).
    pub locked_bps: u32,
    /// **Assumption:** the height until which this holder's allocation stays
    /// off-market.
    pub lock_until: BlockHeight,
}

impl SovereignHolder {
    /// Validate the holder's assumed fraction is within `0..=10_000` bps.
    pub fn validate(&self) -> Result<(), ReserveError> {
        if self.locked_bps > BPS_DENOMINATOR {
            return Err(ReserveError::BpsOutOfRange {
                got: self.locked_bps,
                context: "SovereignHolder.locked_bps",
            });
        }
        Ok(())
    }
}

/// The complete, explicit scenario a caller supplies to drive a projection.
///
/// Every field is an assumption (see the [module docs](self)). Build the empty
/// scenario with [`Assumptions::neutral`] and set only the knobs you mean to
/// model; an unset knob contributes nothing rather than some invented baseline.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Assumptions {
    /// **Assumption:** the fraction of the *circulating* supply held dormant by
    /// long-term holders in aggregate, in basis points (`10_000` = 100%) — the
    /// SOV analog of Bitcoin HODL behavior. Purely a holder-behavior scenario
    /// knob (there is no protocol staking and no yield); it drives how much
    /// emitted supply is treated as off-market beyond what named holders cover.
    pub dormant_holdings_bps: u32,

    /// **Assumption:** named holders that lock specified fractions until set
    /// heights. Empty by default — the model invents no holders.
    pub sovereign_holders: Vec<SovereignHolder>,
}

impl Assumptions {
    /// The empty scenario: zero participation, zero lock, no holders, no assumed
    /// prices. It deliberately models *nothing*, so a base projection over it
    /// reproduces pure protocol mechanics. This is the only built-in
    /// [`Assumptions`] value, and it asserts nothing about the real world.
    pub fn neutral() -> Self {
        Assumptions {
            dormant_holdings_bps: 0,
            sovereign_holders: Vec::new(),
        }
    }

    /// Validate that every basis-points fraction is within `0..=10_000`.
    ///
    /// Out-of-range fractions are a caller error (claiming more than 100%), so
    /// they are rejected rather than silently clamped.
    pub fn validate(&self) -> Result<(), ReserveError> {
        if self.dormant_holdings_bps > BPS_DENOMINATOR {
            return Err(ReserveError::BpsOutOfRange {
                got: self.dormant_holdings_bps,
                context: "Assumptions.dormant_holdings_bps",
            });
        }
        for holder in &self.sovereign_holders {
            holder.validate()?;
        }
        Ok(())
    }

    /// The sum of all named holders' locked fractions, in basis points.
    ///
    /// May exceed `10_000` if the caller's holders collectively claim more than
    /// 100%; the consuming model treats that as a contradiction (it cannot lock
    /// more than exists) and surfaces an error rather than absorbing it.
    pub fn named_locked_bps(&self) -> u64 {
        self.sovereign_holders
            .iter()
            .map(|h| u64::from(h.locked_bps))
            .sum()
    }
}

impl Default for Assumptions {
    /// The default is the [neutral](Assumptions::neutral) (empty) scenario — it
    /// models nothing, by design.
    fn default() -> Self {
        Assumptions::neutral()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_is_empty() {
        let a = Assumptions::neutral();
        assert_eq!(a.dormant_holdings_bps, 0);
        assert!(a.sovereign_holders.is_empty());
        assert_eq!(a, Assumptions::default());
        a.validate().unwrap();
    }

    #[test]
    fn rejects_over_100_percent_participation() {
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 10_001;
        assert_eq!(
            a.validate(),
            Err(ReserveError::BpsOutOfRange {
                got: 10_001,
                context: "Assumptions.dormant_holdings_bps",
            })
        );
    }

    #[test]
    fn rejects_over_100_percent_holder() {
        let mut a = Assumptions::neutral();
        a.sovereign_holders.push(SovereignHolder {
            label: "sovereign-A".to_string(),
            locked_bps: 20_000,
            lock_until: BlockHeight::new(1_000),
        });
        assert!(matches!(
            a.validate(),
            Err(ReserveError::BpsOutOfRange { got: 20_000, .. })
        ));
    }

    #[test]
    fn named_locked_sums_fractions() {
        let mut a = Assumptions::neutral();
        a.sovereign_holders.push(SovereignHolder {
            label: "A".to_string(),
            locked_bps: 1_000,
            lock_until: BlockHeight::new(10),
        });
        a.sovereign_holders.push(SovereignHolder {
            label: "B".to_string(),
            locked_bps: 2_500,
            lock_until: BlockHeight::new(20),
        });
        assert_eq!(a.named_locked_bps(), 3_500);
    }
}
