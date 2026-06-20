//! # sov-reserve
//!
//! Sovereign **reserve-modeling** tooling for SOV: deterministic decision-support
//! projections built from the real protocol mechanics under explicit, labeled
//! assumptions. This crate is *not* a data feed, an oracle, or a price source. It
//! is a calculator: given the chain's real policies and (when available) real
//! chain/pool state, plus a scenario the caller spells out, it computes what
//! follows.
//!
//! ## The real-vs-assumed contract
//!
//! Every figure this crate produces has exactly one of three origins, and the
//! origin travels with the figure (see [`Sourced`] / [`Source`]):
//!
//! - **Protocol fact** ([`Source::Protocol`]) — a fixed protocol constant or the
//!   deterministic output of the real protocol policies. The supply cap and the
//!   mining emission schedule are protocol facts. These come from the real
//!   [`sov_primitives`] and [`sov_mining`] types — never hand-copied numbers.
//! - **Chain-state reading** ([`Source::ChainState`]) — a value read from live
//!   chain state, such as the mined supply at a height.
//! - **Assumption** ([`Source::Assumption`]) — a scenario input the caller
//!   supplies: a holder-dormancy rate or named holders. Every assumption is
//!   labeled as such in the types and in the output.
//!
//! The crate **never embeds invented real-world facts** — no made-up prices,
//! holders, nations, adoption rates, or dates. Where a needed figure is neither a
//! protocol fact nor a chain reading nor a stated assumption (e.g. a reserve
//! asset with no oracle price and no assumed price), the result is reported as
//! *unknown* ([`None`]), never as zero pretending to be real. The empty scenario,
//! [`Assumptions::neutral`], asserts nothing about the world: a projection over it
//! reduces to pure protocol mechanics.
//!
//! ## The provenance mechanism
//!
//! Honesty here is enforced by *types*, not discipline. [`Sourced<T>`] pairs every
//! reported value with its [`Source`], so a consumer can never mistake an
//! assumption for a fact — the distinction is in the data. There is deliberately
//! no "default" or "estimated" source for invented data to hide in.
//!
//! ## What it models
//!
//! - [`ProtocolConstants`] — the fixed facts, derived from the real types.
//! - [`EmissionProjection`] — cumulative mined emission (real; proof-of-work is
//!   the only source) over a height range, monotonic and cap-bounded.
//! - [`Assumptions`] — the explicit, labeled scenario.
//! - [`FloatModel`] — circulating float (`emitted − locked`) and scarcity metrics.
//!
//! All of it is deterministic: no wall-clock, no randomness, integer math for
//! value (basis points for ratios), and [`BTreeMap`](std::collections::BTreeMap)
//! ordering throughout. The same inputs always yield the identical projection.

#![forbid(unsafe_code)]

pub mod assumptions;
pub mod constants;
pub mod emission;
pub mod error;
pub mod float;
pub mod provenance;

pub use assumptions::{Assumptions, SovereignHolder, BPS_DENOMINATOR};
pub use constants::ProtocolConstants;
pub use emission::{mined_supply_after, EmissionPoint, EmissionProjection, HeightRange};
pub use error::ReserveError;
pub use float::{float_at, locked_supply_at, FloatPoint, LockedSupply};
pub use provenance::{Source, Sourced};

use sov_mining::MiningPolicy;

/// The float model over a height range: a float point per sampled height.
///
/// Pairs the real emission curve with the assumed lock schedule to show how the
/// circulating float evolves under a scenario. Built by [`FloatModel::compute`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloatModel {
    /// The range that was sampled (mirrors the emission range).
    pub range: HeightRange,
    /// The float point at each sampled height, in ascending height order.
    pub points: Vec<FloatPoint>,
}

impl FloatModel {
    /// Compute the float model over `range` from the real `mining` policy and the
    /// caller's `assumptions`.
    ///
    /// Mined (emitted) supply at each height is a protocol fact; the locked
    /// portion is derived from the assumptions; the float is their difference.
    /// Returns an error if the assumptions are invalid or self-contradictory
    /// (e.g. locking more than has been emitted).
    pub fn compute(
        mining: &MiningPolicy,
        assumptions: &Assumptions,
        range: HeightRange,
    ) -> Result<Self, ReserveError> {
        assumptions.validate()?;
        let mut points = Vec::new();
        for height in range.heights() {
            let emitted = mined_supply_after(mining, height.get());
            points.push(float_at(assumptions, emitted, height)?);
        }
        Ok(FloatModel { range, points })
    }

    /// The final (highest-height) float point, if any.
    pub fn last(&self) -> Option<&FloatPoint> {
        self.points.last()
    }
}

/// A complete reserve-modeling report: the protocol constants it rests on, the
/// emission projection, and the float model — every figure carrying its
/// [`Source`].
///
/// This is the top-level decision-support artifact: hand it the chain's real
/// policies, an explicit scenario, and a height range, and it assembles the full
/// picture with provenance intact. (There is no cross-chain reserve pool —
/// consensus is pure proof-of-work; SOV's reserve is its own mined supply.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveReport {
    /// The fixed protocol facts (all [`Source::Protocol`]).
    pub constants: ProtocolConstants,
    /// The scenario these projections were computed under (all assumptions).
    pub assumptions: Assumptions,
    /// Cumulative mined emission over the range (proof-of-work is the only source).
    pub emission: EmissionProjection,
    /// Circulating float and scarcity over the range.
    pub float: FloatModel,
}

impl ReserveReport {
    /// Assemble a full report from real policies and an explicit scenario.
    ///
    /// The constants are derived from the supplied policies; the emission and
    /// float are projected over `range` under `assumptions`.
    pub fn build(
        mining: MiningPolicy,
        assumptions: Assumptions,
        range: HeightRange,
    ) -> Result<Self, ReserveError> {
        assumptions.validate()?;
        let constants = ProtocolConstants::from_policies(mining.clone());
        let emission = EmissionProjection::compute(&mining, range)?;
        let float = FloatModel::compute(&mining, &assumptions, range)?;
        Ok(ReserveReport {
            constants,
            assumptions,
            emission,
            float,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_primitives::{Balance, BlockHeight, MAX_SUPPLY_GRAINS};

    fn range() -> HeightRange {
        HeightRange::new(BlockHeight::GENESIS, BlockHeight::new(1_000_000), 200_000).unwrap()
    }

    #[test]
    fn base_projection_zero_assumptions_is_pure_protocol() {
        // The base projection (no assumptions) must reproduce protocol mechanics:
        // float == emitted, all cap-bounded.
        let mining = MiningPolicy::mainnet_like();
        let report = ReserveReport::build(mining, Assumptions::neutral(), range()).unwrap();

        let mut prev = Balance::ZERO;
        for (e, f) in report.emission.points.iter().zip(&report.float.points) {
            assert_eq!(e.mined.source, Source::Protocol); // pure protocol
            assert!(e.mined.value.within_cap());
            assert!(e.mined.value >= prev); // monotonic
            prev = e.mined.value;
            // Float view agrees with emission view.
            assert_eq!(f.emitted.value, e.mined.value);
            assert_eq!(f.float.value, e.mined.value); // nothing locked
            assert_eq!(f.locked.total.value, Balance::ZERO);
        }
    }

    #[test]
    fn long_run_total_never_exceeds_cap() {
        // Compute the asymptote from the real policy (exhaust emission), do not
        // hardcode an invented expected total.
        let mining = MiningPolicy::mainnet_like();
        let converged = mined_supply_after(&mining, u64::MAX);
        assert!(converged.within_cap());
        assert!(converged.grains() <= MAX_SUPPLY_GRAINS);
    }

    #[test]
    fn report_with_assumptions_tags_everything_correctly() {
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 4_000; // 40% held dormant
        a.sovereign_holders.push(SovereignHolder {
            label: "sovereign-A".to_string(),
            locked_bps: 1_000, // an extra 10% locked by a named holder
            lock_until: BlockHeight::new(800_000),
        });

        let report = ReserveReport::build(MiningPolicy::mainnet_like(), a, range()).unwrap();

        // Constants are protocol facts.
        assert_eq!(report.constants.max_supply_grains, MAX_SUPPLY_GRAINS);

        // Emission: mined is protocol — the only emission source.
        for p in &report.emission.points {
            assert_eq!(p.mined.source, Source::Protocol);
        }

        // Float: emitted protocol, locked/float assumption.
        for p in &report.float.points {
            assert_eq!(p.emitted.source, Source::Protocol);
            assert_eq!(p.float.source, Source::Assumption);
            assert_eq!(p.locked.total.source, Source::Assumption);
            // Locked never exceeds emitted.
            assert!(p.locked.total.value <= p.emitted.value);
        }
    }

    #[test]
    fn determinism_full_report() {
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 2_500;
        let build =
            || ReserveReport::build(MiningPolicy::mainnet_like(), a.clone(), range()).unwrap();
        assert_eq!(build(), build());
    }

    #[test]
    fn contradictory_assumptions_rejected_in_full_build() {
        // Lock more than 100% across dormancy + a named holder over the range.
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 7_000;
        a.sovereign_holders.push(SovereignHolder {
            label: "A".to_string(),
            locked_bps: 7_000,
            lock_until: BlockHeight::new(u64::MAX),
        });
        let err = ReserveReport::build(
            MiningPolicy::mainnet_like(),
            a,
            // A range past genesis so emission is non-zero and the lock bites.
            HeightRange::new(
                BlockHeight::new(100_000),
                BlockHeight::new(200_000),
                100_000,
            )
            .unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, ReserveError::LockedExceedsSupply { .. }));
    }
}
