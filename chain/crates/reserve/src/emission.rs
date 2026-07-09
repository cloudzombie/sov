//! Emission projection from the real protocol policy.
//!
//! [`EmissionProjection`] turns the chain's real [`MiningPolicy`] into a
//! cumulative-emission curve over a caller-chosen height range. **Proof-of-work
//! mining is SOV's only emission source** (no staking, exactly as in Bitcoin):
//!
//! - **Mined supply** is a pure function of the [`MiningPolicy`] and the block
//!   count: at every block exactly one coinbase mints
//!   `MiningPolicy::reward_at``(current_supply)`, which advances the supply. This
//!   is protocol mechanics — provenance `Source::Protocol`. It is computed by
//!   walking halving epochs (within which the reward is constant), which
//!   reproduces block-by-block iteration of the real `reward` exactly while
//!   staying efficient over large ranges.
//!
//! The curve is monotonic non-decreasing in height and clamped so it can never
//! exceed [`MAX_SUPPLY_GRAINS`] — the same hard cap the protocol enforces.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_mining::MiningPolicy;
use sov_primitives::{Balance, BlockHeight, MAX_SUPPLY_GRAINS};

use crate::error::ReserveError;
use crate::provenance::Sourced;

/// An inclusive height range walked in fixed steps.
///
/// `start..=end`, advancing by `step` blocks per sample (the final sample is
/// always exactly `end`, even when the span is not a whole multiple of `step`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct HeightRange {
    /// First height sampled.
    pub start: BlockHeight,
    /// Last height sampled (inclusive).
    pub end: BlockHeight,
    /// Blocks between successive samples; must be non-zero.
    pub step: u64,
}

impl HeightRange {
    /// Build a range, rejecting an inverted span (`end < start`) or a zero step.
    pub fn new(start: BlockHeight, end: BlockHeight, step: u64) -> Result<Self, ReserveError> {
        if end.get() < start.get() {
            return Err(ReserveError::InvalidRange {
                start: start.get(),
                end: end.get(),
            });
        }
        if step == 0 {
            return Err(ReserveError::ZeroStep);
        }
        Ok(HeightRange { start, end, step })
    }

    /// The sampled heights: `start`, `start + step`, …, capped so the last entry
    /// is exactly `end`. Deterministic and finite.
    pub fn heights(&self) -> Vec<BlockHeight> {
        let mut out = Vec::new();
        let mut h = self.start.get();
        loop {
            out.push(BlockHeight::new(h));
            if h >= self.end.get() {
                break;
            }
            h = h.saturating_add(self.step).min(self.end.get());
        }
        out
    }
}

/// One sampled point on the emission curve. `mined` is a protocol fact —
/// proof-of-work is the only emission source, so it IS the total emission.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct EmissionPoint {
    /// The height this point describes.
    pub height: BlockHeight,
    /// Cumulative **mined** supply at `height` — protocol mechanics
    /// (`Source::Protocol`(crate::Source::Protocol)), and the total emission
    /// (mining is the only source). Cap-bounded by construction.
    pub mined: Sourced<Balance>,
}

/// A cumulative-emission projection over a height range.
///
/// Built by [`EmissionProjection::compute`]. The points are ordered by height,
/// monotonic non-decreasing in every cumulative field, and cap-bounded.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EmissionProjection {
    /// The range that was sampled.
    pub range: HeightRange,
    /// The sampled points, in ascending height order.
    pub points: Vec<EmissionPoint>,
}

/// Cumulative **mined** supply after the block at height `blocks` (i.e. blocks
/// 1..=`blocks` mined) under `policy`, starting from an empty supply.
///
/// Bitcoin's height-keyed schedule has a closed form per epoch — every epoch is
/// exactly `halving_interval_blocks` blocks at a constant integer subsidy — so
/// this walks epochs (≤ 128 of them) rather than blocks, reproducing exactly
/// the result of calling [`MiningPolicy::reward_at`] once per height and
/// accumulating. The result never exceeds `mining_budget_grains`: the last
/// block before the backstop is clamped exactly as the protocol clamps it.
pub fn mined_supply_after(policy: &MiningPolicy, blocks: u64) -> Balance {
    let interval = u128::from(policy.halving_interval_blocks.max(1));
    let base = policy.base_reward.grains();

    let mut minted: u128 = 0;
    let mut remaining_blocks = u128::from(blocks);
    let mut halvings: u32 = 0;

    while remaining_blocks > 0 {
        if minted >= policy.mining_budget_grains {
            break; // Budget backstop reached: every further block mints zero.
        }
        let scheduled = if halvings >= 127 { 0 } else { base >> halvings };
        if scheduled == 0 {
            break; // Subsidy has decayed to zero: nothing more is minted, ever.
        }

        // Whole blocks left in this epoch, bounded by the request.
        let take = interval.min(remaining_blocks);
        // Mint `take` blocks of `scheduled`, but never overrun the budget: the
        // last block before it is clamped exactly as `reward_at` clamps it.
        let room_to_budget = policy.mining_budget_grains - minted;
        let added = take.saturating_mul(scheduled).min(room_to_budget);
        minted += added;
        remaining_blocks -= take;
        halvings = halvings.saturating_add(1);
    }

    Balance::from_grains(minted)
}

impl EmissionProjection {
    /// Compute the cumulative-emission projection over `range` — pure protocol
    /// mechanics from `mining` (proof-of-work is the only emission source).
    pub fn compute(mining: &MiningPolicy, range: HeightRange) -> Result<Self, ReserveError> {
        let mut points = Vec::new();
        for height in range.heights() {
            // One coinbase per block: blocks elapsed since genesis = the height.
            let mined = mined_supply_after(mining, height.get());
            debug_assert!(mined.grains() <= MAX_SUPPLY_GRAINS);
            points.push(EmissionPoint {
                height,
                mined: Sourced::protocol(mined),
            });
        }
        Ok(EmissionProjection { range, points })
    }

    /// The final (highest-height) point, if the projection is non-empty.
    pub fn last(&self) -> Option<&EmissionPoint> {
        self.points.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ground truth the analytic stepper must match: iterate the *real*
    /// `MiningPolicy::reward_at` once per height and accumulate.
    fn mined_by_naive_iteration(policy: &MiningPolicy, blocks: u64) -> Balance {
        let mut supply = Balance::ZERO;
        for h in 1..=blocks {
            let r = policy.reward_at(h, supply);
            supply = supply.checked_add(r).expect("within cap");
        }
        supply
    }

    #[test]
    fn analytic_stepper_matches_real_reward_iteration() {
        // A policy whose halving interval is small enough that a modest block
        // range crosses several halvings — so the epoch-walking path is exercised.
        let mut policy = MiningPolicy::mainnet_like();
        policy.halving_interval_blocks = 100; // several halvings within the range
        for blocks in [0u64, 1, 2, 3, 5, 10, 25, 100, 500, 1_000, 5_000] {
            assert_eq!(
                mined_supply_after(&policy, blocks),
                mined_by_naive_iteration(&policy, blocks),
                "mismatch at {blocks} blocks"
            );
        }
    }

    #[test]
    fn mined_supply_is_monotonic_and_cap_bounded() {
        let policy = MiningPolicy::mainnet_like();
        let mut prev = Balance::ZERO;
        for blocks in (0..2_000_000).step_by(50_000) {
            let s = mined_supply_after(&policy, blocks);
            assert!(s >= prev, "non-monotonic at {blocks}");
            assert!(s.within_cap(), "exceeded cap at {blocks}");
            prev = s;
        }
    }

    #[test]
    fn mining_never_exceeds_its_budget_even_when_run_forever() {
        // A pathological policy: huge reward, no halving, so only the budget
        // backstop can stop emission. Running it for absurdly many blocks must
        // land on the budget exactly, never beyond — and within the cap.
        let policy = MiningPolicy {
            base_reward: Balance::from_sov(1_000_000).unwrap(),
            halving_interval_blocks: u64::MAX, // effectively never halves
            ..MiningPolicy::mainnet_like()
        };
        let s = mined_supply_after(&policy, u64::MAX);
        assert_eq!(s.grains(), policy.mining_budget_grains);
        assert!(s.within_cap());
        // And once at the budget, further blocks add nothing.
        assert_eq!(mined_supply_after(&policy, u64::MAX), s);
    }

    #[test]
    fn long_run_mining_converges_to_bitcoins_asymptote_under_the_cap() {
        // Derive the eventual mined total from the real policy by exhausting
        // emission, rather than hardcoding behavior: the geometric series of
        // 840,000-block epochs at integer-halved subsidies converges to
        // 20,999,999.9076 SOV — strictly under the cap. With NO genesis
        // allocation, this is the entire money supply.
        let policy = MiningPolicy::mainnet_like();
        let converged = mined_supply_after(&policy, u64::MAX);
        assert_eq!(converged.grains(), 2_099_999_990_760_000);
        assert!(converged.grains() < policy.mining_budget_grains);
        assert!(converged.within_cap());
        // Stable: stepping further mints nothing.
        assert_eq!(mined_supply_after(&policy, u64::MAX), converged);
    }

    #[test]
    fn projection_points_are_monotonic_and_tagged() {
        let mining = MiningPolicy::mainnet_like();
        let range =
            HeightRange::new(BlockHeight::GENESIS, BlockHeight::new(1_000_000), 100_000).unwrap();
        let proj = EmissionProjection::compute(&mining, range).unwrap();

        let mut prev = Balance::ZERO;
        for p in &proj.points {
            // Provenance: mined is pure protocol — the ONLY emission source.
            assert_eq!(p.mined.source, crate::Source::Protocol);
            assert!(p.mined.value >= prev);
            assert!(p.mined.value.within_cap());
            prev = p.mined.value;
        }
    }

    #[test]
    fn height_range_validates() {
        assert_eq!(
            HeightRange::new(BlockHeight::new(10), BlockHeight::new(5), 1),
            Err(ReserveError::InvalidRange { start: 10, end: 5 })
        );
        assert_eq!(
            HeightRange::new(BlockHeight::GENESIS, BlockHeight::new(10), 0),
            Err(ReserveError::ZeroStep)
        );
    }

    #[test]
    fn height_range_samples_include_endpoint() {
        let r = HeightRange::new(BlockHeight::GENESIS, BlockHeight::new(250), 100).unwrap();
        let hs: Vec<u64> = r.heights().iter().map(|h| h.get()).collect();
        // 0, 100, 200, then the endpoint 250 (not 300).
        assert_eq!(hs, vec![0, 100, 200, 250]);
    }

    #[test]
    fn determinism_same_inputs_same_projection() {
        let mining = MiningPolicy::mainnet_like();
        let range =
            HeightRange::new(BlockHeight::GENESIS, BlockHeight::new(900_000), 30_000).unwrap();
        let first = EmissionProjection::compute(&mining, range).unwrap();
        let second = EmissionProjection::compute(&mining, range).unwrap();
        assert_eq!(first, second);
    }
}
