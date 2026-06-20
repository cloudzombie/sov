//! Float model: circulating supply versus locked supply, and scarcity metrics.
//!
//! At any height the *emitted* supply is a protocol fact (the mined curve from
//! [`crate::emission`]). How much of it is *off-market* — by aggregate holder dormancy and by
//! named holders — is a caller [`Assumptions`] scenario. The circulating
//! **float** is what remains:
//!
//! ```text
//! float = emitted (REAL) − locked (ASSUMED)
//! ```
//!
//! Because `emitted` is real and `locked` is assumed, the float is an
//! assumption-derived figure and is tagged as such. Locked supply can never
//! exceed emitted supply: a scenario that locks more than exists is a
//! contradiction and is rejected ([`ReserveError::LockedExceedsSupply`]), never
//! silently clamped.
//!
//! Scarcity is reported as the float ratio in basis points (`float / emitted`),
//! integer math throughout — no floating point touches a supply figure.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::{Balance, BlockHeight};

use crate::assumptions::{Assumptions, BPS_DENOMINATOR};
use crate::error::ReserveError;
use crate::provenance::Sourced;

/// Locked supply at a height, broken down by its (assumed) sources.
///
/// Every figure here is assumption-derived: the protocol does not dictate how
/// much supply holders keep off-market (there is no protocol staking). The
/// breakdown is kept so a consumer can see which part comes from aggregate
/// holder dormancy versus named holders.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct LockedSupply {
    /// Supply held dormant by long-term holders in aggregate (assumption).
    pub by_dormancy: Sourced<Balance>,
    /// Supply locked by named holders still within their lock at this height
    /// (assumption).
    pub by_named_holders: Sourced<Balance>,
    /// Total locked supply (`by_dormancy + by_named_holders`), capped at the
    /// emitted supply (assumption).
    pub total: Sourced<Balance>,
}

/// The float model at a single height.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct FloatPoint {
    /// The height described.
    pub height: BlockHeight,
    /// Emitted (mined) supply — a protocol fact
    /// ([`Source::Protocol`](crate::Source::Protocol)).
    pub emitted: Sourced<Balance>,
    /// Locked supply under the caller's assumptions.
    pub locked: LockedSupply,
    /// Circulating float = `emitted − locked.total` (assumption-derived).
    pub float: Sourced<Balance>,
    /// Float as a fraction of emitted supply, in basis points (`10_000` = 100%).
    /// Assumption-derived; `0` when nothing has been emitted yet.
    pub float_ratio_bps: Sourced<u32>,
}

/// Compute the locked supply at `height` from the assumptions, given the emitted
/// (mined) supply at that height.
///
/// - Aggregate holder dormancy keeps `dormant_holdings_bps` of emitted supply off-market.
/// - Each named holder locks `locked_bps` of emitted supply while `height` is at
///   or before its `lock_until`; once unlocked, it contributes nothing.
///
/// Locked total is capped at emitted supply *only* after checking it does not
/// exceed it by construction: if the assumptions imply locking more than exists,
/// that is a contradiction and an error, not a silent clamp.
pub fn locked_supply_at(
    assumptions: &Assumptions,
    emitted: Balance,
    height: BlockHeight,
) -> Result<LockedSupply, ReserveError> {
    let emitted_grains = emitted.grains();

    let by_dormancy_grains = emitted_grains
        .saturating_mul(u128::from(assumptions.dormant_holdings_bps))
        / u128::from(BPS_DENOMINATOR);

    let mut by_named_grains: u128 = 0;
    for holder in &assumptions.sovereign_holders {
        // The holder's lock is active while we have not passed its unlock height.
        if height.get() <= holder.lock_until.get() {
            let part = emitted_grains.saturating_mul(u128::from(holder.locked_bps))
                / u128::from(BPS_DENOMINATOR);
            by_named_grains = by_named_grains
                .checked_add(part)
                .ok_or(ReserveError::Overflow)?;
        }
    }

    let total_grains = by_dormancy_grains
        .checked_add(by_named_grains)
        .ok_or(ReserveError::Overflow)?;

    // A scenario cannot lock more than has been emitted. Surface the
    // contradiction rather than quietly clamping it away.
    if total_grains > emitted_grains {
        return Err(ReserveError::LockedExceedsSupply {
            locked_grains: total_grains,
            available_grains: emitted_grains,
        });
    }

    Ok(LockedSupply {
        by_dormancy: Sourced::assumption(Balance::from_grains(by_dormancy_grains)),
        by_named_holders: Sourced::assumption(Balance::from_grains(by_named_grains)),
        total: Sourced::assumption(Balance::from_grains(total_grains)),
    })
}

/// The float ratio (`float / emitted`) in basis points, integer math.
///
/// Returns `0` when `emitted` is zero (no supply, so no meaningful ratio). The
/// result is in `0..=10_000`.
fn float_ratio_bps(float: Balance, emitted: Balance) -> u32 {
    let emitted_grains = emitted.grains();
    if emitted_grains == 0 {
        return 0;
    }
    let ratio = float.grains().saturating_mul(u128::from(BPS_DENOMINATOR)) / emitted_grains;
    // float ≤ emitted, so ratio ≤ 10_000 and fits in u32.
    ratio as u32
}

/// Compute the float model at a single height.
///
/// `emitted` must be the real mined supply at `height` (e.g. from
/// [`crate::emission::mined_supply_after`]). Locked supply is derived from the
/// assumptions; the float is `emitted − locked`.
pub fn float_at(
    assumptions: &Assumptions,
    emitted: Balance,
    height: BlockHeight,
) -> Result<FloatPoint, ReserveError> {
    let locked = locked_supply_at(assumptions, emitted, height)?;
    let float = emitted
        .checked_sub(locked.total.value)
        .ok_or(ReserveError::Overflow)?; // unreachable: locked ≤ emitted, checked above
    let ratio = float_ratio_bps(float, emitted);
    Ok(FloatPoint {
        height,
        emitted: Sourced::protocol(emitted),
        locked,
        float: Sourced::assumption(float),
        float_ratio_bps: Sourced::assumption(ratio),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assumptions::SovereignHolder;

    #[test]
    fn float_is_emitted_minus_locked() {
        let emitted = Balance::from_sov(1_000_000).unwrap();
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 4_000; // 40% dormant
        let p = float_at(&a, emitted, BlockHeight::new(10)).unwrap();
        assert_eq!(p.emitted.value, emitted);
        assert_eq!(p.locked.total.value, Balance::from_sov(400_000).unwrap());
        assert_eq!(p.float.value, Balance::from_sov(600_000).unwrap());
        assert_eq!(p.float_ratio_bps.value, 6_000); // 60% floating
                                                    // Provenance: emitted is fact; everything derived is an assumption.
        assert_eq!(p.emitted.source, crate::Source::Protocol);
        assert_eq!(p.float.source, crate::Source::Assumption);
        assert_eq!(p.locked.total.source, crate::Source::Assumption);
    }

    #[test]
    fn zero_assumptions_mean_everything_floats() {
        let emitted = Balance::from_sov(123_456).unwrap();
        let p = float_at(&Assumptions::neutral(), emitted, BlockHeight::new(1)).unwrap();
        assert_eq!(p.locked.total.value, Balance::ZERO);
        assert_eq!(p.float.value, emitted);
        assert_eq!(p.float_ratio_bps.value, 10_000); // 100% floating
    }

    #[test]
    fn locked_never_exceeds_emitted() {
        let emitted = Balance::from_sov(100).unwrap();
        let mut a = Assumptions::neutral();
        // Staking 60% + a named holder locking 60% = 120% > 100%: contradiction.
        a.dormant_holdings_bps = 6_000;
        a.sovereign_holders.push(SovereignHolder {
            label: "A".to_string(),
            locked_bps: 6_000,
            lock_until: BlockHeight::new(1_000),
        });
        let err = float_at(&a, emitted, BlockHeight::new(10)).unwrap_err();
        assert!(matches!(err, ReserveError::LockedExceedsSupply { .. }));
    }

    #[test]
    fn named_holder_unlocks_after_lock_until() {
        let emitted = Balance::from_sov(1_000).unwrap();
        let mut a = Assumptions::neutral();
        a.sovereign_holders.push(SovereignHolder {
            label: "treasury".to_string(),
            locked_bps: 5_000, // 50%
            lock_until: BlockHeight::new(100),
        });
        // At/within the lock window: 50% locked.
        let before = float_at(&a, emitted, BlockHeight::new(100)).unwrap();
        assert_eq!(
            before.locked.by_named_holders.value,
            Balance::from_sov(500).unwrap()
        );
        // After the lock height: contributes nothing — the float reopens.
        let after = float_at(&a, emitted, BlockHeight::new(101)).unwrap();
        assert_eq!(after.locked.by_named_holders.value, Balance::ZERO);
        assert_eq!(after.float.value, emitted);
    }

    #[test]
    fn ratio_is_zero_for_zero_emission() {
        let p = float_at(&Assumptions::neutral(), Balance::ZERO, BlockHeight::GENESIS).unwrap();
        assert_eq!(p.float_ratio_bps.value, 0);
        assert_eq!(p.float.value, Balance::ZERO);
    }

    #[test]
    fn dormancy_and_named_compose() {
        let emitted = Balance::from_sov(1_000).unwrap();
        let mut a = Assumptions::neutral();
        a.dormant_holdings_bps = 1_000; // 10%
        a.sovereign_holders.push(SovereignHolder {
            label: "A".to_string(),
            locked_bps: 2_000, // 20%
            lock_until: BlockHeight::new(50),
        });
        let p = float_at(&a, emitted, BlockHeight::new(10)).unwrap();
        assert_eq!(p.locked.by_dormancy.value, Balance::from_sov(100).unwrap());
        assert_eq!(
            p.locked.by_named_holders.value,
            Balance::from_sov(200).unwrap()
        );
        assert_eq!(p.locked.total.value, Balance::from_sov(300).unwrap());
        assert_eq!(p.float.value, Balance::from_sov(700).unwrap());
    }
}
