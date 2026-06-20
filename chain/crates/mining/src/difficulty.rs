//! Mining difficulty and difficulty retargeting.
//!
//! Difficulty is a scalar `D ≥ 1`. The corresponding proof-of-work [`Target`] is
//! `floor((2^256 − 1) / D)`: higher difficulty ⇒ smaller target ⇒ more leading
//! zero bits required ⇒ more expected hashing. This is the Bitcoin relationship,
//! computed exactly in 256-bit integer arithmetic via the audited
//! `primitive-types` `U256` (no hand-rolled bignum).
//!
//! [`Difficulty::retarget`] adjusts difficulty toward a target block time from
//! the observed interval, clamped to a 4× change per step so difficulty can't
//! swing wildly from one anomalous interval — the same damping Bitcoin uses.

use primitive_types::U256;
use sov_pow::Target;
use sov_primitives::Hash;

/// Proof-of-work difficulty as a scalar (`>= 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difficulty(pub u128);

impl Difficulty {
    /// The easiest difficulty: target is the maximum (every hash qualifies).
    pub const MIN: Difficulty = Difficulty(1);

    /// The proof-of-work target for this difficulty: `(2^256 - 1) / D`.
    pub fn to_target(self) -> Target {
        let d = U256::from(self.0.max(1));
        let value = U256::MAX / d;
        Target::from_hash(Hash::from_bytes(value.to_big_endian()))
    }

    /// Recover the difficulty implied by a `target`: `(2^256 - 1) / target`.
    /// The inverse of [`to_target`](Difficulty::to_target) (up to integer
    /// truncation). Saturates to `u128::MAX` for extremely small targets.
    pub fn from_target(target: Target) -> Difficulty {
        let t = U256::from_big_endian(target.as_hash().as_bytes());
        if t.is_zero() {
            return Difficulty(u128::MAX);
        }
        let d = U256::MAX / t;
        Difficulty(if d > U256::from(u128::MAX) {
            u128::MAX
        } else {
            d.as_u128()
        })
    }

    /// Retarget toward `target_interval_ms` given the `actual_interval_ms` of the
    /// most recent step. Faster-than-target intervals raise difficulty; slower
    /// ones lower it. The multiplicative change is clamped to `[1/4, 4]`.
    pub fn retarget(self, actual_interval_ms: u64, target_interval_ms: u64) -> Difficulty {
        let actual = actual_interval_ms.max(1) as u128;
        let target = target_interval_ms.max(1) as u128;
        // new_D = D * target / actual  (actual < target ⇒ harder).
        let scaled = self.0.saturating_mul(target) / actual;
        let lo = (self.0 / 4).max(1);
        let hi = self.0.saturating_mul(4);
        Difficulty(scaled.clamp(lo, hi).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_difficulty_is_easiest_target() {
        assert_eq!(Difficulty::MIN.to_target(), Target::EASIEST);
    }

    #[test]
    fn higher_difficulty_is_a_smaller_target() {
        // A bigger difficulty must not be met by a hash that a small one is.
        let easy = Difficulty(1).to_target();
        let hard = Difficulty(1_000_000).to_target();
        // The all-0x80 hash (just over half the space) clears the easy target but
        // not the hard one.
        let h = Hash::from_bytes([0x80; 32]);
        assert!(easy.is_met_by(&h));
        assert!(!hard.is_met_by(&h));
    }

    #[test]
    fn target_difficulty_roundtrip_is_close() {
        for d in [1u128, 2, 1000, 1_000_000, 1_000_000_000] {
            let back = Difficulty::from_target(Difficulty(d).to_target()).0;
            // Integer truncation means it can be off by a hair; require within 1%.
            let hi = d + d / 100 + 1;
            let lo = d - d / 100;
            assert!(back >= lo && back <= hi, "d={d} round-tripped to {back}");
        }
    }

    #[test]
    fn retarget_raises_when_blocks_are_fast() {
        let d = Difficulty(1000);
        // Blocks came in twice as fast as target -> difficulty should ~double.
        let faster = d.retarget(500, 1000);
        assert_eq!(faster.0, 2000);
        // ...and halve when twice as slow.
        let slower = d.retarget(2000, 1000);
        assert_eq!(slower.0, 500);
    }

    #[test]
    fn retarget_is_clamped_to_4x() {
        let d = Difficulty(1000);
        // A 100x-fast interval is clamped to a 4x rise.
        assert_eq!(d.retarget(10, 1000).0, 4000);
        // A 100x-slow interval is clamped to a 4x drop.
        assert_eq!(d.retarget(100_000, 1000).0, 250);
    }
}
