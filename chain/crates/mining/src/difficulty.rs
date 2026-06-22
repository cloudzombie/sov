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
    ///
    /// NOTE: this single-step ratio retarget is the classic Bitcoin form, but applied
    /// per block it OVERSHOOTS and OSCILLATES (a few fast blocks ramp it up 4×, then a
    /// very slow block, then it crashes back). Prefer [`lwma`](Difficulty::lwma) for a
    /// per-block schedule. Kept for the one-shot/epoch case and tests.
    pub fn retarget(self, actual_interval_ms: u64, target_interval_ms: u64) -> Difficulty {
        let actual = actual_interval_ms.max(1) as u128;
        let target = target_interval_ms.max(1) as u128;
        // new_D = D * target / actual  (actual < target ⇒ harder).
        let scaled = self.0.saturating_mul(target) / actual;
        let lo = (self.0 / 4).max(1);
        let hi = self.0.saturating_mul(4);
        Difficulty(scaled.clamp(lo, hi).max(1))
    }

    /// Next difficulty by **LWMA-1** (Linearly-Weighted Moving Average) — Monero's /
    /// Zcash-family per-block difficulty algorithm, the standard cure for the
    /// overshoot-and-oscillate behavior of a naive per-block ratio retarget.
    ///
    /// Given the last `N` blocks' difficulties and their solve times (oldest first;
    /// `diffs[i]` is the difficulty of the block whose solve time is `solvetimes_ms[i]`),
    /// it returns the difficulty that would have produced `target_ms` blocks, weighting
    /// recent solve times more (weight `i` for the i-th, so the newest counts most):
    ///
    /// `next = (ΣD · T · (N+1)) / (2 · Σ(i · solvetime_i))`
    ///
    /// Each solve time is clamped to `[1, 6·T]` so a single bad/non-monotonic timestamp
    /// cannot blow up the average. The weighted average makes it converge smoothly to the
    /// real hashrate's equilibrium and STAY there — no 4×/block swings, no minutes-long
    /// blocks. Computed in 256-bit to avoid overflow at any difficulty.
    pub fn lwma(diffs: &[u128], solvetimes_ms: &[u64], target_ms: u64) -> Difficulty {
        let n = diffs.len();
        if n == 0 || solvetimes_ms.len() != n {
            return Difficulty::MIN;
        }
        let t = U256::from(target_ms.max(1));
        let cap = U256::from(6u64) * t; // clamp ceiling for an anomalous solve time
        let mut sum_d = U256::zero();
        let mut weighted = U256::zero(); // Σ(i · solvetime_i), i = 1..=N
        for (idx, (&d, &st)) in diffs.iter().zip(solvetimes_ms).enumerate() {
            let i = U256::from((idx as u64) + 1);
            let mut st = U256::from(st.max(1));
            if st > cap {
                st = cap;
            }
            sum_d += U256::from(d);
            weighted += i * st;
        }
        if weighted.is_zero() {
            weighted = U256::one();
        }
        // next = ΣD · T · (N+1) / (2 · weighted)
        let num = sum_d * t * U256::from((n as u64) + 1);
        let den = U256::from(2u64) * weighted;
        let next = num / den;
        let next = if next > U256::from(u128::MAX) {
            u128::MAX
        } else {
            next.as_u128()
        };
        Difficulty(next.max(1))
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
    fn lwma_converges_to_target_and_stays_stable() {
        // Simulate mining at a FIXED hashrate H (hashes per ms): a block of difficulty D
        // takes ~D/H ms. Starting FAR below equilibrium (the genesis-difficulty cold
        // start that made the old per-block ratio retarget overshoot to 24-minute
        // blocks), LWMA must converge to ~target and STAY there — bounded, no oscillation.
        let target_ms = 30_000u64;
        let hashrate = 1_000u128; // ⇒ equilibrium D = target_ms * H = 30,000,000
        let n = 60usize;
        let mut diffs = vec![1_000u128; n]; // genesis-ish, ~300x too easy
        let mut solvetimes: Vec<u64> =
            diffs.iter().map(|&d| (d / hashrate).max(1) as u64).collect();
        let (mut min_recent, mut max_recent) = (u64::MAX, 0u64);
        for iter in 0..500 {
            let next = Difficulty::lwma(&diffs, &solvetimes, target_ms);
            let solve = (next.0 / hashrate).max(1) as u64;
            diffs.remove(0);
            diffs.push(next.0);
            solvetimes.remove(0);
            solvetimes.push(solve);
            if iter >= 250 {
                // steady state
                min_recent = min_recent.min(solve);
                max_recent = max_recent.max(solve);
            }
        }
        // Steady-state block time stays within 2x of target in BOTH directions — i.e. it
        // converged and does not swing (the old algorithm hit ~50x the target).
        assert!(
            max_recent <= target_ms * 2,
            "block time must not blow up: max {max_recent}ms vs target {target_ms}ms"
        );
        assert!(
            min_recent >= target_ms / 2,
            "block time must not collapse: min {min_recent}ms vs target {target_ms}ms"
        );
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
