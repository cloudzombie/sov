//! Cumulative proof-of-work ("chain work").
//!
//! Nakamoto fork choice selects the chain with the most accumulated proof of
//! work, not the most blocks: a branch mined at higher difficulty can outweigh a
//! longer branch mined at lower difficulty. To compare branches we sum, over
//! every block, the *expected number of hash attempts* it represents — Bitcoin's
//! `GetBlockProof`: for a block whose hash had to land at or below `target`, the
//! work is `2^256 / (target + 1)`, computed exactly as `(~target / (target+1)) + 1`
//! in 256-bit integer arithmetic via the audited `primitive-types` `U256` (no
//! hand-rolled bignum). Smaller target ⇒ more leading zero bits ⇒ more work.

use primitive_types::U256;
use sov_pow::Target;

/// Accumulated proof of work across a chain of blocks — the quantity Nakamoto
/// fork choice maximizes. Ordered, so the heaviest chain is simply the maximum.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Work(U256);

impl Work {
    /// No work (the base for a cumulative sum; genesis' predecessor).
    pub fn zero() -> Work {
        Work(U256::zero())
    }

    /// The raw 256-bit work value.
    pub fn to_u256(self) -> U256 {
        self.0
    }

    /// The raw work value as fixed-width big-endian bytes. This is the wire form
    /// used by P2P status messages so peers can compare chainwork lexicographically.
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_big_endian()
    }

    /// The expected work to find a single block at `target`: Bitcoin's
    /// `GetBlockProof`, `(~target / (target + 1)) + 1`, evaluated without
    /// overflow. The easiest possible target (`2^256 − 1`) yields the minimum
    /// unit of work.
    pub fn of_target(target: &Target) -> Work {
        let t = U256::from_big_endian(target.as_hash().as_bytes());
        if t == U256::MAX {
            // ~t == 0 and (t + 1) would overflow; one unit of work by definition.
            return Work(U256::one());
        }
        let not_t = U256::MAX - t; // ~target
        Work((not_t / (t + U256::one())) + U256::one())
    }

    /// Add the work of one more block, saturating at the 256-bit ceiling (a
    /// chain can never accumulate more work than the hash space, so this never
    /// saturates in practice).
    pub fn saturating_add(self, rhs: Work) -> Work {
        Work(self.0.saturating_add(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Difficulty;

    #[test]
    fn harder_target_is_more_work() {
        let easy = Difficulty(1).to_target();
        let hard = Difficulty(1_000_000).to_target();
        assert!(Work::of_target(&hard) > Work::of_target(&easy));
    }

    #[test]
    fn easiest_target_is_one_unit() {
        assert_eq!(Work::of_target(&Target::EASIEST), Work(U256::one()));
    }

    #[test]
    fn work_accumulates_and_orders() {
        let t = Difficulty(1_000).to_target();
        let one = Work::zero().saturating_add(Work::of_target(&t));
        let two = one.saturating_add(Work::of_target(&t));
        assert!(two > one);
        assert!(one > Work::zero());
        // Two blocks at difficulty D ≈ one block at difficulty 2D, the property
        // that makes a longer-but-easier chain comparable to a shorter-harder one.
        let two_d = Difficulty(2_000).to_target();
        let single_2d = Work::of_target(&two_d);
        // Within integer-truncation slack, 2×work(D) ≈ work(2D).
        let lo = single_2d.to_u256() - single_2d.to_u256() / 100;
        let hi = single_2d.to_u256() + single_2d.to_u256() / 100;
        assert!(two.to_u256() >= lo && two.to_u256() <= hi);
    }
}
