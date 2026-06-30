//! # sov-mining
//!
//! Proof-of-work mining policy: difficulty targets, the emission schedule, and
//! cumulative-work accounting. **Proof of work is SOV's consensus and its only
//! issuance source** (Nakamoto; there is no proof-of-stake of any kind):
//!
//! 1. **The block seal.** A miner grinds the block header's nonce until its
//!    proof-of-work seal ([`PowAlgo`] — RandomX on mainnet, SHA-256d for tests)
//!    meets the live target (`sov-chain`); fork choice picks the chain with the
//!    most cumulative [`Work`].
//! 2. **A diminishing, budgeted coinbase.** [`MiningPolicy::reward`] halves the
//!    reward as *mined* supply grows and clamps every reward to the room left in
//!    the **mining budget** (`mining_budget_grains`) — the portion of the 21M cap
//!    reserved for proof-of-work issuance, independent of genesis allocation.
//!    The coinbase mints *toward* its budget but never past it; after that the
//!    chain runs on fees, exactly like Bitcoin.
//!
//! This crate computes rewards, difficulty, and work; *applying* the coinbase to
//! the ledger is the execution layer's job in `sov-runtime`.

#![forbid(unsafe_code)]

pub mod difficulty;
pub use difficulty::Difficulty;

pub mod work;
pub use work::Work;

// Re-export the proof-of-work target and seal algorithm so consumers (e.g. the
// chain's fork-choice index) can name them without depending on `sov-pow` directly.
pub use sov_pow::{PowAlgo, Target};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::Balance;

/// The resolved **post-quantum sunset schedule** (the Q-day runbook as
/// consensus policy, Phase 18 p18-i3). Once a chain's miner-signaled
/// `pq-sunset` deployment activates (BIP-8 state machine in `sov-governance`,
/// evaluated over the version bits committed in block headers), the chain
/// derives this schedule deterministically and enforces it in the state
/// transition function:
///
/// - **Rotation window** (`rotation_only_height ≤ h < sunset_height`):
///   accounts holding ≥ `threshold_grains` and still controlled by a legacy
///   (`V1` Ed25519) key may execute **only** a `RotateKey` to a hybrid
///   post-quantum key. All their other transactions are rejected — the
///   highest-value targets are forced to migrate first.
/// - **Sunset** (`h ≥ sunset_height`): every `V1`-signed transaction is
///   rejected. Un-rotated accounts are **frozen** — which is the honest
///   trade-off: at the sunset the protocol assumes Ed25519 is breakable, so a
///   `V1` signature no longer proves ownership; freezing protects those funds
///   from quantum forgery rather than leaving them stealable.
///
/// Hybrid-keyed accounts are never affected at any phase.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PqSchedule {
    /// Height at/after which threshold-exceeding legacy accounts may only rotate.
    pub rotation_only_height: u64,
    /// Height at/after which ALL legacy-key transactions are rejected.
    pub sunset_height: u64,
    /// Balance threshold (grains, total holdings) for the rotation window.
    pub threshold_grains: u128,
}

/// The mining parameters of a chain: the difficulty target and the emission
/// schedule. Carried by the chain (set at genesis) and applied at execution.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MiningPolicy {
    /// The proof-of-work **seal algorithm** (genesis-fixed consensus parameter):
    /// `RandomX` on mainnet (memory-hard, ASIC-resistant, M-series-friendly) or
    /// `Sha256d` for fast dev/test chains. See [`PowAlgo`].
    pub pow_algo: PowAlgo,
    /// Proof-of-work difficulty target — the threshold a block header's seal
    /// ([`pow_algo`](Self::pow_algo)) must not exceed.
    pub sha256d_target: Target,
    /// The block subsidy at height 1, before any halving. `mainnet_like` sets
    /// **12.5 SOV** (a 2.5-minute-block, ~4-year-halving curve — Zcash's launch).
    pub base_reward: Balance,
    /// Blocks between successive halvings of the subsidy — **Bitcoin's
    /// height-keyed rule**: `subsidy(height) = base_reward >> ((height − 1) /
    /// halving_interval_blocks)`. `mainnet_like` sets 840,000 with a 12.5-SOV
    /// base, so epoch 0 mints exactly 10,500,000 SOV, epoch 1 half that, and the
    /// geometric series sums to just under the 21M cap (≈20,999,999.9076 SOV),
    /// with NO genesis allocation needed. At 2.5-minute blocks that is a halving
    /// roughly every 4 years (Zcash's exact emission cadence).
    pub halving_interval_blocks: u64,
    /// The hard ceiling (in grains) on cumulative proof-of-work issuance — the
    /// budget backstop the coinbase is clamped to. On mainnet this is the FULL
    /// 21M cap: genesis enforces `genesis + mining_budget <= MAX_SUPPLY_GRAINS`,
    /// so a full-cap budget arithmetically forbids any pre-mine (every genesis
    /// balance would breach the cap). Mining is the ONLY emission source; the
    /// geometric subsidy never actually reaches this ceiling, exactly as in
    /// Bitcoin.
    pub mining_budget_grains: u128,
    /// Target time between blocks, in milliseconds. The chain retargets mining
    /// difficulty toward this cadence (see [`Difficulty::retarget`]).
    pub target_block_ms: u64,
    /// Transaction-fee price per unit of gas, in grains: a sender pays
    /// `gas_used × gas_price`. `0` disables fees. Governance-tunable.
    pub gas_price: Balance,
    /// BIP-110: the maximum bytes of arbitrary data a transaction may carry (its
    /// `Deploy` contract code), keeping block space reserved for monetary use
    /// rather than data storage. `0` means no limit.
    pub max_code_bytes: u32,
    /// Shielded-pool drain limiter (Phase 18 p18-i4): the rolling window length,
    /// in blocks, over which de-shields are capped. `0` disables the limiter.
    /// Defense in depth for assumption A3: even a sound-proof forgery can pull
    /// at most [`deshield_limit_grains`](Self::deshield_limit_grains) out of the
    /// pool per window — slow enough for operators and governance to react.
    pub deshield_window_blocks: u64,
    /// Maximum total grains that may LEAVE the shielded pool (de-shields)
    /// within one rolling window. Ignored when the window length is `0`.
    pub deshield_limit_grains: u128,
}

impl MiningPolicy {
    /// The coinbase subsidy for the block at `height`, clamped to the room left
    /// under the budget given cumulative `mined_supply` — **Bitcoin's standard
    /// emission rule**, height-keyed:
    ///
    /// `subsidy(height) = base_reward >> ((height − 1) / halving_interval_blocks)`
    ///
    /// Heights 1..=interval form epoch 0 at the full base reward; each later
    /// epoch halves it (integer truncation, so the subsidy can only ever
    /// under-pay, never over-mint — Bitcoin's exact behavior). Height 0 is
    /// genesis, which mints nothing: there is no pre-mine. Returns zero once
    /// the subsidy has decayed to zero grains or the budget backstop is hit.
    pub fn reward_at(&self, height: u64, mined_supply: Balance) -> Balance {
        if height == 0 {
            return Balance::ZERO; // genesis is never mined
        }
        let mined = mined_supply.grains();
        if mined >= self.mining_budget_grains {
            return Balance::ZERO;
        }
        let halvings = (height - 1) / self.halving_interval_blocks.max(1);
        let scheduled = if halvings >= 127 {
            0
        } else {
            self.base_reward.grains() >> halvings
        };
        let remaining = self.mining_budget_grains - mined;
        Balance::from_grains(scheduled.min(remaining))
    }

    /// The production default: **Bitcoin's halving rule at Zcash's cadence** — a
    /// 12.5-SOV block subsidy halving every 840,000 blocks (~4-year halvings at
    /// 2.5-minute blocks), geometric total just under the 21M cap, and a budget
    /// backstop equal to the FULL cap, which makes any genesis allocation (any
    /// pre-mine) arithmetically impossible: every coin that will ever exist is
    /// mined.
    pub fn mainnet_like() -> Self {
        MiningPolicy {
            // RandomX: memory-hard, ASIC-resistant, M-series-friendly — the
            // mainnet seal that lets commodity CPUs bootstrap the network.
            pow_algo: PowAlgo::RandomX,
            sha256d_target: Target::from_leading_zero_bits(20),
            // 12.5 XUS = 1,250,000,000 grains. With the 840,000-block interval,
            // base × interval = 10,500,000 SOV = ½ the cap, so the geometric
            // series sums to just under 21M from below (no pre-mine possible).
            base_reward: Balance::from_grains(1_250_000_000),
            halving_interval_blocks: 840_000,
            mining_budget_grains: sov_primitives::MAX_SUPPLY_GRAINS,
            target_block_ms: 150_000, // 2.5-minute blocks (Zcash's cadence ⇒ ~4-year halvings)
            // Fees are live: a 21,000-gas transfer costs ~0.0021 SOV. The entire
            // coinbase AND every fee go to the block's miner — no tax, nothing
            // burned (pure Nakamoto).
            gas_price: Balance::from_grains(10),
            max_code_bytes: 256 * 1024, // 256 KiB (BIP-110)
            // Drain limiter ON: at 2.5-minute blocks, 576 blocks ≈ one day; at most
            // 21,000 SOV (0.1% of the 21M cap) can leave the pool per day even
            // under a proof-system failure. Governance-tunable like every
            // policy parameter here.
            deshield_window_blocks: 576,
            deshield_limit_grains: Balance::from_sov(21_000).expect("representable").grains(),
        }
    }

    /// An easy policy for tests: trivial difficulty so SHA-256d solutions are
    /// found instantly, frequent halving, and a generous budget. The base reward
    /// is ZERO — coinbase issuance OFF in the test preset, mirroring fees OFF
    /// below, so balance/supply assertions are unaffected by every block's
    /// coinbase; dedicated emission tests set a non-zero `base_reward`
    /// explicitly.
    pub fn test() -> Self {
        MiningPolicy {
            // SHA-256d for the test suite: blocks seal instantly (RandomX would
            // make every test that mines memory-heavy and slow).
            pow_algo: PowAlgo::Sha256d,
            sha256d_target: Target::from_leading_zero_bits(8),
            base_reward: Balance::ZERO,
            halving_interval_blocks: 210_000,
            mining_budget_grains: Balance::from_sov(1_000_000)
                .expect("representable")
                .grains(),
            target_block_ms: 1_000,
            // Fees OFF in the test preset (gas_price 0) so existing balance
            // assertions are unaffected; the fee logic is exercised by dedicated
            // tests that set a non-zero gas_price.
            gas_price: Balance::ZERO,
            max_code_bytes: 256 * 1024,
            // Limiter OFF in the test preset; the dedicated rate-limit tests
            // enable it explicitly.
            deshield_window_blocks: 0,
            deshield_limit_grains: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsidy_halves_on_bitcoins_height_schedule() {
        let policy = MiningPolicy {
            pow_algo: PowAlgo::Sha256d,
            sha256d_target: Target::EASIEST,
            base_reward: Balance::from_sov(100).unwrap(),
            halving_interval_blocks: 10,
            mining_budget_grains: Balance::from_sov(1_000_000).unwrap().grains(),
            target_block_ms: 1_000,
            gas_price: Balance::ZERO,
            max_code_bytes: 256 * 1024,
            deshield_window_blocks: 0,
            deshield_limit_grains: 0,
        };
        // Genesis (height 0) mints nothing: NO pre-mine.
        assert_eq!(policy.reward_at(0, Balance::ZERO), Balance::ZERO);
        // Epoch 0 is heights 1..=10 at the full base reward.
        assert_eq!(
            policy.reward_at(1, Balance::ZERO),
            Balance::from_sov(100).unwrap()
        );
        assert_eq!(
            policy.reward_at(10, Balance::ZERO),
            Balance::from_sov(100).unwrap()
        );
        // Height 11: one halving -> 50. Height 21: two halvings -> 25.
        assert_eq!(
            policy.reward_at(11, Balance::ZERO),
            Balance::from_sov(50).unwrap()
        );
        assert_eq!(
            policy.reward_at(21, Balance::ZERO),
            Balance::from_sov(25).unwrap()
        );
    }

    #[test]
    fn mainnet_emission_is_bitcoins_and_forbids_any_premine() {
        // The real mainnet schedule: 12.5 SOV halving every 840,000 blocks
        // (2.5-minute blocks, ~4-year halvings) — Zcash's emission cadence with
        // Bitcoin's rule. base × interval = ½ the cap, so the geometric total
        // converges just under the 21M cap — every coin that will ever exist is mined.
        let p = MiningPolicy::mainnet_like();
        assert_eq!(p.base_reward, Balance::from_grains(1_250_000_000)); // 12.5 XUS
        assert_eq!(p.halving_interval_blocks, 840_000);
        // The budget backstop IS the full cap: any genesis allocation would
        // breach `genesis + budget <= cap`, so a pre-mine is impossible.
        assert_eq!(p.mining_budget_grains, sov_primitives::MAX_SUPPLY_GRAINS);

        // Sum the whole geometric series by epochs (each epoch is 210,000
        // blocks at a constant integer subsidy): the Bitcoin asymptote.
        let mut total: u128 = 0;
        let mut k = 0u64;
        loop {
            let subsidy = p.base_reward.grains() >> k;
            if subsidy == 0 {
                break;
            }
            total += subsidy * u128::from(p.halving_interval_blocks);
            k += 1;
        }
        // 20,999,999.9076 SOV in grains — strictly under the 21M cap, the same
        // geometric convergence (integer-truncated halvings).
        assert_eq!(total, 2_099_999_990_760_000);
        assert!(total < sov_primitives::MAX_SUPPLY_GRAINS);
    }

    #[test]
    fn reward_clamps_to_budget() {
        // The budget backstop: near the ceiling the subsidy is clamped to the
        // room left, and at the ceiling nothing further can ever be minted.
        let budget = Balance::from_sov(1_000_000).unwrap().grains();
        let policy = MiningPolicy {
            pow_algo: PowAlgo::Sha256d,
            sha256d_target: Target::EASIEST,
            base_reward: Balance::from_sov(50).unwrap(),
            halving_interval_blocks: u64::MAX,
            mining_budget_grains: budget,
            target_block_ms: 1_000,
            gas_price: Balance::ZERO,
            max_code_bytes: 256 * 1024,
            deshield_window_blocks: 0,
            deshield_limit_grains: 0,
        };
        // One grain below the budget: the 50-SOV scheduled subsidy is clamped to 1.
        let near_budget = Balance::from_grains(budget - 1);
        assert_eq!(policy.reward_at(1, near_budget), Balance::from_grains(1));
        // At the budget: nothing left to mine.
        assert_eq!(
            policy.reward_at(1, Balance::from_grains(budget)),
            Balance::ZERO
        );
        // The mainnet mining budget fits under the protocol cap.
        assert!(
            MiningPolicy::mainnet_like().mining_budget_grains <= sov_primitives::MAX_SUPPLY_GRAINS
        );
    }

    #[test]
    fn test_and_mainnet_presets_reward_as_documented() {
        // The test preset issues nothing (coinbase OFF, like fees OFF); the
        // mainnet-like preset pays the 12.5-SOV subsidy at block 1.
        assert_eq!(
            MiningPolicy::test().reward_at(1, Balance::ZERO),
            Balance::ZERO
        );
        assert_eq!(
            MiningPolicy::mainnet_like().reward_at(1, Balance::ZERO),
            Balance::from_grains(1_250_000_000) // 12.5 XUS
        );
    }
}
