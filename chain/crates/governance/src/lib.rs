//! # sov-governance
//!
//! SOV governance is **Bitcoin-style, miner-signaled soft-fork activation** —
//! the deployment of a protocol upgrade is decided by *hashpower*, not by token
//! holders. Miners flip a per-deployment signaling bit in the blocks they mine;
//! once enough blocks in a retarget-style window carry the bit, the upgrade
//! locks in and then activates. This is the BIP-9 "version-bits" state machine,
//! with the optional BIP-8 "`lockinontimeout`" (LOT) extension for mandatory,
//! flag-day activation.
//!
//! ## This is NOT stake or holder voting
//!
//! Per the project's explicit design directive, governance here is
//! **proof-of-work consensus, not plutocracy**. There is deliberately no
//! stake-weighted vote, no token-holder ballot, and no coin-weighted tally
//! anywhere in this crate. The only input is the stream of per-block miner
//! signals — the same scarce resource (hashpower) that secures the chain also
//! governs its evolution. A whale's balance has zero weight; a miner's share of
//! blocks is everything.
//!
//! ## The state machine
//!
//! Each [`Deployment`] moves through [`ThresholdState`]:
//!
//! ```text
//!   Defined ─(window ≥ start_height)─▶ Started
//!   Started ─(signaling ≥ threshold over a window)─▶ LockedIn
//!   Started ─(window ≥ timeout_height, LOT off)─▶ Failed
//!   Started ─(window ≥ timeout_height, LOT on)─▶ LockedIn   (BIP-8 mandatory)
//!   LockedIn ─(next window ≥ min_activation_height)─▶ Active
//!   Active, Failed are terminal.
//! ```
//!
//! State is evaluated only at **window boundaries** — heights that are multiples
//! of the deployment's `period`. The state is constant within a window and can
//! only change when one window ends and the next begins. The signaling test is
//! exact integer arithmetic (no floating point): a window of `period` blocks
//! with `signaling` of them carrying the bit locks in iff
//! `signaling * den >= num * period`, where `Threshold { num, den }` is the
//! activation fraction (e.g. `1916/2016`).
//!
//! ## Honest boundary: signals are not yet in the live header
//!
//! `sov_types::BlockHeader` does **not** currently carry a version/signal field,
//! so this crate models governance over an *abstract* per-block miner-signal
//! stream supplied through the [`MinerSignals`] trait (with a concrete,
//! real-data [`SignalLog`] implementation). Wiring the signaling bits into the
//! real block header — so that mining a block *is* casting a signal — is a
//! Phase 8 node-layer task. This crate is the pure, deterministic policy that
//! that wiring will drive; it intentionally has no dependency on `sov-types`.
//!
//! Everything here is deterministic: identical inputs always yield identical
//! outputs (consensus state is held in a [`BTreeMap`], never a `HashMap`), there
//! is no wall-clock and no randomness, and there is no placeholder data.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::BlockHeight;

/// The highest valid version-bits signaling bit (BIP-9 reserves bits `0..=28`;
/// the top three bits of the 32-bit field are fixed to `001` to distinguish
/// version-bits blocks, leaving 29 usable bits, indices `0` through `28`).
pub const MAX_SIGNAL_BIT: u8 = 28;

/// Errors constructing or operating the governance machine.
///
/// All variants describe a *caller* mistake (an invalid deployment definition or
/// a bad registry lookup). The state machine itself is total: once a deployment
/// validates, evaluating its state at any height cannot fail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GovernanceError {
    /// The signaling bit is outside the BIP-9 range `0..=28`.
    #[error("signaling bit {bit} out of range (must be 0..={max})", max = MAX_SIGNAL_BIT)]
    BitOutOfRange {
        /// The offending bit index.
        bit: u8,
    },
    /// The threshold fraction is malformed: the denominator is zero, or the
    /// numerator exceeds the denominator (a fraction greater than one can never
    /// be met and is always a mistake).
    #[error("invalid threshold {num}/{den} (need den > 0 and num <= den)")]
    BadThreshold {
        /// The threshold numerator.
        num: u64,
        /// The threshold denominator.
        den: u64,
    },
    /// The deployment's window length (`period`) is zero; a window must contain
    /// at least one block.
    #[error("period must be greater than zero")]
    ZeroPeriod,
    /// The timeout height is not strictly after the start height, so the
    /// `Started` phase would have no room to signal.
    #[error("timeout height {timeout} must be after start height {start}")]
    TimeoutBeforeStart {
        /// The configured start height.
        start: u64,
        /// The configured timeout height.
        timeout: u64,
    },
    /// A deployment with this name is already registered.
    #[error("deployment {0:?} is already registered")]
    DuplicateDeployment(String),
    /// Two deployments would share the same signaling bit, which would make
    /// their signals indistinguishable.
    #[error("signaling bit {bit} is already used by deployment {existing:?}")]
    DuplicateBit {
        /// The conflicting bit.
        bit: u8,
        /// The name of the deployment that already claims the bit.
        existing: String,
    },
    /// No deployment with this name is registered.
    #[error("unknown deployment {0:?}")]
    UnknownDeployment(String),
}

/// The activation threshold as an exact integer fraction `num/den`.
///
/// Stored as a fraction rather than a float so the lock-in test is bit-for-bit
/// reproducible on every node. For example Bitcoin's mainnet threshold is
/// `1916/2016` (95% of a 2016-block window) and its testnet/`speedy` threshold
/// is `1815/2016` (90%).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Threshold {
    /// Numerator of the activation fraction.
    pub num: u64,
    /// Denominator of the activation fraction (must be non-zero).
    pub den: u64,
}

impl Threshold {
    /// Construct a validated threshold. Requires `den > 0` and `num <= den`
    /// (a fraction in the range `[0, 1]`).
    pub fn new(num: u64, den: u64) -> Result<Self, GovernanceError> {
        if den == 0 || num > den {
            return Err(GovernanceError::BadThreshold { num, den });
        }
        Ok(Threshold { num, den })
    }

    /// Whether `signaling` blocks out of a window of `period` blocks meets this
    /// threshold. Pure integer arithmetic — `signaling/period >= num/den` is
    /// tested by cross-multiplication as `signaling * den >= num * period`, so
    /// there is no rounding and the boundary is exact.
    ///
    /// `u128` intermediates make overflow impossible for any realistic window
    /// (`u64 * u64` cannot overflow `u128`).
    pub fn is_met(&self, signaling: u64, period: u64) -> bool {
        (signaling as u128) * (self.den as u128) >= (self.num as u128) * (period as u128)
    }
}

/// The BIP-9 deployment state. The lifecycle is
/// `Defined → Started → {LockedIn → Active | Failed}`; [`ThresholdState::Active`]
/// and [`ThresholdState::Failed`] are terminal.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum ThresholdState {
    /// The deployment exists but its start height has not yet been reached.
    Defined,
    /// Signaling is open; miners may set the bit and windows are being counted.
    Started,
    /// The threshold was met (or BIP-8 timeout forced it): activation is now
    /// guaranteed at a future window boundary.
    LockedIn,
    /// The upgrade is live and enforced.
    Active,
    /// Signaling timed out without reaching the threshold (only reachable when
    /// `lockinontimeout` is `false`).
    Failed,
}

impl ThresholdState {
    /// Whether this state is terminal (cannot transition further).
    pub const fn is_terminal(self) -> bool {
        matches!(self, ThresholdState::Active | ThresholdState::Failed)
    }
}

/// A named protocol upgrade proposal and the rules for its miner-signaled
/// activation. Constructed via [`Deployment::new`], which enforces every
/// invariant so that the state machine over it is total.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Deployment {
    /// Human-readable, unique name (e.g. `"taproot"`).
    pub name: String,
    /// The signaling bit miners set to vote for this deployment (`0..=28`).
    pub bit: u8,
    /// The first window boundary at which signaling may begin (`Defined →
    /// Started`). Measured in block height.
    pub start_height: BlockHeight,
    /// The window boundary at which an un-locked-in deployment times out. With
    /// `lockinontimeout = false` it then `Fail`s; with `true` it is forced to
    /// `LockedIn` (BIP-8 mandatory activation).
    pub timeout_height: BlockHeight,
    /// The signaling-window length in blocks (the BIP-9 retarget period). Must
    /// be greater than zero.
    pub period: u64,
    /// The activation threshold fraction applied over each `period`-block window.
    pub threshold: Threshold,
    /// The earliest height at which the deployment may become `Active`. Even
    /// after lock-in, the deployment stays `LockedIn` until a window boundary at
    /// or beyond this height (the BIP-9/8 minimum-activation guard).
    pub min_activation_height: BlockHeight,
    /// BIP-8 "lock-in on timeout" (LOT). When `true`, reaching `timeout_height`
    /// without meeting the threshold forces `LockedIn` (a guaranteed flag-day
    /// activation) instead of `Failed`.
    pub lockinontimeout: bool,
}

impl Deployment {
    /// Construct a validated deployment.
    ///
    /// Validates: `bit <= 28`; `period > 0`; the threshold (`den > 0`,
    /// `num <= den`, via [`Threshold`] being pre-validated); and
    /// `timeout_height > start_height`. Returns a [`GovernanceError`] otherwise.
    ///
    /// `min_activation_height` is not range-checked against the other heights: a
    /// value at or below the lock-in window simply imposes no extra delay (the
    /// guard is `window >= min_activation_height`), which is the documented
    /// BIP-9 behavior.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        bit: u8,
        start_height: BlockHeight,
        timeout_height: BlockHeight,
        period: u64,
        threshold: Threshold,
        min_activation_height: BlockHeight,
        lockinontimeout: bool,
    ) -> Result<Self, GovernanceError> {
        if bit > MAX_SIGNAL_BIT {
            return Err(GovernanceError::BitOutOfRange { bit });
        }
        if period == 0 {
            return Err(GovernanceError::ZeroPeriod);
        }
        if timeout_height.get() <= start_height.get() {
            return Err(GovernanceError::TimeoutBeforeStart {
                start: start_height.get(),
                timeout: timeout_height.get(),
            });
        }
        Ok(Deployment {
            name: name.into(),
            bit,
            start_height,
            timeout_height,
            period,
            threshold,
            min_activation_height,
            lockinontimeout,
        })
    }

    /// The window-boundary height at or below `height` — i.e. `height` rounded
    /// down to a multiple of `period`. This is the anchor whose state governs
    /// every block in the window `[window_start, window_start + period)`.
    fn window_start(&self, height: BlockHeight) -> u64 {
        let h = height.get();
        h - (h % self.period)
    }
}

/// A deterministic source of per-block miner signals.
///
/// Implementations answer, for any height, whether the block at that height set
/// a given signaling bit. The state machine ([`state_at`]) reads only through
/// this trait, so the same deployment evaluated against the same signal history
/// always yields the same state — on every node, every time.
pub trait MinerSignals {
    /// `true` iff the block at `height` set signaling `bit`.
    fn signals(&self, height: BlockHeight, bit: u8) -> bool;
}

/// An in-memory, real-data record of the signaling bits each block carried.
///
/// Each entry maps a block height to the 32-bit version-bits mask that block
/// committed. There is no synthetic or default data: a height that was never
/// [`record`](SignalLog::record)ed signals nothing, exactly as an unmined or
/// non-signaling block does. Backed by a [`BTreeMap`] for deterministic
/// iteration and serialization.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct SignalLog {
    /// Recorded signal bitmasks, keyed by block height.
    masks: BTreeMap<u64, u32>,
}

impl SignalLog {
    /// An empty log (no blocks recorded).
    pub fn new() -> Self {
        SignalLog::default()
    }

    /// Record the version-bits `mask` that the block at `height` actually
    /// carried. Re-recording the same height overwrites the previous mask (a
    /// reorg replacing a block). Returns the previous mask, if any.
    pub fn record(&mut self, height: BlockHeight, mask: u32) -> Option<u32> {
        self.masks.insert(height.get(), mask)
    }

    /// Convenience: record a block that set exactly one bit. Bits `> 31` are
    /// out of the version field and record nothing (returns the prior mask
    /// unchanged via a no-op). Most callers use [`record`](SignalLog::record)
    /// with a full mask.
    pub fn record_bit(&mut self, height: BlockHeight, bit: u8) -> Option<u32> {
        if bit >= u32::BITS as u8 {
            return self.masks.get(&height.get()).copied();
        }
        let mask = 1u32 << bit;
        let entry = self.masks.entry(height.get()).or_insert(0);
        let prev = *entry;
        *entry |= mask;
        Some(prev)
    }

    /// Forget the recorded mask at `height` (used when a reorg DISCONNECTS that
    /// block — its signal leaves the active history). Returns the removed mask, if
    /// any. The inverse of [`record`](SignalLog::record).
    pub fn remove(&mut self, height: BlockHeight) -> Option<u32> {
        self.masks.remove(&height.get())
    }

    /// The number of recorded blocks.
    pub fn len(&self) -> usize {
        self.masks.len()
    }

    /// Whether no blocks have been recorded.
    pub fn is_empty(&self) -> bool {
        self.masks.is_empty()
    }
}

impl MinerSignals for SignalLog {
    fn signals(&self, height: BlockHeight, bit: u8) -> bool {
        if bit >= u32::BITS as u8 {
            return false;
        }
        self.masks
            .get(&height.get())
            .is_some_and(|mask| mask & (1u32 << bit) != 0)
    }
}

/// Count the blocks that set the deployment's bit within the window beginning at
/// `window_start` (the half-open range `[window_start, window_start + period)`).
///
/// `O(period)` per call and fully deterministic. Used by the state machine to
/// decide lock-in over a just-completed window.
pub fn signaling_count_in_window<S: MinerSignals>(
    deployment: &Deployment,
    window_start: u64,
    signals: &S,
) -> u64 {
    let mut count = 0u64;
    for offset in 0..deployment.period {
        let h = window_start + offset;
        if signals.signals(BlockHeight::new(h), deployment.bit) {
            count += 1;
        }
    }
    count
}

/// Evaluate a deployment's [`ThresholdState`] as of `height`.
///
/// Walks the windows from genesis to the window containing `height`, applying
/// the BIP-9 (+ optional BIP-8) transitions deterministically. The result is
/// the state in force for the block at `height`. `O(history)` in the number of
/// windows up to `height`, which is the inherent cost of an auditable,
/// reorg-safe state walk.
///
/// State changes only at window boundaries (multiples of `deployment.period`):
/// every block in a window shares that window's state.
pub fn state_at<S: MinerSignals>(
    deployment: &Deployment,
    height: BlockHeight,
    signals: &S,
) -> ThresholdState {
    let target_window = deployment.window_start(height);

    // State at the genesis window is always Defined.
    let mut state = ThresholdState::Defined;
    let mut window = 0u64;

    while window < target_window {
        let next_window = window + deployment.period;
        state = next_state(deployment, state, next_window, window, signals);
        window = next_window;
    }

    state
}

/// The state at window boundary `next_window`, given the state at the previous
/// boundary (`prev_state`, which began at `prev_window`) and the signaling that
/// occurred during the window `[prev_window, next_window)`.
///
/// This is the single source of truth for the transition rules; [`state_at`]
/// merely iterates it.
fn next_state<S: MinerSignals>(
    deployment: &Deployment,
    prev_state: ThresholdState,
    next_window: u64,
    prev_window: u64,
    signals: &S,
) -> ThresholdState {
    match prev_state {
        ThresholdState::Defined => {
            if next_window >= deployment.start_height.get() {
                ThresholdState::Started
            } else {
                ThresholdState::Defined
            }
        }
        ThresholdState::Started => {
            // Did the just-completed window [prev_window, next_window) signal
            // enough to lock in?
            let count = signaling_count_in_window(deployment, prev_window, signals);
            if deployment.threshold.is_met(count, deployment.period) {
                ThresholdState::LockedIn
            } else if next_window >= deployment.timeout_height.get() {
                // Timed out without meeting the threshold.
                if deployment.lockinontimeout {
                    ThresholdState::LockedIn // BIP-8 mandatory activation.
                } else {
                    ThresholdState::Failed
                }
            } else {
                ThresholdState::Started
            }
        }
        ThresholdState::LockedIn => {
            if next_window >= deployment.min_activation_height.get() {
                ThresholdState::Active
            } else {
                ThresholdState::LockedIn // Held back by the activation guard.
            }
        }
        ThresholdState::Active => ThresholdState::Active,
        ThresholdState::Failed => ThresholdState::Failed,
    }
}

/// A registry of named [`Deployment`]s and the entry point for querying their
/// activation state. Deterministic and consensus-safe: deployments are held in a
/// [`BTreeMap`] keyed by name, so iteration order and serialization are stable.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Governance {
    /// Registered deployments, keyed by their unique name.
    deployments: BTreeMap<String, Deployment>,
}

impl Governance {
    /// An empty registry.
    pub fn new() -> Self {
        Governance::default()
    }

    /// Register a deployment. Rejects a duplicate name
    /// ([`GovernanceError::DuplicateDeployment`]) and a signaling bit already
    /// claimed by another registered deployment
    /// ([`GovernanceError::DuplicateBit`]) — two deployments sharing a bit would
    /// make their signals indistinguishable.
    pub fn register(&mut self, deployment: Deployment) -> Result<(), GovernanceError> {
        if self.deployments.contains_key(&deployment.name) {
            return Err(GovernanceError::DuplicateDeployment(deployment.name));
        }
        if let Some(existing) = self.deployments.values().find(|d| d.bit == deployment.bit) {
            return Err(GovernanceError::DuplicateBit {
                bit: deployment.bit,
                existing: existing.name.clone(),
            });
        }
        self.deployments.insert(deployment.name.clone(), deployment);
        Ok(())
    }

    /// Borrow a registered deployment by name.
    pub fn get(&self, name: &str) -> Option<&Deployment> {
        self.deployments.get(name)
    }

    /// The number of registered deployments.
    pub fn len(&self) -> usize {
        self.deployments.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.deployments.is_empty()
    }

    /// The [`ThresholdState`] of the named deployment at `height`, evaluated
    /// against `signals`. Errors with [`GovernanceError::UnknownDeployment`] if
    /// no such deployment is registered.
    pub fn state_of<S: MinerSignals>(
        &self,
        name: &str,
        height: BlockHeight,
        signals: &S,
    ) -> Result<ThresholdState, GovernanceError> {
        let deployment = self
            .deployments
            .get(name)
            .ok_or_else(|| GovernanceError::UnknownDeployment(name.to_owned()))?;
        Ok(state_at(deployment, height, signals))
    }

    /// Whether the named deployment is [`Active`](ThresholdState::Active) at
    /// `height`. An unknown deployment is treated as not active (`false`) — a
    /// rule that is not yet enforced cannot be in force.
    pub fn is_active<S: MinerSignals>(&self, name: &str, height: BlockHeight, signals: &S) -> bool {
        matches!(
            self.state_of(name, height, signals),
            Ok(ThresholdState::Active)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Illustrative test parameters (NOT real-world consensus values): a short
    /// 10-block window with an 8/10 (80%) threshold keeps the hand-computed
    /// expected states small and readable. Real deployments use values like a
    /// 2016-block window at 1916/2016.
    const PERIOD: u64 = 10;

    fn threshold_8_of_10() -> Threshold {
        Threshold::new(8, 10).expect("8/10 is a valid fraction")
    }

    /// A deployment that opens at window 10, times out at window 50, needs 8/10
    /// signaling, has no extra activation delay, and is not LOT.
    fn basic_deployment() -> Deployment {
        Deployment::new(
            "test_upgrade",
            0,
            BlockHeight::new(10),
            BlockHeight::new(50),
            PERIOD,
            threshold_8_of_10(),
            BlockHeight::GENESIS, // no extra activation guard
            false,
        )
        .expect("valid deployment")
    }

    /// Record `count` signaling blocks (for `bit`) starting at `from`, within a
    /// single window. The remaining blocks of the window record an empty mask,
    /// i.e. a real non-signaling block — never fabricated signal data.
    fn record_window(log: &mut SignalLog, from: u64, bit: u8, count: u64) {
        for offset in 0..PERIOD {
            let h = BlockHeight::new(from + offset);
            if offset < count {
                log.record_bit(h, bit);
            } else {
                log.record(h, 0);
            }
        }
    }

    #[test]
    fn threshold_integer_math_is_exact_at_boundary() {
        let t = threshold_8_of_10();
        // 8 of 10 meets 80%; 7 of 10 does not. No rounding either way.
        assert!(t.is_met(8, 10));
        assert!(!t.is_met(7, 10));
        // Equivalent fractions agree: 800/1000 == 80/100 == 8/10.
        let t2 = Threshold::new(800, 1000).unwrap();
        assert!(t2.is_met(8, 10));
        assert!(!t2.is_met(7, 10));
        // A 95% threshold over a 2016 window: 1916 meets, 1915 does not — the
        // exact Bitcoin mainnet boundary.
        let btc = Threshold::new(1916, 2016).unwrap();
        assert!(btc.is_met(1916, 2016));
        assert!(!btc.is_met(1915, 2016));
    }

    #[test]
    fn threshold_validation() {
        assert_eq!(
            Threshold::new(1, 0),
            Err(GovernanceError::BadThreshold { num: 1, den: 0 })
        );
        assert_eq!(
            Threshold::new(11, 10),
            Err(GovernanceError::BadThreshold { num: 11, den: 10 })
        );
        assert!(Threshold::new(0, 10).is_ok()); // 0% is a valid (trivially met) fraction
        assert!(Threshold::new(10, 10).is_ok()); // 100% is valid
    }

    #[test]
    fn never_started_before_start_height() {
        let d = basic_deployment();
        let log = SignalLog::new();
        // Start height is 10, so windows at 0 are still Defined.
        assert_eq!(
            state_at(&d, BlockHeight::new(0), &log),
            ThresholdState::Defined
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(9), &log),
            ThresholdState::Defined
        );
        // At the window boundary 10 it becomes Started.
        assert_eq!(
            state_at(&d, BlockHeight::new(10), &log),
            ThresholdState::Started
        );
    }

    #[test]
    fn exactly_at_threshold_locks_in() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        // The Started window is [10, 20). Signal in exactly 8 of its 10 blocks.
        record_window(&mut log, 10, d.bit, 8);
        // Within the signaling window itself, still Started (lock-in is decided
        // at the *next* boundary, evaluating the completed window).
        assert_eq!(
            state_at(&d, BlockHeight::new(15), &log),
            ThresholdState::Started
        );
        // At boundary 20, the completed [10,20) window's 8/10 meets the
        // threshold -> LockedIn.
        assert_eq!(
            state_at(&d, BlockHeight::new(20), &log),
            ThresholdState::LockedIn
        );
    }

    #[test]
    fn one_signal_below_threshold_does_not_lock_in() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        // 7 of 10 in [10, 20) — one below the 8/10 bar.
        record_window(&mut log, 10, d.bit, 7);
        // ...and keep failing to signal in later windows so it stays Started.
        record_window(&mut log, 20, d.bit, 7);
        record_window(&mut log, 30, d.bit, 7);
        assert_eq!(
            state_at(&d, BlockHeight::new(20), &log),
            ThresholdState::Started
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(40), &log),
            ThresholdState::Started
        );
    }

    #[test]
    fn timeout_without_threshold_fails() {
        let d = basic_deployment(); // lockinontimeout = false, timeout window = 50
        let mut log = SignalLog::new();
        // Never reach the threshold in any window (7/10 throughout).
        for w in (10..60).step_by(PERIOD as usize) {
            record_window(&mut log, w, d.bit, 7);
        }
        // Before timeout: still Started.
        assert_eq!(
            state_at(&d, BlockHeight::new(40), &log),
            ThresholdState::Started
        );
        // At/after the timeout boundary (50): Failed.
        assert_eq!(
            state_at(&d, BlockHeight::new(50), &log),
            ThresholdState::Failed
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(100), &log),
            ThresholdState::Failed
        );
    }

    #[test]
    fn lockinontimeout_forces_lockin_then_active() {
        // BIP-8 mandatory activation: same as basic, but LOT = true.
        let d = Deployment::new(
            "mandatory",
            3,
            BlockHeight::new(10),
            BlockHeight::new(50),
            PERIOD,
            threshold_8_of_10(),
            BlockHeight::GENESIS,
            true, // lockinontimeout
        )
        .unwrap();
        let mut log = SignalLog::new();
        // Miners never meet the threshold (only 1/10 each window).
        for w in (10..70).step_by(PERIOD as usize) {
            record_window(&mut log, w, d.bit, 1);
        }
        // Before timeout: Started.
        assert_eq!(
            state_at(&d, BlockHeight::new(40), &log),
            ThresholdState::Started
        );
        // At the timeout boundary (50): LOT forces LockedIn despite no threshold.
        assert_eq!(
            state_at(&d, BlockHeight::new(50), &log),
            ThresholdState::LockedIn
        );
        // Next boundary (60): Active.
        assert_eq!(
            state_at(&d, BlockHeight::new(60), &log),
            ThresholdState::Active
        );
    }

    #[test]
    fn min_activation_height_delays_active_past_lockin() {
        // Same as basic but cannot activate before height 40.
        let d = Deployment::new(
            "delayed",
            5,
            BlockHeight::new(10),
            BlockHeight::new(100),
            PERIOD,
            threshold_8_of_10(),
            BlockHeight::new(40), // min_activation_height
            false,
        )
        .unwrap();
        let mut log = SignalLog::new();
        // Lock in immediately: 8/10 in the first signaling window [10, 20).
        record_window(&mut log, 10, d.bit, 8);
        // Subsequent windows do not matter for a locked-in deployment, but record
        // real empty blocks so the log is honest.
        record_window(&mut log, 20, d.bit, 0);
        record_window(&mut log, 30, d.bit, 0);
        record_window(&mut log, 40, d.bit, 0);

        // LockedIn at 20.
        assert_eq!(
            state_at(&d, BlockHeight::new(20), &log),
            ThresholdState::LockedIn
        );
        // Still LockedIn at 30 — below min_activation_height (40).
        assert_eq!(
            state_at(&d, BlockHeight::new(30), &log),
            ThresholdState::LockedIn
        );
        // Active exactly at the min_activation_height boundary (40).
        assert_eq!(
            state_at(&d, BlockHeight::new(40), &log),
            ThresholdState::Active
        );
    }

    #[test]
    fn full_happy_path_defined_started_lockedin_active() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        // Below-threshold while warming up, then a clean lock-in window.
        record_window(&mut log, 10, d.bit, 3); // [10,20): not enough
        record_window(&mut log, 20, d.bit, 9); // [20,30): 9/10, locks in at 30
        record_window(&mut log, 30, d.bit, 0); // post lock-in blocks

        assert_eq!(
            state_at(&d, BlockHeight::new(5), &log),
            ThresholdState::Defined
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(10), &log),
            ThresholdState::Started
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(20), &log),
            ThresholdState::Started
        );
        assert_eq!(
            state_at(&d, BlockHeight::new(30), &log),
            ThresholdState::LockedIn
        );
        // No min_activation_height delay -> Active at the very next boundary.
        assert_eq!(
            state_at(&d, BlockHeight::new(40), &log),
            ThresholdState::Active
        );
        // Terminal: stays Active forever.
        assert_eq!(
            state_at(&d, BlockHeight::new(1_000), &log),
            ThresholdState::Active
        );
    }

    #[test]
    fn state_is_constant_within_a_window() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        record_window(&mut log, 10, d.bit, 8); // locks in at 20
                                               // Every height in [20, 30) reports the same LockedIn state.
        for h in 20..30 {
            assert_eq!(
                state_at(&d, BlockHeight::new(h), &log),
                ThresholdState::LockedIn
            );
        }
    }

    #[test]
    fn determinism_repeated_evaluation_is_identical() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        record_window(&mut log, 10, d.bit, 8);
        record_window(&mut log, 20, d.bit, 0);
        let heights = [0u64, 9, 10, 15, 20, 25, 30, 99];
        // Evaluate the whole sequence twice; the two runs must match exactly.
        let first: Vec<_> = heights
            .iter()
            .map(|&h| state_at(&d, BlockHeight::new(h), &log))
            .collect();
        let second: Vec<_> = heights
            .iter()
            .map(|&h| state_at(&d, BlockHeight::new(h), &log))
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn signaling_count_counts_only_the_window_and_only_the_bit() {
        let d = basic_deployment();
        let mut log = SignalLog::new();
        // 8 signaling blocks in [10, 20).
        record_window(&mut log, 10, d.bit, 8);
        // A signaling block in the *next* window must not be counted here.
        log.record_bit(BlockHeight::new(20), d.bit);
        // A *different* bit set inside the window must not be counted.
        log.record_bit(BlockHeight::new(11), d.bit + 1);
        assert_eq!(signaling_count_in_window(&d, 10, &log), 8);
        assert_eq!(signaling_count_in_window(&d, 20, &log), 1);
    }

    #[test]
    fn signal_log_remove_is_the_exact_inverse_of_record() {
        // A reorg disconnecting a block must remove its signal so the log returns to
        // exactly its prior state — record then remove is a no-op.
        let mut log = SignalLog::new();
        log.record(BlockHeight::new(10), 0b11);
        let before_len = log.len();
        log.record(BlockHeight::new(11), 0b1);
        assert_eq!(log.remove(BlockHeight::new(11)), Some(0b1));
        assert_eq!(log.len(), before_len, "removed exactly the added height");
        assert!(!log.signals(BlockHeight::new(11), 0), "height 11 is gone");
        assert!(
            log.signals(BlockHeight::new(10), 0),
            "untouched height remains"
        );
        // Removing an absent height is a harmless None.
        assert_eq!(log.remove(BlockHeight::new(99)), None);
    }

    #[test]
    fn signal_log_records_real_masks_only() {
        let mut log = SignalLog::new();
        assert!(log.is_empty());
        // An unrecorded height signals nothing.
        assert!(!log.signals(BlockHeight::new(7), 0));
        // Record a multi-bit mask and read individual bits back.
        log.record(BlockHeight::new(7), 0b101); // bits 0 and 2
        assert!(log.signals(BlockHeight::new(7), 0));
        assert!(!log.signals(BlockHeight::new(7), 1));
        assert!(log.signals(BlockHeight::new(7), 2));
        assert_eq!(log.len(), 1);
        // record_bit ORs in without clobbering existing bits.
        log.record_bit(BlockHeight::new(7), 1);
        assert!(log.signals(BlockHeight::new(7), 1));
        // Out-of-field bits never signal.
        assert!(!log.signals(BlockHeight::new(7), 40));
    }

    #[test]
    fn deployment_validation_rejects_bad_input() {
        let t = threshold_8_of_10();
        // Bit out of range.
        assert_eq!(
            Deployment::new(
                "x",
                29,
                BlockHeight::new(1),
                BlockHeight::new(2),
                1,
                t,
                BlockHeight::GENESIS,
                false
            ),
            Err(GovernanceError::BitOutOfRange { bit: 29 })
        );
        // Zero period.
        assert_eq!(
            Deployment::new(
                "x",
                0,
                BlockHeight::new(1),
                BlockHeight::new(2),
                0,
                t,
                BlockHeight::GENESIS,
                false
            ),
            Err(GovernanceError::ZeroPeriod)
        );
        // Timeout not after start.
        assert_eq!(
            Deployment::new(
                "x",
                0,
                BlockHeight::new(20),
                BlockHeight::new(20),
                10,
                t,
                BlockHeight::GENESIS,
                false
            ),
            Err(GovernanceError::TimeoutBeforeStart {
                start: 20,
                timeout: 20
            })
        );
        // The maximum legal bit (28) is accepted.
        assert!(Deployment::new(
            "x",
            28,
            BlockHeight::new(1),
            BlockHeight::new(2),
            1,
            t,
            BlockHeight::GENESIS,
            false
        )
        .is_ok());
    }

    #[test]
    fn registry_register_query_and_errors() {
        let mut gov = Governance::new();
        assert!(gov.is_empty());
        let d = basic_deployment();
        gov.register(d.clone())
            .expect("first registration succeeds");
        assert_eq!(gov.len(), 1);
        assert_eq!(gov.get("test_upgrade"), Some(&d));

        // Duplicate name is rejected.
        assert_eq!(
            gov.register(d.clone()),
            Err(GovernanceError::DuplicateDeployment(
                "test_upgrade".to_owned()
            ))
        );

        // A different name sharing bit 0 is rejected.
        let same_bit = Deployment::new(
            "other",
            0,
            BlockHeight::new(10),
            BlockHeight::new(50),
            PERIOD,
            threshold_8_of_10(),
            BlockHeight::GENESIS,
            false,
        )
        .unwrap();
        assert_eq!(
            gov.register(same_bit),
            Err(GovernanceError::DuplicateBit {
                bit: 0,
                existing: "test_upgrade".to_owned()
            })
        );

        // A distinct name and bit registers fine.
        let other = Deployment::new(
            "other",
            1,
            BlockHeight::new(10),
            BlockHeight::new(50),
            PERIOD,
            threshold_8_of_10(),
            BlockHeight::GENESIS,
            false,
        )
        .unwrap();
        gov.register(other).unwrap();
        assert_eq!(gov.len(), 2);
    }

    #[test]
    fn registry_state_of_and_is_active() {
        let mut gov = Governance::new();
        let d = basic_deployment();
        gov.register(d.clone()).unwrap();
        let mut log = SignalLog::new();
        record_window(&mut log, 10, d.bit, 8); // locks in at 20, active at 30

        assert_eq!(
            gov.state_of("test_upgrade", BlockHeight::new(5), &log),
            Ok(ThresholdState::Defined)
        );
        assert!(!gov.is_active("test_upgrade", BlockHeight::new(20), &log)); // LockedIn, not Active
        assert!(gov.is_active("test_upgrade", BlockHeight::new(30), &log));

        // Unknown deployment: error from state_of, false from is_active.
        assert_eq!(
            gov.state_of("missing", BlockHeight::new(30), &log),
            Err(GovernanceError::UnknownDeployment("missing".to_owned()))
        );
        assert!(!gov.is_active("missing", BlockHeight::new(30), &log));
    }

    #[test]
    fn terminal_state_predicate() {
        assert!(ThresholdState::Active.is_terminal());
        assert!(ThresholdState::Failed.is_terminal());
        assert!(!ThresholdState::Defined.is_terminal());
        assert!(!ThresholdState::Started.is_terminal());
        assert!(!ThresholdState::LockedIn.is_terminal());
    }

    #[test]
    fn borsh_roundtrip_of_persistent_types() {
        // Persistent consensus types must survive a byte-exact borsh round-trip.
        let d = basic_deployment();
        let bytes = borsh::to_vec(&d).unwrap();
        let back: Deployment = borsh::from_slice(&bytes).unwrap();
        assert_eq!(d, back);

        let mut gov = Governance::new();
        gov.register(d).unwrap();
        let gbytes = borsh::to_vec(&gov).unwrap();
        let gback: Governance = borsh::from_slice(&gbytes).unwrap();
        assert_eq!(gov, gback);

        let mut log = SignalLog::new();
        log.record(BlockHeight::new(3), 0b1011);
        let lbytes = borsh::to_vec(&log).unwrap();
        let lback: SignalLog = borsh::from_slice(&lbytes).unwrap();
        assert_eq!(log, lback);
    }
}
