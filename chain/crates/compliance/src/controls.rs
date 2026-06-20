//! Institutional compliance controls.
//!
//! Regulated institutions need controls a bare balance cannot express. A
//! [`CompliancePolicy`] is configuration an account attaches to itself (or that a
//! supervising authority attaches) to constrain how value may leave it:
//!
//! - **Freeze** — a regulator hold that blocks all outgoing transfers.
//! - **Counterparty control** — an allow-list (only approved counterparties, e.g.
//!   KYC'd accounts) or a deny-list (everyone except sanctioned accounts).
//! - **Spend velocity limit** — a cap on total outgoing value per rolling window
//!   of blocks (an anti-money-laundering / risk control).
//!
//! [`CompliancePolicy::check_transfer`] is a pure decision function: given the
//! account's rolling [`SpendWindow`], it either rejects the transfer with a
//! specific [`ComplianceError`] or returns the updated window to persist. Keeping
//! it pure makes the policy independently testable; enforcing it inside the
//! runtime's transfer path is the integration follow-on.

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::{AccountId, Balance};

/// How an account's outgoing counterparties are restricted.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum TransferControl {
    /// No counterparty restriction.
    Unrestricted,
    /// Only these counterparties may receive (whitelist).
    AllowList(BTreeSet<AccountId>),
    /// All counterparties except these may receive (blacklist).
    DenyList(BTreeSet<AccountId>),
}

impl TransferControl {
    /// Whether a transfer to `to` is permitted by this control.
    pub fn permits(&self, to: &AccountId) -> bool {
        match self {
            TransferControl::Unrestricted => true,
            TransferControl::AllowList(set) => set.contains(to),
            TransferControl::DenyList(set) => !set.contains(to),
        }
    }
}

/// A spend-velocity limit: at most `max_per_window` may leave the account within
/// any `window_blocks`-long window.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct SpendLimit {
    /// Maximum total outgoing value within one window.
    pub max_per_window: Balance,
    /// Window length, in blocks.
    pub window_blocks: u64,
}

/// The rolling accounting state for a [`SpendLimit`]: how much has been spent in
/// the window that began at `window_start`.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct SpendWindow {
    /// Height at which the current window began.
    pub window_start: u64,
    /// Total spent so far within the current window.
    pub spent: Balance,
}

impl SpendWindow {
    /// A fresh window starting at height 0 with nothing spent.
    pub fn new() -> Self {
        SpendWindow::default()
    }
}

/// An account's institutional compliance policy.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct CompliancePolicy {
    /// When true, a regulator hold blocks all outgoing transfers.
    pub frozen: bool,
    /// Counterparty restriction.
    pub transfer_control: TransferControl,
    /// Optional spend-velocity cap.
    pub spend_limit: Option<SpendLimit>,
}

impl Default for CompliancePolicy {
    fn default() -> Self {
        // The permissive default: no freeze, no counterparty or velocity limits.
        CompliancePolicy {
            frozen: false,
            transfer_control: TransferControl::Unrestricted,
            spend_limit: None,
        }
    }
}

impl CompliancePolicy {
    /// A permissive policy (no controls).
    pub fn unrestricted() -> Self {
        CompliancePolicy::default()
    }

    /// Decide whether the account may send `amount` to `to` at `height`, given
    /// its current rolling `window`. On approval, returns the updated window to
    /// persist (the window rolls over once `window_blocks` have elapsed). On
    /// rejection, returns the specific [`ComplianceError`] and the window is
    /// unchanged.
    pub fn check_transfer(
        &self,
        to: &AccountId,
        amount: Balance,
        height: u64,
        window: &SpendWindow,
    ) -> Result<SpendWindow, ComplianceError> {
        if self.frozen {
            return Err(ComplianceError::Frozen);
        }
        if !self.transfer_control.permits(to) {
            return Err(ComplianceError::CounterpartyBlocked { to: to.to_string() });
        }

        match self.spend_limit {
            None => Ok(*window),
            Some(limit) => {
                // Roll the window forward if the prior one has fully elapsed.
                let window_elapsed =
                    height.saturating_sub(window.window_start) >= limit.window_blocks;
                let base = if window_elapsed {
                    SpendWindow {
                        window_start: height,
                        spent: Balance::ZERO,
                    }
                } else {
                    *window
                };
                let new_spent = base
                    .spent
                    .checked_add(amount)
                    .ok_or(ComplianceError::Overflow)?;
                if new_spent > limit.max_per_window {
                    return Err(ComplianceError::SpendLimitExceeded {
                        limit: limit.max_per_window.grains(),
                        window_spent: base.spent.grains(),
                        attempted: amount.grains(),
                    });
                }
                Ok(SpendWindow {
                    window_start: base.window_start,
                    spent: new_spent,
                })
            }
        }
    }
}

/// Why a transfer was blocked by an account's compliance policy.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComplianceError {
    /// The account is frozen (regulator hold).
    #[error("account is frozen: outgoing transfers are blocked")]
    Frozen,
    /// The counterparty is not permitted by the account's transfer control.
    #[error("counterparty {to} is not permitted by the account's transfer control")]
    CounterpartyBlocked {
        /// The blocked recipient.
        to: String,
    },
    /// The transfer would exceed the spend-velocity limit for the window.
    #[error("spend limit exceeded: limit {limit}, already spent {window_spent}, attempted {attempted} (grains) this window")]
    SpendLimitExceeded {
        /// The per-window cap, in grains.
        limit: u128,
        /// Already spent this window, in grains.
        window_spent: u128,
        /// The attempted amount, in grains.
        attempted: u128,
    },
    /// Spend accounting overflowed (unreachable under the supply cap).
    #[error("spend accounting overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }
    fn sov(n: u128) -> Balance {
        Balance::from_sov(n).unwrap()
    }

    #[test]
    fn frozen_blocks_all_transfers() {
        let policy = CompliancePolicy {
            frozen: true,
            ..CompliancePolicy::default()
        };
        assert_eq!(
            policy.check_transfer(&id("vendor.sov"), sov(1), 0, &SpendWindow::new()),
            Err(ComplianceError::Frozen)
        );
    }

    #[test]
    fn allow_list_only_permits_listed_counterparties() {
        let policy = CompliancePolicy {
            transfer_control: TransferControl::AllowList([id("vendor.sov")].into_iter().collect()),
            ..CompliancePolicy::default()
        };
        assert!(policy
            .check_transfer(&id("vendor.sov"), sov(1), 0, &SpendWindow::new())
            .is_ok());
        assert!(matches!(
            policy.check_transfer(&id("stranger.sov"), sov(1), 0, &SpendWindow::new()),
            Err(ComplianceError::CounterpartyBlocked { .. })
        ));
    }

    #[test]
    fn deny_list_blocks_listed_counterparties() {
        let policy = CompliancePolicy {
            transfer_control: TransferControl::DenyList(
                [id("sanctioned.sov")].into_iter().collect(),
            ),
            ..CompliancePolicy::default()
        };
        assert!(policy
            .check_transfer(&id("anyone.sov"), sov(1), 0, &SpendWindow::new())
            .is_ok());
        assert!(matches!(
            policy.check_transfer(&id("sanctioned.sov"), sov(1), 0, &SpendWindow::new()),
            Err(ComplianceError::CounterpartyBlocked { .. })
        ));
    }

    #[test]
    fn spend_limit_accumulates_within_a_window() {
        let policy = CompliancePolicy {
            spend_limit: Some(SpendLimit {
                max_per_window: sov(100),
                window_blocks: 10,
            }),
            ..CompliancePolicy::default()
        };
        // Spend 60 at height 1.
        let w = policy
            .check_transfer(&id("v.sov"), sov(60), 1, &SpendWindow::new())
            .unwrap();
        assert_eq!(w.spent, sov(60));
        // Another 40 at height 5 (same window): total 100, at the cap.
        let w = policy.check_transfer(&id("v.sov"), sov(40), 5, &w).unwrap();
        assert_eq!(w.spent, sov(100));
        // One more grain exceeds the cap.
        assert!(matches!(
            policy.check_transfer(&id("v.sov"), Balance::from_grains(1), 6, &w),
            Err(ComplianceError::SpendLimitExceeded { .. })
        ));
    }

    #[test]
    fn spend_window_rolls_over_after_elapsing() {
        let policy = CompliancePolicy {
            spend_limit: Some(SpendLimit {
                max_per_window: sov(100),
                window_blocks: 10,
            }),
            ..CompliancePolicy::default()
        };
        // Spend the full 100 in the first window (starts at height 1).
        let w = policy
            .check_transfer(&id("v.sov"), sov(100), 1, &SpendWindow::new())
            .unwrap();
        assert_eq!(w.spent, sov(100));
        // At height 11 (>= 1 + 10) the window has elapsed; spending resets.
        let w = policy
            .check_transfer(&id("v.sov"), sov(80), 11, &w)
            .unwrap();
        assert_eq!(w.window_start, 11);
        assert_eq!(w.spent, sov(80));
    }

    #[test]
    fn combined_controls_all_apply() {
        // Allow-list + spend limit together.
        let policy = CompliancePolicy {
            frozen: false,
            transfer_control: TransferControl::AllowList([id("v.sov")].into_iter().collect()),
            spend_limit: Some(SpendLimit {
                max_per_window: sov(50),
                window_blocks: 100,
            }),
        };
        // Allowed counterparty within limit.
        assert!(policy
            .check_transfer(&id("v.sov"), sov(50), 0, &SpendWindow::new())
            .is_ok());
        // Allowed counterparty over limit.
        assert!(matches!(
            policy.check_transfer(&id("v.sov"), sov(51), 0, &SpendWindow::new()),
            Err(ComplianceError::SpendLimitExceeded { .. })
        ));
        // Disallowed counterparty fails before the limit is even consulted.
        assert!(matches!(
            policy.check_transfer(&id("x.sov"), sov(1), 0, &SpendWindow::new()),
            Err(ComplianceError::CounterpartyBlocked { .. })
        ));
    }

    #[test]
    fn unrestricted_policy_permits_everything() {
        let policy = CompliancePolicy::unrestricted();
        let w = policy
            .check_transfer(&id("anyone.sov"), sov(1_000_000), 0, &SpendWindow::new())
            .unwrap();
        // No limit configured => window unchanged.
        assert_eq!(w, SpendWindow::new());
    }

    #[test]
    fn borsh_roundtrip() {
        let policy = CompliancePolicy {
            frozen: false,
            transfer_control: TransferControl::DenyList([id("bad.sov")].into_iter().collect()),
            spend_limit: Some(SpendLimit {
                max_per_window: sov(10),
                window_blocks: 5,
            }),
        };
        let bytes = borsh::to_vec(&policy).unwrap();
        assert_eq!(
            borsh::from_slice::<CompliancePolicy>(&bytes).unwrap(),
            policy
        );
    }
}
