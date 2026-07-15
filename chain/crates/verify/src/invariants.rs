//! Protocol-wide invariants — the mathematical guarantees that must hold after
//! every block, re-checkable independently of the code that produced the state.
//!
//! Two kinds, both exact integer arithmetic over `u128` grains:
//!
//! - **State invariants** ([`check_ledger`]) hold for any single ledger state:
//!   total supply is within the hard cap, and the mining emission — the chain's
//!   ONLY emission source (proof of work; there is no staking) — stays within
//!   its budget.
//! - **Transition invariants** ([`check_transition`]) relate a `before -> after`
//!   pair: every grain of supply change is accounted for by the mining emission
//!   counter alone. Formally `supply_after == supply_before + Δmined`, which
//!   simultaneously proves **value conservation** (transfers move value, never
//!   create or destroy it) and **no unauthorized mint** (supply can only rise via
//!   the coinbase counter). There is no burn: SOV is not deflationary.

use std::collections::HashMap;

use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance, Hash, MAX_SUPPLY_GRAINS};
use sov_state::Ledger;

/// The small slice of a pre-state that [`check_transition`] compares a post-state
/// against: the supply/emission scalars plus each asset's identity and monotonic
/// counters. Captured with [`TransitionPre::capture`] — O(#assets), cheap — so a caller
/// validating one block need NOT deep-clone the whole ledger (whose authenticated SMT is
/// the dominant cost) just to hold onto the pre-state. This is what lets network import
/// execute in place (with an undo journal for rollback) instead of cloning per block.
pub struct TransitionPre {
    supply: u128,
    mined: u128,
    tokens: HashMap<Hash, TokenPre>,
}

struct TokenPre {
    issuer: AccountId,
    symbol: String,
    issued: Balance,
    burned: Balance,
}

impl TransitionPre {
    /// Capture the transition-relevant pre-state from `ledger`.
    pub fn capture(ledger: &Ledger) -> Result<Self, InvariantViolation> {
        let supply = ledger
            .total_supply()
            .ok_or(InvariantViolation::SupplyOverflow)?
            .grains();
        let mined = ledger.mined_emitted().grains();
        let tokens = ledger
            .token_iter()
            .map(|(asset, info)| {
                (
                    *asset,
                    TokenPre {
                        issuer: info.issuer.clone(),
                        symbol: info.symbol.clone(),
                        issued: info.issued,
                        burned: info.burned,
                    },
                )
            })
            .collect();
        Ok(Self {
            supply,
            mined,
            tokens,
        })
    }
}

/// A violated protocol invariant. Each variant names the exact quantities so a
/// failure is diagnosable, not merely "invalid".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvariantViolation {
    /// Total supply exceeds the hard cap.
    #[error("total supply {supply} grains exceeds the cap {cap}")]
    SupplyCapExceeded {
        /// Observed total supply, in grains.
        supply: u128,
        /// The protocol cap ([`MAX_SUPPLY_GRAINS`]).
        cap: u128,
    },
    /// Cumulative mined emission exceeds the mining budget.
    #[error("mined emission {mined} grains exceeds the mining budget {budget}")]
    MiningBudgetExceeded {
        /// Cumulative mined emission, in grains.
        mined: u128,
        /// The configured mining budget.
        budget: u128,
    },
    /// A balance sum overflowed `u128` (impossible under the cap, but checked
    /// rather than assumed).
    #[error("supply arithmetic overflowed u128")]
    SupplyOverflow,
    /// An emission counter moved backward; emission must be monotonic.
    #[error("{kind} emission regressed: {before} -> {after} grains")]
    EmissionRegressed {
        /// Which counter regressed (currently always `"mined"`).
        kind: &'static str,
        /// Counter value before the transition.
        before: u128,
        /// Counter value after the transition.
        after: u128,
    },
    /// New supply is not exactly accounted for by the emission counter: value was
    /// created from nothing (unauthorized mint) or destroyed.
    #[error("value not conserved: supply {supply_before} -> {supply_after} grains, but minted {minted_delta}")]
    ValueNotConserved {
        /// Total supply before the transition.
        supply_before: u128,
        /// Total supply after the transition.
        supply_after: u128,
        /// Grains minted across the transition (`Δmined`).
        minted_delta: u128,
    },
    /// A native asset's balances do not sum to its recorded supply
    /// (`issued − burned`): units were created from nothing or destroyed
    /// without being recorded.
    #[error("token {asset} not conserved: balances sum to {sum} units, but issued {issued} − burned {burned}")]
    TokenNotConserved {
        /// The asset id (hex).
        asset: String,
        /// Sum of all holder balances of the asset, in units.
        sum: u128,
        /// The asset's cumulative issuance counter.
        issued: u128,
        /// The asset's cumulative burn counter.
        burned: u128,
    },
    /// A native asset's burn counter exceeds its issuance counter — more units
    /// destroyed than were ever minted.
    #[error("token {asset} burned {burned} units exceeds issued {issued}")]
    TokenBurnExceedsIssued {
        /// The asset id (hex).
        asset: String,
        /// The asset's cumulative issuance counter.
        issued: u128,
        /// The asset's cumulative burn counter.
        burned: u128,
    },
    /// A native asset's issuance or burn counter moved backward; both are
    /// monotonic for the life of the asset.
    #[error("token {asset} {kind} counter regressed: {before} -> {after} units")]
    TokenCounterRegressed {
        /// The asset id (hex).
        asset: String,
        /// Which counter regressed (`"issued"` or `"burned"`).
        kind: &'static str,
        /// Counter value before the transition.
        before: u128,
        /// Counter value after the transition.
        after: u128,
    },
    /// A native asset's immutable identity (issuer or symbol) changed, or the
    /// asset disappeared. Once created, an asset's issuance record is permanent
    /// and its identity fixed.
    #[error("token {asset} identity mutated or asset vanished across the transition")]
    TokenIdentityMutated {
        /// The asset id (hex).
        asset: String,
    },
    /// A token balance sum overflowed `u128` — the per-asset analog of
    /// [`InvariantViolation::SupplyOverflow`].
    #[error("token balance arithmetic overflowed u128")]
    TokenSupplyOverflow,
    /// Orphaned compliance state: a policy for an asset that does not exist, or
    /// a spend window for an asset with no policy — committed state with no
    /// governing object.
    #[error("orphaned token compliance state for asset {asset}: {kind}")]
    TokenComplianceOrphaned {
        /// The asset id (hex).
        asset: String,
        /// What was orphaned (`"policy without asset"` or `"window without policy"`).
        kind: &'static str,
    },
}

/// Check the invariants that must hold for any single ledger state: total supply
/// within the cap, and the mining emission (the only emission source) within
/// its budget.
pub fn check_ledger(ledger: &Ledger, mining: &MiningPolicy) -> Result<(), InvariantViolation> {
    let supply = ledger
        .total_supply()
        .ok_or(InvariantViolation::SupplyOverflow)?
        .grains();
    if supply > MAX_SUPPLY_GRAINS {
        return Err(InvariantViolation::SupplyCapExceeded {
            supply,
            cap: MAX_SUPPLY_GRAINS,
        });
    }

    let mined = ledger.mined_emitted().grains();
    if mined > mining.mining_budget_grains {
        return Err(InvariantViolation::MiningBudgetExceeded {
            mined,
            budget: mining.mining_budget_grains,
        });
    }

    check_token_conservation(ledger)?;

    Ok(())
}

/// The per-asset conservation theorem, checked for every native asset: the sum
/// of all holder balances equals the asset's recorded supply (`issued −
/// burned`), with `burned ≤ issued`. This is the token analog of the native
/// supply theorem — units enter circulation only through the issuance counter
/// and leave it only through the burn counter; a transfer changes neither.
fn check_token_conservation(ledger: &Ledger) -> Result<(), InvariantViolation> {
    // Sum every asset's balances in one ordered pass (the balance map is keyed
    // by (asset, holder), so each asset's entries are contiguous).
    let mut sums: std::collections::BTreeMap<sov_primitives::Hash, u128> =
        std::collections::BTreeMap::new();
    for ((asset, _), balance) in ledger.token_balance_iter() {
        let entry = sums.entry(*asset).or_insert(0);
        *entry = entry
            .checked_add(balance.grains())
            .ok_or(InvariantViolation::TokenSupplyOverflow)?;
    }

    for (asset, info) in ledger.token_iter() {
        let issued = info.issued.grains();
        let burned = info.burned.grains();
        if burned > issued {
            return Err(InvariantViolation::TokenBurnExceedsIssued {
                asset: asset.to_string(),
                issued,
                burned,
            });
        }
        let sum = sums.remove(asset).unwrap_or(0);
        if sum != issued - burned {
            return Err(InvariantViolation::TokenNotConserved {
                asset: asset.to_string(),
                sum,
                issued,
                burned,
            });
        }
    }

    // Any balance left in `sums` belongs to an asset with no issuance record:
    // units that exist without ever having been issued.
    if let Some((asset, sum)) = sums.into_iter().next() {
        return Err(InvariantViolation::TokenNotConserved {
            asset: asset.to_string(),
            sum,
            issued: 0,
            burned: 0,
        });
    }

    // Compliance state must be anchored: a policy needs its asset, a velocity
    // window needs a policy (windows are cleared whenever a policy is replaced,
    // so a window without one is unreachable through the runtime).
    for (asset, _) in ledger.token_policy_iter() {
        if ledger.token(asset).is_none() {
            return Err(InvariantViolation::TokenComplianceOrphaned {
                asset: asset.to_string(),
                kind: "policy without asset",
            });
        }
    }
    for ((asset, _), _) in ledger.token_window_iter() {
        if ledger.token_policy(asset).is_none() {
            return Err(InvariantViolation::TokenComplianceOrphaned {
                asset: asset.to_string(),
                kind: "window without policy",
            });
        }
    }

    Ok(())
}

/// Check the invariant relating a `before -> after` transition (e.g. importing
/// one block): all new supply is accounted for by the emission counters.
///
/// The theorem enforced is `supply_after == supply_before + Δmined`, with `mined`
/// required to be monotonic. A transfer keeps supply and the counter fixed
/// (Δ = 0); a block coinbase raises supply and `mined` by the same amount (the
/// coinbase tax only changes *who* is credited, not the total). There is no
/// burn, so supply never decreases. Any other change to supply is a violation.
pub fn check_transition(before: &Ledger, after: &Ledger) -> Result<(), InvariantViolation> {
    check_transition_pre(&TransitionPre::capture(before)?, after)
}

/// Identical to [`check_transition`], but the pre-state is a cheap captured
/// [`TransitionPre`] rather than a full `&Ledger`. This lets the import path execute a
/// block IN PLACE (rolling back via the undo journal on failure) instead of deep-cloning
/// the entire ledger every block — the clone that dominated live-chain import time.
pub fn check_transition_pre(
    before: &TransitionPre,
    after: &Ledger,
) -> Result<(), InvariantViolation> {
    let supply_before = before.supply;
    let supply_after = after
        .total_supply()
        .ok_or(InvariantViolation::SupplyOverflow)?
        .grains();

    let mined_before = before.mined;
    let mined_after = after.mined_emitted().grains();
    if mined_after < mined_before {
        return Err(InvariantViolation::EmissionRegressed {
            kind: "mined",
            before: mined_before,
            after: mined_after,
        });
    }

    // Grains minted (Δmined) across the transition. Non-negative (monotonicity
    // checked above) and bounded by the cap, so the arithmetic cannot overflow.
    let minted_delta = mined_after - mined_before;

    // supply_after == supply_before + minted: every grain of supply change is
    // accounted for by issuance. With no burn, supply never decreases — nothing
    // is created or destroyed between issuance events.
    let expected_after = supply_before
        .checked_add(minted_delta)
        .ok_or(InvariantViolation::SupplyOverflow)?;
    if supply_after != expected_after {
        return Err(InvariantViolation::ValueNotConserved {
            supply_before,
            supply_after,
            minted_delta,
        });
    }

    // Per-asset transition invariants: an asset, once created, is permanent;
    // its issuer and symbol are immutable; and its issuance and burn counters
    // are monotonic. Combined with the per-state conservation check
    // (`sum(balances) == issued − burned`, in `check_ledger`), this gives every
    // native asset the same counter-accounted conservation theorem as SOV.
    for (asset, before_info) in &before.tokens {
        let Some(after_info) = after.token(asset) else {
            return Err(InvariantViolation::TokenIdentityMutated {
                asset: asset.to_string(),
            });
        };
        if after_info.issuer != before_info.issuer || after_info.symbol != before_info.symbol {
            return Err(InvariantViolation::TokenIdentityMutated {
                asset: asset.to_string(),
            });
        }
        if after_info.issued < before_info.issued {
            return Err(InvariantViolation::TokenCounterRegressed {
                asset: asset.to_string(),
                kind: "issued",
                before: before_info.issued.grains(),
                after: after_info.issued.grains(),
            });
        }
        if after_info.burned < before_info.burned {
            return Err(InvariantViolation::TokenCounterRegressed {
                asset: asset.to_string(),
                kind: "burned",
                before: before_info.burned.grains(),
                after: after_info.burned.grains(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_primitives::{AccountId, Balance};
    use sov_state::Account;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn sov(n: u128) -> Balance {
        Balance::from_sov(n).unwrap()
    }

    /// A ledger with a single liquid-balance account.
    fn ledger_with(account: &str, balance: Balance) -> Ledger {
        let mut l = Ledger::new();
        l.set_account(&id(account), Account::with_balance(balance));
        l
    }

    #[test]
    fn within_cap_and_budgets_passes() {
        let l = ledger_with("usa.reserve.sov", sov(1_000));
        assert_eq!(check_ledger(&l, &MiningPolicy::test()), Ok(()));
    }

    #[test]
    fn supply_over_cap_is_caught() {
        // A single account holding one grain more than the entire cap.
        let l = ledger_with("whale.sov", Balance::from_grains(MAX_SUPPLY_GRAINS + 1));
        assert_eq!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::SupplyCapExceeded {
                supply: MAX_SUPPLY_GRAINS + 1,
                cap: MAX_SUPPLY_GRAINS,
            })
        );
    }

    #[test]
    fn mined_over_budget_is_caught() {
        let mining = MiningPolicy::test(); // 1,000,000 SOV mining budget
        let mut l = Ledger::new();
        l.add_mined_emitted(sov(1_000_001)).unwrap();
        assert_eq!(
            check_ledger(&l, &mining),
            Err(InvariantViolation::MiningBudgetExceeded {
                mined: sov(1_000_001).grains(),
                budget: mining.mining_budget_grains,
            })
        );
    }

    #[test]
    fn shield_into_the_pool_is_supply_neutral() {
        // The shielded-pool turnstile: moving value transparent -> shielded debits
        // the account and raises `shielded_value` by the same amount, so total
        // supply is unchanged and conservation holds. Value only MOVES into the
        // pool; it is never created there.
        let before = ledger_with("a.sov", sov(100));
        let mut after = ledger_with("a.sov", sov(70));
        after.add_shielded_value(sov(30)).unwrap();
        assert_eq!(check_transition(&before, &after), Ok(()));
    }

    #[test]
    fn shielded_pool_cannot_manufacture_supply() {
        // The turnstile, proven as a GATED invariant: crediting the shielded pool
        // WITHOUT a matching transparent debit or emission — the exact shape a
        // circuit-soundness forgery would take — inflates total supply and is
        // caught by the conservation theorem. So even if the Halo2 proof system
        // were unsound, the shielded pool can never mint SOV; the worst case is
        // intra-pool theft, bounded further by the execution-layer pool-balance
        // turnstile (a de-shield can never exceed `shielded_value`).
        let before = ledger_with("a.sov", sov(100));
        let mut after = ledger_with("a.sov", sov(100)); // account NOT debited
        after.add_shielded_value(sov(50)).unwrap(); // pool credited from thin air
        assert!(matches!(
            check_transition(&before, &after),
            Err(InvariantViolation::ValueNotConserved { .. })
        ));
    }

    #[test]
    fn transfer_conserves_value() {
        // 100 SOV held by A; after, split 40/60 between A and B. No mint.
        let before = ledger_with("a.sov", sov(100));
        let mut after = Ledger::new();
        after.set_account(&id("a.sov"), Account::with_balance(sov(40)));
        after.set_account(&id("b.sov"), Account::with_balance(sov(60)));
        assert_eq!(check_transition(&before, &after), Ok(()));
    }

    #[test]
    fn mint_is_accounted_by_the_mined_counter() {
        let before = ledger_with("miner.sov", sov(100));
        let mut after = ledger_with("miner.sov", sov(150));
        after.add_mined_emitted(sov(50)).unwrap();
        assert_eq!(check_transition(&before, &after), Ok(()));
    }

    #[test]
    fn unauthorized_mint_is_caught() {
        // Supply rises by 50 SOV but the counters did not move: value from nothing.
        let before = ledger_with("a.sov", sov(100));
        let after = ledger_with("a.sov", sov(150));
        assert_eq!(
            check_transition(&before, &after),
            Err(InvariantViolation::ValueNotConserved {
                supply_before: sov(100).grains(),
                supply_after: sov(150).grains(),
                minted_delta: 0,
            })
        );
    }

    #[test]
    fn destroyed_value_is_caught() {
        // Supply falls with no counter change: value vanished.
        let before = ledger_with("a.sov", sov(100));
        let after = ledger_with("a.sov", sov(40));
        assert!(matches!(
            check_transition(&before, &after),
            Err(InvariantViolation::ValueNotConserved { .. })
        ));
    }

    #[test]
    fn regressed_emission_is_caught() {
        let mut before = Ledger::new();
        before.add_mined_emitted(sov(50)).unwrap();
        let mut after = Ledger::new();
        after.add_mined_emitted(sov(40)).unwrap();
        assert_eq!(
            check_transition(&before, &after),
            Err(InvariantViolation::EmissionRegressed {
                kind: "mined",
                before: sov(50).grains(),
                after: sov(40).grains(),
            })
        );
    }

    #[test]
    fn combined_transfer_and_coinbase_balances() {
        // Before: A=100 liquid. After: a 50-SOV coinbase lands on A, which keeps
        // 130 and sends 20 to B. Supply 100 -> 150, with mined +50.
        let before = ledger_with("a.sov", sov(100));
        let mut after = Ledger::new();
        after.set_account(&id("a.sov"), Account::with_balance(sov(130)));
        after.set_account(&id("b.sov"), Account::with_balance(sov(20)));
        after.add_mined_emitted(sov(50)).unwrap();
        // supply_after = A(130) + B(20) = 150; Δsupply = 50 = mined 50.
        assert_eq!(check_transition(&before, &after), Ok(()));
    }

    // ---- Native assets (tokens) ----

    use sov_primitives::Hash;
    use sov_state::{token_asset_id, TokenInfo};

    /// A ledger holding one asset: `issued`/`burned` counters plus holder balances.
    fn token_ledger(issued: u128, burned: u128, holdings: &[(&str, u128)]) -> (Ledger, Hash) {
        let asset = token_asset_id(&id("issuer.sov"), "USD1");
        let mut l = Ledger::new();
        l.set_token(
            asset,
            TokenInfo {
                issuer: id("issuer.sov"),
                symbol: "USD1".into(),
                issued: sov(issued),
                burned: sov(burned),
            },
        );
        for (holder, units) in holdings {
            l.set_token_balance(&asset, &id(holder), sov(*units));
        }
        (l, asset)
    }

    #[test]
    fn conserved_token_state_passes() {
        // issued 100, burned 10, balances sum to 90: conserved.
        let (l, _) = token_ledger(100, 10, &[("a.sov", 60), ("b.sov", 30)]);
        assert_eq!(check_ledger(&l, &MiningPolicy::test()), Ok(()));
    }

    #[test]
    fn forged_token_balance_is_caught() {
        // Balances sum to 120 against a supply of 100: 20 units from nothing —
        // the exact shape a token-mint forgery would take.
        let (l, _) = token_ledger(100, 0, &[("a.sov", 60), ("b.sov", 60)]);
        assert!(matches!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::TokenNotConserved { sum: s, issued: i, .. })
                if s == sov(120).grains() && i == sov(100).grains()
        ));
    }

    #[test]
    fn token_balance_without_issuance_record_is_caught() {
        // A balance for an asset that was never issued: units with no origin.
        let mut l = Ledger::new();
        let ghost = Hash::digest(b"ghost-asset");
        l.set_token_balance(&ghost, &id("a.sov"), sov(5));
        assert!(matches!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::TokenNotConserved { issued: 0, .. })
        ));
    }

    #[test]
    fn token_burn_exceeding_issuance_is_caught() {
        let (l, _) = token_ledger(100, 150, &[]);
        assert!(matches!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::TokenBurnExceedsIssued { .. })
        ));
    }

    #[test]
    fn token_issue_and_burn_transitions_conserve() {
        // Issue: counter +50, recipient +50 — conserved.
        let (before, _) = token_ledger(100, 0, &[("a.sov", 100)]);
        let (after, _) = token_ledger(150, 0, &[("a.sov", 150)]);
        assert_eq!(check_transition(&before, &after), Ok(()));
        // Burn: counter +20, holder −20 — conserved.
        let (after_burn, _) = token_ledger(150, 20, &[("a.sov", 130)]);
        assert_eq!(check_transition(&after, &after_burn), Ok(()));
    }

    #[test]
    fn token_counter_regression_is_caught() {
        let (before, _) = token_ledger(100, 10, &[("a.sov", 90)]);
        let (less_issued, _) = token_ledger(90, 10, &[("a.sov", 80)]);
        assert!(matches!(
            check_transition(&before, &less_issued),
            Err(InvariantViolation::TokenCounterRegressed { kind: "issued", .. })
        ));
        let (less_burned, _) = token_ledger(100, 5, &[("a.sov", 95)]);
        assert!(matches!(
            check_transition(&before, &less_burned),
            Err(InvariantViolation::TokenCounterRegressed { kind: "burned", .. })
        ));
    }

    #[test]
    fn token_identity_mutation_or_vanishing_is_caught() {
        let (before, asset) = token_ledger(100, 0, &[("a.sov", 100)]);

        // The asset vanishes entirely.
        let gone = Ledger::new();
        assert!(matches!(
            check_transition(&before, &gone),
            Err(InvariantViolation::TokenIdentityMutated { .. })
        ));

        // The issuer is rewritten (a registry-takeover attack).
        let mut hijacked = before.clone();
        hijacked.set_token(
            asset,
            TokenInfo {
                issuer: id("mallory.sov"),
                symbol: "USD1".into(),
                issued: sov(100),
                burned: sov(0),
            },
        );
        assert!(matches!(
            check_transition(&before, &hijacked),
            Err(InvariantViolation::TokenIdentityMutated { .. })
        ));
    }

    #[test]
    fn orphaned_compliance_state_is_caught() {
        use sov_compliance::{CompliancePolicy, SpendWindow};

        // A policy for an asset that does not exist.
        let mut l = Ledger::new();
        let ghost = Hash::digest(b"ghost-asset");
        l.set_token_policy(ghost, CompliancePolicy::unrestricted());
        assert!(matches!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::TokenComplianceOrphaned {
                kind: "policy without asset",
                ..
            })
        ));

        // A spend window for an asset with no policy.
        let (mut l, asset) = token_ledger(100, 0, &[("a.sov", 100)]);
        l.set_token_window(
            &asset,
            &id("a.sov"),
            SpendWindow {
                window_start: 1,
                spent: sov(1),
            },
        );
        assert!(matches!(
            check_ledger(&l, &MiningPolicy::test()),
            Err(InvariantViolation::TokenComplianceOrphaned {
                kind: "window without policy",
                ..
            })
        ));
    }

    #[test]
    fn token_units_never_enter_native_supply() {
        // A trillion token units leave total SOV supply at exactly zero: the
        // 21M cap is about SOV, and tokens cannot touch it.
        let (l, _) = token_ledger(1_000_000_000_000, 0, &[("a.sov", 1_000_000_000_000)]);
        assert_eq!(l.total_supply().unwrap(), Balance::ZERO);
        assert_eq!(check_ledger(&l, &MiningPolicy::test()), Ok(()));
    }

    #[test]
    fn long_tail_is_fixed_supply_once_emission_is_exhausted() {
        let mining = MiningPolicy::mainnet_like();

        // (1) Emission TERMINATES: at the mining budget the schedule mints nothing
        // further — no integer-overflow resumption (the BIP-42 class of bug), so
        // issuance is bounded and eventually exactly zero.
        let mining_budget = Balance::from_grains(mining.mining_budget_grains);
        assert_eq!(mining.reward_at(1, mining_budget), Balance::ZERO);

        // (2) DURING emission, a coinbase adds supply — the issuance phase.
        let e0 = ledger_with("holder.sov", sov(1_000));
        let mut e1 = ledger_with("holder.sov", sov(1_050)); // +50 minted
        e1.add_mined_emitted(sov(50)).unwrap();
        assert_eq!(check_transition(&e0, &e1), Ok(()));
        assert!(e1.total_supply().unwrap() > e0.total_supply().unwrap());

        // (3) POST-emission (the budget fully issued), no mint is possible AND
        // there is NO burn, so total supply is FIXED forever. A fee only MOVES
        // value (sender -> miner/tax); it is supply-neutral. SOV is a hard-capped,
        // non-deflationary reserve asset — like Bitcoin's terminal state.
        let mut before = ledger_with("holder.sov", sov(1_000));
        before.add_mined_emitted(mining_budget).unwrap();
        let supply_before = before.total_supply().unwrap();

        let mut after = before.clone();
        // A 5-SOV fee leaves the holder and is paid to the miner: supply unchanged,
        // and the mined counter is UNCHANGED (Δ = 0).
        after.set_account(&id("holder.sov"), Account::with_balance(sov(995)));
        after.set_account(&id("miner.sov"), Account::with_balance(sov(5)));

        assert_eq!(check_transition(&before, &after), Ok(()));
        assert_eq!(
            after.total_supply().unwrap(),
            supply_before,
            "with emission exhausted and no burn, circulating supply is fixed"
        );
    }
}
