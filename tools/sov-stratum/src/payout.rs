//! Whether a block template actually pays the share window.
//!
//! The pool never signs. A finder (their own wallet, on their own machine)
//! signs ordinary transfers from their account. This module only checks that
//! those transfers, plus what the coinbase leaves with the proposer, are the
//! window [`sov_sharechain`] requires.
//!
//! An empty window requires no transfers: consensus still pays the whole
//! coinbase to the proposer, and the sharechain requires an empty payout map
//! because there is no prior work to split. A non-empty window must match
//! exactly — remainder included — or the block is not forwarded.

use std::collections::{BTreeMap, HashSet};

use sov_primitives::AccountId;
use sov_sharechain::Payouts;

/// A transfer the pool has already signature-checked and relayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferLeg {
    /// Transaction id hex (no `0x`), as the template lists it.
    pub tx_id: String,
    /// Signer. Only the block proposer can spend the coinbase.
    pub from: AccountId,
    /// Recipient.
    pub to: AccountId,
    /// Grains moved.
    pub amount: u128,
}

/// The transfers a proposer must embed for `expected`, excluding their own
/// retained share (that share stays in the coinbase).
pub fn outgoing_transfers(expected: &Payouts, proposer: &AccountId) -> Vec<(AccountId, u128)> {
    expected
        .iter()
        .filter(|(account, amount)| *account != proposer && **amount > 0)
        .map(|(account, amount)| (account.clone(), *amount))
        .collect()
}

/// `true` when `template_tx_ids` plus the relayed legs pay `expected` for a
/// block whose coinbase is `proposer` and whose reward is `reward` grains.
pub fn window_covered(
    proposer: &AccountId,
    reward: u128,
    expected: &Payouts,
    template_tx_ids: &HashSet<String>,
    relayed: &[TransferLeg],
) -> bool {
    if expected.is_empty() {
        // No prior work to split. Extra proposer transfers would pay someone
        // the sharechain did not name; refuse those rather than calling the
        // map empty.
        return !proposer_paid_someone(proposer, template_tx_ids, relayed);
    }
    match distribution(proposer, reward, template_tx_ids, relayed) {
        Some(actual) => &actual == expected,
        None => false,
    }
}

fn proposer_paid_someone(
    proposer: &AccountId,
    template_tx_ids: &HashSet<String>,
    relayed: &[TransferLeg],
) -> bool {
    let mut seen = HashSet::new();
    relayed.iter().any(|leg| {
        leg.from == *proposer
            && leg.amount > 0
            && seen.insert(leg.tx_id.as_str())
            && template_tx_ids.contains(&leg.tx_id)
    })
}

/// Coinbase to `proposer`, then their relayed transfers that this template
/// actually contains. `None` if a transfer spends more than remains.
fn distribution(
    proposer: &AccountId,
    reward: u128,
    template_tx_ids: &HashSet<String>,
    relayed: &[TransferLeg],
) -> Option<Payouts> {
    let mut actual: Payouts = BTreeMap::new();
    if reward > 0 {
        actual.insert(proposer.clone(), reward);
    }
    let mut seen = HashSet::new();
    for leg in relayed {
        if leg.from != *proposer || leg.amount == 0 {
            continue;
        }
        if !template_tx_ids.contains(&leg.tx_id) || !seen.insert(leg.tx_id.clone()) {
            continue;
        }
        let left = actual.get(proposer).copied().unwrap_or(0);
        if leg.amount > left {
            return None;
        }
        match left - leg.amount {
            0 => {
                actual.remove(proposer);
            }
            rest => {
                actual.insert(proposer.clone(), rest);
            }
        }
        *actual.entry(leg.to.clone()).or_default() += leg.amount;
    }
    actual.retain(|_, amount| *amount > 0);
    Some(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn leg(tx: &str, from: &str, to: &str, amount: u128) -> TransferLeg {
        TransferLeg {
            tx_id: tx.into(),
            from: id(from),
            to: id(to),
            amount,
        }
    }

    #[test]
    fn an_empty_window_needs_no_transfers() {
        let ids = HashSet::new();
        assert!(window_covered(
            &id("alice.sov"),
            1_000,
            &Payouts::new(),
            &ids,
            &[]
        ));
    }

    #[test]
    fn a_split_window_matches_only_the_exact_transfers() {
        let alice = id("alice.sov");
        let bob = id("bob.sov");
        let mut expected = Payouts::new();
        expected.insert(alice.clone(), 600);
        expected.insert(bob.clone(), 400);
        let ids = HashSet::from(["aa".to_string()]);
        let good = [leg("aa", "alice.sov", "bob.sov", 400)];
        assert!(window_covered(&alice, 1_000, &expected, &ids, &good));

        // Missing from the template: the leg was relayed but this job does not
        // carry it, so publishing the block would pay only the finder.
        let empty_ids = HashSet::new();
        assert!(!window_covered(&alice, 1_000, &expected, &empty_ids, &good));

        // A shaved grain is not "close enough".
        let shaved = [leg("aa", "alice.sov", "bob.sov", 399)];
        assert!(!window_covered(&alice, 1_000, &expected, &ids, &shaved));

        // Paying a third account does not satisfy the window.
        let mut wrong = expected.clone();
        wrong.remove(&bob);
        wrong.insert(id("carol.sov"), 400);
        assert!(!window_covered(&alice, 1_000, &wrong, &ids, &good));
    }

    #[test]
    fn outgoing_list_omits_the_finders_retained_share() {
        let mut expected = Payouts::new();
        expected.insert(id("alice.sov"), 600);
        expected.insert(id("bob.sov"), 400);
        let out = outgoing_transfers(&expected, &id("alice.sov"));
        assert_eq!(out, vec![(id("bob.sov"), 400)]);
    }
}
