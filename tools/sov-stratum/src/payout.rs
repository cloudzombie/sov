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
///
/// `fee_reserve` grains are not in `expected`. Consensus debits a transfer's
/// fee before the balance check, then credits that fee back to the proposer.
/// A finder whose own share is smaller than the fee cannot move the full
/// remainder: after the debit, the balance is short. The sharechain map is
/// therefore computed on `reward - fee_reserve`, and those reserved grains
/// stay with the proposer so the transfer can execute. They are not a second
/// payee. `reward` here is still the full coinbase.
pub fn window_covered(
    proposer: &AccountId,
    reward: u128,
    fee_reserve: u128,
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
    if fee_reserve > reward {
        return false;
    }
    match distribution(proposer, reward, template_tx_ids, relayed) {
        Some(mut actual) => {
            let held = actual.get(proposer).copied().unwrap_or(0);
            if held < fee_reserve {
                return false;
            }
            match held - fee_reserve {
                0 => {
                    actual.remove(proposer);
                }
                rest => {
                    actual.insert(proposer.clone(), rest);
                }
            }
            actual.retain(|_, amount| *amount > 0);
            &actual == expected
        }
        None => false,
    }
}

/// Grains a finder must keep back so one payout transfer can pay its fee.
///
/// The fee is charged and then returned to the proposer, one transaction at a
/// time, so a sequence of payouts needs a single fee in reserve rather than
/// one per payee. `None` when the node has not published a fee yet; callers
/// treat that as zero and learn the real fee on the next poll.
pub fn fee_reserve_from_estimate(v: &serde_json::Value) -> Option<u128> {
    v.get("feeGrains")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse().ok())
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
            0,
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
        assert!(window_covered(&alice, 1_000, 0, &expected, &ids, &good));

        // Missing from the template: the leg was relayed but this job does not
        // carry it, so publishing the block would pay only the finder.
        let empty_ids = HashSet::new();
        assert!(!window_covered(
            &alice, 1_000, 0, &expected, &empty_ids, &good
        ));

        // A shaved grain is not "close enough".
        let shaved = [leg("aa", "alice.sov", "bob.sov", 399)];
        assert!(!window_covered(&alice, 1_000, 0, &expected, &ids, &shaved));

        // Paying a third account does not satisfy the window.
        let mut wrong = expected.clone();
        wrong.remove(&bob);
        wrong.insert(id("carol.sov"), 400);
        assert!(!window_covered(&alice, 1_000, 0, &wrong, &ids, &good));
    }

    /// The finder's weight of the full coinbase is 100, and the fee is 400.
    /// Sending `900` would fail execution: the fee is debited first, leaving
    /// 600, which cannot cover 900. Reserving the fee and splitting the rest
    /// leaves the finder holding the fee plus their cut, and the transfer fits.
    #[test]
    fn a_finder_share_smaller_than_the_fee_still_covers_the_window() {
        let alice = id("alice.sov");
        let bob = id("bob.sov");
        let reward = 1_000u128;
        let fee = 400u128;
        // 10% of (reward - fee) = 60, which is below the fee. Bob takes the rest.
        let mut expected = Payouts::new();
        expected.insert(alice.clone(), 60);
        expected.insert(bob.clone(), 540);
        assert_eq!(expected.values().sum::<u128>(), reward - fee);
        let ids = HashSet::from(["aa".to_string()]);
        let good = [leg("aa", "alice.sov", "bob.sov", 540)];
        assert!(
            window_covered(&alice, reward, fee, &expected, &ids, &good),
            "the fee reserve stays with the finder and is not a payee"
        );
        // The unreserved map — bob is owed 900 — does not fit after the fee debit.
        let mut naive = Payouts::new();
        naive.insert(alice.clone(), 100);
        naive.insert(bob.clone(), 900);
        let too_much = [leg("aa", "alice.sov", "bob.sov", 900)];
        assert!(!window_covered(
            &alice, reward, fee, &naive, &ids, &too_much
        ));
        // And it would not execute: coinbase, then fee, then the transfer.
        let after_fee = reward - fee;
        assert!(after_fee < 900);
        assert!(after_fee >= 540);
    }

    /// The bytes xus-miner signs are the Borsh transaction the wallet signs.
    /// A drift here would make a locally signed payout fail verification.
    #[test]
    fn the_miner_preimage_matches_a_wallet_transfer() {
        use sov_crypto::Keypair;
        use sov_primitives::Balance;
        use sov_wallet::Wallet;

        let seed = [0x11u8; 32];
        let key = Keypair::from_seed(seed);
        let public = *key.public_key().as_bytes();
        let account = key.public_key().implicit_account_id();
        let mut wallet = Wallet::new();
        wallet.import(account.clone(), Keypair::from_seed(seed));
        let stx = wallet
            .transfer(&account, id("bob.sov"), Balance::from_grains(42), 7)
            .unwrap();
        let preimage = miner_transfer_preimage(account.as_str(), &public, 7, "bob.sov", 42);
        assert!(
            key.public_key().verify(&preimage, &stx.signature),
            "xus-miner must sign the same bytes Wallet::transfer signs"
        );
        assert_eq!(
            account.as_str(),
            "8ce53d0a623b12aac68d7a18ba9c31af1b11f56352e73959c0b484d06d10dfb7"
        );
    }

    fn miner_transfer_preimage(
        signer: &str,
        public: &[u8; 32],
        nonce: u64,
        to: &str,
        amount: u128,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let put_str = |out: &mut Vec<u8>, value: &str| {
            let bytes = value.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        };
        put_str(&mut out, signer);
        out.push(0);
        out.extend_from_slice(public);
        out.extend_from_slice(&nonce.to_le_bytes());
        out.push(0);
        put_str(&mut out, to);
        out.extend_from_slice(&amount.to_le_bytes());
        out
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
