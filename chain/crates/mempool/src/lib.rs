//! # sov-mempool
//!
//! The transaction pool: the staging area between a client submitting a signed
//! transaction and a proposer including it in a block.
//!
//! The pool's job is to hold only transactions that are *plausibly* includable,
//! and to hand a proposer an executable batch. It therefore:
//! - rejects transactions whose signature does not verify (cheap authentication
//!   before anything else);
//! - rejects transactions already past an account's current nonce (stale) or
//!   already pooled (duplicates);
//! - bounds its own size, so it cannot grow without limit; and
//! - on request, returns transactions grouped by sender and ordered by nonce,
//!   skipping any sender whose next expected nonce is missing — never proposing
//!   a transaction that would be rejected for a nonce gap.
//!
//! The pool deliberately does *not* check balances: balances change as a block
//! executes, so affordability is the execution layer's call. The pool's
//! contract is "well-formed and correctly ordered," not "guaranteed to succeed."

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sov_primitives::{AccountId, Hash};
use sov_types::SignedTransaction;

/// Reasons a transaction is not admitted to the pool.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MempoolError {
    /// The signature did not verify.
    #[error("invalid transaction signature")]
    InvalidSignature,
    /// The transaction's nonce is below the account's current nonce, so it can
    /// never be applied.
    #[error("stale transaction: account is at nonce {current}, transaction used {got}")]
    Stale {
        /// The account's current nonce.
        current: u64,
        /// The nonce the transaction carried.
        got: u64,
    },
    /// An identical transaction (same id) is already pooled.
    #[error("transaction already in the pool")]
    Duplicate,
    /// The pool is at capacity.
    #[error("mempool is full ({capacity} transactions)")]
    Full {
        /// The configured capacity.
        capacity: usize,
    },
    /// A different transaction already occupies this `(signer, nonce)` slot.
    /// Replacing it in place would orphan the existing entry, so it is rejected.
    #[error("a transaction with signer {signer} and nonce {nonce} is already pooled")]
    NonceTaken {
        /// The signer whose slot is taken.
        signer: AccountId,
        /// The contested nonce.
        nonce: u64,
    },
    /// The signer already holds its fair share of the pool (anti-DoS cap).
    #[error("sender {signer} has reached its mempool limit of {limit} pending transactions")]
    SenderLimit {
        /// The over-limit signer.
        signer: AccountId,
        /// The per-sender cap.
        limit: usize,
    },
}

/// One sender may occupy at most this fraction of the pool (1/64), floored at 16,
/// so a single account cannot crowd everyone else out — the anti-DoS fairness
/// bound for SOV's *fixed-gas-price* fee model (there is no fee auction to bid for
/// priority, so the mempool's job under pressure is fairness, not fee-bidding).
fn default_per_sender(capacity: usize) -> usize {
    (capacity / 64).max(16)
}

/// A bounded pool of pending, validated transactions.
pub struct Mempool {
    by_id: HashMap<Hash, SignedTransaction>,
    /// Index by `(signer, nonce)` so a sender's transactions are retrievable in
    /// nonce order.
    by_sender: BTreeMap<(AccountId, u64), Hash>,
    capacity: usize,
    /// Max transactions one sender may hold at once (anti-DoS fairness bound).
    max_per_sender: usize,
}

impl Mempool {
    /// Create a pool holding at most `capacity` transactions, with a per-sender
    /// cap derived from capacity (`default_per_sender`).
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, default_per_sender(capacity))
    }

    /// Create a pool with an explicit per-sender cap.
    pub fn with_limits(capacity: usize, max_per_sender: usize) -> Self {
        Mempool {
            by_id: HashMap::new(),
            by_sender: BTreeMap::new(),
            capacity,
            max_per_sender: max_per_sender.max(1),
        }
    }

    /// Number of pending transactions from `signer`.
    fn sender_count(&self, signer: &AccountId) -> usize {
        self.by_sender
            .range((signer.clone(), 0)..=(signer.clone(), u64::MAX))
            .count()
    }

    /// The signer holding the most pending transactions, with that count.
    fn heaviest_sender(&self) -> Option<(AccountId, usize)> {
        let mut counts: HashMap<&AccountId, usize> = HashMap::new();
        for (signer, _) in self.by_sender.keys() {
            *counts.entry(signer).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(s, n)| (s.clone(), n))
    }

    /// Evict `signer`'s highest-nonce pending transaction (the least likely to be
    /// executable soon), freeing one slot.
    fn evict_highest_nonce(&mut self, signer: &AccountId) {
        if let Some(id) = self
            .by_sender
            .range((signer.clone(), 0)..=(signer.clone(), u64::MAX))
            .next_back()
            .map(|(_, id)| *id)
        {
            self.remove(&id);
        }
    }

    /// Number of pooled transactions.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Whether a transaction with this id is pooled.
    pub fn contains(&self, id: &Hash) -> bool {
        self.by_id.contains_key(id)
    }

    /// Try to admit `stx`, given the signer's `current_nonce` (from state).
    pub fn insert(
        &mut self,
        stx: SignedTransaction,
        current_nonce: u64,
    ) -> Result<(), MempoolError> {
        if !stx.verify_signature() {
            return Err(MempoolError::InvalidSignature);
        }
        let nonce = stx.transaction.nonce;
        if nonce < current_nonce {
            return Err(MempoolError::Stale {
                current: current_nonce,
                got: nonce,
            });
        }
        let id = stx.id();
        if self.by_id.contains_key(&id) {
            return Err(MempoolError::Duplicate);
        }
        // Reject a *different* transaction for an already-occupied (signer, nonce):
        // overwriting `by_sender` in place would orphan the existing id in `by_id`
        // (unselectable and unprunable), silently leaking capacity.
        let slot = (stx.transaction.signer.clone(), nonce);
        if self.by_sender.contains_key(&slot) {
            return Err(MempoolError::NonceTaken {
                signer: stx.transaction.signer.clone(),
                nonce,
            });
        }
        // Anti-DoS: bound how much of the pool one sender may occupy, so a single
        // account cannot crowd everyone else out.
        if self.sender_count(&stx.transaction.signer) >= self.max_per_sender {
            return Err(MempoolError::SenderLimit {
                signer: stx.transaction.signer.clone(),
                limit: self.max_per_sender,
            });
        }
        // At capacity: rather than hard-reject, EVICT one transaction from the
        // most over-represented sender (its highest nonce — least executable) to
        // make room. Only evict from a sender holding more than one, so a full,
        // fairly-shared pool rejects new entries instead of thrashing.
        if self.by_id.len() >= self.capacity {
            match self.heaviest_sender() {
                Some((victim, n)) if n > 1 => self.evict_highest_nonce(&victim),
                _ => {
                    return Err(MempoolError::Full {
                        capacity: self.capacity,
                    })
                }
            }
        }
        self.by_sender.insert(slot, id);
        self.by_id.insert(id, stx);
        Ok(())
    }

    /// Remove a transaction by id, returning it if present. Called after a
    /// transaction is committed in a block.
    pub fn remove(&mut self, id: &Hash) -> Option<SignedTransaction> {
        let stx = self.by_id.remove(id)?;
        self.by_sender
            .remove(&(stx.transaction.signer.clone(), stx.transaction.nonce));
        Some(stx)
    }

    /// Drop transactions that have become stale relative to current account
    /// nonces (e.g. after a block advanced them). `current_nonce` returns the
    /// account's nonce in the latest state.
    pub fn prune_stale<F: Fn(&AccountId) -> u64>(&mut self, current_nonce: F) {
        let stale: Vec<Hash> = self
            .by_sender
            .iter()
            .filter(|((signer, nonce), _)| *nonce < current_nonce(signer))
            .map(|(_, id)| *id)
            .collect();
        for id in stale {
            self.remove(&id);
        }
    }

    /// Select an executable batch of up to `max` transactions: for each sender,
    /// a contiguous run of nonces starting at its `current_nonce`, stopping at
    /// the first gap. Transactions are returned grouped by sender (in id order)
    /// and ascending by nonce, ready to apply in sequence.
    pub fn select<F: Fn(&AccountId) -> u64>(
        &self,
        current_nonce: F,
        max: usize,
    ) -> Vec<SignedTransaction> {
        let mut out = Vec::new();
        let signers: BTreeSet<&AccountId> = self.by_sender.keys().map(|(s, _)| s).collect();
        for signer in signers {
            let mut nonce = current_nonce(signer);
            while out.len() < max {
                match self.by_sender.get(&(signer.clone(), nonce)) {
                    Some(id) => {
                        out.push(self.by_id[id].clone());
                        nonce += 1;
                    }
                    None => break,
                }
            }
            if out.len() >= max {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;
    use sov_primitives::Balance;
    use sov_types::{Action, Transaction};

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn tx(seed: [u8; 32], from: &str, nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let t = Transaction {
            signer: id(from),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        SignedTransaction::sign(t, &kp).unwrap()
    }

    #[test]
    fn admits_and_tracks() {
        let mut pool = Mempool::new(100);
        let t = tx([1; 32], "usa.reserve.sov", 0);
        let tid = t.id();
        pool.insert(t, 0).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tid));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut pool = Mempool::new(100);
        let mut t = tx([1; 32], "usa.reserve.sov", 0);
        t.transaction.nonce = 5; // breaks signature
        assert_eq!(pool.insert(t, 0), Err(MempoolError::InvalidSignature));
    }

    #[test]
    fn rejects_stale() {
        let mut pool = Mempool::new(100);
        let t = tx([1; 32], "usa.reserve.sov", 2);
        assert_eq!(
            pool.insert(t, 5),
            Err(MempoolError::Stale { current: 5, got: 2 })
        );
    }

    #[test]
    fn rejects_duplicate() {
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        assert_eq!(
            pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0),
            Err(MempoolError::Duplicate)
        );
    }

    #[test]
    fn rejects_same_signer_nonce_different_action() {
        // A second, *different* transaction at the same (signer, nonce) must be
        // rejected — not silently overwrite the first and orphan it in `by_id`.
        let kp = Keypair::from_seed([1; 32]);
        let mk = |sov: u128| {
            let t = Transaction {
                signer: id("usa.reserve.sov"),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(sov).unwrap(),
                },
            };
            SignedTransaction::sign(t, &kp).unwrap()
        };
        let first = mk(1);
        let second = mk(2);
        assert_ne!(
            first.id(),
            second.id(),
            "different actions => different ids"
        );

        let mut pool = Mempool::new(100);
        pool.insert(first, 0).unwrap();
        assert_eq!(
            pool.insert(second, 0),
            Err(MempoolError::NonceTaken {
                signer: id("usa.reserve.sov"),
                nonce: 0,
            })
        );
        assert_eq!(pool.len(), 1, "no orphaned entry left behind");
    }

    #[test]
    fn rejects_when_full() {
        let mut pool = Mempool::new(1);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        assert_eq!(
            pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0),
            Err(MempoolError::Full { capacity: 1 })
        );
    }

    #[test]
    fn select_returns_contiguous_run_and_stops_at_gap() {
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0).unwrap();
        // Nonce 2 is missing; 3 should be unreachable.
        pool.insert(tx([1; 32], "usa.reserve.sov", 3), 0).unwrap();

        let batch = pool.select(|_| 0, 10);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].transaction.nonce, 0);
        assert_eq!(batch[1].transaction.nonce, 1);
    }

    #[test]
    fn select_respects_current_nonce() {
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 5), 5).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 6), 5).unwrap();
        // Account is at nonce 5, so both are ready.
        assert_eq!(pool.select(|_| 5, 10).len(), 2);
        // If the account were already at 7, neither is selectable.
        assert_eq!(pool.select(|_| 7, 10).len(), 0);
    }

    #[test]
    fn remove_and_prune() {
        let mut pool = Mempool::new(100);
        let t = tx([1; 32], "usa.reserve.sov", 0);
        let tid = t.id();
        pool.insert(t, 0).unwrap();
        assert!(pool.remove(&tid).is_some());
        assert!(pool.is_empty());

        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        // Account advanced to nonce 1; the pooled nonce-0 tx is now stale.
        pool.prune_stale(|_| 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn per_sender_cap_bounds_one_account() {
        // A single sender may hold at most `max_per_sender`; beyond that it is
        // refused even when the pool has room — anti-DoS fairness.
        let mut pool = Mempool::with_limits(100, 2);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0).unwrap();
        let third = pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0);
        assert!(matches!(
            third,
            Err(MempoolError::SenderLimit { limit: 2, .. })
        ));
        // A different sender is unaffected (the cap is per-account).
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0).unwrap();
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn full_pool_evicts_the_heaviest_senders_highest_nonce() {
        // Capacity 3, generous per-sender cap. A hog fills the pool (nonces 0,1,2).
        let mut pool = Mempool::with_limits(3, 10);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0).unwrap();
        assert_eq!(pool.len(), 3);
        // A new sender's tx is admitted by evicting the hog's HIGHEST nonce (2).
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0).unwrap();
        assert_eq!(pool.len(), 3);
        assert!(
            !pool.by_sender.contains_key(&(id("usa.reserve.sov"), 2)),
            "highest nonce evicted"
        );
        assert!(pool.by_sender.contains_key(&(id("usa.reserve.sov"), 0)));
        assert!(pool.by_sender.contains_key(&(id("ecb.reserve.sov"), 0)));
    }

    #[test]
    fn fairly_shared_full_pool_rejects_rather_than_thrash() {
        // Every sender holds exactly one tx: there is no over-represented victim,
        // so a full pool refuses the newcomer instead of evicting a fair sender.
        let mut pool = Mempool::with_limits(2, 10);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0).unwrap();
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0).unwrap();
        let newcomer = pool.insert(tx([3; 32], "boj.reserve.sov", 0), 0);
        assert!(matches!(newcomer, Err(MempoolError::Full { capacity: 2 })));
        assert_eq!(pool.len(), 2);
    }
}
