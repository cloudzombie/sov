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
//! - admits only *gap-free* nonces — a sender's tx must be contiguous with its
//!   on-chain nonce plus what it already has pooled, so a hole that would strand
//!   later nonces can never open in the pool (a client learns immediately via
//!   `NonceGap` and resubmits the missing nonce);
//! - time-evicts any entry stranded behind a pre-existing/edge-case gap after a
//!   TTL, so such a gap self-clears instead of occupying the pool forever;
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

use sov_primitives::{AccountId, Balance, Hash};
use sov_types::{Action, SignedTransaction};

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
    /// The transaction's nonce is beyond the sender's contiguous pending run
    /// (`current_nonce + pending_count`), so admitting it would leave a hole that
    /// strands it — and every later nonce — until the missing one lands. Refusing
    /// it here means a gap can never form in the pool; the client should submit
    /// `expected` (the next mineable nonce) first, then resubmit.
    #[error("nonce gap: next mineable nonce is {expected}, transaction used {got}")]
    NonceGap {
        /// The next contiguous nonce the pool will accept.
        expected: u64,
        /// The nonce the transaction carried.
        got: u64,
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
    /// The signer cannot afford this transaction on top of its already-pooled ones:
    /// the total value it would move exceeds its balance, so it could never be mined
    /// (block building skips a tx that fails, which would strand it at its nonce and
    /// wedge the account). Rejecting it here keeps the pool to only mineable work.
    #[error("insufficient balance: pooled transfers would move {committed} grains but only {available} are held")]
    Insufficient {
        /// The signer's balance, in grains.
        available: u128,
        /// The total grains the signer's pooled transfers (including this one) would move.
        committed: u128,
    },
}

/// The base-XUS an action moves OUT of the signer's account — the value that must be
/// covered by the signer's balance for the transaction to be mineable. Only actions that
/// debit the transparent balance count; token/NFT/shielded moves don't spend base XUS
/// here. This is the quantity the affordability gate reserves so an overspend can never
/// be admitted (and later stall, wedging the nonce).
fn base_outflow(action: &Action) -> u128 {
    match action {
        Action::Transfer { amount, .. } => amount.grains(),
        _ => 0,
    }
}

/// One sender may occupy at most this fraction of the pool (1/64), floored at 16,
/// so a single account cannot crowd everyone else out — the anti-DoS fairness
/// bound for SOV's *fixed-gas-price* fee model (there is no fee auction to bid for
/// priority, so the mempool's job under pressure is fairness, not fee-bidding).
fn default_per_sender(capacity: usize) -> usize {
    (capacity / 64).max(16)
}

/// Wall-clock milliseconds since the Unix epoch, used to age pooled entries for
/// TTL-eviction. Non-monotonic, but the pool only needs a coarse "how long has
/// this been stranded" and tolerates clock jitter (a saturating subtraction
/// never under-flows). Zero on the (impossible) pre-epoch clock.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A bounded pool of pending, validated transactions.
pub struct Mempool {
    by_id: HashMap<Hash, SignedTransaction>,
    /// Index by `(signer, nonce)` so a sender's transactions are retrievable in
    /// nonce order.
    by_sender: BTreeMap<(AccountId, u64), Hash>,
    /// When each pooled tx was admitted (Unix millis), for TTL-eviction of
    /// entries stranded behind a gap. Keyed by tx id; kept in lockstep with
    /// `by_id`.
    inserted_at: HashMap<Hash, u64>,
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
            inserted_at: HashMap::new(),
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

    /// The total base-XUS the signer's already-pooled transactions would move — what a
    /// new transaction must fit under, together with its own outflow, to be affordable.
    fn pending_outflow(&self, signer: &AccountId) -> u128 {
        self.by_sender
            .range((signer.clone(), 0)..=(signer.clone(), u64::MAX))
            .filter_map(|(_, id)| self.by_id.get(id))
            .map(|stx| base_outflow(&stx.transaction.action))
            .fold(0u128, |acc, out| acc.saturating_add(out))
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

    /// Try to admit `stx`, given the signer's `current_nonce` and `balance` (from state).
    pub fn insert(
        &mut self,
        stx: SignedTransaction,
        current_nonce: u64,
        balance: Balance,
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
        // Gap-free admission: a tx may extend the sender's pending run by at most
        // one — its nonce must be contiguous with the account's on-chain nonce plus
        // what is already pooled (`current_nonce ..= current_nonce + pending_len`).
        // A higher nonce would sit behind a hole and could never be mined until the
        // hole fills, stranding it (and every later nonce). Refusing it here means a
        // gap can never form in the pool in the first place; the client learns
        // immediately and resubmits the missing nonce. (Slots at or below `expected`
        // that are already taken are caught by the `NonceTaken`/`Duplicate` checks.)
        let expected =
            current_nonce.saturating_add(self.sender_count(&stx.transaction.signer) as u64);
        if nonce > expected {
            return Err(MempoolError::NonceGap {
                expected,
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
        // Affordability: the signer's pooled transfers, plus this one, may not move more
        // base XUS than the signer holds. An over-balance transfer can never be mined
        // (block building simulates and SKIPS a failing tx), so admitting it would strand
        // it at its nonce and wedge the account. Reject it at the door instead.
        let committed = self
            .pending_outflow(&stx.transaction.signer)
            .saturating_add(base_outflow(&stx.transaction.action));
        if committed > balance.grains() {
            return Err(MempoolError::Insufficient {
                available: balance.grains(),
                committed,
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
        self.inserted_at.insert(id, now_millis());
        Ok(())
    }

    /// Remove a transaction by id, returning it if present. Called after a
    /// transaction is committed in a block.
    pub fn remove(&mut self, id: &Hash) -> Option<SignedTransaction> {
        let stx = self.by_id.remove(id)?;
        self.by_sender
            .remove(&(stx.transaction.signer.clone(), stx.transaction.nonce));
        self.inserted_at.remove(id);
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

    /// Prune both stale AND now-unaffordable transactions. Run after every committed
    /// block (state moved) and when restoring a persisted pool: it drops txs whose nonce
    /// has been consumed, then, for any sender whose pooled transfers now exceed its
    /// balance, evicts its highest-nonce transfers until the rest fit — so a pool never
    /// holds an unmineable tx that would wedge the account. `current_nonce`/`balance` read
    /// live state.
    pub fn prune<F, G>(&mut self, current_nonce: F, balance: G)
    where
        F: Fn(&AccountId) -> u64,
        G: Fn(&AccountId) -> Balance,
    {
        self.prune_stale(&current_nonce);
        // Senders still holding pooled transfers.
        let senders: BTreeSet<AccountId> = self.by_sender.keys().map(|(s, _)| s.clone()).collect();
        for signer in senders {
            let cap = balance(&signer).grains();
            // Evict highest-nonce transfers until the pooled outflow fits the balance.
            while self.pending_outflow(&signer) > cap {
                let before = self.len();
                self.evict_highest_nonce(&signer);
                if self.len() == before {
                    break; // nothing left to evict for this sender
                }
            }
        }
    }

    /// Time-evict transactions stranded behind a nonce gap. For each sender the
    /// contiguous run starting at its `current_nonce` is walked; anything at or
    /// beyond the first missing nonce sits behind a hole and can never be mined
    /// until the hole fills. Any such entry that has been pooled longer than
    /// `ttl_millis` is dropped, so a permanent gap self-clears and the account
    /// recovers once the missing nonce is (re)submitted. Gap-free admission means
    /// a fresh gap can't form; this drains any pre-existing or restored stranded
    /// entry. Returns the number evicted. Run on the same maintenance tick as
    /// `prune` (after every committed block / on restore).
    pub fn evict_stranded<F: Fn(&AccountId) -> u64>(
        &mut self,
        current_nonce: F,
        ttl_millis: u64,
    ) -> usize {
        let now = now_millis();
        let senders: BTreeSet<AccountId> = self.by_sender.keys().map(|(s, _)| s.clone()).collect();
        let mut stranded: Vec<Hash> = Vec::new();
        for signer in senders {
            // The first nonce missing from the pool (at or above the account's
            // current nonce) marks the gap; anything strictly reachable below it
            // is fine.
            let mut nonce = current_nonce(&signer);
            while self.by_sender.contains_key(&(signer.clone(), nonce)) {
                nonce += 1;
            }
            // Everything from the gap upward is stranded — evict the aged ones.
            for (_, id) in self
                .by_sender
                .range((signer.clone(), nonce)..=(signer.clone(), u64::MAX))
            {
                let age = now.saturating_sub(*self.inserted_at.get(id).unwrap_or(&now));
                if age >= ttl_millis {
                    stranded.push(*id);
                }
            }
        }
        let evicted = stranded.len();
        for id in stranded {
            self.remove(&id);
        }
        evicted
    }

    /// All pooled transactions, in `(signer, nonce)` order — the snapshot persisted to
    /// disk so the pool survives a restart.
    pub fn snapshot(&self) -> Vec<SignedTransaction> {
        self.by_sender
            .values()
            .filter_map(|id| self.by_id.get(id).cloned())
            .collect()
    }

    /// Re-admit a persisted snapshot against live state, silently dropping any tx that no
    /// longer validates (stale nonce, now unaffordable, duplicate). Used on startup so a
    /// restored pool holds only mineable work.
    pub fn restore<F, G>(&mut self, txs: Vec<SignedTransaction>, current_nonce: F, balance: G)
    where
        F: Fn(&AccountId) -> u64,
        G: Fn(&AccountId) -> Balance,
    {
        for stx in txs {
            let signer = &stx.transaction.signer;
            let _ = self.insert(stx.clone(), current_nonce(signer), balance(signer));
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

    /// A balance large enough that the affordability gate never trips in these tests.
    fn big() -> Balance {
        Balance::from_grains(u128::MAX)
    }

    /// A transfer of `amount_sov` XUS from `from` at `nonce`.
    fn tx_amt(seed: [u8; 32], from: &str, nonce: u64, amount_sov: u128) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let t = Transaction {
            signer: id(from),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(amount_sov).unwrap(),
            },
        };
        SignedTransaction::sign(t, &kp).unwrap()
    }

    #[test]
    fn overspend_is_rejected_at_admission() {
        // A transfer of 10 XUS from an account holding 5 can never be mined — reject it at
        // the door so it can't strand at its nonce and wedge the account.
        let mut pool = Mempool::new(100);
        let bal = Balance::from_sov(5).unwrap();
        let over = tx_amt([1; 32], "usa.reserve.sov", 0, 10);
        assert_eq!(
            pool.insert(over, 0, bal),
            Err(MempoolError::Insufficient {
                available: bal.grains(),
                committed: Balance::from_sov(10).unwrap().grains(),
            })
        );
        assert!(pool.is_empty(), "the overspend must not enter the pool");
    }

    #[test]
    fn cumulative_overspend_is_rejected() {
        // Two 3-XUS transfers from a 5-XUS account: the first fits, the second would push
        // the pooled total to 6 > 5, so it is refused.
        let mut pool = Mempool::new(100);
        let bal = Balance::from_sov(5).unwrap();
        pool.insert(tx_amt([1; 32], "usa.reserve.sov", 0, 3), 0, bal)
            .unwrap();
        assert!(matches!(
            pool.insert(tx_amt([1; 32], "usa.reserve.sov", 1, 3), 0, bal),
            Err(MempoolError::Insufficient { .. })
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn prune_evicts_a_now_unaffordable_tx() {
        // A 4-XUS transfer admitted when the account held 5; the balance then drops to 1.
        // The next prune must evict it (it can no longer be mined).
        let mut pool = Mempool::new(100);
        let sender = id("usa.reserve.sov");
        pool.insert(
            tx_amt([1; 32], "usa.reserve.sov", 0, 4),
            0,
            Balance::from_sov(5).unwrap(),
        )
        .unwrap();
        assert_eq!(pool.len(), 1);
        pool.prune(
            |_| 0,
            |a| {
                if *a == sender {
                    Balance::from_sov(1).unwrap()
                } else {
                    big()
                }
            },
        );
        assert!(
            pool.is_empty(),
            "an unaffordable tx must be reaped by prune"
        );
    }

    #[test]
    fn snapshot_then_restore_keeps_affordable_drops_stale() {
        let mut pool = Mempool::new(100);
        pool.insert(tx_amt([1; 32], "usa.reserve.sov", 0, 1), 0, big())
            .unwrap();
        pool.insert(tx_amt([1; 32], "usa.reserve.sov", 1, 1), 0, big())
            .unwrap();
        let snap = pool.snapshot();
        assert_eq!(snap.len(), 2);

        // Restore into a fresh pool where the account has already advanced to nonce 1:
        // the nonce-0 tx is now stale and dropped; the nonce-1 tx survives.
        let mut fresh = Mempool::new(100);
        fresh.restore(snap, |_| 1, |_| big());
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn admits_and_tracks() {
        let mut pool = Mempool::new(100);
        let t = tx([1; 32], "usa.reserve.sov", 0);
        let tid = t.id();
        pool.insert(t, 0, big()).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tid));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut pool = Mempool::new(100);
        let mut t = tx([1; 32], "usa.reserve.sov", 0);
        t.transaction.nonce = 5; // breaks signature
        assert_eq!(
            pool.insert(t, 0, big()),
            Err(MempoolError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_stale() {
        let mut pool = Mempool::new(100);
        let t = tx([1; 32], "usa.reserve.sov", 2);
        assert_eq!(
            pool.insert(t, 5, big()),
            Err(MempoolError::Stale { current: 5, got: 2 })
        );
    }

    #[test]
    fn rejects_duplicate() {
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        assert_eq!(
            pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big()),
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
        pool.insert(first, 0, big()).unwrap();
        assert_eq!(
            pool.insert(second, 0, big()),
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
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        assert_eq!(
            pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big()),
            Err(MempoolError::Full { capacity: 1 })
        );
    }

    #[test]
    fn select_returns_contiguous_run_and_stops_at_gap() {
        // Gap-free admission means a hole can't be *inserted* directly, so build one
        // the only way it can now arise: admit a contiguous run, then remove an
        // interior nonce (as if it were dropped some other way).
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        let gap = tx([1; 32], "usa.reserve.sov", 2);
        let gap_id = gap.id();
        pool.insert(gap, 0, big()).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 3), 0, big())
            .unwrap();
        // Punch a hole at nonce 2; nonce 3 is now unreachable behind the gap.
        assert!(pool.remove(&gap_id).is_some());

        let batch = pool.select(|_| 0, 10);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].transaction.nonce, 0);
        assert_eq!(batch[1].transaction.nonce, 1);
    }

    #[test]
    fn rejects_nonce_gap_at_admission() {
        // (a) A tx whose nonce leaps past the sender's contiguous pending run is
        // refused at the door — a gap can never form in the pool.
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        // Account at nonce 0 with one pooled tx (nonce 0): the next mineable nonce
        // is 1. Submitting nonce 2 would strand it behind the missing nonce 1.
        assert_eq!(
            pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0, big()),
            Err(MempoolError::NonceGap {
                expected: 1,
                got: 2,
            })
        );
        assert_eq!(pool.len(), 1, "the gapped tx must not enter the pool");
    }

    #[test]
    fn contiguous_fill_promotes_and_mines_in_order() {
        // (b) Submitting exactly the next nonce each time is always accepted, and
        // the whole run selects in ascending nonce order.
        let mut pool = Mempool::new(100);
        for n in 0..5 {
            pool.insert(tx([1; 32], "usa.reserve.sov", n), 0, big())
                .unwrap();
        }
        let batch = pool.select(|_| 0, 10);
        assert_eq!(batch.len(), 5);
        for (i, stx) in batch.iter().enumerate() {
            assert_eq!(stx.transaction.nonce, i as u64);
        }
    }

    #[test]
    fn stranded_entry_is_ttl_evicted_and_account_recovers() {
        // (c) A permanent gap: admit a contiguous run, then drop the head nonce (as
        // if it were rejected/never mined) so the account's nonce stays at 0 while
        // higher nonces sit stranded behind the hole.
        let mut pool = Mempool::new(100);
        let head = tx([1; 32], "usa.reserve.sov", 0);
        let head_id = head.id();
        pool.insert(head, 0, big()).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0, big())
            .unwrap();
        assert!(pool.remove(&head_id).is_some());
        // Nonces 1 and 2 are now stranded behind the gap at 0.
        assert_eq!(pool.len(), 2);
        assert_eq!(
            pool.select(|_| 0, 10).len(),
            0,
            "nothing mineable behind the gap"
        );

        // A generous TTL keeps them: not yet expired, so nothing is evicted.
        assert_eq!(pool.evict_stranded(|_| 0, u64::MAX), 0);
        assert_eq!(pool.len(), 2);

        // A zero TTL reaps every stranded entry immediately (the maintenance tick
        // clearing a permanent gap).
        assert_eq!(pool.evict_stranded(|_| 0, 0), 2);
        assert!(pool.is_empty(), "the permanent gap self-cleared");

        // The account recovers: resubmit the missing nonce, then the rest, and the
        // run mines in order again.
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0, big())
            .unwrap();
        let batch = pool.select(|_| 0, 10);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].transaction.nonce, 0);
    }

    #[test]
    fn evict_stranded_keeps_the_contiguous_run() {
        // A healthy contiguous run has no gap, so TTL-eviction never touches it —
        // even at ttl 0.
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        assert_eq!(pool.evict_stranded(|_| 0, 0), 0);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn select_never_proposes_a_gap_tx() {
        // (d) Even with a stranded entry present, block-building selects only the
        // contiguous prefix and never the tx behind the gap.
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        let mid = tx([1; 32], "usa.reserve.sov", 2);
        let mid_id = mid.id();
        pool.insert(mid, 0, big()).unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 3), 0, big())
            .unwrap();
        // Drop nonce 2, stranding nonce 3.
        assert!(pool.remove(&mid_id).is_some());

        let batch = pool.select(|_| 0, 10);
        assert!(batch.iter().all(|stx| stx.transaction.nonce < 2));
        assert_eq!(batch.len(), 2, "only the gap-free prefix is proposed");
    }

    #[test]
    fn select_respects_current_nonce() {
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 5), 5, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 6), 5, big())
            .unwrap();
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
        pool.insert(t, 0, big()).unwrap();
        assert!(pool.remove(&tid).is_some());
        assert!(pool.is_empty());

        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        // Account advanced to nonce 1; the pooled nonce-0 tx is now stale.
        pool.prune_stale(|_| 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn per_sender_cap_bounds_one_account() {
        // A single sender may hold at most `max_per_sender`; beyond that it is
        // refused even when the pool has room — anti-DoS fairness.
        let mut pool = Mempool::with_limits(100, 2);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        let third = pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0, big());
        assert!(matches!(
            third,
            Err(MempoolError::SenderLimit { limit: 2, .. })
        ));
        // A different sender is unaffected (the cap is per-account).
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn full_pool_evicts_the_heaviest_senders_highest_nonce() {
        // Capacity 3, generous per-sender cap. A hog fills the pool (nonces 0,1,2).
        let mut pool = Mempool::with_limits(3, 10);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "usa.reserve.sov", 2), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 3);
        // A new sender's tx is admitted by evicting the hog's HIGHEST nonce (2).
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big())
            .unwrap();
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
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big())
            .unwrap();
        let newcomer = pool.insert(tx([3; 32], "boj.reserve.sov", 0), 0, big());
        assert!(matches!(newcomer, Err(MempoolError::Full { capacity: 2 })));
        assert_eq!(pool.len(), 2);
    }
}
