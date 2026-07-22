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
//! - bounds its own size — and at capacity runs a blockspace AUCTION: a new tx
//!   that outbids (tips more than) the pool's cheapest safely-evictable tx
//!   displaces it, so "mempool full" is economically impossible for an adequate
//!   bid, while an underbid gets the actionable [`MempoolError::BelowFloor`];
//! - supports replace-by-fee: a same-`(signer, nonce)` resubmission that raises
//!   the tip by [`MIN_RBF_BUMP_GRAINS`] replaces the pooled original — the
//!   unstick/cancel path; and
//! - on request, returns a block template batch by the auction: highest
//!   [`effective_tip`] first across signers, ascending nonce within a signer (a
//!   nonce package — a later nonce never jumps its own signer's earlier one),
//!   never proposing a transaction that would be rejected for a nonce gap. A
//!   low- or zero-tip tx is never *rejected* for being cheap (the auction is
//!   ordering, not admission): it waits, and with no tips anywhere the schedule
//!   is byte-identical to the legacy fair nonce ordering.
//!
//! The pool deliberately does *not* check balances: balances change as a block
//! executes, so affordability is the execution layer's call. The pool's
//! contract is "well-formed and correctly ordered," not "guaranteed to succeed."

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sov_primitives::{AccountId, Balance, Hash, SigningDomain};
use sov_types::{Action, SignedTransaction};

/// TTL for [`Mempool::evict_stranded`]: an entry left behind a nonce hole (only
/// possible via reorg re-admission — gap-free admission prevents fresh holes) that
/// has been stuck this long is dropped so the account self-heals. 30 minutes is far
/// longer than any honest confirmation wait, so a live, soon-mineable tx is never
/// evicted, while a genuinely stranded one clears.
pub const STRANDED_TTL_MS: u64 = 30 * 60 * 1000;

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
    /// The pool is at capacity and no displacement is possible at this bid: either
    /// every evictable transaction belongs to the submitting signer itself (evicting
    /// one would strand the newcomer behind its own hole), or — with a zero bid
    /// against a zero floor — the pool is fairly shared with no over-represented
    /// sender to trim. With the blockspace auction this is only reachable when the
    /// floor is zero (or self-displacement is the sole option); any bid ABOVE the
    /// floor displaces instead of erroring, and an inadequate bid against a nonzero
    /// floor gets the actionable [`MempoolError::BelowFloor`] instead.
    #[error("mempool is full ({capacity} transactions)")]
    Full {
        /// The configured capacity.
        capacity: usize,
    },
    /// The pool is at capacity and the transaction's tip does not BEAT the current
    /// mempool floor — the lowest tip among evictable (per-signer highest-nonce)
    /// pooled transactions, i.e. the emergent market price of a pool slot. The
    /// transaction is not "too cheap to be valid" — it is outbid *right now*: raise
    /// the tip above `floor` (or wait for demand to fall) and resubmit. This is the
    /// auction's only refusal; a bid above the floor always finds room (Rule B).
    #[error(
        "mempool at capacity: tip does not beat the current floor of {floor} — raise the tip and resubmit"
    )]
    BelowFloor {
        /// The lowest tip currently protecting a pool slot; a new tx must bid
        /// strictly more than this to displace it.
        floor: Balance,
    },
    /// A replace-by-fee attempt raised the tip, but not by the anti-churn minimum
    /// bump: a replacement for a pooled `(signer, nonce)` must tip at least
    /// `required` (= old tip + [`MIN_RBF_BUMP_GRAINS`]). Prevents zero-cost
    /// replacement spam while keeping the unstick/cancel path open.
    #[error("replacement underpriced: this (signer, nonce) slot requires a tip of at least {required} to replace")]
    RbfUnderpriced {
        /// The minimum tip a successful replacement must carry.
        required: Balance,
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
        // A fee-auction envelope debits the TIP from the signer (to the miner) on top
        // of whatever its inner action moves — both must be affordable or the tx can
        // never execute. `Tipped` never nests (rejected at decode and execution), so
        // this recursion is depth-1 in practice and decode-bounded regardless.
        Action::Tipped { tip, inner } => tip.grains().saturating_add(base_outflow(inner)),
        _ => 0,
    }
}

/// The priority bid a transaction carries in the blockspace auction: the `tip` of a
/// top-level [`Action::Tipped`] envelope, else zero. Exactly ONE level is unwrapped —
/// a `Tipped` is never nested (execution and decode both reject nesting), and even if
/// one slipped in, the outer tip alone is the bid. An untipped (legacy v1) transaction
/// bids zero: it is never *rejected* for that (Rule A) — it simply waits its turn
/// behind funded bids when blockspace or pool slots are contested.
pub fn effective_tip(stx: &SignedTransaction) -> Balance {
    match &stx.transaction.action {
        Action::Tipped { tip, .. } => *tip,
        _ => Balance::ZERO,
    }
}

/// Minimum tip increase (in grains, 10⁻⁸ XUS) a replace-by-fee must add over the
/// pooled transaction it displaces: `new_tip ≥ old_tip + MIN_RBF_BUMP_GRAINS`.
/// 1_000 grains = 0.00001 XUS — economically negligible for a genuine repricing, but
/// nonzero so an attacker cannot churn the pool (and the relay layer) with an endless
/// stream of free equal-tip replacements. Same rationale as Bitcoin's BIP-125 rule 4
/// incremental-relay-fee bump.
pub const MIN_RBF_BUMP_GRAINS: u128 = 1_000;

/// One sender may occupy at most this fraction of the pool (1/64), floored at 16,
/// so a single account cannot crowd everyone else out — the anti-DoS fairness
/// bound that complements the blockspace auction: tips decide WHO WINS contested
/// slots ([`effective_tip`]), this cap bounds how many slots one account may
/// contest at all.
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

/// The safely-evictable pooled transaction a full pool would displace first — the
/// auction's marginal slot. See [`Mempool::eviction_victim`].
struct EvictionVictim {
    /// The victim's tx id.
    id: Hash,
    /// The victim's [`effective_tip`], in grains — the pool's current price floor.
    tip: u128,
    /// How many transactions the victim's sender holds (legacy-fairness tie-break;
    /// a zero-tip tie only displaces a sender holding more than one).
    sender_count: usize,
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
    /// The active network signing domain once the miner-signaled `tx-domain` hard
    /// fork has activated (`None` before activation, and until the node sets it via
    /// [`set_domain`](Self::set_domain)). Admission verifies signatures under this
    /// domain, so post-activation a legacy (un-bound) or cross-network-replayed
    /// signature is refused at the door — matching what block execution enforces.
    /// `None` is byte-identical to pre-fork admission.
    domain: Option<SigningDomain>,
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
            domain: None,
        }
    }

    /// Set the network signing domain used to verify admitted signatures. The node
    /// refreshes this on every tip advance to the domain resolved at the next
    /// height (`None` while the `tx-domain` fork is dormant). Once the fork is
    /// active this is `Some`, and admission rejects legacy/cross-network signatures
    /// exactly as block execution does.
    pub fn set_domain(&mut self, domain: Option<SigningDomain>) {
        self.domain = domain;
    }

    /// Number of pending transactions from `signer`.
    fn sender_count(&self, signer: &AccountId) -> usize {
        self.by_sender
            .range((signer.clone(), 0)..=(signer.clone(), u64::MAX))
            .count()
    }

    /// The next nonce a NEW transaction from `signer` should carry, given the
    /// signer's `on_chain_nonce` (its committed ledger nonce): the first FREE slot at
    /// or above `on_chain_nonce`, i.e. the first nonce not already pooled for the
    /// signer. Normally the pool keeps a sender's pending nonces gap-free and
    /// contiguous from the on-chain nonce (admission refuses any hole), so this equals
    /// `on_chain_nonce + pending_count`; a reorg can transiently strand higher nonces
    /// above a hole, and then this returns the hole — the slot the wallet must fill.
    ///
    /// This is the fix for "I already have a transaction waiting in the mempool":
    /// a wallet that signs with the bare `sov_getNonce` (on-chain) value reuses a
    /// slot already taken and is rejected with [`MempoolError::NonceTaken`]; signing
    /// with THIS value instead queues the new transaction behind the pending one, so
    /// several sends can be in flight at once and mine in order. Pure read; changes
    /// no consensus rule — the pool already accepts this nonce today.
    ///
    /// Implemented as a first-FREE-slot walk from `on_chain_nonce`, NOT
    /// `on_chain_nonce + count`. When the sender's pooled run is contiguous (the
    /// normal case, since admission is gap-free) the two are identical. But a reorg
    /// re-admission can leave a HOLE below the run (a reverted low-nonce tx that fails
    /// re-admission while higher nonces stay pooled); the count formula would then
    /// point AT a taken slot and wedge the wallet permanently, whereas the walk
    /// returns the hole — the exact nonce the wallet must fill to unstick itself. The
    /// walk is bounded: a sender holds at most `max_per_sender` entries, so the first
    /// free slot is within `on_chain_nonce ..= on_chain_nonce + max_per_sender`.
    pub fn next_nonce(&self, signer: &AccountId, on_chain_nonce: u64) -> u64 {
        let mut n = on_chain_nonce;
        // `max_per_sender + 1` steps suffice: with at most `max_per_sender` occupied
        // slots for this signer, at least one of the first `max_per_sender + 1` nonces
        // from `on_chain_nonce` is free. The `+1` bound also guarantees termination.
        for _ in 0..=self.max_per_sender {
            if !self.by_sender.contains_key(&(signer.clone(), n)) {
                return n;
            }
            n = n.saturating_add(1);
        }
        n
    }

    /// The transaction a full pool would evict to make room — the auction's
    /// marginal slot — or `None` if nothing is safely evictable.
    ///
    /// Candidates are restricted to each signer's TAIL (its highest pooled nonce):
    /// evicting an interior nonce would open a hole that strands every later nonce
    /// of that signer (the no-stranding rule), so only tails are ever displaced.
    /// The victim is the tail with the LOWEST [`effective_tip`] — its tip is the
    /// pool's emergent price floor. Ties on tip prefer the tail of the sender
    /// holding the MOST pooled transactions (the legacy fairness rule, which makes
    /// the all-zero-tip case byte-identical to the pre-auction
    /// heaviest-sender/highest-nonce eviction), then the first sender in id order
    /// (deterministic).
    ///
    /// `exclude`'s tails are never candidates: evicting the submitting signer's own
    /// tail (nonce t) to admit its next nonce (t+1) would trade one tx for another
    /// AND leave the newcomer stranded behind the hole at t — a pure loss.
    fn eviction_victim(&self, exclude: &AccountId) -> Option<EvictionVictim> {
        let mut best: Option<EvictionVictim> = None;
        let senders: BTreeSet<&AccountId> = self.by_sender.keys().map(|(s, _)| s).collect();
        for signer in senders {
            if signer == exclude {
                continue;
            }
            let Some((_, id)) = self
                .by_sender
                .range((signer.clone(), 0)..=(signer.clone(), u64::MAX))
                .next_back()
            else {
                continue;
            };
            let tip = effective_tip(&self.by_id[id]).grains();
            let count = self.sender_count(signer);
            // Strictly-better comparisons keep the FIRST (lowest-id) sender on full
            // ties, making the choice deterministic.
            let better = match &best {
                None => true,
                Some(b) => tip < b.tip || (tip == b.tip && count > b.sender_count),
            };
            if better {
                best = Some(EvictionVictim {
                    id: *id,
                    tip,
                    sender_count: count,
                });
            }
        }
        best
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
        if !stx.verify_signature_in(self.domain.as_ref()) {
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
        // An already-occupied (signer, nonce) slot: this is either replace-by-fee
        // (the unstick/cancel path — reprice a stuck tx, or cancel it by replacing
        // it with a self-transfer) or a collision. A replacement must RAISE the tip
        // by at least the anti-churn bump to displace the incumbent:
        //   new_tip ≥ old_tip + MIN_RBF_BUMP_GRAINS  →  atomically replace;
        //   old_tip < new_tip < required             →  RbfUnderpriced (raise more);
        //   new_tip ≤ old_tip                        →  NonceTaken (not a bid at all
        //                                               — byte-identical to the
        //                                               pre-auction behavior for
        //                                               untipped 0-vs-0 collisions).
        // Silent in-place overwrite is never allowed: it would orphan the old id in
        // `by_id` (unselectable, unprunable), silently leaking capacity.
        let slot = (stx.transaction.signer.clone(), nonce);
        if let Some(old_id) = self.by_sender.get(&slot).copied() {
            let old_tip = effective_tip(&self.by_id[&old_id]).grains();
            let new_tip = effective_tip(&stx).grains();
            if new_tip <= old_tip {
                return Err(MempoolError::NonceTaken {
                    signer: stx.transaction.signer.clone(),
                    nonce,
                });
            }
            let required = old_tip.saturating_add(MIN_RBF_BUMP_GRAINS);
            if new_tip < required {
                return Err(MempoolError::RbfUnderpriced {
                    required: Balance::from_grains(required),
                });
            }
            // Affordability of the post-replacement pool: the incumbent's outflow is
            // released and the replacement's reserved, atomically.
            let old_outflow = base_outflow(&self.by_id[&old_id].transaction.action);
            let committed = self
                .pending_outflow(&stx.transaction.signer)
                .saturating_sub(old_outflow)
                .saturating_add(base_outflow(&stx.transaction.action));
            if committed > balance.grains() {
                return Err(MempoolError::Insufficient {
                    available: balance.grains(),
                    committed,
                });
            }
            // Replace atomically: pool size and the sender's slot count are
            // unchanged, so neither the capacity auction nor the per-sender cap
            // applies, and the gap-free invariant is untouched (same slot).
            self.remove(&old_id);
            self.by_sender.insert(slot, id);
            self.by_id.insert(id, stx);
            self.inserted_at.insert(id, now_millis());
            return Ok(());
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
        // At capacity: the blockspace auction (Rule B — "full" must be economically
        // impossible for an adequate bid). The victim is the lowest-tip TAIL in the
        // pool (see `eviction_victim`; only tails are displaced, so no signer's run
        // is ever holed — the no-stranding rule) and its tip is the pool's emergent
        // price floor:
        //   new_tip > floor  →  the newcomer OUTBIDS the marginal slot: evict the
        //                       victim (it can rebid with a higher tip) and admit;
        //   new_tip == floor →  not an outbid; the legacy FAIRNESS rule decides the
        //                       tie: displace only a sender holding more than one tx
        //                       (with all tips zero this is byte-identical to the
        //                       pre-auction heaviest-sender/highest-nonce eviction);
        //   otherwise        →  refuse — BelowFloor (raise the tip) when a nonzero
        //                       price exists, the legacy Full when the floor is zero
        //                       (a zero bid against a fairly-shared zero-tip pool)
        //                       or nothing is evictable at all (every tail is the
        //                       submitting signer's own).
        if self.by_id.len() >= self.capacity {
            let new_tip = effective_tip(&stx).grains();
            match self.eviction_victim(&stx.transaction.signer) {
                // Displace either by STRICTLY outbidding the cheapest displaceable tail,
                // OR — only at a ZERO floor — by the legacy heaviest-sender fairness tie
                // (a sender holding >1 tx yields a slot). Gating the tie on `v.tip == 0`
                // keeps the no-tips path byte-identical to the pre-auction eviction AND
                // closes an equal-tip sybil displacement: at any NONZERO tip a newcomer
                // must strictly outbid (new_tip > v.tip), never merely match, to evict.
                Some(v)
                    if new_tip > v.tip
                        || (new_tip == v.tip && v.tip == 0 && v.sender_count > 1) =>
                {
                    self.remove(&v.id);
                }
                Some(v) if v.tip > 0 => {
                    return Err(MempoolError::BelowFloor {
                        floor: Balance::from_grains(v.tip),
                    });
                }
                _ => {
                    return Err(MempoolError::Full {
                        capacity: self.capacity,
                    });
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

    /// Select an executable batch of up to `max` transactions by the blockspace
    /// AUCTION: highest-tip-first across signers, per-signer nonce order within.
    ///
    /// Each signer contributes its contiguous mineable run (nonces from its
    /// `current_nonce` up to the first gap) as an ordered NONCE PACKAGE — nonce
    /// N+1 is only ever mineable after N, so a later nonce can never jump its own
    /// signer's earlier one, whatever its tip. The batch is then filled greedily:
    /// each step takes, across all signers, the one whose HEAD (lowest unselected)
    /// transaction carries the highest [`effective_tip`], appends that head, and
    /// advances the signer. A signer's head tip reprices at every step (a cheap
    /// nonce ahead of an expensive one holds the package to the cheap head's bid —
    /// the account-model equivalent of ancestor-feerate scoring).
    ///
    /// Ties on the head tip go to the FIRST signer in id order; with every tip
    /// zero (the no-demand / pre-activation case) this therefore degenerates to
    /// EXACTLY the legacy fair schedule — signers in ascending id order, each
    /// contributing its full contiguous run — byte-identical output, so untipped
    /// behavior is unchanged.
    ///
    /// A low- or zero-tip transaction is never dropped here (Rule A): it simply
    /// sorts later, stays pooled when the block fills, and is picked up by a
    /// future template once demand clears.
    pub fn select<F: Fn(&AccountId) -> u64>(
        &self,
        current_nonce: F,
        max: usize,
    ) -> Vec<SignedTransaction> {
        // Per-signer mineable queues: the contiguous run from the on-chain nonce,
        // in nonce order. BTreeMap keeps signers in ascending id order for the
        // deterministic (and legacy-identical) tie-break below.
        let mut queues: BTreeMap<&AccountId, std::collections::VecDeque<&SignedTransaction>> =
            BTreeMap::new();
        let signers: BTreeSet<&AccountId> = self.by_sender.keys().map(|(s, _)| s).collect();
        for signer in signers {
            let mut nonce = current_nonce(signer);
            let mut queue = std::collections::VecDeque::new();
            while let Some(id) = self.by_sender.get(&(signer.clone(), nonce)) {
                queue.push_back(&self.by_id[id]);
                nonce += 1;
            }
            if !queue.is_empty() {
                queues.insert(signer, queue);
            }
        }
        let mut out = Vec::new();
        while out.len() < max && !queues.is_empty() {
            // Head-tip greedy: the signer whose NEXT mineable tx bids highest.
            // Strict `>` keeps the first (lowest-id) signer on ties.
            let mut best: Option<(&AccountId, u128)> = None;
            for (signer, queue) in &queues {
                let head_tip = effective_tip(queue.front().expect("queues are non-empty")).grains();
                if best.is_none_or(|(_, t)| head_tip > t) {
                    best = Some((*signer, head_tip));
                }
            }
            let winner = best.expect("queues is non-empty").0;
            let queue = queues.get_mut(&winner).expect("winner is present");
            out.push(queue.pop_front().expect("queues are non-empty").clone());
            if queue.is_empty() {
                queues.remove(&winner);
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
    fn next_nonce_is_the_on_chain_nonce_when_pool_is_empty() {
        let pool = Mempool::new(100);
        assert_eq!(pool.next_nonce(&id("usa.reserve.sov"), 7), 7);
    }

    #[test]
    fn next_nonce_queues_a_second_send_behind_a_pending_one() {
        // I9 — the fix for "I already have a transaction waiting in the mempool":
        // with one tx pooled at the on-chain nonce, `next_nonce` advances so a second
        // send takes the NEXT slot and is ADMITTED (not rejected `NonceTaken`), and
        // both select in ascending nonce order. Same signer/key, back-to-back sends.
        let mut pool = Mempool::new(100);
        let signer = id("usa.reserve.sov");
        assert_eq!(
            pool.next_nonce(&signer, 0),
            0,
            "empty pool → on-chain nonce"
        );

        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        assert_eq!(pool.next_nonce(&signer, 0), 1, "one pending → queue at N+1");

        // The queued send at nonce 1 is accepted; at nonce 0 it would be NonceTaken.
        pool.insert(tx([1; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();
        assert_eq!(pool.next_nonce(&signer, 0), 2);

        let picked = pool.select(|_| 0, 10);
        assert_eq!(picked.len(), 2, "both queued sends are mineable");
        assert_eq!(picked[0].transaction.nonce, 0);
        assert_eq!(picked[1].transaction.nonce, 1);
    }

    #[test]
    fn next_nonce_returns_the_hole_when_a_reorg_strands_higher_nonces() {
        // Finding 1 (Fable audit): a reorg can leave {5,6} pooled with on-chain nonce
        // still 3 (the reverted low nonces 3,4 failed re-admission). The OLD count
        // formula (3 + 2 pending = 5) points AT a taken slot → NonceTaken → permanent
        // wedge. The first-free-slot walk returns 3 — the exact hole to fill to unstick.
        let mut pool = Mempool::new(100);
        let signer = id("usa.reserve.sov");
        for n in 3..=6 {
            pool.insert(tx([1; 32], "usa.reserve.sov", n), 3, big())
                .unwrap();
        }
        // Strand: drop nonces 3 and 4, leaving {5,6} with on-chain still 3.
        pool.remove(&tx([1; 32], "usa.reserve.sov", 3).id());
        pool.remove(&tx([1; 32], "usa.reserve.sov", 4).id());
        assert_eq!(
            pool.next_nonce(&signer, 3),
            3,
            "walk returns the hole nonce, not the count-formula's taken slot"
        );
        // And the hole is immediately fillable (admission accepts it → self-heal).
        pool.insert(tx([1; 32], "usa.reserve.sov", 3), 3, big())
            .unwrap();
        assert_eq!(pool.next_nonce(&signer, 3), 4);
    }

    #[test]
    fn next_nonce_drops_back_after_eviction_restores_contiguity() {
        // Eviction always removes the HIGHEST nonce, so contiguity from the bottom is
        // preserved and next_nonce falls back to the freed slot.
        let mut pool = Mempool::new(100);
        let signer = id("usa.reserve.sov");
        for n in 0..3 {
            pool.insert(tx([1; 32], "usa.reserve.sov", n), 0, big())
                .unwrap();
        }
        assert_eq!(pool.next_nonce(&signer, 0), 3);
        pool.evict_highest_nonce(&signer); // drops nonce 2
        assert_eq!(pool.next_nonce(&signer, 0), 2);
    }

    #[test]
    fn next_nonce_is_bounded_at_the_sender_limit() {
        // A full sender run returns the slot just past the limit; that nonce will be
        // rejected SenderLimit at insert — the wallet is correctly told the queue is full,
        // and the walk still terminates (no unbounded loop).
        let mut pool = Mempool::with_limits(100, 3);
        let signer = id("usa.reserve.sov");
        for n in 0..3 {
            pool.insert(tx([1; 32], "usa.reserve.sov", n), 0, big())
                .unwrap();
        }
        assert_eq!(pool.next_nonce(&signer, 0), 3);
        assert!(matches!(
            pool.insert(tx([1; 32], "usa.reserve.sov", 3), 0, big()),
            Err(MempoolError::SenderLimit { .. })
        ));
    }

    #[test]
    fn reusing_the_on_chain_nonce_while_pending_is_still_rejected() {
        // The bug the fix avoids: signing the SECOND send with the bare on-chain nonce
        // (0) instead of `next_nonce` collides with the pooled slot → NonceTaken. This
        // pins the exact failure the wallet must not reproduce.
        let mut pool = Mempool::new(100);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        assert!(matches!(
            pool.insert(tx([2; 32], "usa.reserve.sov", 0), 0, big()),
            Err(MempoolError::NonceTaken { .. })
        ));
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

    // ── Blockspace auction (v0.1.98 slice 3) ────────────────────────────────────

    /// A signed `Tipped { tip, Transfer(1 XUS) }` from `from` at `nonce`, bidding
    /// `tip_grains` for priority.
    fn tipped(seed: [u8; 32], from: &str, nonce: u64, tip_grains: u128) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let t = Transaction {
            signer: id(from),
            public_key: kp.public_key(),
            nonce,
            action: Action::Tipped {
                tip: Balance::from_grains(tip_grains),
                inner: Box::new(Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(1).unwrap(),
                }),
            },
        };
        SignedTransaction::sign(t, &kp).unwrap()
    }

    #[test]
    fn effective_tip_reads_the_envelope_else_zero() {
        assert_eq!(
            effective_tip(&tipped([1; 32], "usa.reserve.sov", 0, 777)),
            Balance::from_grains(777)
        );
        assert_eq!(
            effective_tip(&tx([1; 32], "usa.reserve.sov", 0)),
            Balance::ZERO,
            "an untipped tx bids zero"
        );
    }

    #[test]
    fn low_tip_waits_behind_high_tip_in_the_template() {
        // Rule A: both admit without error; the auction ORDERS them. With room for
        // only 1 tx, the high bid is templated first and the low bid stays pooled.
        let mut pool = Mempool::new(100);
        let low = tx([1; 32], "usa.reserve.sov", 0); // tip 0
        let low_id = low.id();
        pool.insert(low, 0, big()).unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 5_000), 0, big())
            .unwrap();

        let template = pool.select(|_| 0, 1);
        assert_eq!(template.len(), 1);
        assert_eq!(
            template[0].transaction.signer,
            id("ecb.reserve.sov"),
            "the high bid wins the contested slot"
        );
        assert!(
            pool.contains(&low_id),
            "the low bid WAITS — still pooled, never errored"
        );
        // With room for both, the low bid rides along after the high one.
        let both = pool.select(|_| 0, 2);
        assert_eq!(both.len(), 2);
        assert_eq!(both[1].transaction.signer, id("usa.reserve.sov"));
    }

    #[test]
    fn nonce_package_never_jumps_its_own_earlier_nonce() {
        // Signer A: nonce 0 bids low, nonce 1 bids huge. The package rule holds:
        // A's nonce 0 must still be selected before A's nonce 1 — the huge bid can
        // never leapfrog its own predecessor. A middling other-signer bid slots
        // between packages, not inside one.
        let mut pool = Mempool::new(100);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 1), 0, big())
            .unwrap();
        pool.insert(tipped([1; 32], "usa.reserve.sov", 1, 1_000_000), 0, big())
            .unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 500), 0, big())
            .unwrap();

        let batch = pool.select(|_| 0, 3);
        assert_eq!(batch.len(), 3);
        // ecb's 500 beats usa's HEAD (1), so it goes first; then usa 0 unlocks usa 1.
        assert_eq!(batch[0].transaction.signer, id("ecb.reserve.sov"));
        assert_eq!(batch[1].transaction.signer, id("usa.reserve.sov"));
        assert_eq!(
            batch[1].transaction.nonce, 0,
            "own nonce order is inviolable"
        );
        assert_eq!(batch[2].transaction.nonce, 1);
    }

    #[test]
    fn capacity_outbid_evicts_the_cheapest_tail_and_admits() {
        // Rule B: a full pool is not "full" to a better bid. Three tip=1 txs fill
        // it; a tip=5 newcomer displaces one tip=1 TAIL, pool size unchanged.
        let mut pool = Mempool::with_limits(3, 10);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 1), 0, big())
            .unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 1), 0, big())
            .unwrap();
        pool.insert(tipped([3; 32], "boj.reserve.sov", 0, 1), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 3);

        let winner = tipped([4; 32], "rba.reserve.sov", 0, 5);
        let winner_id = winner.id();
        pool.insert(winner, 0, big()).unwrap();
        assert_eq!(pool.len(), 3, "one-in, one-out: capacity is preserved");
        assert!(pool.contains(&winner_id), "the outbidder is admitted");
        // Exactly one tip=1 tx was displaced (it can rebid with a higher tip).
        let survivors = pool.select(|_| 0, 10);
        assert_eq!(
            survivors
                .iter()
                .filter(|stx| effective_tip(stx).grains() == 1)
                .count(),
            2
        );
    }

    #[test]
    fn capacity_underbid_is_refused_below_floor_not_full() {
        // Rule B's flip side: a bid under the floor is refused with the actionable
        // BelowFloor (carrying the price to beat) — never the dead-end Full.
        let mut pool = Mempool::with_limits(2, 10);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 5), 0, big())
            .unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 5), 0, big())
            .unwrap();

        let underbid = tipped([3; 32], "boj.reserve.sov", 0, 1);
        let underbid_id = underbid.id();
        assert_eq!(
            pool.insert(underbid, 0, big()),
            Err(MempoolError::BelowFloor {
                floor: Balance::from_grains(5),
            })
        );
        assert!(!pool.contains(&underbid_id), "the underbid is not admitted");
        assert_eq!(pool.len(), 2, "nothing was evicted for an underbid");
    }

    #[test]
    fn rule_a_zero_tip_is_admitted_under_capacity_and_waits() {
        // Rule A is absolute: with room in the pool, a zero-tip tx is ADMITTED —
        // no error for being cheap — and remains selectable.
        let mut pool = Mempool::new(100);
        let cheap = tx([1; 32], "usa.reserve.sov", 0);
        let cheap_id = cheap.id();
        pool.insert(cheap, 0, big()).unwrap();
        assert!(pool.contains(&cheap_id));
        assert_eq!(pool.select(|_| 0, 10).len(), 1, "it waits and gets mined");
    }

    #[test]
    fn eviction_never_strands_a_package_and_the_floor_is_the_tail_price() {
        // Signer A holds [n0 tip 0, n1 tip 9]: its n0 is NOT evictable (a hole at
        // n0 would strand n1) — only tails are. Signer B holds [n0 tip 3].
        // Entry price (floor) is therefore min over TAILS = 3, not the global min 0.
        let mut pool = Mempool::with_limits(3, 10);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 0), 0, big())
            .unwrap();
        pool.insert(tipped([1; 32], "usa.reserve.sov", 1, 9), 0, big())
            .unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 3), 0, big())
            .unwrap();

        // An underbid is priced against the TAIL floor (3), not the buried 0.
        assert_eq!(
            pool.insert(tipped([3; 32], "boj.reserve.sov", 0, 1), 0, big()),
            Err(MempoolError::BelowFloor {
                floor: Balance::from_grains(3),
            })
        );
        // A tip-5 bid beats the 3-tip tail: B is displaced; A's package is intact.
        pool.insert(tipped([3; 32], "boj.reserve.sov", 0, 5), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 3);
        let batch = pool.select(|_| 0, 10);
        let usa: Vec<u64> = batch
            .iter()
            .filter(|s| s.transaction.signer == id("usa.reserve.sov"))
            .map(|s| s.transaction.nonce)
            .collect();
        assert_eq!(usa, vec![0, 1], "A's nonce package was never holed");
        assert!(!batch
            .iter()
            .any(|s| s.transaction.signer == id("ecb.reserve.sov")));
    }

    #[test]
    fn own_tail_is_never_evicted_to_admit_own_next_nonce() {
        // A signer that filled the pool alone cannot displace its OWN tail to admit
        // its next nonce — that would hole its package (net loss). It gets Full.
        let mut pool = Mempool::with_limits(2, 10);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 5), 0, big())
            .unwrap();
        pool.insert(tipped([1; 32], "usa.reserve.sov", 1, 5), 0, big())
            .unwrap();
        assert_eq!(
            pool.insert(tipped([1; 32], "usa.reserve.sov", 2, 50), 0, big()),
            Err(MempoolError::Full { capacity: 2 })
        );
        // A DIFFERENT signer outbidding the floor still gets in normally.
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 9), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn rbf_replaces_at_the_bump_and_rejects_below_it() {
        // The unstick/cancel path: same (signer, nonce), tip raised by the minimum
        // bump ⇒ atomic replacement. Raised but under the bump ⇒ RbfUnderpriced.
        // Not raised at all ⇒ the legacy NonceTaken.
        let mut pool = Mempool::new(100);
        let original = tipped([1; 32], "usa.reserve.sov", 0, 100);
        let original_id = original.id();
        pool.insert(original, 0, big()).unwrap();

        // Raised, but under old + MIN_RBF_BUMP_GRAINS: refused with the price.
        assert_eq!(
            pool.insert(
                tipped([1; 32], "usa.reserve.sov", 0, 100 + MIN_RBF_BUMP_GRAINS - 1),
                0,
                big()
            ),
            Err(MempoolError::RbfUnderpriced {
                required: Balance::from_grains(100 + MIN_RBF_BUMP_GRAINS),
            })
        );
        assert!(
            pool.contains(&original_id),
            "underpriced RBF changes nothing"
        );

        // Exactly old + bump: replaces atomically — old id gone, new id in, len 1.
        let replacement = tipped([1; 32], "usa.reserve.sov", 0, 100 + MIN_RBF_BUMP_GRAINS);
        let replacement_id = replacement.id();
        pool.insert(replacement, 0, big()).unwrap();
        assert!(!pool.contains(&original_id), "the incumbent was displaced");
        assert!(pool.contains(&replacement_id));
        assert_eq!(pool.len(), 1, "replacement is one-for-one");
        // The replacement is what mines.
        assert_eq!(
            effective_tip(&pool.select(|_| 0, 1)[0]).grains(),
            100 + MIN_RBF_BUMP_GRAINS
        );
    }

    #[test]
    fn rbf_without_a_raise_is_still_nonce_taken() {
        // Equal (or lower) tip is not a bid: the legacy NonceTaken stands — which
        // also pins the untipped 0-vs-0 collision to its pre-auction behavior.
        let mut pool = Mempool::new(100);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 100), 0, big())
            .unwrap();
        assert_eq!(
            pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 50), 0, big()),
            Err(MempoolError::NonceTaken {
                signer: id("usa.reserve.sov"),
                nonce: 0,
            })
        );
    }

    #[test]
    fn tipped_affordability_reserves_tip_plus_transfer() {
        // The affordability gate counts tip + inner outflow: 2 XUS tip + 1 XUS
        // transfer needs 3 XUS. A 2.5-XUS account refuses it; 3 XUS admits it.
        let mut pool = Mempool::new(100);
        let need = Balance::from_sov(3).unwrap();
        let short = Balance::from_grains(need.grains() - 1);
        let bid = tipped(
            [1; 32],
            "usa.reserve.sov",
            0,
            Balance::from_sov(2).unwrap().grains(),
        );
        assert!(matches!(
            pool.insert(bid.clone(), 0, short),
            Err(MempoolError::Insufficient { .. })
        ));
        pool.insert(bid, 0, need).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn equal_tip_cannot_displace_at_a_nonzero_floor_must_strictly_outbid() {
        // Finding 3 (Fable audit): at a NONZERO floor, matching the tip is NOT enough
        // — a newcomer must STRICTLY outbid to evict. Closes zero-premium sybil
        // displacement of an honest multi-tx sender.
        let mut pool = Mempool::with_limits(3, 10);
        for n in 0..3 {
            pool.insert(tipped([1; 32], "usa.reserve.sov", n, 5), 0, big())
                .unwrap();
        }
        // A distinct signer MATCHING the tip (5) is refused — must outbid, not match.
        assert!(matches!(
            pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 5), 0, big()),
            Err(MempoolError::BelowFloor { .. })
        ));
        assert_eq!(pool.len(), 3, "equal tip did not displace");
        // A strict outbid (6) does get in.
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 6), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn a_zero_floor_refusal_is_full_never_belowfloor_zero() {
        // BelowFloor must NEVER quote a floor of 0: a full pool of single-tx, zero-tip
        // senders refuses a zero-tip newcomer with the legacy `Full`, not `BelowFloor{0}`.
        let mut pool = Mempool::with_limits(3, 10);
        pool.insert(tx([1; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([3; 32], "boj.reserve.sov", 0), 0, big())
            .unwrap();
        assert!(matches!(
            pool.insert(tx([9; 32], "rba.reserve.sov", 0), 0, big()),
            Err(MempoolError::Full { .. })
        ));
    }

    #[test]
    fn rbf_at_capacity_replaces_in_place_without_touching_the_floor() {
        // A same-slot RBF is one-for-one, so it replaces even at capacity — bypassing
        // the floor/eviction path entirely; pool size is unchanged.
        let mut pool = Mempool::with_limits(2, 10);
        pool.insert(tipped([1; 32], "usa.reserve.sov", 0, 5), 0, big())
            .unwrap();
        pool.insert(tipped([2; 32], "ecb.reserve.sov", 0, 5_000), 0, big())
            .unwrap();
        assert_eq!(pool.len(), 2);
        let bumped = tipped([1; 32], "usa.reserve.sov", 0, 5 + MIN_RBF_BUMP_GRAINS);
        let bumped_id = bumped.id();
        pool.insert(bumped, 0, big()).unwrap();
        assert_eq!(
            pool.len(),
            2,
            "RBF is one-for-one; capacity is not consumed"
        );
        assert!(pool.contains(&bumped_id), "the bumped tx replaced its slot");
    }

    #[test]
    fn no_tips_select_is_byte_identical_to_the_legacy_fair_order() {
        // THE regression pin: with zero tips everywhere, the auction MUST degenerate
        // to the legacy schedule — signers in ascending id order, each contributing
        // its full contiguous nonce run, truncated at `max`. Pinned explicitly.
        let mut pool = Mempool::new(100);
        // Insert in a scrambled order to prove ordering comes from the pool.
        pool.insert(tx([3; 32], "usa.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "boj.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([2; 32], "ecb.reserve.sov", 0), 0, big())
            .unwrap();
        pool.insert(tx([1; 32], "boj.reserve.sov", 1), 0, big())
            .unwrap();
        pool.insert(tx([3; 32], "usa.reserve.sov", 1), 0, big())
            .unwrap();

        let picked = pool.select(|_| 0, 10);
        let order: Vec<(AccountId, u64)> = picked
            .iter()
            .map(|s| (s.transaction.signer.clone(), s.transaction.nonce))
            .collect();
        // Legacy `select`: BTreeSet of signers (ascending id), full run each.
        assert_eq!(
            order,
            vec![
                (id("boj.reserve.sov"), 0),
                (id("boj.reserve.sov"), 1),
                (id("ecb.reserve.sov"), 0),
                (id("usa.reserve.sov"), 0),
                (id("usa.reserve.sov"), 1),
            ],
            "zero tips ⇒ byte-identical legacy fair ordering"
        );
        // And truncation at `max` cuts the same prefix as before.
        assert_eq!(
            pool.select(|_| 0, 3)
                .iter()
                .map(|s| (s.transaction.signer.clone(), s.transaction.nonce))
                .collect::<Vec<_>>(),
            order[..3].to_vec()
        );
    }
}
