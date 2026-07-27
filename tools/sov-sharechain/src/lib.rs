//! The SOV sharechain: **who gets paid, decided by a rule rather than by an
//! operator** (pool-mining Phase 3).
//!
//! # What a sharechain is for
//!
//! A pool exists because one miner alone waits a very long time between blocks.
//! Pooling smooths that out — but the naive way to do it is custodial: everyone
//! mines for the operator's address and trusts the operator to pay them. That
//! trust is the entire problem, and it is the thing this crate removes.
//!
//! A **share** is the same RandomX computation a block is, evaluated against an
//! easier target. Shares are therefore frequent and cheap to check, which makes
//! them a usable unit of accounting. Miners build a chain of them. When a share
//! happens to *also* meet the network target, the SOV block it carries must pay
//! out the recent share history — and the sharechain **rejects the share if it
//! does not**. The finder cannot keep the reward, because a block that pays only
//! the finder is not a valid share, so the rest of the network builds past it.
//!
//! That is the whole trick: payout is not enforced by an operator's honesty, it
//! is enforced by the same rule everyone is already following to earn credit.
//!
//! # What is NOT here
//!
//! **No consensus surface.** SOV sees ordinary blocks with ordinary
//! [`Transfer`](sov_primitives)-shaped payouts. Nothing in this crate changes
//! block or transaction encoding, the state root, emission, difficulty, or any
//! KAT vector. Nothing here signs anything: the block producer signs its own
//! payout transfers with its own key, exactly as it would sign any transaction.
//!
//! **No new cryptography.** Share seals are the node's `pow_seal`; transport is
//! the node's Noise/ML-KEM channel. This crate is accounting.
//!
//! # Why payouts can spend the same block's coinbase
//!
//! Verified against the runtime rather than assumed: `apply_coinbase` runs
//! **before** `apply_transactions` when a block is produced and when it is
//! imported. The producer's account is therefore credited with the block reward
//! before that block's own transactions execute, so the payout transfers can
//! spend the very coinbase they are distributing. No operator float is required,
//! and — because they are ordinary transactions — they are signed under whatever
//! tx-domain regime is active, needing no special authorization path. This was
//! the open design question recorded in `notes/activation-pool-mining.md`.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};

use sov_primitives::AccountId;

/// A share's identity — the hash of the block candidate it seals.
///
/// A share IS a block candidate; it simply met an easier target. Using the
/// candidate's hash as the identity means a share cannot be restated or
/// duplicated under another name.
pub type ShareId = [u8; 32];

/// Payout weights, in grains, keyed by the account that earned them.
///
/// `BTreeMap` deliberately: payouts are consensus-visible through the transfers
/// they require, so two peers must produce byte-identical output for identical
/// history. A `HashMap` would iterate in an arbitrary order and the resulting
/// transfer list could differ between nodes that agree on everything else.
pub type Payouts = BTreeMap<AccountId, u128>;

/// How many shares back the PPLNS window reaches.
///
/// PPLNS ("pay per last N shares") pays the *recent* history rather than the
/// round since the last block, which is what removes the incentive to hop
/// between pools: leaving forfeits the tail of your window, so loyal and
/// disloyal hashrate earn the same expected value.
pub const PPLNS_WINDOW: usize = 1_000;

/// The share an uncle earns relative to a share on the main line, as a
/// percentage.
///
/// Uncles are shares that were valid but lost the race. Paying them nothing
/// would punish miners for network latency they cannot control — which
/// centralizes toward whoever is closest to everyone else. Paying them in full
/// would make losing free. The compromise is deliberate and is the same reason
/// Ethereum paid uncles.
pub const UNCLE_WEIGHT_PCT: u128 = 75;

/// One share: a block candidate that met the share target, plus the sharechain
/// metadata that makes it accountable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// This share's identity (the sealed candidate's hash).
    pub id: ShareId,
    /// The share this one builds on. `None` only for the first share ever.
    pub prev: Option<ShareId>,
    /// Valid shares that lost the race, referenced so their finders still earn.
    /// A share may not uncle itself, its own ancestors, or the same id twice.
    pub uncles: Vec<ShareId>,
    /// The account that earns this share's weight — the finder's payout address.
    pub finder: AccountId,
    /// The work this share represents. A share at twice the difficulty counts
    /// twice, so miners cannot game the window by choosing an easier target.
    pub work: u128,
    /// Whether this share ALSO met the network target, i.e. it is a real block.
    pub is_block: bool,
}

/// Why a share was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareError {
    /// A share with this id is already known. Shares are unique by construction
    /// (the id is the sealed hash), so a duplicate is either a replay or a
    /// misbehaving peer.
    Duplicate(ShareId),
    /// The parent share is not known, so the share cannot be placed.
    UnknownParent(ShareId),
    /// Zero work would earn a share of the payout for nothing.
    ZeroWork,
    /// An uncle is unknown, is the share itself, is already an ancestor, or is
    /// listed twice.
    BadUncle(ShareId),
    /// The share claims to be a block but the payouts it embeds are not the ones
    /// the window requires. **This is the rule that makes the pool trustless.**
    WrongPayouts {
        /// What the sharechain requires, given the window.
        expected: Payouts,
        /// What the finder actually embedded.
        got: Payouts,
    },
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareError::Duplicate(_) => write!(f, "share already known"),
            ShareError::UnknownParent(_) => write!(f, "parent share is unknown"),
            ShareError::ZeroWork => write!(f, "share carries zero work"),
            ShareError::BadUncle(_) => write!(f, "invalid uncle reference"),
            ShareError::WrongPayouts { expected, got } => write!(
                f,
                "block share embeds the wrong payouts: {} entries expected, {} given",
                expected.len(),
                got.len()
            ),
        }
    }
}

impl std::error::Error for ShareError {}

/// A share and the position the chain assigned it.
#[derive(Clone, Debug)]
struct Entry {
    share: Share,
    /// Distance from the first share.
    height: u64,
    /// Total work of this share's whole ancestry, including uncles. Fork choice
    /// is heaviest-work, exactly as SOV's own is — the branch representing the
    /// most computation wins, not the longest one.
    cumulative_work: u128,
}

/// The share DAG and its accounting.
#[derive(Debug, Default)]
pub struct ShareChain {
    entries: HashMap<ShareId, Entry>,
    /// The current heaviest tip.
    tip: Option<ShareId>,
}

impl ShareChain {
    /// An empty sharechain.
    pub fn new() -> Self {
        Self::default()
    }

    /// The heaviest tip, if any share has been accepted.
    pub fn tip(&self) -> Option<ShareId> {
        self.tip
    }

    /// Total work along the current best branch.
    pub fn tip_work(&self) -> u128 {
        self.tip
            .and_then(|t| self.entries.get(&t))
            .map(|e| e.cumulative_work)
            .unwrap_or(0)
    }

    /// Number of shares known (across all branches).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no share is known yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The best branch, newest first, walking back from the tip.
    pub fn best_branch(&self) -> Vec<&Share> {
        let mut out = Vec::new();
        let mut cur = self.tip;
        while let Some(id) = cur {
            let Some(e) = self.entries.get(&id) else {
                break;
            };
            out.push(&e.share);
            cur = e.share.prev;
        }
        out
    }

    /// The payouts a block found NOW — on top of `parent` — must embed.
    ///
    /// Walks back at most [`PPLNS_WINDOW`] shares from `parent`, weighting each
    /// finder by the work they contributed, and splits `reward_grains` in those
    /// proportions. Uncles earn [`UNCLE_WEIGHT_PCT`] of a main-line share.
    ///
    /// Deterministic by construction: the same history yields byte-identical
    /// output on every peer, which is what lets the rule be checked rather than
    /// trusted. Remainder from integer division is given to the largest
    /// contributor (ties broken by account id) so the payouts always sum to
    /// exactly `reward_grains` — no dust is created or destroyed.
    pub fn payouts_for(&self, parent: Option<ShareId>, reward_grains: u128) -> Payouts {
        let mut weights: BTreeMap<AccountId, u128> = BTreeMap::new();
        let mut total: u128 = 0;
        let mut cur = parent;
        let mut seen = 0usize;

        while let Some(id) = cur {
            if seen >= PPLNS_WINDOW {
                break;
            }
            let Some(e) = self.entries.get(&id) else {
                break;
            };
            *weights.entry(e.share.finder.clone()).or_default() += e.share.work;
            total += e.share.work;
            for u in &e.share.uncles {
                if let Some(ue) = self.entries.get(u) {
                    let w = ue.share.work * UNCLE_WEIGHT_PCT / 100;
                    *weights.entry(ue.share.finder.clone()).or_default() += w;
                    total += w;
                }
            }
            seen += 1;
            cur = e.share.prev;
        }

        let mut out: Payouts = BTreeMap::new();
        if total == 0 || reward_grains == 0 {
            return out;
        }
        let mut assigned: u128 = 0;
        for (acct, w) in &weights {
            let cut = reward_grains * w / total;
            if cut > 0 {
                out.insert(acct.clone(), cut);
                assigned += cut;
            }
        }
        // Integer division loses a few grains; give them to the largest earner so
        // the sum is exact. Dropping them would quietly burn value on every block.
        if assigned < reward_grains {
            if let Some((acct, _)) = weights
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            {
                *out.entry(acct.clone()).or_default() += reward_grains - assigned;
            }
        }
        out
    }

    /// Accept a share, enforcing every sharechain rule.
    ///
    /// `embedded_payouts` is what the share's block actually pays and is checked
    /// only when `share.is_block` — a share below the network target carries no
    /// block, so there is nothing to pay yet.
    pub fn accept(
        &mut self,
        share: Share,
        reward_grains: u128,
        embedded_payouts: &Payouts,
    ) -> Result<(), ShareError> {
        if self.entries.contains_key(&share.id) {
            return Err(ShareError::Duplicate(share.id));
        }
        if share.work == 0 {
            return Err(ShareError::ZeroWork);
        }
        let parent = match share.prev {
            None => None,
            Some(p) => Some(
                self.entries
                    .get(&p)
                    .ok_or(ShareError::UnknownParent(p))?
                    .clone(),
            ),
        };

        // Uncles: known, not self, not already an ancestor, and not repeated. An
        // ancestor uncled again would be paid twice for one piece of work.
        let ancestry: HashSet<ShareId> = {
            let mut set = HashSet::new();
            let mut cur = share.prev;
            while let Some(id) = cur {
                if !set.insert(id) {
                    break;
                }
                cur = self.entries.get(&id).and_then(|e| e.share.prev);
            }
            set
        };
        let mut uncle_work: u128 = 0;
        let mut seen_uncles: HashSet<ShareId> = HashSet::new();
        for u in &share.uncles {
            if *u == share.id || ancestry.contains(u) || !seen_uncles.insert(*u) {
                return Err(ShareError::BadUncle(*u));
            }
            let ue = self.entries.get(u).ok_or(ShareError::BadUncle(*u))?;
            uncle_work += ue.share.work * UNCLE_WEIGHT_PCT / 100;
        }

        // THE RULE. A share that carries a real block must pay the window. This
        // is the only thing standing between a pool and its operator's honesty,
        // so it is checked before the share is recorded, and an exact match is
        // required — "close enough" would let a finder shave every payout.
        if share.is_block {
            let expected = self.payouts_for(share.prev, reward_grains);
            if &expected != embedded_payouts {
                return Err(ShareError::WrongPayouts {
                    expected,
                    got: embedded_payouts.clone(),
                });
            }
        }

        let height = parent.as_ref().map(|p| p.height + 1).unwrap_or(0);
        let cumulative_work =
            parent.as_ref().map(|p| p.cumulative_work).unwrap_or(0) + share.work + uncle_work;

        let id = share.id;
        self.entries.insert(
            id,
            Entry {
                share,
                height,
                cumulative_work,
            },
        );

        // Heaviest-work fork choice, matching SOV's own. A tie keeps the
        // incumbent so peers do not flap between equal branches.
        let better = match self.tip.and_then(|t| self.entries.get(&t)) {
            None => true,
            Some(t) => cumulative_work > t.cumulative_work,
        };
        if better {
            self.tip = Some(id);
        }
        Ok(())
    }

    /// The sharechain height of a known share.
    pub fn height_of(&self, id: &ShareId) -> Option<u64> {
        self.entries.get(id).map(|e| e.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(s: &str) -> AccountId {
        AccountId::new(s).expect("valid account id")
    }

    fn id(n: u8) -> ShareId {
        [n; 32]
    }

    fn share(n: u8, prev: Option<ShareId>, finder: &str, work: u128) -> Share {
        Share {
            id: id(n),
            prev,
            uncles: Vec::new(),
            finder: acct(finder),
            work,
            is_block: false,
        }
    }

    /// Build a chain of `n` equal-work shares alternating between two miners.
    fn chain_of(n: u8) -> ShareChain {
        let mut sc = ShareChain::new();
        let mut prev = None;
        for i in 0..n {
            let who = if i % 2 == 0 { "alice.sov" } else { "bob.sov" };
            sc.accept(share(i, prev, who, 100), 0, &Payouts::new())
                .expect("accept");
            prev = Some(id(i));
        }
        sc
    }

    #[test]
    fn shares_accumulate_work_and_the_heaviest_branch_wins() {
        let mut sc = ShareChain::new();
        sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new())
            .expect("root");
        sc.accept(share(1, Some(id(0)), "bob.sov", 100), 0, &Payouts::new())
            .expect("extend");
        assert_eq!(sc.tip(), Some(id(1)));
        assert_eq!(sc.tip_work(), 200);

        // A heavier sibling branch takes the tip.
        sc.accept(share(2, Some(id(0)), "carol.sov", 500), 0, &Payouts::new())
            .expect("fork");
        assert_eq!(sc.tip(), Some(id(2)), "heaviest work wins, not longest");
        assert_eq!(sc.tip_work(), 600);

        // The orphaned branch is still KNOWN — it may be uncled — but it is not
        // the best branch.
        let best: Vec<ShareId> = sc.best_branch().iter().map(|s| s.id).collect();
        assert_eq!(best, vec![id(2), id(0)]);
        assert_eq!(sc.len(), 3);
    }

    #[test]
    fn a_tie_keeps_the_incumbent_tip() {
        let mut sc = ShareChain::new();
        sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new())
            .expect("root");
        sc.accept(share(1, Some(id(0)), "bob.sov", 100), 0, &Payouts::new())
            .expect("a");
        sc.accept(share(2, Some(id(0)), "carol.sov", 100), 0, &Payouts::new())
            .expect("b");
        assert_eq!(
            sc.tip(),
            Some(id(1)),
            "equal work must not flap the tip between peers"
        );
    }

    /// The determinism requirement: identical history MUST produce identical
    /// weights, or peers cannot check each other's payouts at all.
    #[test]
    fn identical_history_yields_identical_payouts() {
        let a = chain_of(20);
        let b = chain_of(20);
        let pa = a.payouts_for(a.tip(), 12_500_000_000);
        let pb = b.payouts_for(b.tip(), 12_500_000_000);
        assert_eq!(pa, pb, "same history must pay identically on every peer");
        assert!(!pa.is_empty());
    }

    /// Payouts must sum to EXACTLY the reward — integer division must not quietly
    /// burn grains on every block.
    #[test]
    fn payouts_sum_to_exactly_the_reward() {
        let sc = chain_of(7); // 7 shares: an odd split that will not divide evenly
        for reward in [1u128, 3, 12_500_000_000, 999_999_999_999] {
            let p = sc.payouts_for(sc.tip(), reward);
            let total: u128 = p.values().sum();
            assert_eq!(
                total, reward,
                "payouts must sum exactly for reward {reward}"
            );
        }
    }

    /// Weight follows WORK, not share count — otherwise a miner could farm
    /// credit by submitting many easy shares.
    #[test]
    fn payout_weight_follows_work_not_share_count() {
        let mut sc = ShareChain::new();
        // alice: one heavy share. bob: three light ones totalling less.
        sc.accept(share(0, None, "alice.sov", 900), 0, &Payouts::new())
            .expect("a");
        let mut prev = Some(id(0));
        for i in 1..4u8 {
            sc.accept(share(i, prev, "bob.sov", 100), 0, &Payouts::new())
                .expect("b");
            prev = Some(id(i));
        }
        let p = sc.payouts_for(sc.tip(), 1_200);
        // total work 900 + 300 = 1200 ⇒ alice 900, bob 300.
        assert_eq!(p.get(&acct("alice.sov")), Some(&900));
        assert_eq!(p.get(&acct("bob.sov")), Some(&300));
    }

    /// An uncle earns proportional weight — losing a race to latency must not
    /// mean earning nothing, or the pool centralizes toward the best-connected.
    #[test]
    fn an_uncle_earns_proportional_weight() {
        let mut sc = ShareChain::new();
        sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new())
            .expect("root");
        // carol's share loses the race...
        sc.accept(share(1, Some(id(0)), "carol.sov", 100), 0, &Payouts::new())
            .expect("orphan");
        // ...and bob's wins, but references it as an uncle.
        let mut s = share(2, Some(id(0)), "bob.sov", 100);
        s.uncles = vec![id(1)];
        sc.accept(s, 0, &Payouts::new()).expect("with uncle");

        let p = sc.payouts_for(Some(id(2)), 275);
        // bob 100 + alice 100 + carol 75 (75% of 100) = 275 total weight.
        assert_eq!(p.get(&acct("bob.sov")), Some(&100));
        assert_eq!(p.get(&acct("alice.sov")), Some(&100));
        assert_eq!(
            p.get(&acct("carol.sov")),
            Some(&75),
            "an uncle earns UNCLE_WEIGHT_PCT of a main-line share"
        );
    }

    /// An uncle may not be an ancestor, itself, or repeated — each would pay the
    /// same work twice.
    #[test]
    fn double_counting_uncles_is_refused() {
        let mut sc = ShareChain::new();
        sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new())
            .expect("root");
        sc.accept(share(1, Some(id(0)), "bob.sov", 100), 0, &Payouts::new())
            .expect("mid");

        // uncling an ancestor
        let mut s = share(2, Some(id(1)), "carol.sov", 100);
        s.uncles = vec![id(0)];
        assert!(matches!(
            sc.accept(s, 0, &Payouts::new()),
            Err(ShareError::BadUncle(_))
        ));

        // uncling itself
        let mut s = share(3, Some(id(1)), "carol.sov", 100);
        s.uncles = vec![id(3)];
        assert!(matches!(
            sc.accept(s, 0, &Payouts::new()),
            Err(ShareError::BadUncle(_))
        ));

        // the same uncle twice
        sc.accept(share(4, Some(id(0)), "dave.sov", 100), 0, &Payouts::new())
            .expect("orphan");
        let mut s = share(5, Some(id(1)), "carol.sov", 100);
        s.uncles = vec![id(4), id(4)];
        assert!(matches!(
            sc.accept(s, 0, &Payouts::new()),
            Err(ShareError::BadUncle(_))
        ));

        // an unknown uncle
        let mut s = share(6, Some(id(1)), "carol.sov", 100);
        s.uncles = vec![id(200)];
        assert!(matches!(
            sc.accept(s, 0, &Payouts::new()),
            Err(ShareError::BadUncle(_))
        ));
    }

    /// **THE CHEATING-FINDER TEST.** A share that carries a real block and pays
    /// itself instead of the window is REJECTED. This is the single rule that
    /// makes the pool non-custodial: without it, the finder simply keeps the
    /// reward and everyone else has mined for free.
    #[test]
    fn a_block_share_paying_the_wrong_accounts_is_rejected() {
        let mut sc = chain_of(6);
        let reward = 12_500_000_000u128;
        let honest = sc.payouts_for(sc.tip(), reward);
        assert!(honest.len() >= 2, "the window must span several miners");

        // The finder tries to keep it all.
        let mut greedy = Payouts::new();
        greedy.insert(acct("mallory.sov"), reward);
        let mut s = share(200, sc.tip(), "mallory.sov", 100);
        s.is_block = true;
        let out = sc.accept(s.clone(), reward, &greedy);
        assert!(
            matches!(out, Err(ShareError::WrongPayouts { .. })),
            "a block share keeping the reward must be refused, got {out:?}"
        );
        assert_eq!(sc.len(), 6, "a rejected share must not be recorded");

        // Shaving a single grain off one payee is still wrong.
        let mut shaved = honest.clone();
        if let Some((k, _)) = shaved.iter().next().map(|(k, v)| (k.clone(), *v)) {
            *shaved.get_mut(&k).expect("present") -= 1;
        }
        let out = sc.accept(s.clone(), reward, &shaved);
        assert!(
            matches!(out, Err(ShareError::WrongPayouts { .. })),
            "an exact match is required — 'close enough' lets a finder shave every block"
        );

        // The honest payouts are accepted.
        sc.accept(s, reward, &honest)
            .expect("the correct payouts must be accepted");
        assert_eq!(sc.tip(), Some(id(200)));
    }

    /// A share BELOW the network target carries no block, so it embeds no
    /// payouts and none are demanded of it.
    #[test]
    fn a_non_block_share_is_not_asked_to_pay() {
        let mut sc = chain_of(3);
        let s = share(50, sc.tip(), "alice.sov", 100);
        sc.accept(s, 12_500_000_000, &Payouts::new())
            .expect("a plain share owes nothing");
    }

    /// The window is bounded: history older than PPLNS_WINDOW does not earn.
    #[test]
    fn the_pplns_window_is_bounded() {
        let mut sc = ShareChain::new();
        // One ancient share from a miner who then stops.
        sc.accept(share(0, None, "ancient.sov", 100), 0, &Payouts::new())
            .expect("root");
        let mut prev = Some(id(0));
        // Fill well past the window with someone else.
        for i in 1..=(PPLNS_WINDOW + 5) {
            let mut sid = [0u8; 32];
            sid[..8].copy_from_slice(&(i as u64).to_le_bytes());
            sc.accept(
                Share {
                    id: sid,
                    prev,
                    uncles: Vec::new(),
                    finder: acct("current.sov"),
                    work: 100,
                    is_block: false,
                },
                0,
                &Payouts::new(),
            )
            .expect("fill");
            prev = Some(sid);
        }
        let p = sc.payouts_for(sc.tip(), 1_000_000);
        assert!(
            !p.contains_key(&acct("ancient.sov")),
            "work older than the window must not earn — that is what PPLNS means"
        );
        assert_eq!(p.get(&acct("current.sov")), Some(&1_000_000));
    }

    #[test]
    fn duplicates_zero_work_and_unknown_parents_are_refused() {
        let mut sc = ShareChain::new();
        sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new())
            .expect("root");
        assert!(matches!(
            sc.accept(share(0, None, "alice.sov", 100), 0, &Payouts::new()),
            Err(ShareError::Duplicate(_))
        ));
        assert!(matches!(
            sc.accept(share(1, Some(id(0)), "a.sov", 0), 0, &Payouts::new()),
            Err(ShareError::ZeroWork)
        ));
        assert!(matches!(
            sc.accept(share(2, Some(id(99)), "a.sov", 100), 0, &Payouts::new()),
            Err(ShareError::UnknownParent(_))
        ));
    }
}
