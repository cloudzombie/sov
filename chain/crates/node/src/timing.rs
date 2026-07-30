//! The node-local **transaction timing index**: how long each mined transaction
//! waited, as THIS node observed it.
//!
//! # What this is, and what it can never be
//!
//! A SOV block commits a `tx_root`, a `receipts_root`, and a state root. Nothing
//! in this module touches any of them. The index is built from data a node
//! already has — its own mempool's admission stamps and the block headers it
//! imports — and it is stored in a flat file beside `mempool.dat` in the node's
//! `data_dir`, never in a block, a receipt, or the ledger. Two nodes with
//! byte-identical chains will hold DIFFERENT timing indexes, and that is correct:
//! the index answers "what did I see?", not "what is true for everyone?".
//!
//! That is also why it cannot affect consensus. There is no code path from a
//! [`TxTimingIndex`] into block validation, execution, selection, or fork choice;
//! deleting `txtiming.dat` changes nothing a peer can observe about this node's
//! chain.
//!
//! # The honesty rule
//!
//! A transaction's `first_seen` is **an observation of this node**. If the
//! transaction arrived already mined, inside a peer's block, this node never saw
//! it wait and therefore does not know how long it waited. In that case
//! [`TxTiming::first_seen_ms`] is `None` and every derived wait is `None` too.
//! The block's own timestamp is NOT substituted — that would report a wait of
//! zero for a transaction that may have queued for an hour on the network, which
//! is a fabricated number dressed as a measurement.
//!
//! # Bounded by construction
//!
//! An index that grows with the chain is a disk leak. Two independent bounds
//! apply on every insertion, whichever binds first (see
//! [`DEFAULT_RETENTION_BLOCKS`] and [`DEFAULT_MAX_ENTRIES`]), and eviction is
//! always oldest-inclusion-height-first.

use std::collections::{BTreeMap, HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use sov_primitives::Hash;

/// How many blocks of history the timing index retains by default.
///
/// Derivation: SOV targets a 2.5-minute block, so 4,320 blocks is
/// `4320 × 150 s = 648,000 s ≈ 7.5 days`. A week and a half is long enough to
/// answer every question this index exists for — "did my transaction sit in the
/// mempool, and for how long?", "is the auction floor actually clearing work?",
/// "did last Tuesday's backlog drain?" — while keeping the file small and the
/// scan bounded. Older rows are answered by the block explorer's own history,
/// not by a node's private observation log.
pub const DEFAULT_RETENTION_BLOCKS: u64 = 4_320;

/// Hard ceiling on retained rows, applied regardless of how many blocks they
/// span.
///
/// Derivation: the depth bound alone is not a memory bound, because a block's
/// transaction count is not fixed — 4,320 full blocks could hold far more than a
/// quiet week's worth. 200,000 rows is roughly 4,320 blocks × ~46 transactions,
/// i.e. a sustained load well above anything the live chain has produced, and at
/// ~60 bytes per encoded row it is ~12 MB on disk and a comparable amount
/// resident. Whichever of the two bounds binds first applies.
pub const DEFAULT_MAX_ENTRIES: usize = 200_000;

/// One transaction's node-local inclusion timing.
///
/// **`first_seen_ms` is this node's OBSERVATION**, not a property of the
/// transaction (see the module docs). `None` means this node genuinely never had
/// the transaction in its mempool — it arrived already mined — and every derived
/// wait is `None` with it. Two honest nodes will legitimately report different
/// values for the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxTiming {
    /// Unix-epoch milliseconds at which THIS node admitted the transaction to
    /// its mempool, or `None` if it never did.
    pub first_seen_ms: Option<u64>,
    /// The chain height THIS node was at when it admitted the transaction, or
    /// `None` if it never did.
    pub first_seen_height: Option<u64>,
    /// The active-chain height of the block that included the transaction.
    pub included_height: u64,
    /// That block's header timestamp, in Unix-epoch milliseconds. This is a
    /// miner-declared time (bounded by consensus to a sane window), not this
    /// node's clock — so a wait derived from it mixes one honest observation
    /// with one attested value.
    pub included_timestamp_ms: u64,
}

impl TxTiming {
    /// A row for a transaction this node DID observe waiting.
    pub fn observed(
        first_seen_ms: u64,
        first_seen_height: u64,
        included_height: u64,
        included_timestamp_ms: u64,
    ) -> Self {
        TxTiming {
            first_seen_ms: Some(first_seen_ms),
            first_seen_height: Some(first_seen_height),
            included_height,
            included_timestamp_ms,
        }
    }

    /// A row for a transaction this node never held: the inclusion facts are
    /// known, the wait is not, and no value is invented for it.
    pub fn unobserved(included_height: u64, included_timestamp_ms: u64) -> Self {
        TxTiming {
            first_seen_ms: None,
            first_seen_height: None,
            included_height,
            included_timestamp_ms,
        }
    }

    /// Whether this node actually observed the transaction waiting — exactly
    /// `first_seen_ms.is_some()`. The RPC surfaces this as `observed` so a
    /// caller never has to guess whether a `null` wait means "instant" or
    /// "unknown": it always means unknown.
    pub fn is_observed(&self) -> bool {
        self.first_seen_ms.is_some()
    }

    /// How long the transaction waited, in milliseconds, or `None` when
    /// unobserved.
    ///
    /// Saturating: the block timestamp is a miner-declared value and this node's
    /// clock is its own, so the two can legitimately cross under skew. A wait
    /// clamps to zero rather than wrapping to an absurd number.
    pub fn waited_ms(&self) -> Option<u64> {
        self.first_seen_ms
            .map(|seen| self.included_timestamp_ms.saturating_sub(seen))
    }

    /// How many blocks the transaction waited, or `None` when unobserved.
    ///
    /// Zero means it was mined into the very next block after this node saw it.
    /// Saturating for the same reason as [`waited_ms`](Self::waited_ms): a reorg
    /// can re-point a row to a height at or below the one it was first seen at.
    pub fn waited_blocks(&self) -> Option<u64> {
        self.first_seen_height
            .map(|h| self.included_height.saturating_sub(h))
    }
}

/// A bounded, node-local map of `txid -> `[`TxTiming`].
///
/// Non-consensus in the strongest sense: no method here is reachable from block
/// validation, execution, selection, or fork choice, and its persisted form
/// lives outside every committed root. See the module docs.
#[derive(Debug, Clone)]
pub struct TxTimingIndex {
    /// The rows themselves.
    rows: HashMap<Hash, TxTiming>,
    /// Inclusion height -> the ids recorded at that height, in the order they
    /// appeared in the block.
    ///
    /// This is what makes both bounds cheap AND makes eviction honest: the
    /// oldest rows are exactly the lowest key, and a reorg's disconnected
    /// heights are a contiguous range at the top. Kept in lockstep with `rows`.
    by_height: BTreeMap<u64, Vec<Hash>>,
    /// Retention depth in blocks (see [`DEFAULT_RETENTION_BLOCKS`]).
    retention_blocks: u64,
    /// Hard row ceiling (see [`DEFAULT_MAX_ENTRIES`]).
    max_entries: usize,
}

impl Default for TxTimingIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl TxTimingIndex {
    /// An empty index with the default bounds: [`DEFAULT_RETENTION_BLOCKS`]
    /// blocks of depth and at most [`DEFAULT_MAX_ENTRIES`] rows.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_RETENTION_BLOCKS, DEFAULT_MAX_ENTRIES)
    }

    /// An empty index with explicit bounds — the operator-configurable form.
    ///
    /// Both are floored at 1: a zero bound would mean "retain nothing", which is
    /// better expressed by not querying the index than by a configuration that
    /// silently makes every answer a miss.
    pub fn with_limits(retention_blocks: u64, max_entries: usize) -> Self {
        TxTimingIndex {
            rows: HashMap::new(),
            by_height: BTreeMap::new(),
            retention_blocks: retention_blocks.max(1),
            max_entries: max_entries.max(1),
        }
    }

    /// The configured retention depth in blocks.
    pub fn retention_blocks(&self) -> u64 {
        self.retention_blocks
    }

    /// The configured hard row ceiling.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// How many rows are retained right now.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the index holds no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The timing of `id`, or `None` when this node has no row for it — either
    /// it was never mined on this node's active chain, or its row has aged out
    /// of the retention window.
    pub fn get(&self, id: &Hash) -> Option<TxTiming> {
        self.rows.get(id).copied()
    }

    /// Record (or overwrite) `id`'s timing, then re-apply both bounds.
    ///
    /// Overwriting is how a reorg RE-POINTS a transaction that appears in both
    /// the old and the new branch: the row's `included_height` follows the
    /// active chain rather than being left as a stale claim about a block that
    /// is no longer on it.
    pub fn record(&mut self, id: Hash, timing: TxTiming) {
        if let Some(old) = self.rows.insert(id, timing) {
            // Re-pointed: drop the id from its previous height bucket so
            // `by_height` never claims a row lives at a height it no longer does.
            self.detach_from_height(old.included_height, &id);
        }
        self.by_height
            .entry(timing.included_height)
            .or_default()
            .push(id);
        self.enforce_bounds(timing.included_height);
    }

    /// Remove `id`'s row, returning it if there was one.
    ///
    /// Used by the reorg path: a transaction whose including block left the
    /// active chain has no honest `included_height`, so the claim is withdrawn
    /// rather than left to rot.
    pub fn remove(&mut self, id: &Hash) -> Option<TxTiming> {
        let old = self.rows.remove(id)?;
        self.detach_from_height(old.included_height, id);
        Some(old)
    }

    /// Drop `id` from `by_height`'s bucket for `height`, removing the bucket
    /// once it empties so the map stays proportional to the retained rows.
    fn detach_from_height(&mut self, height: u64, id: &Hash) {
        if let Some(ids) = self.by_height.get_mut(&height) {
            ids.retain(|h| h != id);
            if ids.is_empty() {
                self.by_height.remove(&height);
            }
        }
    }

    /// Apply BOTH retention bounds, oldest-inclusion-height-first.
    ///
    /// `tip_height` is the newest height the index knows about — the depth bound
    /// is measured back from it, so an index that stops being written (a stopped
    /// node) also stops evicting, rather than draining itself against a
    /// wall clock it does not own.
    fn enforce_bounds(&mut self, tip_height: u64) {
        // 1. Depth: keep the most recent `retention_blocks` HEIGHTS, tip
        //    included — so `retention_blocks = 1` retains exactly the tip, and
        //    the default retains 4,320 blocks rather than 4,321.
        let cutoff = tip_height
            .saturating_add(1)
            .saturating_sub(self.retention_blocks);
        while let Some((&h, _)) = self.by_height.iter().next() {
            if h >= cutoff {
                break;
            }
            self.drop_height(h);
        }
        // 2. Count: still oldest-first, one whole height at a time until the
        //    ceiling holds. A single block can carry the index below the
        //    ceiling in one step, which is why this is a loop over heights and
        //    not a per-row drain.
        while self.rows.len() > self.max_entries {
            let Some((&h, _)) = self.by_height.iter().next() else {
                break;
            };
            self.drop_height(h);
        }
    }

    /// Evict every row recorded at `height`.
    fn drop_height(&mut self, height: u64) {
        if let Some(ids) = self.by_height.remove(&height) {
            for id in ids {
                // Only drop the row if it still points HERE: a re-pointed row
                // was already re-filed under its new height and must survive.
                if self.rows.get(&id).map(|t| t.included_height) == Some(height) {
                    self.rows.remove(&id);
                }
            }
        }
    }

    /// The lowest inclusion height still retained, or `None` when empty.
    pub fn lowest_height(&self) -> Option<u64> {
        self.by_height.keys().next().copied()
    }

    /// All rows, as `(txid, timing)` — the persisted form written to
    /// `data_dir/txtiming.dat`.
    ///
    /// Sorted by `(included_height, txid)` so the file is deterministic for a
    /// given index state: an operator diffing two nodes' files sees real
    /// differences in observation, not `HashMap` iteration order.
    pub fn snapshot(&self) -> Vec<(Hash, TxTiming)> {
        let mut out: Vec<(Hash, TxTiming)> = self.rows.iter().map(|(id, t)| (*id, *t)).collect();
        out.sort_by(|a, b| {
            a.1.included_height
                .cmp(&b.1.included_height)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        out
    }

    /// Reload a persisted snapshot, replacing any current contents and
    /// re-applying the CONFIGURED bounds.
    ///
    /// Re-applying matters: an operator who lowers `retention_blocks` between
    /// runs gets the smaller window immediately, rather than carrying a file
    /// written under the old, larger one until it happens to churn out.
    pub fn restore(&mut self, rows: Vec<(Hash, TxTiming)>) {
        self.rows.clear();
        self.by_height.clear();
        let tip = rows.iter().map(|(_, t)| t.included_height).max();
        for (id, timing) in rows {
            if self.rows.insert(id, timing).is_none() {
                self.by_height
                    .entry(timing.included_height)
                    .or_default()
                    .push(id);
            }
        }
        if let Some(tip) = tip {
            self.enforce_bounds(tip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        Hash::digest(&[n])
    }

    #[test]
    fn waits_are_derived_only_from_an_actual_observation() {
        // Observed: both waits are real numbers.
        let seen = TxTiming::observed(1_000, 7, 10, 4_000);
        assert!(seen.is_observed());
        assert_eq!(seen.waited_ms(), Some(3_000));
        assert_eq!(seen.waited_blocks(), Some(3));

        // Unobserved: NOTHING is substituted for the missing arrival — not the
        // block time, not zero. Both waits are unknown, and stay unknown.
        let unseen = TxTiming::unobserved(10, 4_000);
        assert!(!unseen.is_observed());
        assert_eq!(unseen.first_seen_ms, None);
        assert_eq!(unseen.first_seen_height, None);
        assert_eq!(unseen.waited_ms(), None);
        assert_eq!(unseen.waited_blocks(), None);
    }

    #[test]
    fn waits_saturate_instead_of_wrapping_under_skew() {
        // A miner-declared block time EARLIER than this node's admission stamp
        // is possible under clock skew; the wait must clamp to zero, never wrap.
        let skewed = TxTiming::observed(9_000, 12, 10, 4_000);
        assert_eq!(skewed.waited_ms(), Some(0));
        assert_eq!(skewed.waited_blocks(), Some(0));
    }

    #[test]
    fn count_cap_evicts_oldest_first_and_the_index_stays_bounded() {
        // Ceiling of 2 rows, one row per height: recording a third must evict
        // the LOWEST height, not an arbitrary one.
        let mut idx = TxTimingIndex::with_limits(1_000_000, 2);
        idx.record(h(1), TxTiming::unobserved(1, 100));
        idx.record(h(2), TxTiming::unobserved(2, 200));
        idx.record(h(3), TxTiming::unobserved(3, 300));
        assert_eq!(idx.len(), 2, "hard ceiling holds");
        assert!(idx.get(&h(1)).is_none(), "oldest evicted");
        assert!(idx.get(&h(2)).is_some());
        assert!(idx.get(&h(3)).is_some());
        assert_eq!(idx.lowest_height(), Some(2));
    }

    #[test]
    fn depth_cap_evicts_everything_older_than_the_window() {
        // Window of 5 blocks: recording at height 100 must retire everything
        // below 95, and the by-height map must shrink with it.
        let mut idx = TxTimingIndex::with_limits(5, 1_000_000);
        for height in 90..=94u64 {
            idx.record(h(height as u8), TxTiming::unobserved(height, height * 10));
        }
        assert_eq!(idx.len(), 5);
        idx.record(h(100), TxTiming::unobserved(100, 1_000));
        assert_eq!(idx.len(), 1, "only the in-window row survives");
        assert_eq!(idx.lowest_height(), Some(100));
        assert!(idx.get(&h(90)).is_none());
    }

    #[test]
    fn removing_and_repointing_leaves_no_stale_height_claim() {
        let mut idx = TxTimingIndex::new();
        idx.record(h(1), TxTiming::observed(10, 1, 5, 500));
        idx.record(h(2), TxTiming::observed(10, 1, 5, 500));

        // Re-point h(1) to a different height (what a reorg does to a tx present
        // on both branches). Its old bucket must not keep claiming it.
        idx.record(h(1), TxTiming::observed(10, 1, 9, 900));
        assert_eq!(idx.get(&h(1)).unwrap().included_height, 9);
        assert_eq!(idx.lowest_height(), Some(5), "h(2) still at 5");

        // Withdraw h(2) entirely; height 5 empties out.
        assert!(idx.remove(&h(2)).is_some());
        assert_eq!(idx.lowest_height(), Some(9));
        assert!(idx.remove(&h(2)).is_none(), "second removal is a no-op");
    }

    #[test]
    fn a_restored_snapshot_round_trips_and_re_applies_the_configured_bounds() {
        let mut idx = TxTimingIndex::with_limits(1_000, 1_000);
        for height in 1..=10u64 {
            idx.record(
                h(height as u8),
                TxTiming::observed(height * 100, height, height, height * 1_000),
            );
        }
        let snap = idx.snapshot();
        assert_eq!(snap.len(), 10);
        assert!(
            snap.windows(2)
                .all(|w| w[0].1.included_height <= w[1].1.included_height),
            "snapshot is deterministically ordered by height"
        );

        // Same bounds → identical contents.
        let mut same = TxTimingIndex::with_limits(1_000, 1_000);
        same.restore(snap.clone());
        assert_eq!(same.len(), 10);
        assert_eq!(same.get(&h(3)), idx.get(&h(3)));

        // TIGHTER bounds → the smaller window applies immediately on reload.
        let mut tighter = TxTimingIndex::with_limits(3, 1_000);
        tighter.restore(snap);
        assert_eq!(tighter.len(), 3, "heights 8,9,10 survive a 3-block window");
        assert_eq!(tighter.lowest_height(), Some(8));
    }
}
