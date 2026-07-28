//! Pool-v2 **consensus state** (v0.2.0 slice S2a): the v2 note-commitment
//! tree frontier, the bounded anchor ring, and the v2 nullifier set.
//!
//! This is the authoritative state a validator maintains for the post-quantum
//! shielded pool, mirroring the Orchard pool's [`sov-shielded` `ShieldedState`]
//! discipline one-for-one:
//!
//! - an **append-only note-commitment tree** (depth [`TREE_DEPTH`], the same
//!   domain-separated Rescue-Prime Merkle tree the STARK proves membership
//!   in), maintained as an O(depth)-per-append *frontier* so consensus never
//!   rehashes the whole tree;
//! - the **anchor ring**: the last [`ANCHOR_RING_LEN`] tree roots (decision
//!   D5). Unlike pool v1 (which keeps every root forever), v2 accepts only a
//!   bounded recent window — a spend proven against an older root must be
//!   re-proven, which bounds this set's size *by construction*;
//! - the **nullifier set**: spent-note nullifiers, so a note can never be
//!   spent twice. Monotone, one 32-byte entry per real spent note.
//!
//! The pool-value turnstile and the v2 de-shield drain limiter are *ledger*
//! state (committed counters in `sov-state`, exactly like v1's); this module
//! owns only the cryptographic pool state. Everything here is DORMANT until
//! the `shielded-v2` deployment (signal bit 2, defined but NOT armed in
//! v0.2.0) activates: no execution path constructs or mutates this state on
//! any chain today.
//!
//! # Determinism
//!
//! All collections are ordered (`BTreeSet`, `VecDeque` in insertion order,
//! `Vec` in append order); there is no map-iteration-order dependence, no
//! wall clock, and no floating point. [`ShieldedV2State::commitment`] is a
//! pure function of the state.

use std::collections::{BTreeSet, VecDeque};

use crate::domains::RESCUE_DOMAIN_MERKLE_NODE;
use crate::hash::{merge_domain, PqDigest};
use crate::tree::{empty_levels, MAX_TREE_LEAVES, TREE_DEPTH};

/// Worst-case pool-v2 note commitments a single block can contain.
///
/// Derived, not guessed. A block is bounded by `MAX_BLOCK_WEIGHT` (4 MiB). One
/// v2 bundle costs ~96 KiB on the wire plus `SHIELDED_V2_VERIFY_WEIGHT`
/// (16 ms x 512 units) = ~106,496 weight, so at most 39 bundles fit; each
/// carries at most `NUM_SLOTS` = 4 real outputs. 39 x 4 = 156, rounded up to
/// 160 for headroom against future weight-schedule changes.
pub const MAX_V2_COMMITMENTS_PER_BLOCK: usize = 160;

/// How many BLOCKS of anchor history a spend may be proven against.
///
/// 128 blocks is ~5.3 hours at the 2.5-minute target: far beyond the
/// 6-confirmation finality depth, and far beyond the ~25 s a wallet spends
/// generating a STARK plus propagation.
pub const ANCHOR_HORIZON_BLOCKS: usize = 128;

/// How many recent v2 tree roots (anchors) consensus accepts a spend against
/// (decision D5 — the same window shape as Orchard's).
///
/// # Why this is a derived product, not 128 (audit PQV2-03)
///
/// This constant was 128 — with the comment "the same window shape as
/// Orchard's, sized at 128". But an anchor is pushed **per commitment**, not
/// per block, and a saturated block can contain 156 commitments. So a SINGLE
/// block could evict the entire ring, and every spend already in flight —
/// proven seconds earlier against a then-valid root — would become
/// unspendable until re-proven. That is not a theoretical corner: it is what
/// a busy block does.
///
/// "128" was the right number against the wrong unit. Sizing it as
/// `MAX_V2_COMMITMENTS_PER_BLOCK * ANCHOR_HORIZON_BLOCKS` restores the intent:
/// the ring spans at least 128 BLOCKS no matter how full each one is.
///
/// The cost is 20,480 x 32 bytes = 640 KiB of node memory, which is a trivial
/// price for spends not being invalidated by someone else's traffic.
pub const ANCHOR_RING_LEN: usize = MAX_V2_COMMITMENTS_PER_BLOCK * ANCHOR_HORIZON_BLOCKS;

/// Maximum notes the depth-[`TREE_DEPTH`] pool tree can hold: `2^20 - 1`
/// ([`MAX_TREE_LEAVES`]). Appending beyond this is a typed error, never a wrap,
/// a panic, or a silent divergence.
///
/// The final leaf slot of the `2^20`-slot leaf space is **deliberately
/// unusable**: an O(depth) frontier stores one ommer per set bit of `size`, so
/// a depth-`D` frontier represents `0..2^D` faithfully and cannot represent
/// `2^D` at all (every low bit is zero there — the encoding collides with the
/// empty tree, and the completed root has no slot to live in). Capping one
/// short keeps "the frontier is a total, injective encoding of the tree at
/// every reachable size" true unconditionally, which is exactly what the
/// anchor ring and the STARK membership proofs depend on. See
/// [`MAX_TREE_LEAVES`] for why this beats special-casing the full tree.
pub const MAX_V2_NOTES: u64 = MAX_TREE_LEAVES;

/// Compile-time guard for the frontier's totality precondition: the usable
/// capacity must stay strictly inside the depth-`TREE_DEPTH` leaf space, or
/// `root()` would report the empty-tree root for a full pool. This build fails
/// if that ever drifts.
const _: () = assert!(MAX_V2_NOTES < (1u64 << TREE_DEPTH));

/// Typed failures of pool-v2 state transitions. Every reject path is an
/// explicit variant; nothing here panics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShieldedV2StateError {
    /// The note-commitment tree is at [`MAX_V2_NOTES`] capacity.
    #[error("pool-v2 note-commitment tree is full ({MAX_V2_NOTES} notes)")]
    TreeFull,
    /// A nullifier was already in the spent set (or repeated within the batch).
    #[error("pool-v2 nullifier already spent (double spend)")]
    DoubleSpend,
    /// A supplied nullifier or commitment was the all-zero digest — the wire
    /// format's *dummy-slot* convention. Dummies must be filtered by the
    /// caller (the S2c executor); the state layer refuses them outright as
    /// defense in depth.
    #[error("pool-v2 state refuses the zero (dummy) digest")]
    ZeroDigest,
    /// A digest carried a non-canonical field encoding (a limb `>= p`) —
    /// either in a persisted snapshot or handed to a mutator. Such a digest
    /// cannot survive a snapshot round-trip, so it never enters the state.
    #[error("non-canonical digest in pool-v2 state ({0})")]
    Decode(&'static str),
}

/// The root implied by a Merkle frontier of depth `ommers.len()`.
///
/// `ommers[l]` is the completed left-sibling subtree at level `l`, meaningful
/// exactly where bit `l` of `size` is 1; where it is 0 the sibling is the empty
/// subtree `empty[l]`. `empty` must carry at least `ommers.len() + 1` levels.
///
/// **Totality precondition:** `size < 2^ommers.len()`. Bits of `size` at or
/// above the frontier depth are invisible to this walk, so a caller that let
/// `size` reach `2^depth` would get the empty-tree root back for a full tree.
/// Consensus guarantees the precondition by capping usable leaves at
/// [`MAX_V2_NOTES`], which the compile-time assertion below makes impossible to
/// drift, and by [`frontier_append`] refusing an index with no free slot.
fn frontier_root(ommers: &[PqDigest], empty: &[PqDigest], size: u64) -> PqDigest {
    debug_assert!(empty.len() > ommers.len(), "empty levels cover the depth");
    let mut acc = empty[0];
    for (level, &ommer) in ommers.iter().enumerate() {
        acc = if (size >> level) & 1 == 1 {
            merge_domain(RESCUE_DOMAIN_MERKLE_NODE, ommer, acc)
        } else {
            merge_domain(RESCUE_DOMAIN_MERKLE_NODE, acc, empty[level])
        };
    }
    acc
}

/// Fold the leaf appended at index `size` into the frontier (O(depth) merges).
///
/// Returns `false` — mutating **nothing** — when index `size` has no free ommer
/// slot, i.e. when its low `depth` bits are all 1 and the append would complete
/// the whole tree. That is precisely the size the frontier cannot represent, so
/// the caller must reject rather than store a root that has nowhere to go.
fn frontier_append(ommers: &mut [PqDigest], size: u64, cm: PqDigest) -> bool {
    let mut acc = cm;
    let mut idx = size;
    for slot in ommers.iter_mut() {
        if idx & 1 == 0 {
            *slot = acc;
            return true;
        }
        acc = merge_domain(RESCUE_DOMAIN_MERKLE_NODE, *slot, acc);
        idx >>= 1;
    }
    false
}

/// The post-quantum shielded pool's consensus state (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedV2State {
    /// Merkle *frontier*: `ommers[l]` is the root of the completed left
    /// sibling subtree at level `l` along the path of the next append, valid
    /// wherever bit `l` of [`size`](Self::size) is 1. O(depth) storage.
    ommers: [PqDigest; TREE_DEPTH],
    /// Number of leaves appended so far (`≤ MAX_V2_NOTES`).
    size: u64,
    /// The last [`ANCHOR_RING_LEN`] tree roots, oldest first. Seeded with the
    /// empty-tree root so a fresh pool has a valid anchor, exactly like v1.
    anchor_ring: VecDeque<[u8; 32]>,
    /// Spent-note nullifiers (canonical digest bytes), ordered.
    nullifiers: BTreeSet<[u8; 32]>,
    /// Note commitments in append order (canonical digest bytes) — kept so the
    /// state can be snapshotted and faithfully reconstructed (the frontier
    /// exposes only the root), which `sov-state` persistence relies on. Same
    /// pattern as pool v1.
    commitments: Vec<[u8; 32]>,
}

impl Default for ShieldedV2State {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedV2State {
    /// A fresh, empty pool. The empty-tree root is the ring's first anchor,
    /// so the genesis state already has a valid (empty) anchor.
    pub fn new() -> Self {
        let mut anchor_ring = VecDeque::with_capacity(ANCHOR_RING_LEN);
        anchor_ring.push_back(empty_levels()[TREE_DEPTH].to_bytes());
        ShieldedV2State {
            ommers: [PqDigest::ZERO; TREE_DEPTH],
            size: 0,
            anchor_ring,
            nullifiers: BTreeSet::new(),
            commitments: Vec::new(),
        }
    }

    /// The current note-commitment tree root (the newest anchor).
    ///
    /// `size <= MAX_V2_NOTES < 2^TREE_DEPTH` is an invariant of every mutator
    /// here, so the frontier walk sees every set bit of `size` and this root
    /// equals the reference [`CommitmentTree`](crate::CommitmentTree) root at
    /// every reachable size — including full capacity.
    pub fn root(&self) -> PqDigest {
        frontier_root(&self.ommers, empty_levels(), self.size)
    }

    /// Whether `anchor` is within the accepted ring of the last
    /// [`ANCHOR_RING_LEN`] roots — the precondition (D5) for accepting a
    /// spend proven against it.
    pub fn anchor_is_known(&self, anchor: &PqDigest) -> bool {
        let bytes = anchor.to_bytes();
        self.anchor_ring.iter().any(|a| *a == bytes)
    }

    /// Whether `nf` has already been spent (a double spend if seen again).
    pub fn nullifier_seen(&self, nf: &PqDigest) -> bool {
        self.nullifiers.contains(&nf.to_bytes())
    }

    /// Number of note commitments appended to the tree.
    pub fn note_count(&self) -> u64 {
        self.size
    }

    /// Number of spent nullifiers recorded.
    pub fn nullifier_count(&self) -> u64 {
        self.nullifiers.len() as u64
    }

    /// The anchors currently in the ring, oldest first (read-only view).
    pub fn anchors(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.anchor_ring.iter()
    }

    /// Whether the pool has never been touched — no notes and no nullifiers.
    /// An empty pool contributes NOTHING to the ledger commitment (its state
    /// slot is absent), so a chain with no v2 activity has exactly the state
    /// root it would have without the pool existing at all. This is the
    /// non-retroactivity linchpin of slice S2a.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty() && self.nullifiers.is_empty()
    }

    /// Append one commitment leaf via the frontier (O(depth) merges) and
    /// record the new root in the anchor ring, evicting the oldest entry
    /// beyond [`ANCHOR_RING_LEN`].
    fn append_commitment(&mut self, cm: PqDigest) -> Result<(), ShieldedV2StateError> {
        if self.size >= MAX_V2_NOTES {
            return Err(ShieldedV2StateError::TreeFull);
        }
        // Unreachable given the bound above (index `MAX_V2_NOTES - 1` always
        // has a zero bit below the depth), but belt-and-braces: a frontier that
        // cannot place the new ommer is a full tree, and we reject it as one
        // rather than dropping the completed root on the floor. Nothing has
        // been mutated on this path.
        if !frontier_append(&mut self.ommers, self.size, cm) {
            return Err(ShieldedV2StateError::TreeFull);
        }
        self.size += 1;
        self.commitments.push(cm.to_bytes());
        self.anchor_ring.push_back(self.root().to_bytes());
        while self.anchor_ring.len() > ANCHOR_RING_LEN {
            self.anchor_ring.pop_front();
        }
        Ok(())
    }

    /// Apply one authorized bundle's state effect **atomically**: spend
    /// `nullifiers` (rejecting double spends) and append `commitments`
    /// (advancing the tree and the anchor ring).
    ///
    /// Validates BEFORE mutating — a rejected batch leaves the state
    /// untouched, bit-for-bit. The caller (the S2c executor) must already
    /// have verified the bundle's STARK proof and that its anchors are in the
    /// ring, and must have *filtered dummy slots out* (the zero digest is
    /// refused here as defense in depth). This method owns only the
    /// double-spend rule and tree growth — exactly the v1 division of labor.
    pub fn apply(
        &mut self,
        nullifiers: &[PqDigest],
        commitments: &[PqDigest],
    ) -> Result<(), ShieldedV2StateError> {
        // Validate everything first: capacity, no zero (dummy) digests, no
        // nullifier already spent or repeated within the batch.
        let new_size = self
            .size
            .checked_add(commitments.len() as u64)
            .ok_or(ShieldedV2StateError::TreeFull)?;
        if new_size > MAX_V2_NOTES {
            return Err(ShieldedV2StateError::TreeFull);
        }
        if commitments.contains(&PqDigest::ZERO) {
            return Err(ShieldedV2StateError::ZeroDigest);
        }
        // Canonicality is a state invariant, not just a decoder rule: a digest
        // with a limb >= p round-trips through `to_bytes` but is refused by
        // `from_bytes`, so accepting one would make the state unrestorable from
        // its own snapshot. Digests reaching here come from decoded wire
        // bundles (already canonical), so this is defense in depth.
        for cm in commitments {
            if !cm.is_canonical() {
                return Err(ShieldedV2StateError::Decode("commitment"));
            }
        }
        let mut batch = BTreeSet::new();
        for nf in nullifiers {
            if *nf == PqDigest::ZERO {
                return Err(ShieldedV2StateError::ZeroDigest);
            }
            if !nf.is_canonical() {
                return Err(ShieldedV2StateError::Decode("nullifier"));
            }
            let bytes = nf.to_bytes();
            if self.nullifiers.contains(&bytes) || !batch.insert(bytes) {
                return Err(ShieldedV2StateError::DoubleSpend);
            }
        }

        // All checks passed — mutate.
        for nf in nullifiers {
            self.nullifiers.insert(nf.to_bytes());
        }
        for cm in commitments {
            self.append_commitment(*cm)
                .expect("capacity and canonicality pre-checked above");
        }
        Ok(())
    }

    /// A compact, deterministic snapshot for persistence: the note
    /// commitments in append order and the spent nullifiers (sorted).
    /// [`restore`](Self::restore) rebuilds an identical state — same frontier,
    /// same anchor ring, same nullifier set — so a reloaded ledger reproduces
    /// the exact v2 commitment. Same shape as pool v1's snapshot.
    pub fn snapshot(&self) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        (
            self.commitments.clone(),
            self.nullifiers.iter().copied().collect(),
        )
    }

    /// Reconstruct a state from a [`snapshot`](Self::snapshot): replay the
    /// commitments in order (rebuilding the frontier and the anchor ring
    /// deterministically) then insert the nullifiers. Non-canonical digest
    /// bytes are a typed error, never a panic.
    pub fn restore(
        commitments: &[[u8; 32]],
        nullifiers: &[[u8; 32]],
    ) -> Result<Self, ShieldedV2StateError> {
        let mut state = ShieldedV2State::new();
        for c in commitments {
            let cm = PqDigest::from_bytes(c).ok_or(ShieldedV2StateError::Decode("commitment"))?;
            if cm == PqDigest::ZERO {
                return Err(ShieldedV2StateError::ZeroDigest);
            }
            state.append_commitment(cm)?;
        }
        for n in nullifiers {
            let nf = PqDigest::from_bytes(n).ok_or(ShieldedV2StateError::Decode("nullifier"))?;
            if nf == PqDigest::ZERO {
                return Err(ShieldedV2StateError::ZeroDigest);
            }
            state.nullifiers.insert(nf.to_bytes());
        }
        Ok(state)
    }

    /// A deterministic digest of the authoritative v2 state — leaf count,
    /// current root, the anchor ring (oldest first), and the spent-nullifier
    /// set (sorted) — for folding into the ledger's state root under its own
    /// absent-when-empty slot. Domain-tagged and length-prefixed so distinct
    /// states can never encode to the same preimage.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"sov-shielded-v2-state-v1");
        h.update(&self.size.to_le_bytes());
        h.update(&self.root().to_bytes());
        h.update(&(self.anchor_ring.len() as u64).to_le_bytes());
        for a in &self.anchor_ring {
            h.update(a);
        }
        h.update(&(self.nullifiers.len() as u64).to_le_bytes());
        for nf in &self.nullifiers {
            h.update(nf);
        }
        *h.finalize().as_bytes()
    }

    /// Test-only: a state that CLAIMS `size` leaves (frontier/ring contents
    /// are not meaningful) so capacity boundaries can be exercised without
    /// paying 2^20 real appends.
    #[cfg(test)]
    fn with_claimed_size(size: u64) -> Self {
        let mut s = ShieldedV2State::new();
        s.size = size;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::digest_from_bytes;
    use crate::tree::CommitmentTree;

    /// A distinct, canonical, nonzero digest per index.
    fn d(n: u64) -> PqDigest {
        digest_from_bytes(crate::domains::B3_TEST, &n.to_le_bytes())
    }

    /// Empty-subtree digests for an arbitrary depth (level 0 = leaf).
    fn empty_levels_of(depth: usize) -> Vec<PqDigest> {
        let mut empty = vec![PqDigest::ZERO; depth + 1];
        for l in 1..=depth {
            empty[l] = merge_domain(RESCUE_DOMAIN_MERKLE_NODE, empty[l - 1], empty[l - 1]);
        }
        empty
    }

    /// Depth-parameterized O(n·depth) reference root — the *same* algorithm
    /// [`CommitmentTree::root`] uses (the tree the STARK's witnesses are built
    /// against), lifted to an arbitrary depth so the frontier can be pinned
    /// against it at capacity boundaries that are unreachable in a test at
    /// depth 20. `reference_root_agrees_with_the_stark_reference_tree` proves
    /// this really is that algorithm.
    fn reference_root(leaves: &[PqDigest], depth: usize) -> PqDigest {
        fn subtree(leaves: &[PqDigest], empty: &[PqDigest], level: usize, index: u64) -> PqDigest {
            let first = (index as usize) << level;
            if first >= leaves.len() {
                return empty[level];
            }
            if level == 0 {
                return leaves[first];
            }
            let left = subtree(leaves, empty, level - 1, index * 2);
            let right = subtree(leaves, empty, level - 1, index * 2 + 1);
            merge_domain(RESCUE_DOMAIN_MERKLE_NODE, left, right)
        }
        subtree(leaves, &empty_levels_of(depth), depth, 0)
    }

    #[test]
    fn empty_root_matches_the_reference_tree_and_is_a_known_anchor() {
        let state = ShieldedV2State::new();
        let reference = CommitmentTree::new();
        assert_eq!(state.root(), reference.root(), "empty roots agree");
        assert!(state.anchor_is_known(&state.root()));
        assert_eq!(state.note_count(), 0);
        assert!(state.is_empty());
    }

    #[test]
    fn frontier_root_matches_the_reference_tree_at_every_size() {
        // The O(depth) frontier is a REIMPLEMENTATION of the root the O(n)
        // reference tree (tree.rs, which the STARK's witnesses are built
        // against) computes. Pin them to each other leaf-by-leaf across sizes
        // that cross every carry boundary up to 80 (so the 2^6 carry into a
        // fresh ommer level is exercised too). The capacity boundary itself
        // (2^TREE_DEPTH) is out of reach here — it is covered exhaustively at
        // every small depth by
        // `frontier_is_exact_below_capacity_and_cannot_represent_a_full_tree`,
        // and at the real depth by the release-only
        // `frontier_matches_the_reference_tree_at_full_capacity`.
        let mut state = ShieldedV2State::new();
        let mut reference = CommitmentTree::new();
        for i in 0..80u64 {
            state.apply(&[], &[d(i)]).expect("append");
            reference.append(d(i)).expect("append");
            assert_eq!(state.root(), reference.root(), "size {}", i + 1);
        }
    }

    #[test]
    fn reference_root_agrees_with_the_stark_reference_tree() {
        // The depth-parameterized reference used by the boundary tests below
        // is the SAME function tree.rs computes — pinned at the real depth so
        // small-depth conclusions transfer to depth 20.
        let mut reference = CommitmentTree::new();
        let mut leaves = Vec::new();
        assert_eq!(reference_root(&leaves, TREE_DEPTH), reference.root());
        for i in 0..40u64 {
            reference.append(d(i)).expect("append");
            leaves.push(d(i));
            assert_eq!(
                reference_root(&leaves, TREE_DEPTH),
                reference.root(),
                "size {}",
                i + 1
            );
        }
    }

    #[test]
    fn frontier_is_exact_below_capacity_and_cannot_represent_a_full_tree() {
        // THE BUG THIS FILE ONCE HAD, pinned structurally at every small depth
        // (the same algorithms production runs at depth 20, driven directly so
        // the whole leaf space is affordable):
        //
        //   * for every size in 0..2^depth the frontier root EQUALS the
        //     reference root; and
        //   * at index 2^depth - 1 the append has NO free ommer slot, i.e. a
        //     depth-`d` frontier provably cannot hold 2^d leaves. Were such an
        //     append allowed, `size == 2^depth` would have all-zero low bits
        //     and the frontier would report the EMPTY-TREE root for a full
        //     tree — a full-pool anchor colliding with the empty anchor.
        for depth in 1..=6usize {
            let empty = empty_levels_of(depth);
            let mut ommers = vec![PqDigest::ZERO; depth];
            let mut leaves: Vec<PqDigest> = Vec::new();
            assert_eq!(
                frontier_root(&ommers, &empty, 0),
                reference_root(&leaves, depth),
                "depth {depth} size 0"
            );
            let capacity = 1u64 << depth;
            for size in 0..capacity - 1 {
                assert!(
                    frontier_append(&mut ommers, size, d(size)),
                    "depth {depth}: index {size} must have a free ommer slot"
                );
                leaves.push(d(size));
                assert_eq!(
                    frontier_root(&ommers, &empty, size + 1),
                    reference_root(&leaves, depth),
                    "depth {depth} size {}",
                    size + 1
                );
            }
            // The final slot: no ommer can hold the completed root.
            let mut probe = ommers.clone();
            assert!(
                !frontier_append(&mut probe, capacity - 1, d(capacity - 1)),
                "depth {depth}: the 2^{depth}-th leaf has no ommer slot"
            );
            assert_eq!(probe, ommers, "a refused append mutates nothing");
            // And the reason it must be refused: at size 2^depth the frontier
            // walk sees only zero bits — the empty-tree root.
            leaves.push(d(capacity - 1));
            assert_eq!(
                frontier_root(&ommers, &empty, capacity),
                frontier_root(&vec![PqDigest::ZERO; depth], &empty, 0),
                "depth {depth}: size 2^{depth} would collide with the empty root"
            );
            assert_ne!(
                frontier_root(&ommers, &empty, capacity),
                reference_root(&leaves, depth),
                "depth {depth}: and would disagree with the reference tree"
            );
        }
    }

    #[test]
    fn frontier_boundary_holds_at_larger_depths() {
        // Same boundary, at depths where the leaf space is 1k/4k slots: the
        // last USABLE size is exact against the reference, and the slot beyond
        // it is unrepresentable. Guards against the conclusion above being an
        // artifact of tiny depths.
        for depth in [10usize, 12] {
            let empty = empty_levels_of(depth);
            let mut ommers = vec![PqDigest::ZERO; depth];
            let mut leaves: Vec<PqDigest> = Vec::new();
            let capacity = 1u64 << depth;
            for size in 0..capacity - 1 {
                assert!(frontier_append(&mut ommers, size, d(size)), "depth {depth}");
                leaves.push(d(size));
            }
            assert_eq!(
                frontier_root(&ommers, &empty, capacity - 1),
                reference_root(&leaves, depth),
                "depth {depth}: exact at the last usable size (all ommers set)"
            );
            assert!(
                !frontier_append(&mut ommers, capacity - 1, d(capacity - 1)),
                "depth {depth}: the full tree is unrepresentable"
            );
        }
    }

    #[test]
    fn usable_capacity_is_one_short_of_the_leaf_space() {
        // The cap that makes the frontier total. If MAX_V2_NOTES ever grew to
        // the full 2^TREE_DEPTH again, `root()` would return the empty-tree
        // root for a full pool.
        assert_eq!(MAX_V2_NOTES, (1u64 << TREE_DEPTH) - 1);
        const { assert!(MAX_V2_NOTES < (1u64 << TREE_DEPTH)) };
        assert_eq!(MAX_V2_NOTES, crate::tree::MAX_TREE_LEAVES);
        // Every reachable append index has a free ommer slot, and every
        // reachable size is fully visible to the depth-TREE_DEPTH bit walk.
        assert!(
            (MAX_V2_NOTES - 1).trailing_ones() < TREE_DEPTH as u32,
            "the last appendable index must have a zero bit below the depth"
        );
        assert_eq!(
            MAX_V2_NOTES >> TREE_DEPTH,
            0,
            "no reachable size has bits above the frontier depth"
        );
    }

    #[test]
    fn capacity_boundary_is_exact_for_real_appends_at_the_real_depth() {
        // One below / at / one above capacity, for BOTH mutators, with a real
        // leaf appended at the boundary (the size is faked to make 2^20
        // affordable; the append, the frontier update and the root are real).
        for size in [MAX_V2_NOTES - 1, MAX_V2_NOTES] {
            // append_commitment
            let mut s = ShieldedV2State::with_claimed_size(size);
            let r = s.append_commitment(d(7));
            if size < MAX_V2_NOTES {
                assert_eq!(r, Ok(()), "the last leaf fits");
                assert_eq!(s.note_count(), MAX_V2_NOTES);
                // The root at full capacity is NOT the empty-tree root.
                assert_ne!(
                    s.root(),
                    ShieldedV2State::new().root(),
                    "a full pool must never share the empty pool's anchor"
                );
                assert_eq!(
                    s.append_commitment(d(8)),
                    Err(ShieldedV2StateError::TreeFull),
                    "one past capacity"
                );
                assert_eq!(s.note_count(), MAX_V2_NOTES);
            } else {
                assert_eq!(r, Err(ShieldedV2StateError::TreeFull), "at capacity");
                assert_eq!(s.note_count(), MAX_V2_NOTES);
            }
            // apply
            let mut s = ShieldedV2State::with_claimed_size(size);
            let before = s.commitment();
            let r = s.apply(&[d(9)], &[d(7)]);
            if size < MAX_V2_NOTES {
                assert_eq!(r, Ok(()));
                assert_eq!(s.note_count(), MAX_V2_NOTES);
                assert_eq!(
                    s.apply(&[d(10)], &[d(8)]),
                    Err(ShieldedV2StateError::TreeFull),
                    "one past capacity"
                );
                assert!(!s.nullifier_seen(&d(10)), "the rejected batch is atomic");
            } else {
                assert_eq!(r, Err(ShieldedV2StateError::TreeFull));
                assert_eq!(s.commitment(), before, "rejected apply mutates nothing");
            }
        }
    }

    #[test]
    fn a_state_at_full_capacity_never_reports_the_empty_root() {
        // The exact collision the audit found, in the shape it would have
        // taken: a frontier whose size is the full leaf space reports the
        // empty-tree root. Capping capacity is what makes that size
        // unreachable, and this test fails the moment it becomes reachable.
        let full = ShieldedV2State::with_claimed_size(1u64 << TREE_DEPTH);
        assert_eq!(
            full.root(),
            ShieldedV2State::new().root(),
            "documenting WHY 2^TREE_DEPTH must be unreachable"
        );
        // ...and it is unreachable: no mutator can take size past
        // MAX_V2_NOTES, which the build itself now enforces.
        const { assert!((1u64 << TREE_DEPTH) > MAX_V2_NOTES) };
    }

    /// Release-only (~2 minutes): fill the REAL depth-20 tree to capacity with
    /// real appends and pin the frontier root against the reference tree there.
    /// Run with:
    /// `cargo test -p sov-shielded-pq --release -- --ignored full_capacity`
    #[test]
    #[ignore = "fills the real 2^20 tree; ~2 min in release, far longer in debug"]
    fn frontier_matches_the_reference_tree_at_full_capacity() {
        let mut state = ShieldedV2State::new();
        let mut reference = CommitmentTree::new();
        for i in 0..MAX_V2_NOTES {
            state.apply(&[], &[d(i)]).expect("append");
            reference.append(d(i)).expect("append");
        }
        assert_eq!(state.note_count(), MAX_V2_NOTES);
        assert_eq!(reference.len() as u64, MAX_V2_NOTES);
        assert_eq!(
            state.root(),
            reference.root(),
            "frontier and reference agree at FULL capacity"
        );
        assert_ne!(state.root(), ShieldedV2State::new().root());
        assert_eq!(
            state.apply(&[], &[d(0)]),
            Err(ShieldedV2StateError::TreeFull)
        );
        assert!(
            reference.append(d(0)).is_none(),
            "reference caps identically"
        );
    }

    #[test]
    fn the_anchor_ring_evicts_only_at_its_derived_bound() {
        // Was `anchor_ring_holds_exactly_the_last_128_roots`, asserting a
        // hardcoded 128. The bound is now DERIVED
        // (MAX_V2_COMMITMENTS_PER_BLOCK * ANCHOR_HORIZON_BLOCKS), because 128
        // anchors was less than one saturated block's worth of commitments —
        // see `anchor_horizon_tests`. The BEHAVIOUR asserted here is unchanged:
        // fill to the cap, everything is known; one more evicts exactly the
        // oldest and nothing else.
        let mut state = ShieldedV2State::new();
        let empty_anchor = state.root();
        let mut roots = vec![empty_anchor];
        // Fill to exactly the cap: the seeded empty root plus CAP-1 appends.
        for i in 0..(ANCHOR_RING_LEN as u64 - 1) {
            state.apply(&[], &[d(i)]).expect("append");
            roots.push(state.root());
        }
        assert_eq!(state.anchors().count(), ANCHOR_RING_LEN);
        for r in &roots {
            assert!(state.anchor_is_known(r), "every root is known at the cap");
        }
        // One more crosses the bound: the OLDEST (empty) root is evicted,
        // everything newer stays, and the ring never exceeds the cap.
        state
            .apply(&[], &[d(ANCHOR_RING_LEN as u64 - 1)])
            .expect("append");
        roots.push(state.root());
        assert_eq!(state.anchors().count(), ANCHOR_RING_LEN);
        assert!(
            !state.anchor_is_known(&empty_anchor),
            "crossing the bound evicts exactly the oldest anchor"
        );
        for r in &roots[1..] {
            assert!(state.anchor_is_known(r));
        }
    }

    #[test]
    fn double_spends_are_rejected_within_and_across_batches() {
        let mut state = ShieldedV2State::new();
        state.apply(&[d(1)], &[d(100)]).expect("first spend");
        assert!(state.nullifier_seen(&d(1)));
        // Across batches.
        let before = state.commitment();
        assert_eq!(
            state.apply(&[d(1)], &[d(101)]),
            Err(ShieldedV2StateError::DoubleSpend)
        );
        // Within one batch.
        assert_eq!(
            state.apply(&[d(2), d(2)], &[d(101)]),
            Err(ShieldedV2StateError::DoubleSpend)
        );
        // Atomicity: both rejections left the state bit-identical.
        assert_eq!(state.commitment(), before, "rejected apply mutates nothing");
        assert_eq!(state.note_count(), 1);
    }

    #[test]
    fn zero_dummy_digests_are_refused() {
        let mut state = ShieldedV2State::new();
        let before = state.commitment();
        assert_eq!(
            state.apply(&[PqDigest::ZERO], &[d(1)]),
            Err(ShieldedV2StateError::ZeroDigest)
        );
        assert_eq!(
            state.apply(&[d(1)], &[PqDigest::ZERO]),
            Err(ShieldedV2StateError::ZeroDigest)
        );
        assert_eq!(state.commitment(), before);
        assert!(state.is_empty());
    }

    #[test]
    fn tree_capacity_boundary_is_exact() {
        // At MAX-1 one more note fits; at MAX nothing does; a 2-note batch at
        // MAX-1 is rejected WHOLE (atomic).
        let mut nearly = ShieldedV2State::with_claimed_size(MAX_V2_NOTES - 1);
        assert!(nearly.apply(&[], &[d(1)]).is_ok());
        assert_eq!(nearly.note_count(), MAX_V2_NOTES);
        assert_eq!(
            nearly.apply(&[], &[d(2)]),
            Err(ShieldedV2StateError::TreeFull)
        );

        let mut nearly = ShieldedV2State::with_claimed_size(MAX_V2_NOTES - 1);
        assert_eq!(
            nearly.apply(&[], &[d(1), d(2)]),
            Err(ShieldedV2StateError::TreeFull),
            "a batch that would overflow is rejected whole"
        );
        assert_eq!(nearly.note_count(), MAX_V2_NOTES - 1);
    }

    #[test]
    fn snapshot_restore_reproduces_the_exact_state() {
        let mut state = ShieldedV2State::new();
        for i in 0..131u64 {
            // Cross the ring bound so eviction history is exercised too.
            state.apply(&[d(1000 + i)], &[d(i)]).expect("apply");
        }
        let (cms, nfs) = state.snapshot();
        let restored = ShieldedV2State::restore(&cms, &nfs).expect("restore");
        assert_eq!(restored, state, "field-for-field identical");
        assert_eq!(restored.commitment(), state.commitment());
        assert_eq!(restored.root(), state.root());
        assert_eq!(
            restored.anchors().collect::<Vec<_>>(),
            state.anchors().collect::<Vec<_>>(),
            "the anchor ring (including evictions) is reproduced exactly"
        );
    }

    #[test]
    fn apply_refuses_non_canonical_digests_so_snapshots_always_restore() {
        // `PqDigest`'s limbs are a public field, so a hand-built digest can
        // hold a limb >= p. It survives `to_bytes` but `from_bytes` refuses
        // it — a state that accepted one could not be reloaded from its own
        // snapshot. Refuse at the door instead, in both roles.
        let non_canonical = PqDigest([u64::MAX, 0, 0, 0]);
        assert!(!non_canonical.is_canonical());
        assert!(PqDigest::from_bytes(&non_canonical.to_bytes()).is_none());

        let mut state = ShieldedV2State::new();
        let before = state.commitment();
        assert_eq!(
            state.apply(&[], &[non_canonical]),
            Err(ShieldedV2StateError::Decode("commitment"))
        );
        assert_eq!(
            state.apply(&[non_canonical], &[d(1)]),
            Err(ShieldedV2StateError::Decode("nullifier"))
        );
        assert_eq!(state.commitment(), before, "rejected apply mutates nothing");
        assert!(state.is_empty());

        // Totality: whatever `apply` accepts, `restore` reproduces exactly.
        state.apply(&[d(1)], &[d(2), d(3)]).expect("apply");
        let (cms, nfs) = state.snapshot();
        assert_eq!(
            ShieldedV2State::restore(&cms, &nfs).expect("restore"),
            state
        );
    }

    #[test]
    fn restore_rejects_non_canonical_and_zero_digests() {
        let mut bad = [0u8; 32];
        bad[..8].copy_from_slice(&u64::MAX.to_le_bytes()); // limb >= p
        assert_eq!(
            ShieldedV2State::restore(&[bad], &[]),
            Err(ShieldedV2StateError::Decode("commitment"))
        );
        assert_eq!(
            ShieldedV2State::restore(&[], &[bad]),
            Err(ShieldedV2StateError::Decode("nullifier"))
        );
        assert_eq!(
            ShieldedV2State::restore(&[[0u8; 32]], &[]),
            Err(ShieldedV2StateError::ZeroDigest)
        );
        assert_eq!(
            ShieldedV2State::restore(&[], &[[0u8; 32]]),
            Err(ShieldedV2StateError::ZeroDigest)
        );
    }

    #[test]
    fn state_commitment_is_pinned_and_content_sensitive() {
        // KAT pins for the NEW v2 fold (these are new vectors, not re-pins —
        // the fold did not exist before S2a). If either hex ever changes, the
        // v2 state commitment changed and every v2-active chain would fork.
        let empty = ShieldedV2State::new();
        assert_eq!(
            hex::encode(empty.commitment()),
            "a9a49bfab47ef7521b59bb2a921fdef5b085f960d6839a427a5f1045b49d809f",
        );
        let mut one = ShieldedV2State::new();
        one.apply(&[d(1)], &[d(2)]).expect("apply");
        assert_eq!(
            hex::encode(one.commitment()),
            "934a9a2a06aae8ca1dece468472d990c918a7bbe787704e0683666687b2849e5",
        );
        // Deterministic and distinct.
        assert_eq!(one.commitment(), one.clone().commitment());
        assert_ne!(empty.commitment(), one.commitment());
    }
}

#[cfg(test)]
mod anchor_horizon_tests {
    use super::*;

    /// **Audit PQV2-03.** A saturated block must not be able to evict the ring.
    ///
    /// The ring was 128 entries and an anchor is pushed per COMMITMENT, so one
    /// block carrying 156 commitments wiped it entirely — invalidating every
    /// spend already in flight, proven seconds earlier against a then-valid
    /// root. Sizing the ring in BLOCKS is what fixes that.
    #[test]
    fn one_saturated_block_cannot_evict_the_ring() {
        // Compile-time: a relationship between constants, so the BUILD fails if
        // anyone ever shrinks the ring below one block's worth again.
        const {
            assert!(
                ANCHOR_RING_LEN > MAX_V2_COMMITMENTS_PER_BLOCK,
                "one saturated block must not be able to evict the whole ring"
            )
        };
        // And not merely by one: the ring must still span a real horizon after
        // the busiest possible block.
        let remaining = ANCHOR_RING_LEN - MAX_V2_COMMITMENTS_PER_BLOCK;
        assert!(
            remaining >= MAX_V2_COMMITMENTS_PER_BLOCK * (ANCHOR_HORIZON_BLOCKS - 1),
            "after one saturated block the ring must still cover the rest of the horizon"
        );
    }

    /// The ring spans at least the confirmation horizon under worst-case load —
    /// the property the constant is supposed to express.
    #[test]
    fn the_ring_spans_the_block_horizon_under_saturation() {
        assert_eq!(
            ANCHOR_RING_LEN,
            MAX_V2_COMMITMENTS_PER_BLOCK * ANCHOR_HORIZON_BLOCKS
        );
        const {
            assert!(
                ANCHOR_HORIZON_BLOCKS >= 6,
                "the horizon must exceed the 6-confirmation finality depth"
            )
        };
    }

    /// Filling the ring past capacity keeps the NEWEST entries and drops the
    /// oldest — and never grows without bound.
    #[test]
    fn the_ring_is_bounded_and_keeps_the_newest() {
        let mut st = ShieldedV2State::new();
        // Push a handful past capacity; each append pushes one anchor.
        let mut last = None;
        for i in 0..(ANCHOR_RING_LEN + 50) {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let cm = PqDigest::from_bytes(&b).expect("canonical");
            if st.apply(&[], &[cm]).is_err() {
                break;
            }
            last = Some(st.root());
        }
        assert!(
            st.anchors().count() <= ANCHOR_RING_LEN,
            "the ring must never exceed its bound"
        );
        if let Some(newest) = last {
            assert!(
                st.anchor_is_known(&newest),
                "the most recent root must always be spendable against"
            );
        }
    }
}
