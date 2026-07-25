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
use std::sync::OnceLock;

use crate::domains::RESCUE_DOMAIN_MERKLE_NODE;
use crate::hash::{merge_domain, PqDigest};
use crate::tree::TREE_DEPTH;

/// How many recent v2 tree roots (anchors) consensus accepts a spend against
/// (decision D5 — the same window shape as Orchard's, sized at 128). The ring
/// holds *at most* this many entries, always the most recent ones; it can
/// never grow past this bound regardless of input.
pub const ANCHOR_RING_LEN: usize = 128;

/// Maximum notes the depth-[`TREE_DEPTH`] tree can hold (`2^20`). Appending
/// beyond this is a typed error, never a wrap or a panic.
pub const MAX_V2_NOTES: u64 = 1u64 << TREE_DEPTH;

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
    /// A persisted snapshot carried a non-canonical digest encoding.
    #[error("non-canonical digest in pool-v2 snapshot ({0})")]
    Decode(&'static str),
}

/// `empty[l]` = digest of an empty subtree of height `l` (level 0 = leaf).
/// Deterministic; computed once per process.
fn empty_levels() -> &'static [PqDigest; TREE_DEPTH + 1] {
    static EMPTY: OnceLock<[PqDigest; TREE_DEPTH + 1]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut empty = [PqDigest::ZERO; TREE_DEPTH + 1];
        for l in 1..=TREE_DEPTH {
            empty[l] = merge_domain(RESCUE_DOMAIN_MERKLE_NODE, empty[l - 1], empty[l - 1]);
        }
        empty
    })
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
    pub fn root(&self) -> PqDigest {
        let empty = empty_levels();
        let mut acc = empty[0];
        // `ommers` has TREE_DEPTH entries and `empty` TREE_DEPTH + 1, so the
        // zip walks levels 0..TREE_DEPTH exactly.
        for (level, (&ommer, &empty_l)) in self.ommers.iter().zip(empty.iter()).enumerate() {
            acc = if (self.size >> level) & 1 == 1 {
                merge_domain(RESCUE_DOMAIN_MERKLE_NODE, ommer, acc)
            } else {
                merge_domain(RESCUE_DOMAIN_MERKLE_NODE, acc, empty_l)
            };
        }
        acc
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
        let mut acc = cm;
        let mut idx = self.size;
        for level in 0..TREE_DEPTH {
            if idx & 1 == 0 {
                self.ommers[level] = acc;
                break;
            }
            acc = merge_domain(RESCUE_DOMAIN_MERKLE_NODE, self.ommers[level], acc);
            idx >>= 1;
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
        let mut batch = BTreeSet::new();
        for nf in nullifiers {
            if *nf == PqDigest::ZERO {
                return Err(ShieldedV2StateError::ZeroDigest);
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
        // that cross every carry boundary up to 40.
        let mut state = ShieldedV2State::new();
        let mut reference = CommitmentTree::new();
        for i in 0..40u64 {
            state.apply(&[], &[d(i)]).expect("append");
            reference.append(d(i)).expect("append");
            assert_eq!(state.root(), reference.root(), "size {}", i + 1);
        }
    }

    #[test]
    fn anchor_ring_holds_exactly_the_last_128_roots() {
        let mut state = ShieldedV2State::new();
        let empty_anchor = state.root();
        let mut roots = vec![empty_anchor];
        // 127 appends: ring = empty root + 127 roots = 128 entries; all known.
        for i in 0..127u64 {
            state.apply(&[], &[d(i)]).expect("append");
            roots.push(state.root());
        }
        assert_eq!(state.anchors().count(), ANCHOR_RING_LEN);
        for r in &roots {
            assert!(state.anchor_is_known(r), "all 128 roots known at the cap");
        }
        // One more append crosses the bound: the OLDEST (empty) root is
        // evicted, everything newer stays, and the ring never exceeds 128.
        state.apply(&[], &[d(127)]).expect("append");
        roots.push(state.root());
        assert_eq!(state.anchors().count(), ANCHOR_RING_LEN);
        assert!(
            !state.anchor_is_known(&empty_anchor),
            "the 129th root evicts the oldest anchor"
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
