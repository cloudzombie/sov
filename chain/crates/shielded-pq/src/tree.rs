//! Fixed-depth append-only note-commitment tree over domain-separated
//! Rescue-Prime (`RESCUE_DOMAIN_MERKLE_NODE` on every internal node).
//!
//! Depth-[`TREE_DEPTH`] binary Merkle tree; empty leaves are the all-zero
//! digest and empty internal nodes are the usual precomputed
//! `merge(empty, empty)` chain. The API mirrors the Orchard-side
//! `NoteWitnessTree` (`sov-shielded::wallet`): `append`, `mark`, `witness`,
//! `root` — so a future pool-v2 wallet feels familiar. Unlike the bridgetree
//! version this prototype keeps all appended leaves (no pruning); fine for a
//! prototype, noted in the design doc.

use std::sync::OnceLock;

use crate::domains::RESCUE_DOMAIN_MERKLE_NODE;
use crate::hash::{merge_domain, PqDigest};

/// Merkle tree depth — a 2^32-slot (~4.29 billion) leaf space.
///
/// This is the **horizon-safe** depth ([`HORIZON_SAFE_TREE_DEPTH`]): sized so
/// the tree cannot be exhausted within the asset's intended lifetime, even
/// under sustained worst-case growth. See [`HORIZON_SAFE_TREE_DEPTH`] for the
/// capacity derivation. Raising the depth from the earlier depth-20 prototype
/// to 32 was audit **PQV2-04** — a re-derived, re-proven STARK spend-circuit
/// revision (the Merkle-verify segment of the AIR trace grows from 20 to 32
/// path steps; see [`crate::air`]).
pub const TREE_DEPTH: usize = 32;

/// **Usable** leaf capacity of the depth-[`TREE_DEPTH`] tree: `2^TREE_DEPTH - 1`,
/// one slot short of the leaf space.
///
/// The last slot is deliberately unusable. Consensus maintains this tree as an
/// O(depth) *frontier* ([`ShieldedV2State`](crate::ShieldedV2State)), whose
/// entire representation is "one ommer per set bit of `size`". A depth-`D`
/// frontier can therefore represent every size in `0..2^D` and **cannot**
/// represent `2^D`: at exactly `2^D` all `D` low bits are zero, so the
/// representation is indistinguishable from the empty tree and the completed
/// root has nowhere to live. Refusing the final leaf keeps the frontier a
/// total, injective encoding of tree contents at every reachable size, which
/// is the invariant the anchor ring and the STARK's membership proofs stand
/// on. The alternative (a 21st ommer slot holding the completed root, special
/// -cased in `root()`) buys one note out of 4,294,967,296 and pays for it with
/// a state field that is only ever meaningful in one unreachable-in-practice
/// configuration; capping is strictly simpler to reason about and strictly
/// safer for the executor that consumes this next.
///
/// This reference tree enforces the same bound as the frontier so that a
/// wallet-side tree can never build a witness against a tree state consensus
/// is unable to hold.
pub const MAX_TREE_LEAVES: u64 = (1u64 << TREE_DEPTH) - 1;

/// The tree depth a **production** pool needs so its capacity cannot be
/// exhausted within the asset's intended lifetime — DERIVED, audit **PQV2-04**.
///
/// Capacity must outrun the fastest way leaves are added: a fully-saturated
/// block. Block weight bounds one block to `MAX_V2_COMMITMENTS_PER_BLOCK` (160)
/// commitments, so over a horizon of `H` blocks the tree must hold `160·H`
/// leaves. Sizing `H` at ~20 years of blocks at the 2.5-minute target
/// (`20·365·24·3600 / 150 ≈ 4.2M` blocks) needs `160 · 4.2M ≈ 6.7×10^8` leaves,
/// i.e. depth `ceil(log2(6.7×10^8)) = 30`. Rounding up to Orchard's depth **32**
/// (4.29×10^9 leaves) leaves >6× headroom.
///
/// As of audit **PQV2-04** the shipped [`TREE_DEPTH`] **is** this depth: the
/// two are equal (asserted below), and the earlier depth-20 prototype — whose
/// capacity was exhaustible by a bounded griefing attack in ~11 days — is gone.
/// Deepening the tree was a STARK **spend-circuit** revision: the AIR trace
/// row-map derives the Merkle path length from [`TREE_DEPTH`]
/// ([`air::root_row`](crate::air::root_row),
/// [`INPUT_SEGMENT_ROWS`](crate::air::INPUT_SEGMENT_ROWS),
/// [`TRACE_LENGTH`](crate::air::TRACE_LENGTH), now 2048), and every proof KAT
/// and the measured verify-cost basis were re-derived and re-measured with it.
/// The circuit was re-proven to CONSTRAIN a full 32-deep authentication path
/// (a spend whose path is shorter, longer, or tampered fails verification —
/// see `tests/kat.rs`). This remains gated behind signal bit 2, which is
/// dormant on every canonical network today.
pub const HORIZON_SAFE_TREE_DEPTH: usize = 32;

/// The shipped tree is now the horizon-safe depth (audit PQV2-04). This build
/// fails if the two ever diverge again — the "prototype depth" era is over.
const _: () = assert!(TREE_DEPTH == HORIZON_SAFE_TREE_DEPTH);

/// `empty[l]` = digest of an empty subtree of height `l` (level 0 = leaf).
///
/// THE one source of truth for the empty-subtree ladder: the reference tree
/// here and the consensus frontier in `state.rs` must agree on it digest-for-
/// digest or their roots diverge, so they share this function rather than each
/// recomputing the chain. Deterministic; computed once per process.
pub(crate) fn empty_levels() -> &'static [PqDigest; TREE_DEPTH + 1] {
    static EMPTY: OnceLock<[PqDigest; TREE_DEPTH + 1]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut empty = [PqDigest::ZERO; TREE_DEPTH + 1];
        for l in 1..=TREE_DEPTH {
            empty[l] = merge_domain(RESCUE_DOMAIN_MERKLE_NODE, empty[l - 1], empty[l - 1]);
        }
        empty
    })
}

/// A Merkle membership witness: the leaf position and one sibling per level
/// (level 0 = leaf level).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerklePath {
    /// Leaf index of the witnessed commitment.
    pub position: u64,
    /// Sibling digests, leaf level first.
    pub siblings: [PqDigest; TREE_DEPTH],
}

impl MerklePath {
    /// Recompute the root implied by this path for `leaf` (native check —
    /// the same computation the STARK proves).
    pub fn compute_root(&self, leaf: PqDigest) -> PqDigest {
        let mut acc = leaf;
        for (level, sib) in self.siblings.iter().enumerate() {
            let bit = (self.position >> level) & 1;
            acc = if bit == 0 {
                merge_domain(RESCUE_DOMAIN_MERKLE_NODE, acc, *sib)
            } else {
                merge_domain(RESCUE_DOMAIN_MERKLE_NODE, *sib, acc)
            };
        }
        acc
    }
}

/// Append-only note-commitment tree with membership witnesses.
#[derive(Clone)]
pub struct CommitmentTree {
    /// All appended leaves, in order.
    leaves: Vec<PqDigest>,
    /// Positions the wallet wants witnesses for (API parity with
    /// `NoteWitnessTree::mark`; this prototype can witness any leaf).
    marked: Vec<u64>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    /// A fresh, empty tree.
    pub fn new() -> Self {
        CommitmentTree {
            leaves: Vec::new(),
            marked: Vec::new(),
        }
    }

    /// Number of appended leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True if no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a note commitment in chain order, returning its leaf position.
    /// `None` if the tree is full ([`MAX_TREE_LEAVES`] — the final leaf slot is
    /// not usable; see that constant).
    pub fn append(&mut self, cm: PqDigest) -> Option<u64> {
        if self.leaves.len() as u64 >= MAX_TREE_LEAVES {
            return None;
        }
        self.leaves.push(cm);
        Some((self.leaves.len() - 1) as u64)
    }

    /// Mark the most-recently-appended commitment as one to witness later.
    /// Returns its position. (API parity with the Orchard-side tree.)
    pub fn mark(&mut self) -> Option<u64> {
        let pos = self.leaves.len().checked_sub(1)? as u64;
        self.marked.push(pos);
        Some(pos)
    }

    /// The current root over the fixed-depth tree.
    pub fn root(&self) -> PqDigest {
        self.subtree_hash(TREE_DEPTH, 0)
    }

    /// Build the Merkle witness (path + anchor) for the leaf at `position`
    /// against the current root. `None` if out of range.
    pub fn witness(&self, position: u64) -> Option<(MerklePath, PqDigest)> {
        if (position as usize) >= self.leaves.len() {
            return None;
        }
        let mut siblings = [PqDigest::ZERO; TREE_DEPTH];
        let mut index = position;
        for (level, sib) in siblings.iter_mut().enumerate() {
            *sib = self.subtree_hash(level, index ^ 1);
            index >>= 1;
        }
        let path = MerklePath { position, siblings };
        Some((path, self.root()))
    }

    /// Digest of the subtree of height `level` whose leftmost leaf is
    /// `index << level`.
    fn subtree_hash(&self, level: usize, index: u64) -> PqDigest {
        let first = (index as usize) << level;
        if first >= self.leaves.len() {
            return empty_levels()[level];
        }
        if level == 0 {
            return self.leaves[first];
        }
        let left = self.subtree_hash(level - 1, index * 2);
        let right = self.subtree_hash(level - 1, index * 2 + 1);
        merge_domain(RESCUE_DOMAIN_MERKLE_NODE, left, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::digest_from_bytes;

    #[test]
    fn witness_verifies_against_root() {
        let mut tree = CommitmentTree::new();
        let mut cms = Vec::new();
        for i in 0u64..5 {
            let cm = digest_from_bytes(crate::domains::B3_TEST, &i.to_le_bytes());
            tree.append(cm).expect("append");
            tree.mark().expect("mark");
            cms.push(cm);
        }
        for (i, cm) in cms.iter().enumerate() {
            let (path, anchor) = tree.witness(i as u64).expect("witness");
            assert_eq!(anchor, tree.root());
            assert_eq!(path.compute_root(*cm), anchor);
        }
    }

    #[test]
    fn wrong_leaf_fails_native_check() {
        let mut tree = CommitmentTree::new();
        let cm = digest_from_bytes(crate::domains::B3_TEST, b"leaf");
        tree.append(cm).expect("append");
        let (path, anchor) = tree.witness(0).expect("witness");
        let wrong = digest_from_bytes(crate::domains::B3_TEST, b"other");
        assert_ne!(path.compute_root(wrong), anchor);
    }
}
