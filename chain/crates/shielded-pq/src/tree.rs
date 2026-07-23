//! Fixed-depth append-only note-commitment tree over Rescue-Prime.
//!
//! Depth-[`TREE_DEPTH`] binary Merkle tree; empty leaves are the all-zero
//! digest and empty internal nodes are the usual precomputed
//! `merge(empty, empty)` chain. The API mirrors the Orchard-side
//! `NoteWitnessTree` (`sov-shielded::wallet`): `append`, `mark`, `witness`,
//! `root` — so a future pool-v2 wallet feels familiar. Unlike the bridgetree
//! version this prototype keeps all appended leaves (no pruning); fine for a
//! prototype, noted in the design doc.

use crate::hash::{merge, PqDigest};

/// Merkle tree depth — up to 2^20 (~1M) notes.
pub const TREE_DEPTH: usize = 20;

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
                merge(acc, *sib)
            } else {
                merge(*sib, acc)
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
    /// `empty[l]` = digest of an empty subtree of height `l`.
    empty: [PqDigest; TREE_DEPTH + 1],
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
        let mut empty = [PqDigest::ZERO; TREE_DEPTH + 1];
        for l in 1..=TREE_DEPTH {
            empty[l] = merge(empty[l - 1], empty[l - 1]);
        }
        CommitmentTree {
            leaves: Vec::new(),
            empty,
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
    /// `None` if the tree is full.
    pub fn append(&mut self, cm: PqDigest) -> Option<u64> {
        if self.leaves.len() >= 1usize << TREE_DEPTH {
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
            return self.empty[level];
        }
        if level == 0 {
            return self.leaves[first];
        }
        let left = self.subtree_hash(level - 1, index * 2);
        let right = self.subtree_hash(level - 1, index * 2 + 1);
        merge(left, right)
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
            let cm = digest_from_bytes("sov-shielded-pq:test:v1", &i.to_le_bytes());
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
        let cm = digest_from_bytes("sov-shielded-pq:test:v1", b"leaf");
        tree.append(cm).expect("append");
        let (path, anchor) = tree.witness(0).expect("witness");
        let wrong = digest_from_bytes("sov-shielded-pq:test:v1", b"other");
        assert_ne!(path.compute_root(wrong), anchor);
    }
}
