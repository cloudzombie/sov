//! A Sparse Merkle Tree (SMT): an authenticated key/value map.
//!
//! This is the standard construction used to commit to blockchain world state:
//! a fixed-depth binary Merkle tree over a 256-bit key space, where the vast
//! majority of subtrees are empty and therefore share precomputed *default*
//! hashes. That lets a tree with a handful of entries be represented (and
//! proven over) without materializing 2^256 nodes.
//!
//! Guarantees this provides, which is why state lives here rather than in a
//! plain map:
//! - a single 32-byte [`root`](SparseMerkleTree::root) commits to the entire
//!   key/value set, independent of insertion order;
//! - [`MerkleProof`]s prove both **inclusion** (a key maps to a value) and
//!   **exclusion** (a key is absent) against just the root.
//!
//! Domain separation (distinct `0x00`/`0x01` prefixes for leaves and internal
//! nodes) prevents a node from being reinterpreted at the wrong position — the
//! same second-preimage protection used in [`sov_primitives`]'s block Merkle
//! root, applied here to authenticated state.

use std::collections::HashMap;

use sov_primitives::Hash;

/// Depth of the tree: keys are 256-bit, so the path from root to leaf is 256
/// branch decisions.
pub const TREE_HEIGHT: usize = 256;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Commitment to a stored value (the leaf payload at a key's slot).
fn hash_leaf(value: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + value.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(value);
    Hash::digest(&buf)
}

/// Hash of an internal node from its two child hashes.
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 2 * Hash::LEN];
    buf[0] = NODE_PREFIX;
    buf[1..1 + Hash::LEN].copy_from_slice(left.as_bytes());
    buf[1 + Hash::LEN..].copy_from_slice(right.as_bytes());
    Hash::digest(&buf)
}

/// The `i`-th bit of `key`, MSB-first (bit 0 is the most significant bit of the
/// first byte). Determines whether a key descends left (`false`) or right
/// (`true`) at each level.
fn bit(key: &Hash, i: usize) -> bool {
    let byte = key.as_bytes()[i / 8];
    (byte >> (7 - (i % 8))) & 1 == 1
}

/// Precompute the default (empty-subtree) hash for every height, `0..=HEIGHT`.
/// `defaults[0]` is the empty-leaf placeholder; each higher level is the hash of
/// two empty subtrees of the level below.
fn compute_defaults() -> Vec<Hash> {
    let mut defaults = Vec::with_capacity(TREE_HEIGHT + 1);
    defaults.push(Hash::ZERO); // empty leaf
    for h in 1..=TREE_HEIGHT {
        let below = defaults[h - 1];
        defaults.push(hash_node(&below, &below));
    }
    defaults
}

/// A Merkle proof for one key: the sibling hash at each level (top-down) plus
/// the leaf value committed at the key's slot. An empty slot proves exclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// The leaf commitment at the key's slot (`Hash::ZERO` if the key is absent).
    pub leaf: Hash,
    /// Sibling hashes from the root level down to the leaf level (`TREE_HEIGHT`).
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// Verify this proof against `root` for `key`.
    ///
    /// - For inclusion of `value`, pass `Some(value)`: the proof must commit to
    ///   `hash_leaf(value)`.
    /// - For exclusion, pass `None`: the proof must commit to the empty leaf.
    #[must_use]
    pub fn verify(&self, root: Hash, key: &Hash, value: Option<&[u8]>) -> bool {
        if self.siblings.len() != TREE_HEIGHT {
            return false;
        }
        let expected_leaf = match value {
            Some(v) => hash_leaf(v),
            None => Hash::ZERO,
        };
        if self.leaf != expected_leaf {
            return false;
        }
        let mut node = self.leaf;
        for level in 1..=TREE_HEIGHT {
            let sibling = self.siblings[TREE_HEIGHT - level];
            node = if bit(key, TREE_HEIGHT - level) {
                hash_node(&sibling, &node)
            } else {
                hash_node(&node, &sibling)
            };
        }
        node == root
    }
}

/// An in-memory Sparse Merkle Tree.
///
/// Nodes are content-addressed: `nodes` maps an internal node's hash to its
/// children, so the same structure can later be backed by a persistent
/// key/value store without changing the hashing. Only non-empty internal nodes
/// are stored; empty subtrees are recognized by their default hashes.
#[derive(Clone)]
pub struct SparseMerkleTree {
    nodes: HashMap<Hash, (Hash, Hash)>,
    values: HashMap<Hash, Vec<u8>>,
    defaults: Vec<Hash>,
    root: Hash,
}

impl SparseMerkleTree {
    /// Create an empty tree. Its root is the all-empty default root.
    pub fn new() -> Self {
        let defaults = compute_defaults();
        let root = defaults[TREE_HEIGHT];
        SparseMerkleTree {
            nodes: HashMap::new(),
            values: HashMap::new(),
            defaults,
            root,
        }
    }

    /// The current root hash, committing to all key/value pairs.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// The value stored at `key`, if any.
    pub fn get(&self, key: &Hash) -> Option<&[u8]> {
        self.values.get(key).map(Vec::as_slice)
    }

    /// The children of `node`, which sits at `level`. A node not present in the
    /// store is an empty subtree, whose children are the level-below default.
    fn children(&self, node: Hash, level: usize) -> (Hash, Hash) {
        match self.nodes.get(&node) {
            Some(&(l, r)) => (l, r),
            None => (self.defaults[level - 1], self.defaults[level - 1]),
        }
    }

    /// Collect the sibling hashes along `key`'s path, root level down to leaf.
    fn siblings_for(&self, key: &Hash) -> Vec<Hash> {
        let mut siblings = Vec::with_capacity(TREE_HEIGHT);
        let mut cur = self.root;
        for level in (1..=TREE_HEIGHT).rev() {
            let (l, r) = self.children(cur, level);
            if bit(key, TREE_HEIGHT - level) {
                siblings.push(l);
                cur = r;
            } else {
                siblings.push(r);
                cur = l;
            }
        }
        siblings
    }

    /// Recompute the path from a (possibly empty) leaf up to a new root, storing
    /// the internal nodes along the way.
    fn recompute(&mut self, key: &Hash, leaf: Hash, siblings: &[Hash]) {
        let mut node = leaf;
        for level in 1..=TREE_HEIGHT {
            let sibling = siblings[TREE_HEIGHT - level];
            let (l, r) = if bit(key, TREE_HEIGHT - level) {
                (sibling, node)
            } else {
                (node, sibling)
            };
            let parent = hash_node(&l, &r);
            // Don't store empty subtrees; they're implied by the defaults.
            if parent != self.defaults[level] {
                self.nodes.insert(parent, (l, r));
            }
            node = parent;
        }
        self.root = node;
    }

    /// Insert or overwrite `key` with `value`.
    pub fn insert(&mut self, key: Hash, value: Vec<u8>) {
        let siblings = self.siblings_for(&key);
        let leaf = hash_leaf(&value);
        self.values.insert(key, value);
        self.recompute(&key, leaf, &siblings);
    }

    /// Remove `key` if present, returning the old value.
    pub fn remove(&mut self, key: &Hash) -> Option<Vec<u8>> {
        let old = self.values.remove(key)?;
        let siblings = self.siblings_for(key);
        self.recompute(key, Hash::ZERO, &siblings);
        Some(old)
    }

    /// Produce a Merkle proof for `key` (inclusion or exclusion).
    pub fn prove(&self, key: &Hash) -> MerkleProof {
        let siblings = self.siblings_for(key);
        let leaf = match self.values.get(key) {
            Some(v) => hash_leaf(v),
            None => Hash::ZERO,
        };
        MerkleProof { leaf, siblings }
    }

    /// Number of stored key/value pairs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the tree holds no entries.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: &[u8]) -> Hash {
        Hash::digest(b)
    }

    #[test]
    fn empty_root_is_the_default_root() {
        let a = SparseMerkleTree::new();
        let b = SparseMerkleTree::new();
        assert_eq!(a.root(), b.root());
        assert!(a.is_empty());
    }

    #[test]
    fn insert_changes_root_and_get_returns_value() {
        let mut t = SparseMerkleTree::new();
        let empty = t.root();
        t.insert(key(b"usa.reserve.sov"), b"account-a".to_vec());
        assert_ne!(t.root(), empty);
        assert_eq!(t.get(&key(b"usa.reserve.sov")), Some(&b"account-a"[..]));
        assert_eq!(t.get(&key(b"absent")), None);
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let mut a = SparseMerkleTree::new();
        a.insert(key(b"one"), b"1".to_vec());
        a.insert(key(b"two"), b"2".to_vec());
        a.insert(key(b"three"), b"3".to_vec());

        let mut b = SparseMerkleTree::new();
        b.insert(key(b"three"), b"3".to_vec());
        b.insert(key(b"one"), b"1".to_vec());
        b.insert(key(b"two"), b"2".to_vec());

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn overwrite_then_restore_returns_to_same_root() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(b"k"), b"v1".to_vec());
        let r1 = t.root();
        t.insert(key(b"k"), b"v2".to_vec());
        assert_ne!(t.root(), r1);
        t.insert(key(b"k"), b"v1".to_vec());
        assert_eq!(t.root(), r1);
    }

    #[test]
    fn remove_returns_to_empty_root() {
        let mut t = SparseMerkleTree::new();
        let empty = t.root();
        t.insert(key(b"k"), b"v".to_vec());
        assert_eq!(t.remove(&key(b"k")), Some(b"v".to_vec()));
        assert_eq!(t.root(), empty);
        assert_eq!(t.get(&key(b"k")), None);
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(b"a"), b"alpha".to_vec());
        t.insert(key(b"b"), b"beta".to_vec());
        let proof = t.prove(&key(b"a"));
        assert!(proof.verify(t.root(), &key(b"a"), Some(b"alpha")));
        // Wrong value must not verify.
        assert!(!proof.verify(t.root(), &key(b"a"), Some(b"WRONG")));
    }

    #[test]
    fn exclusion_proof_verifies() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(b"a"), b"alpha".to_vec());
        let proof = t.prove(&key(b"missing"));
        assert!(proof.verify(t.root(), &key(b"missing"), None));
        // Claiming a value for an absent key must fail.
        assert!(!proof.verify(t.root(), &key(b"missing"), Some(b"anything")));
    }

    #[test]
    fn proof_against_wrong_root_fails() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(b"a"), b"alpha".to_vec());
        let proof = t.prove(&key(b"a"));
        let bogus = Hash::digest(b"not the root");
        assert!(!proof.verify(bogus, &key(b"a"), Some(b"alpha")));
    }
}
