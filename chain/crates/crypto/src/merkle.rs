//! Binary Merkle trees over [`Hash`](struct@Hash) leaves.
//!
//! Used to commit to ordered collections — the transactions in a block, the
//! receipts they produce — with a single root hash. Two design choices follow
//! best practice for Merkle constructions:
//!
//! - **Domain separation:** leaves and internal nodes are hashed with distinct
//!   one-byte prefixes (`0x00` / `0x01`). Without this, an attacker could
//!   present an internal node as if it were a leaf (a second-preimage attack).
//! - **Lone-node promotion:** when a level has an odd count, the unpaired node
//!   is promoted unchanged to the next level rather than duplicated. Duplicating
//!   the last leaf is the classic source of Merkle malleability bugs.
//!
//! [`merkle_proof`] / [`verify_merkle_proof`] turn that commitment into an
//! *inclusion proof*: a logarithmic sibling path that lets a verifier which holds
//! only the root — a light client that trusts no node — check that a specific
//! leaf is committed under it.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::Hash;

/// Prefix byte distinguishing a leaf hash.
const LEAF_PREFIX: u8 = 0x00;
/// Prefix byte distinguishing an internal-node hash.
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf with domain separation.
fn hash_leaf(leaf: &Hash) -> Hash {
    let mut buf = [0u8; 1 + Hash::LEN];
    buf[0] = LEAF_PREFIX;
    buf[1..].copy_from_slice(leaf.as_bytes());
    Hash::digest(&buf)
}

/// Hash two child nodes with domain separation.
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 2 * Hash::LEN];
    buf[0] = NODE_PREFIX;
    buf[1..1 + Hash::LEN].copy_from_slice(left.as_bytes());
    buf[1 + Hash::LEN..].copy_from_slice(right.as_bytes());
    Hash::digest(&buf)
}

/// Compute the Merkle root committing to `leaves` in order.
///
/// - An empty input has a fixed, well-defined root (the domain-separated hash of
///   no leaves), so "no transactions" still commits to a stable value.
/// - The root is sensitive to both the values and their order.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::digest(&[LEAF_PREFIX]);
    }

    let mut level: Vec<Hash> = leaves.iter().map(hash_leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(hash_node(left, right)),
                [lone] => next.push(*lone), // promote unchanged
                _ => unreachable!("chunks(2) yields 1 or 2 elements"),
            }
        }
        level = next;
    }
    level[0]
}

/// One step of a Merkle inclusion proof: the sibling hash to combine with, and
/// which side it sits on.
///
/// The side is carried EXPLICITLY rather than being re-derived from a leaf
/// index, so [`verify_merkle_proof`] needs nothing but `(leaf, proof, root)`.
/// That keeps a light client's verification input minimal and makes the check
/// total: any inconsistent path simply folds to a hash that is not the root.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct MerkleStep {
    /// The sibling node's hash at this level.
    pub sibling: Hash,
    /// `true` when the sibling is the LEFT child (so the running value is the
    /// right one), `false` when it is the right child.
    pub sibling_is_left: bool,
}

/// The sibling path proving that `leaves[index]` is committed under
/// `merkle_root(leaves)`, or `None` if `index` is out of range.
///
/// The path has one entry per level at which the node actually had a sibling.
/// Levels where the node was the lone, promoted odd element contribute NO entry
/// — mirroring [`merkle_root`]'s promotion rule exactly — which is why proof
/// length is `<= ceil(log2(n))` rather than exactly it.
pub fn merkle_proof(leaves: &[Hash], index: usize) -> Option<Vec<MerkleStep>> {
    if index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash> = leaves.iter().map(hash_leaf).collect();
    let mut idx = index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        // The sibling exists only when this node is part of a full pair. A lone
        // trailing node (odd level length, last position) is promoted unchanged,
        // contributing no proof step — exactly what `merkle_root` does.
        let sibling_is_left = idx % 2 == 1;
        let sibling_idx = if sibling_is_left { idx - 1 } else { idx + 1 };
        if let Some(sibling) = level.get(sibling_idx) {
            proof.push(MerkleStep {
                sibling: *sibling,
                sibling_is_left,
            });
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(hash_node(left, right)),
                [lone] => next.push(*lone),
                _ => unreachable!("chunks(2) yields 1 or 2 elements"),
            }
        }
        level = next;
        idx /= 2;
    }
    Some(proof)
}

/// Whether `leaf` is committed under `root` via `proof`.
///
/// This is the whole point of the construction: it needs only the leaf, the
/// path, and the root — no tree, no node, no trust. A tampered leaf, a wrong
/// sibling, a flipped side, or a truncated/extended path all fold to a value
/// that is not `root`, so the check is fail-closed by construction.
pub fn verify_merkle_proof(leaf: &Hash, proof: &[MerkleStep], root: &Hash) -> bool {
    let mut acc = hash_leaf(leaf);
    for step in proof {
        acc = if step.sibling_is_left {
            hash_node(&step.sibling, &acc)
        } else {
            hash_node(&acc, &step.sibling)
        };
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: &[u8]) -> Hash {
        Hash::digest(b)
    }

    #[test]
    fn empty_is_stable_and_distinct() {
        assert_eq!(merkle_root(&[]), merkle_root(&[]));
        assert_ne!(merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn single_leaf_is_its_leaf_hash() {
        let leaf = h(b"only");
        assert_eq!(merkle_root(&[leaf]), hash_leaf(&leaf));
    }

    #[test]
    fn two_leaves_match_manual_node() {
        let a = h(b"a");
        let b = h(b"b");
        let expected = hash_node(&hash_leaf(&a), &hash_leaf(&b));
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn order_sensitive() {
        let a = h(b"a");
        let b = h(b"b");
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    #[test]
    fn leaf_and_node_domains_differ() {
        // A single leaf must not collide with an internal node over the same bytes.
        let x = h(b"x");
        assert_ne!(hash_leaf(&x), hash_node(&x, &x));
    }

    #[test]
    fn deterministic_for_odd_counts() {
        let leaves: Vec<Hash> = (0u8..5).map(|i| h(&[i])).collect();
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }

    #[test]
    fn proof_verifies_for_every_index_and_size() {
        // Sizes 1..=17 cover single-leaf trees, exact powers of two, and every
        // shape where lone-node promotion kicks in at one or more levels.
        for n in 1usize..=17 {
            let leaves: Vec<Hash> = (0..n).map(|i| h(&[i as u8])).collect();
            let root = merkle_root(&leaves);
            for i in 0..n {
                let proof = merkle_proof(&leaves, i).expect("index is in range");
                assert!(
                    verify_merkle_proof(&leaves[i], &proof, &root),
                    "n={n} i={i} must verify"
                );
                assert!(
                    proof.len() <= (usize::BITS - (n - 1).leading_zeros()) as usize,
                    "n={n} i={i}: path is at most ceil(log2(n)) long"
                );
            }
        }
    }

    #[test]
    fn proof_index_out_of_range_is_none() {
        let leaves: Vec<Hash> = (0u8..3).map(|i| h(&[i])).collect();
        assert!(merkle_proof(&leaves, 3).is_none());
        assert!(merkle_proof(&[], 0).is_none());
    }

    #[test]
    fn proof_fails_closed_on_tampering() {
        let leaves: Vec<Hash> = (0u8..6).map(|i| h(&[i])).collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 2).unwrap();
        assert!(verify_merkle_proof(&leaves[2], &proof, &root));

        // A different leaf with the same path.
        assert!(!verify_merkle_proof(&leaves[3], &proof, &root));
        // A tampered sibling.
        let mut bad = proof.clone();
        bad[0].sibling = h(b"forged");
        assert!(!verify_merkle_proof(&leaves[2], &bad, &root));
        // A flipped side.
        let mut flipped = proof.clone();
        flipped[0].sibling_is_left = !flipped[0].sibling_is_left;
        assert!(!verify_merkle_proof(&leaves[2], &flipped, &root));
        // A truncated path.
        assert!(!verify_merkle_proof(&leaves[2], &proof[..1], &root));
        // A wrong root.
        assert!(!verify_merkle_proof(&leaves[2], &proof, &h(b"other root")));
    }

    #[test]
    fn single_leaf_proof_is_empty_and_still_binds() {
        let leaf = h(b"only");
        let proof = merkle_proof(&[leaf], 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_merkle_proof(&leaf, &proof, &merkle_root(&[leaf])));
        // Domain separation means a bare leaf hash is never a valid root.
        assert!(!verify_merkle_proof(&leaf, &proof, &leaf));
    }
}
