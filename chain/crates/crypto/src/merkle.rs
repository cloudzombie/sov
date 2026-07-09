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
}
