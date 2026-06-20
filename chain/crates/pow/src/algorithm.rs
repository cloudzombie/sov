//! The proof-of-work hash: **SHA-256d** (Bitcoin's double-SHA-256).
//!
//! SOV's consensus seal is Bitcoin's, verbatim: a block is validly mined iff the
//! double-SHA-256 of its header is at or below the difficulty target
//! ([`Target`](crate::target::Target)). The header grind and the meets-target
//! check live in `sov-chain`; this module provides only the hash primitive.
//!
//! The hash is not implemented by hand — it uses the `sha2` crate.

use sha2::{Digest, Sha256};

/// One SHA-256 round.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256, as used by Bitcoin — SOV's proof-of-work seal.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_is_double_sha256() {
        // Known relation: double hashing, not single.
        assert_ne!(sha256(b"abc"), sha256d(b"abc"));
        assert_eq!(sha256d(b"abc"), sha256(&sha256(b"abc")));
    }
}
