//! STARK-friendly hashing for the PQ shielded pool prototype.
//!
//! Everything in this module is built on **Rescue-Prime** (`Rp64_256` from
//! `winter-crypto`) over the 64-bit "Goldilocks" field `p = 2^64 - 2^32 + 1` —
//! the hash the winterfell proof system proves natively. There are **no
//! elliptic curves anywhere in this crate**: hiding and binding of commitments
//! rest on hash assumptions only, which survive a cryptographically relevant
//! quantum computer (Grover halves margins; no structural break).
//!
//! The digest type [`PqDigest`] is 4 field elements (32 bytes). All composite
//! structures (note commitments, nullifiers, Merkle nodes) are built from the
//! single 2-to-1 compression [`merge_domain`], which is byte-identical to
//! `Rp64_256::merge` (pinned by a test).

use winter_crypto::hashers::Rp64_256;
use winter_math::{fields::f64::BaseElement, FieldElement, StarkField};

/// The base field element of the proof system (Goldilocks, `p = 2^64 - 2^32 + 1`).
pub type Felt = BaseElement;

/// Number of field elements in a digest.
pub const DIGEST_ELEMENTS: usize = 4;

/// Rescue-Prime sponge state width (12 elements: 4 capacity + 8 rate).
pub const STATE_WIDTH: usize = Rp64_256::STATE_WIDTH;

/// Number of Rescue-Prime rounds per permutation.
pub const NUM_ROUNDS: usize = Rp64_256::NUM_ROUNDS;

/// A 32-byte digest: 4 canonical Goldilocks field elements, little-endian.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash, PartialOrd, Ord)]
pub struct PqDigest(pub [u64; DIGEST_ELEMENTS]);

impl PqDigest {
    /// The all-zero digest.
    pub const ZERO: PqDigest = PqDigest([0; DIGEST_ELEMENTS]);

    /// The digest as field elements.
    pub fn to_elements(self) -> [Felt; DIGEST_ELEMENTS] {
        self.0.map(Felt::new)
    }

    /// Build a digest from field elements (stored canonically).
    pub fn from_elements(e: [Felt; DIGEST_ELEMENTS]) -> Self {
        PqDigest(e.map(|x| x.as_int()))
    }

    /// Canonical 32-byte encoding: each element `< p`, little-endian.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// Parse a canonical 32-byte encoding. `None` if any limb is `>= p`
    /// (non-canonical encodings are rejected, so the byte form is injective).
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; DIGEST_ELEMENTS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let v = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
            if v >= Felt::MODULUS {
                return None;
            }
            *limb = v;
        }
        Some(PqDigest(limbs))
    }

    /// Lowercase hex of the canonical 32-byte encoding.
    pub fn to_hex(self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// The DOMAIN-SEPARATED 2-to-1 Rescue-Prime compression.
///
/// Sponge convention (matches `winter-crypto` except for the domain slot):
/// capacity = `[8, domain, 0, 0]` (first capacity element is the rate width,
/// second carries the domain constant from [`crate::domains`]), rate =
/// `left || right`, one permutation, digest = state elements 4..8.
///
/// `merge_domain(0, l, r)` is byte-identical to `Rp64_256::merge` (pinned by
/// a test below); domain 0 is reserved and never used by the protocol.
/// Distinct domains initialize the sponge capacity differently, so outputs
/// under different domains are computationally independent (a cross-domain
/// collision would be a collision of the Rescue permutation itself).
pub fn merge_domain(domain: u64, left: PqDigest, right: PqDigest) -> PqDigest {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[0] = Felt::new(8); // RATE_WIDTH, per Rp64_256::merge
    state[1] = Felt::new(domain);
    state[4..8].copy_from_slice(&left.to_elements());
    state[8..12].copy_from_slice(&right.to_elements());
    Rp64_256::apply_permutation(&mut state);
    PqDigest::from_elements(state[4..8].try_into().expect("4 elements"))
}

/// Map arbitrary bytes to a digest via blake3 + per-limb reduction mod `p`.
///
/// Used only to derive *tags and secrets* (owner tags from KEM public keys,
/// `nsk`/`rho` from seeds) — never as the in-circuit hash. The mod-`p`
/// reduction has bias `< 2^-32` per limb, which is irrelevant for tags and
/// documented here for honesty.
pub fn digest_from_bytes(domain: &str, bytes: &[u8]) -> PqDigest {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    let wide = hasher.finalize();
    let raw = wide.as_bytes();
    let mut limbs = [0u64; DIGEST_ELEMENTS];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let v = u64::from_le_bytes(raw[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
        *limb = v % Felt::MODULUS;
    }
    PqDigest(limbs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_crypto::{Digest as _, Hasher as _};

    #[test]
    fn merge_domain_zero_matches_rp64_256() {
        // Pin our sponge convention byte-for-byte to the upstream hasher at
        // the reserved domain 0: if either drifts, the circuit and the
        // native hash disagree and this screams.
        let a = digest_from_bytes(crate::domains::B3_TEST, b"left");
        let b = digest_from_bytes(crate::domains::B3_TEST, b"right");
        type UpstreamDigest = <Rp64_256 as winter_crypto::Hasher>::Digest;
        let ua = UpstreamDigest::new(a.to_elements());
        let ub = UpstreamDigest::new(b.to_elements());
        let upstream = Rp64_256::merge(&[ua, ub]);
        assert_eq!(merge_domain(0, a, b).to_bytes(), upstream.as_bytes());
    }

    #[test]
    fn digest_bytes_roundtrip_and_canonical() {
        let d = digest_from_bytes(crate::domains::B3_TEST, b"roundtrip");
        assert_eq!(PqDigest::from_bytes(&d.to_bytes()), Some(d));
        // A limb >= p must be rejected.
        let mut bad = [0u8; 32];
        bad[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(PqDigest::from_bytes(&bad), None);
    }
}
