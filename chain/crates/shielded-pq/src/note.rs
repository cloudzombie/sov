//! Notes, spending keys, commitments, and nullifiers for the PQ pool.
//!
//! A note is `{value_grains, owner_tag, rho}`:
//! - `value_grains` — the amount, a `u64` bounded by [`MAX_NOTE_VALUE`]
//!   (see the no-wrap argument below).
//! - `owner_tag` — a hash binding the note to its owner's nullifier secret:
//!   `owner_tag = merge_d(TAG, nsk, 0)`. Only the holder of `nsk` can derive
//!   the nullifier the spend circuit requires, so knowledge of a note's
//!   opening alone (e.g. by its sender) does NOT confer the ability to
//!   spend it.
//! - `rho` — per-note randomness; makes the commitment hiding and the
//!   nullifier unique.
//!
//! Every hash below is a domain-separated Rescue-Prime merge (see
//! [`crate::domains`] and [`crate::hash::merge_domain`]):
//!
//! ```text
//! cm = merge_d(C2, merge_d(C1, [value,0,0,0], owner_tag), rho)
//! nf = merge_d(NF, nsk, rho)
//! ```
//!
//! Both equations are exactly what the STARK bundle circuit proves (see
//! [`crate::air`]).
//!
//! # Why the value bound is 61 bits (field-arithmetic soundness, D3)
//!
//! Values live in-circuit as witnesses over the Goldilocks field
//! `p = 2^64 - 2^32 + 1 ≈ 1.845 × 10^19`. The in-circuit conservation check
//!
//! ```text
//! v_in_0 + .. + v_in_3 + t_in  =  v_out_0 + .. + v_out_3 + t_out + fee   (mod p)
//! ```
//!
//! is only meaningful over the INTEGERS if neither side can wrap `p`. Sums
//! of four full-width u64s can reach ~2^66 > p, so a "64-bit" range check
//! is NOT sound here (D3's `< 2^66 in field elements` premise does not hold
//! in Goldilocks). Instead every private value is range-checked in-circuit
//! to **61 bits** (`v < 2^61`), and the public legs `t_in`, `t_out`,
//! `fee` are bounded to [`MAX_NOTE_VALUE`] `< 2^61` natively by the
//! verifier before the proof is checked. Then:
//!
//! - LHS `< 4·2^61 + 2^61 = 5·2^61 ≈ 1.153 × 10^19 < p`
//! - RHS `< 4·2^61 + 2·2^61 = 6·2^61 ≈ 1.384 × 10^19 < p`
//!
//! Both sides are integers below `p`, so equality mod `p` implies exact
//! integer equality: **no wrap is reachable**. The bound costs nothing
//! real: SOV's entire supply is ~2.1 × 10^15 grains ≈ 2^51, a factor of
//! ~2^10 below `MAX_NOTE_VALUE`.

use crate::domains::{
    B3_NSK, B3_RHO, RESCUE_DOMAIN_COMMIT_STAGE1, RESCUE_DOMAIN_COMMIT_STAGE2,
    RESCUE_DOMAIN_NULLIFIER, RESCUE_DOMAIN_OWNER_TAG,
};
use crate::hash::{digest_from_bytes, merge_domain, PqDigest};

/// Number of range-checked bits per value: every in-circuit value is proven
/// `< 2^61`. See the module docs for why 61 (not 64) is the sound width.
pub const VALUE_BITS: usize = 61;

/// Maximum value a note (or the public `t_in`/`t_out`/`fee` legs) may
/// carry: `2^61 - 1`. Enforced at construction natively and by the 61-bit
/// in-circuit range check. See the module docs for the no-wrap argument.
pub const MAX_NOTE_VALUE: u64 = (1u64 << VALUE_BITS) - 1;

/// A wallet's PQ spending secret: the nullifier-deriving key `nsk`.
///
/// Derived deterministically from a 32-byte seed. The public `owner_tag`
/// (which appears inside note commitments) is `merge_d(TAG, nsk, 0)` — a
/// one-way commitment to `nsk`.
#[derive(Clone)]
pub struct SpendingKey {
    nsk: PqDigest,
}

impl SpendingKey {
    /// Derive the spending key from a 32-byte seed (domain-separated blake3).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SpendingKey {
            nsk: digest_from_bytes(B3_NSK, seed),
        }
    }

    /// The nullifier secret. Exposed for proving; treat as secret material.
    pub fn nsk(&self) -> PqDigest {
        self.nsk
    }

    /// The public owner tag committed inside notes owned by this key:
    /// `merge_d(TAG, nsk, 0)`.
    pub fn owner_tag(&self) -> PqDigest {
        merge_domain(RESCUE_DOMAIN_OWNER_TAG, self.nsk, PqDigest::ZERO)
    }

    /// Derive the nullifier for a note with randomness `rho`:
    /// `nf = merge_d(NF, nsk, rho)`.
    pub fn nullifier(&self, rho: PqDigest) -> PqDigest {
        merge_domain(RESCUE_DOMAIN_NULLIFIER, self.nsk, rho)
    }
}

/// A shielded note (plaintext form).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    /// Amount in grains.
    pub value_grains: u64,
    /// `merge_d(TAG, owner_nsk, 0)` — see [`SpendingKey::owner_tag`].
    pub owner_tag: PqDigest,
    /// Per-note randomness.
    pub rho: PqDigest,
}

impl Note {
    /// Build a note; rejects values above [`MAX_NOTE_VALUE`].
    pub fn new(value_grains: u64, owner_tag: PqDigest, rho: PqDigest) -> Option<Note> {
        if value_grains > MAX_NOTE_VALUE {
            return None;
        }
        Some(Note {
            value_grains,
            owner_tag,
            rho,
        })
    }

    /// The note commitment:
    /// `merge_d(C2, merge_d(C1, [value,0,0,0], owner_tag), rho)`.
    pub fn commitment(&self) -> PqDigest {
        let value_pad = PqDigest([self.value_grains, 0, 0, 0]);
        let stage1 = merge_domain(RESCUE_DOMAIN_COMMIT_STAGE1, value_pad, self.owner_tag);
        merge_domain(RESCUE_DOMAIN_COMMIT_STAGE2, stage1, self.rho)
    }

    /// Serialize the note plaintext (for encryption): value LE ‖ tag ‖ rho.
    pub fn to_plaintext(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..8].copy_from_slice(&self.value_grains.to_le_bytes());
        out[8..40].copy_from_slice(&self.owner_tag.to_bytes());
        out[40..72].copy_from_slice(&self.rho.to_bytes());
        out
    }

    /// Parse a note plaintext. `None` on non-canonical digests or a value
    /// above [`MAX_NOTE_VALUE`].
    pub fn from_plaintext(bytes: &[u8; 72]) -> Option<Note> {
        let value = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
        let owner_tag = PqDigest::from_bytes(bytes[8..40].try_into().expect("32 bytes"))?;
        let rho = PqDigest::from_bytes(bytes[40..72].try_into().expect("32 bytes"))?;
        Note::new(value, owner_tag, rho)
    }
}

/// Derive deterministic per-note randomness from a seed and an index
/// (wallet-side convenience; any unpredictable `rho` works).
pub fn derive_rho(seed: &[u8; 32], index: u64) -> PqDigest {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_le_bytes());
    digest_from_bytes(B3_RHO, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_plaintext_roundtrip() {
        let sk = SpendingKey::from_seed(&[7u8; 32]);
        let note = Note::new(1234, sk.owner_tag(), derive_rho(&[7u8; 32], 0)).expect("note");
        let pt = note.to_plaintext();
        assert_eq!(Note::from_plaintext(&pt), Some(note));
    }

    #[test]
    fn oversized_value_rejected() {
        assert!(Note::new(MAX_NOTE_VALUE + 1, PqDigest::ZERO, PqDigest::ZERO).is_none());
        assert!(Note::new(MAX_NOTE_VALUE, PqDigest::ZERO, PqDigest::ZERO).is_some());
    }

    #[test]
    fn no_wrap_bound_argument_holds() {
        // The module-doc argument, checked numerically: both sides of the
        // conservation identity stay strictly below the Goldilocks modulus.
        let p: u128 = (1u128 << 64) - (1u128 << 32) + 1;
        let max = MAX_NOTE_VALUE as u128;
        let lhs_max = 4 * max + max; // 4 inputs + t_in
        let rhs_max = 4 * max + max + max; // 4 outputs + t_out + fee
        assert!(lhs_max < p, "LHS of conservation can wrap the field");
        assert!(rhs_max < p, "RHS of conservation can wrap the field");
    }
}
