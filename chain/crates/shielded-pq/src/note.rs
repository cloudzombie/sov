//! Notes, spending keys, commitments, and nullifiers for the PQ pool
//! prototype.
//!
//! A note is `{value_grains, owner_tag, rho}`:
//! - `value_grains` — the amount, a `u64` (well below the field modulus for
//!   any reachable SOV amount; enforced at construction).
//! - `owner_tag` — a hash binding the note to its owner's nullifier secret:
//!   `owner_tag = merge(nsk, 0)`. Only the holder of `nsk` can derive the
//!   nullifier the spend circuit requires, so knowledge of a note's opening
//!   alone (e.g. by its sender) does NOT confer the ability to spend it.
//! - `rho` — per-note randomness; makes the commitment hiding and the
//!   nullifier unique.
//!
//! Commitment (all `merge` = Rescue-Prime 2-to-1, see [`crate::hash`]):
//!
//! ```text
//! cm = merge( merge([value,0,0,0], owner_tag), rho )
//! nf = merge( nsk, rho )
//! ```
//!
//! Both equations are exactly what the STARK spend circuit proves (see
//! [`crate::air`]).

use crate::hash::{digest_from_bytes, merge, PqDigest};

/// Maximum value a note may carry. SOV's total supply in grains is far below
/// this; the bound also keeps sums of any realistic number of notes away from
/// the field modulus. NOTE (prototype honesty): the *circuit* does not range
/// check the value — the value is a public input in this increment, so the
/// verifier sees it directly. See the design doc.
pub const MAX_NOTE_VALUE: u64 = 1 << 62;

/// A wallet's PQ spending secret: the nullifier-deriving key `nsk`.
///
/// Derived deterministically from a 32-byte seed. The public `owner_tag`
/// (which appears inside note commitments) is `merge(nsk, 0)` — a one-way
/// commitment to `nsk`.
#[derive(Clone)]
pub struct SpendingKey {
    nsk: PqDigest,
}

impl SpendingKey {
    /// Derive the spending key from a 32-byte seed (domain-separated blake3).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SpendingKey {
            nsk: digest_from_bytes("sov-shielded-pq:nsk:v1", seed),
        }
    }

    /// The nullifier secret. Exposed for proving; treat as secret material.
    pub fn nsk(&self) -> PqDigest {
        self.nsk
    }

    /// The public owner tag committed inside notes owned by this key:
    /// `merge(nsk, 0)`.
    pub fn owner_tag(&self) -> PqDigest {
        merge(self.nsk, PqDigest::ZERO)
    }

    /// Derive the nullifier for a note with randomness `rho`:
    /// `nf = merge(nsk, rho)`.
    pub fn nullifier(&self, rho: PqDigest) -> PqDigest {
        merge(self.nsk, rho)
    }
}

/// A shielded note (plaintext form).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    /// Amount in grains.
    pub value_grains: u64,
    /// `merge(owner_nsk, 0)` — see [`SpendingKey::owner_tag`].
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

    /// The note commitment: `merge(merge([value,0,0,0], owner_tag), rho)`.
    pub fn commitment(&self) -> PqDigest {
        let value_pad = PqDigest([self.value_grains, 0, 0, 0]);
        merge(merge(value_pad, self.owner_tag), self.rho)
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
    digest_from_bytes("sov-shielded-pq:rho:v1", &buf)
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
    }
}
