//! Difficulty targets.
//!
//! A [`Target`] is a 256-bit threshold a proof-of-work hash must not exceed.
//! "Meets the target" is the universal Bitcoin-style rule: read the 32-byte hash
//! big-endian and require it `<=` the target. A smaller target demands more
//! leading zero bits, i.e. more work. The same `Target` governs both supported
//! algorithms, so difficulty is comparable across them.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::Hash;

/// A 256-bit proof-of-work difficulty target.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Target(Hash);

impl Target {
    /// The easiest possible target: every hash satisfies it.
    pub const EASIEST: Target = Target(Hash::from_bytes([0xff; 32]));

    /// Build a target from a raw big-endian threshold.
    pub const fn from_hash(hash: Hash) -> Self {
        Target(hash)
    }

    /// A target requiring at least `bits` leading zero bits. `0` accepts
    /// anything; `256` is unsatisfiable. Each extra zero bit doubles expected work.
    pub fn from_leading_zero_bits(bits: u32) -> Self {
        if bits == 0 {
            return Target::EASIEST;
        }
        if bits >= 256 {
            return Target(Hash::ZERO);
        }
        let mut bytes = [0xffu8; 32];
        let full_zero_bytes = (bits / 8) as usize;
        for b in bytes.iter_mut().take(full_zero_bytes) {
            *b = 0;
        }
        let remainder = bits % 8;
        if remainder != 0 {
            bytes[full_zero_bytes] = 0xffu8 >> remainder;
        }
        Target(Hash::from_bytes(bytes))
    }

    /// Whether `hash` satisfies this target.
    pub fn is_met_by(&self, hash: &Hash) -> bool {
        hash <= &self.0
    }

    /// The target as its raw 256-bit threshold hash.
    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }

    /// Encode this target in **Bitcoin's compact "nBits" form**: a 32-bit
    /// floating-point-like packing of the 256-bit threshold carried in every
    /// block header. The top byte is the *size* (the number of bytes needed to
    /// represent the value); the low three bytes are the *mantissa* (the value's
    /// most-significant three bytes). This is Bitcoin's `GetCompact`, including
    /// its rule that a mantissa whose high bit (`0x00800000`) is set is shifted
    /// down and the size bumped, so the encoding is unambiguous and never
    /// "negative". The result round-trips exactly with [`from_compact`](Self::from_compact)
    /// for any canonically encoded target.
    pub fn to_compact(&self) -> u32 {
        let bytes = self.0.as_bytes();
        // Index of the most-significant non-zero byte (big-endian).
        let first = match bytes.iter().position(|&b| b != 0) {
            Some(i) => i,
            None => return 0, // target zero encodes to 0
        };
        // Significant size in bytes: a value whose top byte sits at index
        // `first` needs `32 - first` bytes.
        let mut size = (32 - first) as u32;
        // Mantissa = the value's top three bytes, big-endian. Missing low bytes
        // (when size < 3) read as zero, matching `value << (8*(3-size))`.
        let b = |k: usize| -> u32 { bytes.get(first + k).copied().unwrap_or(0) as u32 };
        let mut mantissa = (b(0) << 16) | (b(1) << 8) | b(2);
        // Bitcoin keeps the mantissa "positive": if its high bit is set, shift it
        // right one byte and grow the size, so 0x00800000..=0x00ffffff never
        // appear ambiguously.
        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            size += 1;
        }
        (size << 24) | mantissa
    }

    /// Decode **Bitcoin's compact "nBits" form** back to a 256-bit target, or
    /// `None` if the encoding is not a valid positive target that fits in 256
    /// bits. This is Bitcoin's `SetCompact` with its overflow/negative guards:
    ///
    /// - the sign bit (`0x00800000`) must be clear (targets are unsigned), and
    /// - the decoded value must fit in 32 bytes (no overflow).
    ///
    /// Consensus uses this on the value a header *claims*; an out-of-range or
    /// negative `bits` is rejected outright rather than silently clamped.
    pub fn from_compact(bits: u32) -> Option<Target> {
        let size = (bits >> 24) as usize;
        let mantissa = bits & 0x007f_ffff;
        // Negative is meaningless for a difficulty target.
        if bits & 0x0080_0000 != 0 {
            return None;
        }
        if mantissa == 0 {
            return Some(Target(Hash::ZERO));
        }
        // Overflow guard (Bitcoin's exact test): a non-zero mantissa byte must
        // not be pushed past the top of the 256-bit word.
        if size > 34 || (mantissa > 0xff && size > 33) || (mantissa > 0xffff && size > 32) {
            return None;
        }
        let mut out = [0u8; 32];
        if size <= 3 {
            // value = mantissa >> (8 * (3 - size)); lives in the low bytes.
            let val = mantissa >> (8 * (3 - size));
            out[29] = (val >> 16) as u8;
            out[30] = (val >> 8) as u8;
            out[31] = val as u8;
        } else {
            // value = mantissa << (8 * (size - 3)). The mantissa's three bytes
            // (most- to least-significant) land at big-endian indices
            // 32-size, 33-size, 34-size; the overflow guard above ensures any
            // byte with an out-of-range (negative) index is zero, so we skip it.
            for (k, byte) in [
                (mantissa >> 16) as u8,
                (mantissa >> 8) as u8,
                mantissa as u8,
            ]
            .into_iter()
            .enumerate()
            {
                // index = (32 - size) + k, guarded against underflow.
                if let Some(idx) = (32 + k).checked_sub(size) {
                    if idx < 32 {
                        out[idx] = byte;
                    }
                }
            }
        }
        Some(Target(Hash::from_bytes(out)))
    }
}

/// The Blake3 PoW hash of a preimage at a nonce: `Blake3(preimage || nonce)`.
/// Used by the lightweight generic miner ([`mine`]) for difficulty demonstrations
/// and tests; the on-chain algorithms live in [`crate::algorithm`].
pub fn pow_hash(preimage: &[u8], nonce: u64) -> Hash {
    let mut buf = Vec::with_capacity(preimage.len() + 8);
    buf.extend_from_slice(preimage);
    buf.extend_from_slice(&nonce.to_le_bytes());
    Hash::digest(&buf)
}

/// Verify a Blake3 PoW: that `nonce` over `preimage` meets `target`.
#[must_use]
pub fn verify(preimage: &[u8], nonce: u64, target: &Target) -> bool {
    target.is_met_by(&pow_hash(preimage, nonce))
}

/// Search `0..max_iterations` for a Blake3 nonce meeting `target`.
pub fn mine(preimage: &[u8], target: &Target, max_iterations: u64) -> Option<(u64, Hash)> {
    (0..max_iterations).find_map(|nonce| {
        let hash = pow_hash(preimage, nonce);
        target.is_met_by(&hash).then_some((nonce, hash))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easiest_accepts_anything() {
        assert!(Target::EASIEST.is_met_by(&Hash::digest(b"x")));
    }

    #[test]
    fn leading_zero_bits_shape() {
        let t = Target::from_leading_zero_bits(8);
        let mut ok = [0u8; 32];
        ok[1] = 0xff;
        assert!(t.is_met_by(&Hash::from_bytes(ok)));
        let mut bad = [0u8; 32];
        bad[0] = 0x01;
        assert!(!t.is_met_by(&Hash::from_bytes(bad)));
    }

    #[test]
    fn mine_then_verify() {
        let target = Target::from_leading_zero_bits(12);
        let (nonce, hash) = mine(b"sov", &target, 1_000_000).expect("found");
        assert!(target.is_met_by(&hash));
        assert!(verify(b"sov", nonce, &target));
    }

    #[test]
    fn unsatisfiable_within_budget() {
        assert_eq!(mine(b"h", &Target::from_leading_zero_bits(64), 10), None);
    }

    #[test]
    fn compact_matches_bitcoin_max_target() {
        // Bitcoin's `powLimit` compact encoding is 0x1d00ffff and decodes to the
        // target 0x00000000FFFF0000…0000 — the canonical genesis difficulty.
        let t = Target::from_compact(0x1d00_ffff).expect("valid");
        let mut expected = [0u8; 32];
        expected[4] = 0xff;
        expected[5] = 0xff;
        assert_eq!(t.as_hash().as_bytes(), &expected);
        // And it re-encodes to exactly the same compact value (round-trip).
        assert_eq!(t.to_compact(), 0x1d00_ffff);
    }

    #[test]
    fn compact_matches_historical_bitcoin_bits() {
        // A real historical Bitcoin header value: 0x1b0404cb.
        let t = Target::from_compact(0x1b04_04cb).expect("valid");
        let mut expected = [0u8; 32];
        expected[5] = 0x04;
        expected[6] = 0x04;
        expected[7] = 0xcb;
        assert_eq!(t.as_hash().as_bytes(), &expected);
        assert_eq!(t.to_compact(), 0x1b04_04cb);
    }

    #[test]
    fn compact_handles_high_bit_mantissa_shift() {
        // A target whose top three bytes are 0x00ffff has its high bit set after
        // packing, so Bitcoin shifts the mantissa down and grows the size: the
        // all-0xff (easiest) target encodes as 0x2100ffff, not 0x20ffffff.
        assert_eq!(Target::EASIEST.to_compact(), 0x2100_ffff);
        // Decoding it is lossy (only 3 mantissa bytes survive), exactly as in
        // Bitcoin — the compact form keeps the top 0xffff and zeroes the rest.
        let back = Target::from_compact(0x2100_ffff).expect("valid");
        let mut expected = [0u8; 32];
        expected[0] = 0xff;
        expected[1] = 0xff;
        assert_eq!(back.as_hash().as_bytes(), &expected);
    }

    #[test]
    fn compact_round_trips_for_canonical_values() {
        // compact -> target -> compact is exact for any canonically encoded bits.
        for bits in [
            0x0312_3456u32,
            0x0512_3456,
            0x1b04_04cb,
            0x1d00_ffff,
            0x1f00_ffff,
            0x2100_ffff,
        ] {
            let t = Target::from_compact(bits).expect("valid");
            assert_eq!(t.to_compact(), bits, "round-trip failed for {bits:#010x}");
        }
    }

    #[test]
    fn compact_rejects_negative_and_overflow() {
        // Sign bit set -> negative -> rejected.
        assert_eq!(Target::from_compact(0x0180_0000), None);
        // Mantissa pushed past 256 bits -> overflow -> rejected.
        assert_eq!(Target::from_compact(0x2300_ffff), None); // size 35
        assert_eq!(Target::from_compact(0x2200_0100), None); // size 34, m1 nonzero
                                                             // Zero target encodes/decodes as 0.
        assert_eq!(Target::from_hash(Hash::ZERO).to_compact(), 0);
        assert_eq!(Target::from_compact(0), Some(Target::from_hash(Hash::ZERO)));
    }

    #[test]
    fn compact_small_size_low_bytes() {
        // size <= 3 places the value directly in the low bytes.
        let t = Target::from_compact(0x0312_3456).expect("valid"); // size 3
        let mut expected = [0u8; 32];
        expected[29] = 0x12;
        expected[30] = 0x34;
        expected[31] = 0x56;
        assert_eq!(t.as_hash().as_bytes(), &expected);
        assert_eq!(t.to_compact(), 0x0312_3456);
    }
}
