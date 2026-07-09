//! Cryptographic hashing for the SOV protocol.
//!
//! Every block, transaction, and state root is identified by a [`Hash`](struct@Hash): a
//! 32-byte Blake3 digest. Blake3 is chosen for its speed, parallelism, and
//! 256-bit security — appropriate for a high-throughput, sharded chain.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte Blake3 cryptographic hash.
///
/// This is the canonical identifier used throughout the protocol. It is
/// serialized as raw bytes over Borsh (the consensus-critical encoding) and as
/// a `0x`-prefixed hex string over JSON (the human/RPC-facing encoding).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct Hash([u8; Self::LEN]);

impl Hash {
    /// Length of a hash in bytes.
    pub const LEN: usize = 32;

    /// The all-zero hash. Used as the parent of the genesis block, never as a
    /// real digest (the probability of Blake3 producing it is negligible).
    pub const ZERO: Hash = Hash([0u8; Self::LEN]);

    /// Compute the Blake3 digest of `bytes`.
    pub fn digest(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }

    /// Construct a hash from raw bytes (e.g. a precomputed digest).
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Hash(bytes)
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Lowercase hex encoding, without a `0x` prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex, with or without a leading `0x`.
    pub fn from_hex(s: &str) -> Result<Self, HashParseError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| HashParseError::InvalidHex)?;
        let arr: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| HashParseError::WrongLength { got: v.len() })?;
        Ok(Hash(arr))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Human-readable formats (JSON for RPC) get hex; binary formats get raw bytes.
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = <String as Deserialize>::deserialize(d)?;
            Hash::from_hex(&s).map_err(de::Error::custom)
        } else {
            let bytes = <[u8; Self::LEN] as Deserialize>::deserialize(d)?;
            Ok(Hash(bytes))
        }
    }
}

/// Error returned when parsing a [`Hash`](struct@Hash) from a hex string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashParseError {
    /// The string was not valid hexadecimal.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// The decoded byte length was not exactly [`Hash::LEN`].
    #[error("expected {expected} bytes, got {got}", expected = Hash::LEN)]
    WrongLength {
        /// The number of bytes actually decoded.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(Hash::digest(b"sov"), Hash::digest(b"sov"));
        assert_ne!(Hash::digest(b"sov"), Hash::digest(b"sob"));
    }

    #[test]
    fn hex_roundtrip() {
        let h = Hash::digest(b"genesis");
        let s = h.to_string();
        assert!(s.starts_with("0x"));
        assert_eq!(Hash::from_hex(&s).unwrap(), h);
        // Without the prefix too.
        assert_eq!(Hash::from_hex(&h.to_hex()).unwrap(), h);
    }

    #[test]
    fn rejects_bad_hex() {
        assert_eq!(
            Hash::from_hex("0xzz").unwrap_err(),
            HashParseError::InvalidHex
        );
        assert!(matches!(
            Hash::from_hex("0xab").unwrap_err(),
            HashParseError::WrongLength { got: 1 }
        ));
    }

    #[test]
    fn borsh_roundtrip() {
        let h = Hash::digest(b"block");
        let bytes = borsh::to_vec(&h).unwrap();
        assert_eq!(bytes.len(), Hash::LEN); // raw, no length prefix
        assert_eq!(borsh::from_slice::<Hash>(&bytes).unwrap(), h);
    }

    #[test]
    fn json_is_hex_string() {
        let h = Hash::digest(b"tx");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{h}\""));
    }
}
