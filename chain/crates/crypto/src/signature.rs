//! Versioned detached signatures.
//!
//! Like [`crate::PublicKey`], a [`Signature`] is a versioned enum whose Borsh
//! discriminant is the on-chain scheme byte (`0x00` = Ed25519). A signature
//! only ever verifies under a key of the *same* scheme
//! ([`crate::PublicKey::verify`] rejects scheme mismatches), and the scheme
//! byte of the transaction's public key is itself inside the signed payload —
//! so schemes cannot be confused or downgraded.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Length of an ML-DSA-65 signature (FIPS 204).
pub const ML_DSA_65_SIG_LEN: usize = fips204::ml_dsa_65::SIG_LEN; // 3309

/// A versioned detached signature. The Borsh discriminant is the scheme byte:
/// `0x00` = Ed25519 (64 bytes), `0x01` = hybrid Ed25519 + ML-DSA-65
/// (64 + 3309 bytes; valid only if **both** components verify).
///
/// Serialized scheme-tagged over Borsh and as a hex string over JSON (bare
/// hex always means Ed25519; hybrid signatures carry a `hybrid65:` prefix).
// The hybrid (`V2`) variant is intentionally large (the ~3309-byte ML-DSA-65
// signature) and is the PQ-native common case; boxing adds indirection for no gain.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Signature {
    /// Scheme `0x00`: a 64-byte Ed25519 signature.
    V1Ed25519([u8; 64]),
    /// Scheme `0x01`: a hybrid signature — both component signatures over the
    /// same message; verification is their conjunction.
    V2HybridMlDsa65 {
        /// The Ed25519 component.
        ed25519: [u8; 64],
        /// The ML-DSA-65 component (3309 bytes).
        ml_dsa: [u8; ML_DSA_65_SIG_LEN],
    },
}

impl Signature {
    /// Length of an Ed25519 signature's raw bytes (excluding the scheme byte).
    pub const LEN: usize = 64;

    /// Construct an Ed25519 (`V1`) signature from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Signature::V1Ed25519(bytes)
    }

    /// Borrow the signature's **Ed25519 component** bytes (every scheme
    /// includes one; for `V1` this is the whole signature).
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        match self {
            Signature::V1Ed25519(bytes) => bytes,
            Signature::V2HybridMlDsa65 { ed25519, .. } => ed25519,
        }
    }

    /// The scheme's human-readable name.
    pub const fn scheme(&self) -> &'static str {
        match self {
            Signature::V1Ed25519(_) => "ed25519",
            Signature::V2HybridMlDsa65 { .. } => "hybrid65",
        }
    }

    /// Lowercase hex of the scheme's full raw signature bytes (V1: 64 bytes;
    /// V2: the 64-byte Ed25519 then the 3309-byte ML-DSA component).
    pub fn to_hex(&self) -> String {
        match self {
            Signature::V1Ed25519(bytes) => hex::encode(bytes),
            Signature::V2HybridMlDsa65 { ed25519, ml_dsa } => {
                let mut s = hex::encode(ed25519);
                s.push_str(&hex::encode(ml_dsa.as_slice()));
                s
            }
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}:{self})", self.scheme())
    }
}

// serde is the JSON/RPC encoding only (hex string); the canonical binary
// encoding for consensus is Borsh, handled by the derives above.
impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Signature::V1Ed25519(_) => s.serialize_str(&self.to_string()),
            Signature::V2HybridMlDsa65 { .. } => {
                s.serialize_str(&format!("hybrid65:0x{}", self.to_hex()))
            }
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        if let Some(rest) = s.strip_prefix("hybrid65:") {
            let rest = rest.strip_prefix("0x").unwrap_or(rest);
            let bytes = hex::decode(rest).map_err(de::Error::custom)?;
            if bytes.len() != 64 + ML_DSA_65_SIG_LEN {
                return Err(de::Error::custom("hybrid65 signature must be 3373 bytes"));
            }
            let mut ed25519 = [0u8; 64];
            ed25519.copy_from_slice(&bytes[..64]);
            let mut ml_dsa = [0u8; ML_DSA_65_SIG_LEN];
            ml_dsa.copy_from_slice(&bytes[64..]);
            return Ok(Signature::V2HybridMlDsa65 { ed25519, ml_dsa });
        }
        let s = s.strip_prefix("ed25519:").unwrap_or(&s);
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(de::Error::custom)?;
        let arr: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("signature must be 64 bytes"))?;
        Ok(Signature::V1Ed25519(arr))
    }
}
