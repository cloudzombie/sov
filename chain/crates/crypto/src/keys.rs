//! Versioned key material: public keys and signing keypairs.
//!
//! **Cryptographic agility (Phase 18).** [`PublicKey`] and
//! [`crate::Signature`] are *versioned enums*: every key and signature
//! carries its scheme as the leading Borsh discriminant byte. Because a
//! transaction's public key sits inside its canonical signing bytes, the
//! scheme is **committed under the signature itself** — a signature produced
//! for one scheme can never be replayed as another (no cross-scheme
//! malleability), and adding a post-quantum scheme later is a new variant,
//! not a re-architecture.
//!
//! Two schemes exist:
//!
//! - `V1Ed25519` (`0x00`) — small keys/signatures, fast verification,
//!   deterministic signing.
//! - `V2HybridMlDsa65` (`0x01`) — **hybrid post-quantum**: Ed25519 *and*
//!   ML-DSA-65 (FIPS 204, via the `fips204` crate). Verification requires
//!   **both** component signatures to verify, so a hybrid key is at least as
//!   strong as the stronger of the two schemes: forging it needs a break of
//!   Ed25519 *and* of ML-DSA-65 simultaneously. Honest caveat: pure-Rust
//!   FIPS 204 implementations do not yet have `ed25519-dalek`'s audit depth —
//!   which is exactly why the hybrid is a conjunction and the chain never
//!   trusts ML-DSA alone.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sov_primitives::{AccountId, Hash};

use crate::signature::Signature;

/// Length of an ML-DSA-65 public key (FIPS 204).
pub const ML_DSA_65_PK_LEN: usize = ml_dsa_65::PK_LEN; // 1952

pub use crate::signature::ML_DSA_65_SIG_LEN;

/// A versioned public key. The Borsh discriminant is the on-chain scheme
/// byte: `0x00` = Ed25519, `0x01` = hybrid Ed25519 + ML-DSA-65.
// The hybrid (`V2`) variant is intentionally large (the 1952-byte ML-DSA-65 key)
// and is the PQ-native *common* case, so the size gap to `V1` is by design;
// boxing would add indirection to the hot path for no real benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum PublicKey {
    /// Scheme `0x00`: a 32-byte Ed25519 verifying key.
    V1Ed25519([u8; 32]),
    /// Scheme `0x01`: hybrid post-quantum — an Ed25519 verifying key **and**
    /// an ML-DSA-65 (FIPS 204) verifying key. A signature under this key is
    /// valid only if both component signatures verify.
    V2HybridMlDsa65 {
        /// The Ed25519 component.
        ed25519: [u8; 32],
        /// The ML-DSA-65 component (1952 bytes).
        ml_dsa: [u8; ML_DSA_65_PK_LEN],
    },
}

impl PublicKey {
    /// Length of an Ed25519 public key's raw bytes (excluding the scheme byte).
    pub const LEN: usize = 32;

    /// Construct an Ed25519 (`V1`) key from raw bytes. Note this does not
    /// validate that the bytes are a canonical curve point; that check happens
    /// lazily in [`PublicKey::verify`].
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        PublicKey::V1Ed25519(bytes)
    }

    /// Borrow the key's **Ed25519 component** bytes (every scheme includes
    /// one; for `V1` this is the whole key).
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        match self {
            PublicKey::V1Ed25519(bytes) => bytes,
            PublicKey::V2HybridMlDsa65 { ed25519, .. } => ed25519,
        }
    }

    /// The scheme's human-readable name (also the `Display`/JSON prefix).
    pub const fn scheme(&self) -> &'static str {
        match self {
            PublicKey::V1Ed25519(_) => "ed25519",
            PublicKey::V2HybridMlDsa65 { .. } => "hybrid65",
        }
    }

    /// Lowercase hex of the scheme's full raw key bytes (V1: 32 bytes; V2:
    /// the 32-byte Ed25519 then the 1952-byte ML-DSA component), no prefix.
    pub fn to_hex(&self) -> String {
        match self {
            PublicKey::V1Ed25519(bytes) => hex::encode(bytes),
            PublicKey::V2HybridMlDsa65 { ed25519, ml_dsa } => {
                let mut s = hex::encode(ed25519);
                s.push_str(&hex::encode(ml_dsa));
                s
            }
        }
    }

    /// This key's **implicit account id**: the lowercase hex of BLAKE3 over the
    /// key's canonical Borsh encoding (the scheme byte **and** every component,
    /// so the binding covers the ML-DSA half of a hybrid key, not just
    /// Ed25519). The digest is 32 bytes → 64 hex chars, a valid
    /// [`AccountId`] that [`AccountId::is_implicit`] recognizes.
    ///
    /// The id is collision-resistant and bound to the exact key, so value sent
    /// to it (a coinbase, a transfer) is claimable **only** by this key:
    /// consensus lets an implicit account be key-bound solely to the key whose
    /// hash equals the id. This is what makes a miner's payout unsquattable —
    /// knowing the id reveals nothing that lets anyone else claim it.
    pub fn implicit_account_id(&self) -> AccountId {
        let bytes = borsh::to_vec(self).expect("PublicKey always Borsh-serializes");
        AccountId::new(Hash::digest(&bytes).to_hex())
            .expect("64-char lowercase hex is always a valid account id")
    }

    /// Verify a detached `signature` over `message`. Returns `false` for any
    /// failure — malformed key, malformed signature, a genuine mismatch, or a
    /// **scheme mismatch** (a signature of one scheme never verifies under a
    /// key of another). A hybrid (`V2`) signature verifies only if **both**
    /// the Ed25519 and the ML-DSA-65 components verify — the conjunction is
    /// what makes the hybrid at least as strong as its stronger component.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (self, signature) {
            (PublicKey::V1Ed25519(key), Signature::V1Ed25519(sig)) => {
                verify_ed25519(key, message, sig)
            }
            (
                PublicKey::V2HybridMlDsa65 { ed25519, ml_dsa },
                Signature::V2HybridMlDsa65 {
                    ed25519: ed_sig,
                    ml_dsa: ml_sig,
                },
            ) => {
                // BOTH components must verify; short-circuit on the cheap one.
                verify_ed25519(ed25519, message, ed_sig)
                    && ml_dsa_65::PublicKey::try_from_bytes(*ml_dsa)
                        .map(|vk| vk.verify(message, ml_sig, b""))
                        .unwrap_or(false)
            }
            // Scheme mismatch: never verifies.
            _ => false,
        }
    }
}

/// Strict Ed25519 verification (rejects non-canonical points/signatures).
fn verify_ed25519(key: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(message, &sig).is_ok()
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:0x{}", self.scheme(), self.to_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

// serde is the JSON/RPC encoding only; Borsh is the canonical binary encoding.
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            // V1 keeps the historical bare-hex interface encoding.
            PublicKey::V1Ed25519(_) => s.serialize_str(&format!("0x{}", self.to_hex())),
            // Hybrid keys are always scheme-prefixed.
            PublicKey::V2HybridMlDsa65 { .. } => {
                s.serialize_str(&format!("hybrid65:0x{}", self.to_hex()))
            }
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // JSON keeps the V1 interface encoding: plain (optionally
        // `ed25519:`-prefixed) 32-byte hex — bare hex always means Ed25519.
        // Hybrid keys carry the mandatory `hybrid65:` prefix over the
        // concatenated (32 + 1952)-byte component hex.
        let s = <String as Deserialize>::deserialize(d)?;
        if let Some(rest) = s.strip_prefix("hybrid65:") {
            let rest = rest.strip_prefix("0x").unwrap_or(rest);
            let bytes = hex::decode(rest).map_err(de::Error::custom)?;
            if bytes.len() != 32 + ML_DSA_65_PK_LEN {
                return Err(de::Error::custom("hybrid65 key must be 1984 bytes"));
            }
            let mut ed25519 = [0u8; 32];
            ed25519.copy_from_slice(&bytes[..32]);
            let mut ml_dsa = [0u8; ML_DSA_65_PK_LEN];
            ml_dsa.copy_from_slice(&bytes[32..]);
            return Ok(PublicKey::V2HybridMlDsa65 { ed25519, ml_dsa });
        }
        let s = s.strip_prefix("ed25519:").unwrap_or(&s);
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(de::Error::custom)?;
        let arr: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("public key must be 32 bytes"))?;
        Ok(PublicKey::V1Ed25519(arr))
    }
}

/// A signing keypair (Ed25519, or hybrid Ed25519 + ML-DSA-65). Holds secret
/// key material, so it is never serialized and is deliberately not `Clone`.
pub struct Keypair(KeypairInner);

// The hybrid (`V2`) variant intentionally dominates the size (ML-DSA-65 key
// material) and is the PQ-native common case; boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
enum KeypairInner {
    /// An Ed25519 (`V1`) keypair.
    V1(SigningKey),
    /// A hybrid (`V2`) keypair: both component signing keys plus the
    /// deterministic ML-DSA signing seed (FIPS 204 deterministic mode).
    V2 {
        ed25519: SigningKey,
        ml_dsa_sk: ml_dsa_65::PrivateKey,
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        ml_dsa_sign_seed: [u8; 32],
    },
}

/// Blake3 with a domain-separation tag, for component-key derivation.
fn derive_seed(domain: &str, seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(seed);
    *hasher.finalize().as_bytes()
}

impl Keypair {
    /// Generate a fresh Ed25519 keypair from operating-system entropy.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| KeyError::Entropy)?;
        let kp = Keypair(KeypairInner::V1(SigningKey::from_bytes(&seed)));
        seed.fill(0); // best-effort wipe of the seed copy
        Ok(kp)
    }

    /// Deterministically derive an Ed25519 keypair from a 32-byte seed. Useful
    /// for tests and for reproducible key derivation; the seed must be secret.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Keypair(KeypairInner::V1(SigningKey::from_bytes(&seed)))
    }

    /// Deterministically derive a **hybrid Ed25519 + ML-DSA-65** keypair from
    /// a 32-byte master seed. Each component key is derived under its own
    /// Blake3 domain tag, so the components are independent; the same seed
    /// always yields the same hybrid key (HD-wallet friendly).
    pub fn hybrid_from_seed(seed: [u8; 32]) -> Self {
        let ed_seed = derive_seed("sov:hybrid65:ed25519:v1", &seed);
        let xi = derive_seed("sov:hybrid65:ml-dsa-65:v1", &seed);
        let ml_dsa_sign_seed = derive_seed("sov:hybrid65:ml-dsa-sign:v1", &seed);
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&xi);
        Keypair(KeypairInner::V2 {
            ed25519: SigningKey::from_bytes(&ed_seed),
            ml_dsa_sk: sk,
            ml_dsa_pk: pk.into_bytes(),
            ml_dsa_sign_seed,
        })
    }

    /// Generate a fresh hybrid keypair from operating-system entropy.
    pub fn hybrid_generate() -> Result<Self, KeyError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| KeyError::Entropy)?;
        let kp = Self::hybrid_from_seed(seed);
        seed.fill(0);
        Ok(kp)
    }

    /// The public (verifying) key for this keypair.
    pub fn public_key(&self) -> PublicKey {
        match &self.0 {
            KeypairInner::V1(sk) => PublicKey::V1Ed25519(sk.verifying_key().to_bytes()),
            KeypairInner::V2 {
                ed25519, ml_dsa_pk, ..
            } => PublicKey::V2HybridMlDsa65 {
                ed25519: ed25519.verifying_key().to_bytes(),
                ml_dsa: *ml_dsa_pk,
            },
        }
    }

    /// Sign `message`, producing a detached signature of the keypair's scheme.
    /// Hybrid signing produces **both** component signatures (the ML-DSA half
    /// in FIPS 204 deterministic mode, seeded per keypair).
    pub fn sign(&self, message: &[u8]) -> Signature {
        match &self.0 {
            KeypairInner::V1(sk) => Signature::from_bytes(sk.sign(message).to_bytes()),
            KeypairInner::V2 {
                ed25519,
                ml_dsa_sk,
                ml_dsa_sign_seed,
                ..
            } => {
                let ml_sig = ml_dsa_sk
                    .try_sign_with_seed(ml_dsa_sign_seed, message, b"")
                    .expect("ML-DSA-65 signing fails only on a >255-byte ctx; ours is empty");
                Signature::V2HybridMlDsa65 {
                    ed25519: ed25519.sign(message).to_bytes(),
                    ml_dsa: ml_sig,
                }
            }
        }
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose secret bytes.
        write!(f, "Keypair(public={})", self.public_key())
    }
}

/// Error produced while generating key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The OS entropy source failed.
    #[error("failed to obtain entropy from the operating system")]
    Entropy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::from_seed([7u8; 32]);
        let pk = kp.public_key();
        let msg = b"transfer 5 SOV to ecb.reserve.sov";
        let sig = kp.sign(msg);
        assert!(pk.verify(msg, &sig));
    }

    #[test]
    fn rejects_tampered_message() {
        let kp = Keypair::from_seed([7u8; 32]);
        let pk = kp.public_key();
        let sig = kp.sign(b"send 5");
        assert!(!pk.verify(b"send 6", &sig));
    }

    #[test]
    fn rejects_wrong_key() {
        let signer = Keypair::from_seed([1u8; 32]);
        let other = Keypair::from_seed([2u8; 32]).public_key();
        let msg = b"vote yes";
        let sig = signer.sign(msg);
        assert!(!other.verify(msg, &sig));
    }

    #[test]
    fn deterministic_from_seed() {
        let a = Keypair::from_seed([9u8; 32]).public_key();
        let b = Keypair::from_seed([9u8; 32]).public_key();
        assert_eq!(a, b);
    }

    #[test]
    fn implicit_account_id_is_deterministic_key_bound_and_well_formed() {
        // Deterministic: the same key always yields the same id, and it is a
        // valid 64-hex implicit id.
        let k = Keypair::from_seed([9u8; 32]).public_key();
        let id = k.implicit_account_id();
        assert_eq!(
            id,
            Keypair::from_seed([9u8; 32])
                .public_key()
                .implicit_account_id()
        );
        assert!(
            id.is_implicit(),
            "derived id must be recognized as implicit"
        );

        // Distinct keys → distinct ids (no squatting another key's id).
        let other = Keypair::from_seed([10u8; 32]).public_key();
        assert_ne!(id, other.implicit_account_id());

        // The hybrid variant binds the ML-DSA half too: a hybrid key's id is
        // not the same as its Ed25519-only namesake, even from the same seed.
        let hybrid = Keypair::hybrid_from_seed([9u8; 32]).public_key();
        assert!(hybrid.implicit_account_id().is_implicit());
        assert_ne!(
            hybrid.implicit_account_id(),
            id,
            "hybrid id must cover the ML-DSA component, not just Ed25519"
        );
    }

    #[test]
    fn public_key_json_roundtrip() {
        let pk = Keypair::from_seed([3u8; 32]).public_key();
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), pk);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = Keypair::generate().unwrap().public_key();
        let b = Keypair::generate().unwrap().public_key();
        assert_ne!(a, b);
    }

    // ---- Hybrid Ed25519 + ML-DSA-65 (post-quantum) ----

    #[test]
    fn hybrid_sign_and_verify_roundtrip_and_determinism() {
        let kp = Keypair::hybrid_from_seed([11u8; 32]);
        let pk = kp.public_key();
        assert_eq!(pk.scheme(), "hybrid65");
        let msg = b"rotate the reserve to post-quantum keys";
        let sig = kp.sign(msg);
        assert_eq!(sig.scheme(), "hybrid65");
        assert!(pk.verify(msg, &sig));
        assert!(!pk.verify(b"a different message", &sig));

        // Deterministic: the same seed yields the same hybrid key, and
        // (FIPS 204 deterministic mode) the same signature bytes.
        let again = Keypair::hybrid_from_seed([11u8; 32]);
        assert_eq!(again.public_key(), pk);
        assert_eq!(again.sign(msg), sig);
        // A different seed yields an entirely different key.
        assert_ne!(Keypair::hybrid_from_seed([12u8; 32]).public_key(), pk);
    }

    #[test]
    fn hybrid_verification_is_a_conjunction_half_forgeries_fail() {
        // The defining property: BOTH components must verify. An attacker who
        // breaks one scheme but not the other still cannot forge.
        let kp = Keypair::hybrid_from_seed([21u8; 32]);
        let pk = kp.public_key();
        let msg = b"hybrid conjunction";
        let Signature::V2HybridMlDsa65 { ed25519, ml_dsa } = kp.sign(msg) else {
            unreachable!()
        };

        // Valid Ed25519 half + corrupted ML-DSA half: rejected.
        let mut bad_ml = ml_dsa;
        bad_ml[0] ^= 0xff;
        assert!(!pk.verify(
            msg,
            &Signature::V2HybridMlDsa65 {
                ed25519,
                ml_dsa: bad_ml
            }
        ));

        // Valid ML-DSA half + corrupted Ed25519 half: rejected.
        let mut bad_ed = ed25519;
        bad_ed[0] ^= 0xff;
        assert!(!pk.verify(
            msg,
            &Signature::V2HybridMlDsa65 {
                ed25519: bad_ed,
                ml_dsa
            }
        ));

        // The untampered pair verifies.
        assert!(pk.verify(msg, &Signature::V2HybridMlDsa65 { ed25519, ml_dsa }));
    }

    #[test]
    fn cross_scheme_verification_always_fails() {
        // A V1 signature never verifies under a hybrid key, and a hybrid
        // signature never verifies under a V1 key — even when the Ed25519
        // component key is THE SAME. No downgrade path exists.
        let seed = [31u8; 32];
        let hybrid = Keypair::hybrid_from_seed(seed);
        let hybrid_pk = hybrid.public_key();
        let msg = b"no downgrade";

        // Build a V1 keypair on the hybrid's exact Ed25519 component seed.
        let ed_seed = derive_seed("sov:hybrid65:ed25519:v1", &seed);
        let v1 = Keypair::from_seed(ed_seed);
        assert_eq!(v1.public_key().as_bytes(), hybrid_pk.as_bytes());

        // The V1 signature is a VALID Ed25519 signature by the same component
        // key — but the hybrid key refuses it (missing the ML-DSA half).
        assert!(!hybrid_pk.verify(msg, &v1.sign(msg)));
        // And the V1 key refuses the hybrid signature.
        assert!(!v1.public_key().verify(msg, &hybrid.sign(msg)));
    }

    #[test]
    fn hybrid_borsh_and_json_roundtrip_with_scheme_tags() {
        let kp = Keypair::hybrid_from_seed([41u8; 32]);
        let pk = kp.public_key();
        let sig = kp.sign(b"encode me");

        // Borsh: discriminant 0x01, then 32 + 1952 key bytes.
        let pk_bytes = borsh::to_vec(&pk).unwrap();
        assert_eq!(pk_bytes.len(), 1 + 32 + ML_DSA_65_PK_LEN);
        assert_eq!(pk_bytes[0], 0x01, "scheme byte 0x01 = hybrid65");
        assert_eq!(borsh::from_slice::<PublicKey>(&pk_bytes).unwrap(), pk);
        let sig_bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(sig_bytes.len(), 1 + 64 + ML_DSA_65_SIG_LEN);
        assert_eq!(sig_bytes[0], 0x01);
        assert_eq!(borsh::from_slice::<Signature>(&sig_bytes).unwrap(), sig);

        // JSON: mandatory hybrid65: prefix, round-trips exactly.
        let pk_json = serde_json::to_string(&pk).unwrap();
        assert!(pk_json.starts_with("\"hybrid65:0x"));
        assert_eq!(serde_json::from_str::<PublicKey>(&pk_json).unwrap(), pk);
        let sig_json = serde_json::to_string(&sig).unwrap();
        assert!(sig_json.starts_with("\"hybrid65:0x"));
        assert_eq!(serde_json::from_str::<Signature>(&sig_json).unwrap(), sig);
    }

    #[test]
    fn borsh_encoding_carries_the_scheme_byte() {
        // Cryptographic agility: the canonical binary encoding of a key is
        // scheme-tagged — 0x00 (Ed25519) followed by the 32 raw bytes — and
        // a signature likewise (0x00 + 64 bytes). Because the public key sits
        // inside a transaction's signing bytes, the scheme is committed under
        // the signature itself.
        let kp = Keypair::from_seed([5u8; 32]);
        let pk = kp.public_key();
        let pk_bytes = borsh::to_vec(&pk).unwrap();
        assert_eq!(pk_bytes.len(), 33);
        assert_eq!(pk_bytes[0], 0x00, "scheme byte 0x00 = Ed25519");
        assert_eq!(&pk_bytes[1..], pk.as_bytes());
        assert_eq!(borsh::from_slice::<PublicKey>(&pk_bytes).unwrap(), pk);

        let sig = kp.sign(b"rotate");
        let sig_bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(sig_bytes.len(), 65);
        assert_eq!(sig_bytes[0], 0x00);
        assert_eq!(borsh::from_slice::<Signature>(&sig_bytes).unwrap(), sig);

        // An unknown scheme byte refuses to decode — no silent fallback.
        let mut unknown = pk_bytes.clone();
        unknown[0] = 0x7f;
        assert!(borsh::from_slice::<PublicKey>(&unknown).is_err());
    }
}
