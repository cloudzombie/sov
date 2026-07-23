//! Carrier-level spend authorization: ML-DSA-65 (FIPS 204), pure lattice —
//! no elliptic-curve component in this crate.
//!
//! The signature covers the bundle digest (nullifiers ‖ output commitments ‖
//! values ‖ fee), computed in [`crate::bundle`]. This mirrors the chain's
//! existing carrier-auth design; an in-circuit signature check is future
//! work (see the design doc). Uses the same `fips204` crate `sov-crypto`
//! already trusts for the transparent layer's hybrid signatures.

use crate::domains::{AUTH_SIGN_CTX, B3_AUTH_KEYGEN, B3_AUTH_SIGN};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

/// ML-DSA-65 public-key length (1952 bytes).
pub const AUTH_PK_LEN: usize = ml_dsa_65::PK_LEN;
/// ML-DSA-65 signature length (3309 bytes).
pub const AUTH_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// Errors from spend authorization.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Key generation or signing failed inside fips204.
    #[error("ml-dsa failure: {0}")]
    MlDsa(&'static str),
}

/// An authorization keypair (ML-DSA-65).
pub struct AuthKeypair {
    sk: ml_dsa_65::PrivateKey,
    pk: [u8; AUTH_PK_LEN],
    sign_seed: [u8; 32],
}

impl AuthKeypair {
    /// Derive the keypair deterministically from a 32-byte seed
    /// (domain-separated, FIPS 204 seeded keygen — same pattern as
    /// `sov-crypto`'s hybrid keys).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let xi = *blake3::Hasher::new_derive_key(B3_AUTH_KEYGEN)
            .update(seed)
            .finalize()
            .as_bytes();
        let sign_seed = *blake3::Hasher::new_derive_key(B3_AUTH_SIGN)
            .update(seed)
            .finalize()
            .as_bytes();
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&xi);
        AuthKeypair {
            sk,
            pk: pk.into_bytes(),
            sign_seed,
        }
    }

    /// The public verification key bytes.
    pub fn public_bytes(&self) -> [u8; AUTH_PK_LEN] {
        self.pk
    }

    /// Sign a bundle digest (deterministic, seeded FIPS 204 mode).
    pub fn sign(&self, digest: &[u8; 32]) -> Result<[u8; AUTH_SIG_LEN], AuthError> {
        self.sk
            .try_sign_with_seed(&self.sign_seed, digest, AUTH_SIGN_CTX)
            .map_err(|_| AuthError::MlDsa("sign"))
    }
}

/// Verify an ML-DSA-65 spend-authorization signature over a bundle digest.
pub fn verify_auth(pk: &[u8; AUTH_PK_LEN], digest: &[u8; 32], sig: &[u8; AUTH_SIG_LEN]) -> bool {
    match ml_dsa_65::PublicKey::try_from_bytes(*pk) {
        Ok(vk) => vk.verify(digest, sig, AUTH_SIGN_CTX),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let kp = AuthKeypair::from_seed(&[9u8; 32]);
        let digest = [42u8; 32];
        let sig = kp.sign(&digest).expect("sign");
        assert!(verify_auth(&kp.public_bytes(), &digest, &sig));
        // Tampered digest rejected.
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!verify_auth(&kp.public_bytes(), &bad, &sig));
        // Tampered signature rejected.
        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert!(!verify_auth(&kp.public_bytes(), &digest, &bad_sig));
        // Wrong key rejected.
        let other = AuthKeypair::from_seed(&[10u8; 32]);
        assert!(!verify_auth(&other.public_bytes(), &digest, &sig));
    }
}
