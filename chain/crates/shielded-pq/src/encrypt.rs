//! Post-quantum note encryption: ML-KEM-768 (FIPS 203) + ChaCha20-Poly1305.
//!
//! Uses the SAME primitives the transparent layer already trusts:
//! `fips203` (as `sov-network`'s PQ transport does) and the
//! `chacha20poly1305` AEAD (also from the transport stack). The KEM shared
//! secret is expanded into a one-time AEAD key with domain-separated blake3;
//! because the key is used exactly once, a fixed zero nonce is sound (and
//! standard for KEM-DEM constructions).

use crate::note::Note;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// ML-KEM-768 encapsulation-key length (1184 bytes).
pub const KEM_PK_LEN: usize = ml_kem_768::EK_LEN;
/// ML-KEM-768 ciphertext length (1088 bytes).
pub const KEM_CT_LEN: usize = ml_kem_768::CT_LEN;

const AEAD_DOMAIN: &str = "sov-shielded-pq:note-aead:v1";

/// Errors from note encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum NoteEncryptionError {
    /// The KEM rejected a key or ciphertext, or encapsulation failed.
    #[error("ml-kem failure: {0}")]
    Kem(&'static str),
    /// AEAD decryption failed (wrong key or tampered ciphertext).
    #[error("aead failure")]
    Aead,
    /// The decrypted plaintext is not a valid note.
    #[error("invalid note plaintext")]
    InvalidPlaintext,
}

/// A recipient's note-encryption keypair (ML-KEM-768).
pub struct EncryptionKeypair {
    ek: ml_kem_768::EncapsKey,
    dk: ml_kem_768::DecapsKey,
}

impl EncryptionKeypair {
    /// Generate a fresh keypair from the OS RNG.
    pub fn generate() -> Result<Self, NoteEncryptionError> {
        let (ek, dk) =
            ml_kem_768::KG::try_keygen().map_err(|_| NoteEncryptionError::Kem("keygen"))?;
        Ok(EncryptionKeypair { ek, dk })
    }

    /// The public encapsulation key bytes (shared as the shielded address's
    /// encryption component).
    pub fn public_bytes(&self) -> [u8; KEM_PK_LEN] {
        self.ek.clone().into_bytes()
    }

    /// Decrypt a note ciphertext addressed to this keypair.
    pub fn decrypt(&self, ct: &NoteCiphertext) -> Result<Note, NoteEncryptionError> {
        let kem_ct = ml_kem_768::CipherText::try_from_bytes(ct.kem_ct)
            .map_err(|_| NoteEncryptionError::Kem("ciphertext"))?;
        let shared = self
            .dk
            .try_decaps(&kem_ct)
            .map_err(|_| NoteEncryptionError::Kem("decaps"))?;
        let key = derive_aead_key(&shared.into_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let pt = cipher
            .decrypt(Nonce::from_slice(&[0u8; 12]), ct.aead_ct.as_slice())
            .map_err(|_| NoteEncryptionError::Aead)?;
        let pt: [u8; 72] = pt
            .try_into()
            .map_err(|_| NoteEncryptionError::InvalidPlaintext)?;
        Note::from_plaintext(&pt).ok_or(NoteEncryptionError::InvalidPlaintext)
    }
}

/// An encrypted note: KEM ciphertext + AEAD-sealed plaintext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteCiphertext {
    /// ML-KEM-768 ciphertext carrying the one-time key.
    pub kem_ct: [u8; KEM_CT_LEN],
    /// ChaCha20-Poly1305 sealed note plaintext (72 bytes + 16-byte tag).
    pub aead_ct: Vec<u8>,
}

/// Encrypt `note` to the holder of `recipient_ek` (their ML-KEM-768
/// encapsulation key bytes).
pub fn encrypt_note(
    recipient_ek: &[u8; KEM_PK_LEN],
    note: &Note,
) -> Result<NoteCiphertext, NoteEncryptionError> {
    let ek = ml_kem_768::EncapsKey::try_from_bytes(*recipient_ek)
        .map_err(|_| NoteEncryptionError::Kem("encaps key"))?;
    let (shared, kem_ct) = ek
        .try_encaps()
        .map_err(|_| NoteEncryptionError::Kem("encaps"))?;
    let key = derive_aead_key(&shared.into_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let aead_ct = cipher
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            note.to_plaintext().as_slice(),
        )
        .map_err(|_| NoteEncryptionError::Aead)?;
    Ok(NoteCiphertext {
        kem_ct: kem_ct.into_bytes(),
        aead_ct,
    })
}

fn derive_aead_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(AEAD_DOMAIN)
        .update(shared_secret)
        .finalize()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::digest_from_bytes;
    use crate::note::SpendingKey;

    fn test_note() -> Note {
        let sk = SpendingKey::from_seed(&[3u8; 32]);
        Note::new(
            777,
            sk.owner_tag(),
            digest_from_bytes("sov-shielded-pq:test:v1", b"rho"),
        )
        .expect("note")
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = EncryptionKeypair::generate().expect("keygen");
        let note = test_note();
        let ct = encrypt_note(&kp.public_bytes(), &note).expect("encrypt");
        assert_eq!(kp.decrypt(&ct).expect("decrypt"), note);
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let kp = EncryptionKeypair::generate().expect("keygen");
        let other = EncryptionKeypair::generate().expect("keygen");
        let ct = encrypt_note(&kp.public_bytes(), &test_note()).expect("encrypt");
        assert!(other.decrypt(&ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kp = EncryptionKeypair::generate().expect("keygen");
        let mut ct = encrypt_note(&kp.public_bytes(), &test_note()).expect("encrypt");
        ct.aead_ct[0] ^= 1;
        assert!(kp.decrypt(&ct).is_err());
    }
}
