//! Post-quantum note encryption: ML-KEM-768 (FIPS 203) + ChaCha20-Poly1305.
//!
//! Uses the SAME primitives the transparent layer already trusts:
//! `fips203` (as `sov-network`'s PQ transport does) and the
//! `chacha20poly1305` AEAD (also from the transport stack). The KEM shared
//! secret is expanded into a one-time AEAD key with domain-separated blake3;
//! because the key is used exactly once, a fixed zero nonce is sound (and
//! standard for KEM-DEM constructions).

use crate::domains::{B3_DETECTION_TAG, B3_NOTE_AEAD};
use crate::note::Note;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// ML-KEM-768 encapsulation-key length (1184 bytes).
pub const KEM_PK_LEN: usize = ml_kem_768::EK_LEN;
/// ML-KEM-768 ciphertext length (1088 bytes).
pub const KEM_CT_LEN: usize = ml_kem_768::CT_LEN;

/// Errors from note encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum NoteEncryptionError {
    /// The KEM rejected a key or ciphertext, or encapsulation failed.
    #[error("ml-kem failure: {0}")]
    Kem(&'static str),
    /// The D7 detection tag mismatched (not our note, or a tampered tag) —
    /// returned BEFORE any AEAD work, so scanning stays cheap.
    #[error("detection tag mismatch")]
    DetectionTag,
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

    /// Decrypt a note ciphertext addressed to this keypair. Checks the D7
    /// detection tag FIRST: a mismatch (the usual case when a scanning
    /// wallet trial-decapsulates someone else's note) returns
    /// [`NoteEncryptionError::DetectionTag`] before any AEAD work.
    pub fn decrypt(&self, ct: &NoteCiphertext) -> Result<Note, NoteEncryptionError> {
        let kem_ct = ml_kem_768::CipherText::try_from_bytes(ct.kem_ct)
            .map_err(|_| NoteEncryptionError::Kem("ciphertext"))?;
        let shared = self
            .dk
            .try_decaps(&kem_ct)
            .map_err(|_| NoteEncryptionError::Kem("decaps"))?;
        let shared = shared.into_bytes();
        if derive_detection_tag(&shared) != ct.detection_tag {
            return Err(NoteEncryptionError::DetectionTag);
        }
        let key = derive_aead_key(&shared);
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

/// An encrypted note: KEM ciphertext + detection tag + AEAD-sealed
/// plaintext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteCiphertext {
    /// ML-KEM-768 ciphertext carrying the one-time key.
    pub kem_ct: [u8; KEM_CT_LEN],
    /// 4-byte detection checksum (D7) — see [`derive_detection_tag`].
    pub detection_tag: [u8; 4],
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
    let shared = shared.into_bytes();
    let key = derive_aead_key(&shared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let aead_ct = cipher
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            note.to_plaintext().as_slice(),
        )
        .map_err(|_| NoteEncryptionError::Aead)?;
    Ok(NoteCiphertext {
        kem_ct: kem_ct.into_bytes(),
        detection_tag: derive_detection_tag(&shared),
        aead_ct,
    })
}

fn derive_aead_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(B3_NOTE_AEAD)
        .update(shared_secret)
        .finalize()
        .as_bytes()
}

/// The 4-byte detection checksum (D7): `blake3_derive_key(DETECT,
/// shared_secret)[..4]`. A scanning wallet trial-decapsulates every note;
/// a wrong-key decapsulation yields a different shared secret, so the tag
/// mismatches and the note is rejected in ~µs without any AEAD work. The
/// tag leaks nothing beyond "this decapsulation matched" (it is derived
/// from the shared secret under its own domain, independent of the AEAD
/// key), and a forged tag only costs the scanner one AEAD failure.
pub fn derive_detection_tag(shared_secret: &[u8; 32]) -> [u8; 4] {
    let full = *blake3::Hasher::new_derive_key(B3_DETECTION_TAG)
        .update(shared_secret)
        .finalize()
        .as_bytes();
    [full[0], full[1], full[2], full[3]]
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
            digest_from_bytes(crate::domains::B3_TEST, b"rho"),
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
    fn wrong_key_fails_fast_at_detection_tag() {
        // D7: a scanning wallet trial-decapsulating a note that is not
        // addressed to it must be turned away at the 4-byte tag, BEFORE
        // any AEAD work.
        let kp = EncryptionKeypair::generate().expect("keygen");
        let other = EncryptionKeypair::generate().expect("keygen");
        let ct = encrypt_note(&kp.public_bytes(), &test_note()).expect("encrypt");
        assert!(matches!(
            other.decrypt(&ct),
            Err(NoteEncryptionError::DetectionTag)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kp = EncryptionKeypair::generate().expect("keygen");
        let mut ct = encrypt_note(&kp.public_bytes(), &test_note()).expect("encrypt");
        ct.aead_ct[0] ^= 1;
        assert!(matches!(kp.decrypt(&ct), Err(NoteEncryptionError::Aead)));
    }

    #[test]
    fn tampered_detection_tag_rejected() {
        let kp = EncryptionKeypair::generate().expect("keygen");
        let mut ct = encrypt_note(&kp.public_bytes(), &test_note()).expect("encrypt");
        ct.detection_tag[0] ^= 1;
        assert!(matches!(
            kp.decrypt(&ct),
            Err(NoteEncryptionError::DetectionTag)
        ));
    }
}
