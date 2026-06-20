//! The hybrid post-quantum channel layer (Phase 18, p18-i2).
//!
//! The Noise XX handshake gives every connection an X25519-derived channel —
//! strong today, but **harvest-now-decrypt-later** vulnerable: an adversary
//! recording traffic now could decrypt it once a quantum computer breaks
//! X25519. This module closes that hole with the same construction TLS and
//! Signal deployed: a **hybrid key exchange**.
//!
//! Immediately after the Noise handshake, the two peers run an ML-KEM-768
//! (FIPS 203, via the `fips203` crate) encapsulation *inside* the
//! already-encrypted, mutually-bound Noise channel. Both sides then derive
//! per-direction inner keys:
//!
//! ```text
//! k_dir = Blake3("sov:pq-channel:<dir>:v1" ‖ noise_handshake_hash ‖ kem_secret)
//! ```
//!
//! and every application frame is sealed **twice**: an inner
//! ChaCha20-Poly1305 layer under the hybrid key, inside the outer Noise
//! encryption. Reading recorded traffic therefore requires breaking *both*
//! X25519 (for the outer layer and the handshake hash) *and* ML-KEM-768 (for
//! the KEM secret) — confidentiality holds as long as **either** assumption
//! survives. There is no fallback: a connection that cannot complete the KEM
//! exchange is dropped (fail closed).
//!
//! Honest scope: this hybridizes *confidentiality*. Channel *authentication*
//! is the signed application `Hello` over the channel binding — post-quantum
//! exactly when the node's identity key is a hybrid key (p18-i1).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// The shared-secret length ML-KEM produces (FIPS 203).
pub const KEM_SECRET_LEN: usize = fips203::SSK_LEN; // 32

/// Derive one direction's inner channel key.
fn direction_key(domain: &str, handshake_hash: &[u8], kem_secret: &[u8; KEM_SECRET_LEN]) -> Key {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(handshake_hash);
    hasher.update(kem_secret);
    Key::from(*hasher.finalize().as_bytes())
}

/// The inner hybrid AEAD channel: one ChaCha20-Poly1305 cipher and a monotone
/// counter nonce per direction. Distinct per-direction keys mean the counters
/// can never collide across directions, and a counter never repeats within
/// one (it only increments), so nonce reuse is impossible by construction.
pub struct PqChannel {
    seal_cipher: ChaCha20Poly1305,
    open_cipher: ChaCha20Poly1305,
    seal_counter: u64,
    open_counter: u64,
}

impl PqChannel {
    /// Build the channel from the Noise handshake hash and the ML-KEM shared
    /// secret. Both peers derive identical keys; `initiator` decides which
    /// direction key is used for sealing vs opening.
    pub fn new(
        handshake_hash: &[u8],
        kem_secret: &[u8; KEM_SECRET_LEN],
        initiator: bool,
    ) -> PqChannel {
        let i2r = direction_key("sov:pq-channel:i2r:v1", handshake_hash, kem_secret);
        let r2i = direction_key("sov:pq-channel:r2i:v1", handshake_hash, kem_secret);
        let (seal_key, open_key) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        PqChannel {
            seal_cipher: ChaCha20Poly1305::new(&seal_key),
            open_cipher: ChaCha20Poly1305::new(&open_key),
            seal_counter: 0,
            open_counter: 0,
        }
    }

    /// The 12-byte counter nonce: 4 zero bytes then the counter little-endian.
    fn nonce(counter: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&counter.to_le_bytes());
        Nonce::from(bytes)
    }

    /// Seal one outbound frame (adds a 16-byte tag), consuming one nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Self::nonce(self.seal_counter);
        self.seal_counter += 1;
        self.seal_cipher
            .encrypt(&nonce, plaintext)
            .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers")
    }

    /// Open one inbound frame. `None` on any authentication failure — a
    /// tampered, truncated, reordered, or replayed frame all fail the tag
    /// check (the expected nonce advances only on success... and on failure
    /// the channel is torn down by the caller, so a desync is terminal).
    pub fn open(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Self::nonce(self.open_counter);
        let plaintext = self.open_cipher.decrypt(&nonce, ciphertext).ok()?;
        self.open_counter += 1;
        Some(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (PqChannel, PqChannel) {
        let hh = b"noise-handshake-hash-32-bytes!!!";
        let secret = [7u8; KEM_SECRET_LEN];
        (
            PqChannel::new(hh, &secret, true),
            PqChannel::new(hh, &secret, false),
        )
    }

    #[test]
    fn seals_and_opens_in_both_directions() {
        let (mut a, mut b) = pair();
        let m1 = b"gossip: block 42".to_vec();
        let m2 = b"vote: approve".to_vec();
        assert_eq!(b.open(&a.seal(&m1)), Some(m1));
        assert_eq!(a.open(&b.seal(&m2)), Some(m2));
        // Multiple frames in sequence (counters advance in lockstep).
        for i in 0..10u8 {
            let m = vec![i; 100];
            assert_eq!(b.open(&a.seal(&m)), Some(m));
        }
    }

    #[test]
    fn tampered_frames_are_rejected() {
        let (mut a, mut b) = pair();
        let mut ct = a.seal(b"authentic");
        ct[0] ^= 0xff;
        assert_eq!(b.open(&ct), None);
    }

    #[test]
    fn replayed_and_reordered_frames_are_rejected() {
        let (mut a, mut b) = pair();
        let ct1 = a.seal(b"first");
        let ct2 = a.seal(b"second");
        assert!(b.open(&ct1).is_some());
        // Replay of frame 1: the receive counter has moved on — rejected.
        assert_eq!(b.open(&ct1), None);
        // (The channel is torn down on failure in practice; a fresh receiver
        // shows reordering also fails: frame 2 under counter 0 is invalid.)
        let (_, mut fresh_b) = pair();
        assert_eq!(fresh_b.open(&ct2), None);
    }

    #[test]
    fn different_secrets_or_bindings_cannot_interoperate() {
        let hh = b"noise-handshake-hash-32-bytes!!!";
        let mut a = PqChannel::new(hh, &[7u8; KEM_SECRET_LEN], true);
        // Wrong KEM secret: nothing decrypts.
        let mut b_wrong_secret = PqChannel::new(hh, &[8u8; KEM_SECRET_LEN], false);
        assert_eq!(b_wrong_secret.open(&a.seal(b"hello")), None);
        // Wrong channel binding (a different connection's handshake hash).
        let mut b_wrong_binding = PqChannel::new(
            b"a-different-noise-channel-hash!!",
            &[7u8; KEM_SECRET_LEN],
            false,
        );
        assert_eq!(b_wrong_binding.open(&a.seal(b"hello")), None);
        // Direction keys are distinct: a peer cannot decrypt its own direction.
        let mut a2 = PqChannel::new(hh, &[7u8; KEM_SECRET_LEN], true);
        assert_eq!(a2.open(&a.seal(b"hello")), None);
    }
}
