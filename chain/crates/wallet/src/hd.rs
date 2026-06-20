//! Hierarchical-deterministic (HD) wallets — Rust side, at parity with the SDK
//! (`sdk/src/hd.ts`).
//!
//! SOV signs with Ed25519, so HD follows the Ed25519 standards rather than
//! BIP-32's secp256k1 math:
//!
//!   - **BIP-39** turns a mnemonic into a 512-bit seed (PBKDF2-HMAC-SHA512),
//!     via the audited `bip39` crate;
//!   - **SLIP-0010** derives a tree of Ed25519 keys from that seed using
//!     HMAC-SHA512 (`hmac` + `sha2`). Ed25519 supports *hardened* derivation
//!     only, so every path component is hardened;
//!   - **BIP-44** gives the path `m / 44' / SOV_COIN_TYPE' / account' / 0' /
//!     index'`.
//!
//! The 32-byte key SLIP-0010 produces at a leaf is the deterministic **leaf
//! seed**. SOV expands it into the account's signing key: the default is the
//! **hybrid Ed25519 + ML-DSA-65** post-quantum key ([`Keypair::hybrid_from_seed`]
//! / [`HdWallet::derive_keypair`]), with a legacy classical Ed25519 key
//! ([`HdWallet::derive_ed25519_keypair`]) also available. The leaf-seed
//! derivation is pinned byte-for-byte to the SDK by a cross-implementation
//! known-answer test, so the same mnemonic restores the same SOV wallet in Rust
//! and TypeScript (the SDK currently expands the leaf to the Ed25519 key; its
//! hybrid expansion lands with ML-DSA-65 in TypeScript).

use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use sov_crypto::Keypair;

type HmacSha512 = Hmac<Sha512>;

/// The hardened-derivation offset (2^31). SLIP-0010 Ed25519 derivation is
/// hardened-only, so every path component carries this bit.
const HARDENED: u32 = 0x8000_0000;

/// BIP-44 purpose.
const PURPOSE: u32 = 44;

/// SOV's BIP-44 coin type — the ASCII bytes `"SOV"` (`0x53_4f_56` = 5_459_798).
/// PROVISIONAL: SOV is not yet SLIP-0044 registered; fixed here so every wallet
/// derives the same addresses. Must equal `SOV_COIN_TYPE` in `sdk/src/hd.ts`.
pub const SOV_COIN_TYPE: u32 = 0x53_4f_56;

/// SLIP-0010 master HMAC key for the Ed25519 curve.
const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// Errors building an HD wallet.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    /// The mnemonic failed BIP-39 validation (wordlist or checksum).
    #[error("invalid BIP-39 mnemonic: {0}")]
    Mnemonic(String),
}

/// Generate a fresh BIP-39 mnemonic of `word_count` words (12 or 24) from
/// operating-system entropy (`getrandom`). The phrase is the ONLY backup of the
/// wallet it seeds — whoever holds it controls the account — so it must be
/// generated privately and never transmitted. Returns the space-separated phrase.
pub fn generate_mnemonic(word_count: usize) -> Result<String, HdError> {
    let entropy_len = match word_count {
        12 => 16,
        24 => 32,
        other => {
            return Err(HdError::Mnemonic(format!(
                "word count must be 12 or 24, got {other}"
            )))
        }
    };
    let mut entropy = [0u8; 32];
    let slice = &mut entropy[..entropy_len];
    getrandom::getrandom(slice).map_err(|e| HdError::Mnemonic(format!("OS entropy: {e}")))?;
    let mnemonic = Mnemonic::from_entropy(slice).map_err(|e| HdError::Mnemonic(e.to_string()))?;
    let phrase = mnemonic.to_string();
    slice.fill(0); // best-effort wipe of the entropy copy
    Ok(phrase)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    bytes
}

fn split(i: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    (key, chain)
}

/// SLIP-0010 Ed25519 master: `I = HMAC-SHA512("ed25519 seed", seed)`.
fn master(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    split(hmac_sha512(ED25519_CURVE, seed))
}

/// SLIP-0010 Ed25519 hardened child: `I = HMAC-SHA512(c_par, 0x00 || k_par ||
/// ser32(index))`; the child key is `I_L` directly (no scalar add).
fn ckd(key: &[u8; 32], chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let mut data = [0u8; 1 + 32 + 4];
    data[1..33].copy_from_slice(key);
    data[33..].copy_from_slice(&index.to_be_bytes());
    split(hmac_sha512(chain, &data))
}

/// A hierarchical-deterministic SOV wallet: one BIP-39 seed from which an entire
/// tree of Ed25519 [`Keypair`]s is derived deterministically.
pub struct HdWallet {
    seed: [u8; 64],
}

impl HdWallet {
    /// Build a wallet from a BIP-39 mnemonic, optionally salted by a passphrase
    /// (the "25th word"). Rejects a phrase that fails the wordlist/checksum.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, HdError> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|e| HdError::Mnemonic(e.to_string()))?;
        Ok(HdWallet {
            seed: mnemonic.to_seed(passphrase),
        })
    }

    /// Build a wallet directly from a raw 64-byte BIP-39 seed.
    pub fn from_seed(seed: [u8; 64]) -> Self {
        HdWallet { seed }
    }

    /// Derive the raw 32-byte **leaf seed** at a path of indices (each hardened
    /// automatically — SLIP-0010 Ed25519 has no non-hardened derivation). This is
    /// the deterministic, scheme-agnostic HD output: the SDK derives the identical
    /// bytes for the same mnemonic and path. Feed it to whichever key scheme the
    /// account uses — [`Keypair::hybrid_from_seed`] for SOV's default post-quantum
    /// key, or [`Keypair::from_seed`] for a legacy Ed25519 key.
    pub fn derive_seed_at_path(&self, path: &[u32]) -> [u8; 32] {
        let (mut key, mut chain) = master(&self.seed);
        for &index in path {
            let (k, c) = ckd(&key, &chain, index | HARDENED);
            key = k;
            chain = c;
        }
        key
    }

    /// The 32-byte leaf seed for a SOV `account` and address `index` on the
    /// standard BIP-44 path `m/44'/SOV_COIN_TYPE'/account'/0'/index'`.
    pub fn derive_seed(&self, account: u32, index: u32) -> [u8; 32] {
        self.derive_seed_at_path(&[PURPOSE, SOV_COIN_TYPE, account, 0, index])
    }

    /// Derive the **hybrid Ed25519 + ML-DSA-65** keypair (SOV's default,
    /// post-quantum scheme `0x01`) at a path of indices. The same mnemonic always
    /// reproduces the same hybrid key.
    pub fn derive_keypair_at_path(&self, path: &[u32]) -> Keypair {
        Keypair::hybrid_from_seed(self.derive_seed_at_path(path))
    }

    /// Derive the hybrid post-quantum keypair for a SOV `account` and address
    /// `index` on the standard BIP-44 path. Its public key is the value that
    /// authorizes a named account on-chain. This is the scheme new wallets should
    /// use — a 12/24-word phrase restores this exact keypair every time.
    pub fn derive_keypair(&self, account: u32, index: u32) -> Keypair {
        Keypair::hybrid_from_seed(self.derive_seed(account, index))
    }

    /// Derive the legacy classical **Ed25519** keypair (scheme `0x00`) for an
    /// `account`/`index`. The SDK derives the identical key from the same leaf, so
    /// this is the cross-implementation parity anchor; prefer
    /// [`derive_keypair`](Self::derive_keypair) (post-quantum) for new accounts.
    pub fn derive_ed25519_keypair(&self, account: u32, index: u32) -> Keypair {
        Keypair::from_seed(self.derive_seed(account, index))
    }

    /// The raw 64-byte BIP-39 seed (secret material — handle with care).
    pub fn export_seed(&self) -> [u8; 64] {
        self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREZOR: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn cross_impl_parity_with_the_sdk() {
        // The SDK (sdk/src/hd.ts) derives this Ed25519 public key for the Trezor
        // reference mnemonic at the standard SOV path m/44'/SOV'/0'/0'/0'. Both
        // implementations derive the identical SLIP-0010 leaf, so the classical
        // key matches byte-for-byte — the cross-impl HD parity anchor.
        let w = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        assert_eq!(
            w.derive_ed25519_keypair(0, 0).public_key().to_hex(),
            "cfedb9535588130e7215859f1346fce339c40c6601196d465fea5c7d43f14464"
        );
    }

    #[test]
    fn hybrid_derivation_is_deterministic_and_post_quantum() {
        // SOV's default: one mnemonic restores the same HYBRID post-quantum key
        // every time — this is what a 12/24-word phrase recovers for a real wallet.
        let a = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        let b = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        let ka = a.derive_keypair(0, 0).public_key();
        assert_eq!(
            ka,
            b.derive_keypair(0, 0).public_key(),
            "a phrase reproduces the same hybrid key every time"
        );
        assert_eq!(
            ka.scheme(),
            "hybrid65",
            "HD default is the post-quantum hybrid"
        );
        // The hybrid key is a distinct scheme from the legacy Ed25519 key derived
        // from the same leaf (independent Blake3 domain-separated components).
        assert_ne!(ka, a.derive_ed25519_keypair(0, 0).public_key());
        // And the underlying leaf is itself deterministic.
        assert_eq!(a.derive_seed(0, 0), b.derive_seed(0, 0));
    }

    #[test]
    fn deterministic_and_distinct_per_account_and_index() {
        let a = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        let b = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        // Deterministic: one mnemonic always yields the same account key.
        assert_eq!(
            a.derive_keypair(0, 0).public_key(),
            b.derive_keypair(0, 0).public_key()
        );
        // Distinct per account and per index.
        let keys = [
            a.derive_keypair(0, 0).public_key(),
            a.derive_keypair(0, 1).public_key(),
            a.derive_keypair(1, 0).public_key(),
        ];
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn a_passphrase_changes_derivation() {
        let plain = HdWallet::from_mnemonic(TREZOR, "").unwrap();
        let salted = HdWallet::from_mnemonic(TREZOR, "TREZOR").unwrap();
        assert_ne!(plain.export_seed(), salted.export_seed());
    }

    #[test]
    fn a_bad_mnemonic_is_rejected() {
        // Valid words but a broken checksum.
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(HdWallet::from_mnemonic(bad, "").is_err());
    }

    #[test]
    fn generated_mnemonics_are_valid_distinct_and_recoverable() {
        let m12 = generate_mnemonic(12).unwrap();
        let m24 = generate_mnemonic(24).unwrap();
        assert_eq!(m12.split_whitespace().count(), 12);
        assert_eq!(m24.split_whitespace().count(), 24);
        // A generated phrase passes BIP-39 validation and seeds a deterministic
        // wallet (so `new` then `import` recover the identical account).
        let a = HdWallet::from_mnemonic(&m24, "").unwrap();
        let b = HdWallet::from_mnemonic(&m24, "").unwrap();
        assert_eq!(
            a.derive_keypair(0, 0).public_key(),
            b.derive_keypair(0, 0).public_key()
        );
        // Real entropy: two generations are overwhelmingly unlikely to collide.
        assert_ne!(
            generate_mnemonic(24).unwrap(),
            generate_mnemonic(24).unwrap()
        );
        // Only 12 or 24 words are accepted.
        assert!(generate_mnemonic(15).is_err());
    }
}
