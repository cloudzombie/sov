//! Pool-v2 wallet keys: HD derivation from the BIP-44 leaf, and the v2
//! payment address (decision **D9**).
//!
//! # One phrase restores three tiers
//!
//! SOV's HD tree is BIP-39 → SLIP-0010 (Ed25519) → BIP-44, exactly as
//! `sov_wallet::HdWallet` implements it. The scheme-agnostic output is the
//! 32-byte **leaf seed** at
//!
//! ```text
//! m / 44' / 0x53_4F_56' / account' / 0' / index'
//! ```
//!
//! (`0x53_4F_56` = 5_459_798 = the ASCII bytes `"SOV"`;
//! `sov_wallet::SOV_COIN_TYPE`). Every component is hardened — SLIP-0010
//! Ed25519 has no unhardened derivation.
//!
//! That one leaf already feeds two tiers today:
//!
//! | tier | expansion of the leaf |
//! |------|-----------------------|
//! | transparent | `sov_crypto::Keypair::hybrid_from_seed(leaf)` |
//! | shielded v1 (Orchard) | `sov_shielded::ShieldedKey::from_seed(leaf)` |
//! | **shielded v2 (this module)** | **a domain-separated blake3 subtree of `leaf`** |
//!
//! # The v2 subtree
//!
//! [`PqShieldedKey::from_leaf_seed`] expands the leaf into five independent
//! secrets, each `blake3::derive_key(<domain>, leaf)` under its OWN context
//! string (see [`crate::domains`]):
//!
//! ```text
//! spend_seed = blake3_dk("sov-shielded-pq:hd-spend:v2",  leaf)  -> SpendingKey::from_seed
//! kem_d      = blake3_dk("sov-shielded-pq:hd-kem-d:v2",  leaf)  \ ML-KEM-768
//! kem_z      = blake3_dk("sov-shielded-pq:hd-kem-z:v2",  leaf)  / keygen_from_seed(d, z)
//! auth_seed  = blake3_dk("sov-shielded-pq:hd-auth:v2",   leaf)  -> AuthKeypair::from_seed
//! rho_seed   = blake3_dk("sov-shielded-pq:hd-rho:v2",    leaf)  -> derive_rho(rho_seed, i)
//! ```
//!
//! blake3's `derive_key` mode gives full cryptographic context separation,
//! so compromise of any one of these reveals nothing about the others or
//! about the leaf. Because the whole subtree is a pure function of the
//! leaf, **the 24-word phrase alone restores every v2 key, every v2
//! address, and every note's `rho`** — no additional backup exists or is
//! needed. This is pinned by cross-checked vectors in
//! `chain/crates/shielded/tests/pq_wallet_vectors.rs` and
//! `sdk/vectors/pq-shielded-v2-key.json`.
//!
//! # Hygiene
//!
//! The leaf and all five derived seeds live in [`Zeroizing`] buffers and are
//! wiped when the derivation returns; the long-lived key material
//! (`SpendingKey`'s `nsk`, the ML-KEM decapsulation key, the ML-DSA private
//! key) is held by [`PqShieldedKey`], which zeroizes what it owns on drop.
//! Nothing here is ever serialized, logged, or put on the wire — the only
//! externally visible artifact is the PUBLIC [`PqAddress`].

use zeroize::Zeroizing;

use crate::auth::AuthKeypair;
use crate::domains::{B3_HD_AUTH, B3_HD_KEM_D, B3_HD_KEM_Z, B3_HD_RHO, B3_HD_SPEND};
use crate::encrypt::{EncryptionKeypair, KEM_PK_LEN};
use crate::hash::PqDigest;
use crate::note::{derive_rho, SpendingKey};

/// The BIP-44 path whose leaf this module expands, as a format string with
/// `{account}` / `{index}` placeholders. Documented here so wallets, the
/// CLI, and the SDK all print the same thing.
pub const PQ_HD_PATH_TEMPLATE: &str = "m/44'/5459798'/{account}'/0'/{index}'";

/// Length of the canonical pool-v2 payment address: a 32-byte owner tag
/// followed by the 1184-byte ML-KEM-768 encapsulation key.
pub const PQ_ADDRESS_LEN: usize = 32 + KEM_PK_LEN;

/// Render the BIP-44 path for an `account`/`index` pair (the path a wallet
/// should show next to a derived v2 address).
pub fn pq_hd_path(account: u32, index: u32) -> String {
    format!("m/44'/5459798'/{account}'/0'/{index}'")
}

/// blake3 `derive_key` expansion of the leaf under one HD domain. The
/// output is zeroized when the returned buffer drops.
fn expand(domain: &str, leaf: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        *blake3::Hasher::new_derive_key(domain)
            .update(leaf)
            .finalize()
            .as_bytes(),
    )
}

/// A wallet's complete pool-v2 key material, derived from one BIP-44 leaf.
///
/// Holds the spend key (`nsk`), the ML-KEM-768 note-encryption keypair, the
/// ML-DSA-65 carrier-auth keypair, and the per-wallet `rho` seed. All of it
/// is secret except [`PqShieldedKey::address`].
pub struct PqShieldedKey {
    spend: SpendingKey,
    kem: EncryptionKeypair,
    auth: AuthKeypair,
    rho_seed: Zeroizing<[u8; 32]>,
}

impl PqShieldedKey {
    /// Derive the whole v2 key set from a 32-byte BIP-44 leaf seed
    /// (`sov_wallet::HdWallet::derive_seed(account, index)`).
    ///
    /// Deterministic and total: every 32-byte string is a valid leaf (unlike
    /// pool v1, where a negligible fraction of strings are not valid Orchard
    /// keys), so this cannot fail and a phrase can never derive "no v2
    /// address".
    pub fn from_leaf_seed(leaf: &[u8; 32]) -> Self {
        let spend_seed = expand(B3_HD_SPEND, leaf);
        let kem_d = expand(B3_HD_KEM_D, leaf);
        let kem_z = expand(B3_HD_KEM_Z, leaf);
        let auth_seed = expand(B3_HD_AUTH, leaf);
        let rho_seed = expand(B3_HD_RHO, leaf);
        PqShieldedKey {
            spend: SpendingKey::from_seed(&spend_seed),
            kem: EncryptionKeypair::from_kem_seeds(&kem_d, &kem_z),
            auth: AuthKeypair::from_seed(&auth_seed),
            rho_seed,
        }
    }

    /// The spend key (`nsk`) — derives nullifiers and the owner tag.
    pub fn spend_key(&self) -> &SpendingKey {
        &self.spend
    }

    /// The ML-KEM-768 note-encryption keypair — trial-decapsulates incoming
    /// notes.
    pub fn encryption_key(&self) -> &EncryptionKeypair {
        &self.kem
    }

    /// The ML-DSA-65 carrier spend-authorization keypair (D4).
    pub fn auth_key(&self) -> &AuthKeypair {
        &self.auth
    }

    /// The public owner tag committed inside every note this key owns.
    pub fn owner_tag(&self) -> PqDigest {
        self.spend.owner_tag()
    }

    /// This wallet's deterministic `rho` for output note `index`. Recovering
    /// the phrase recovers every `rho` the wallet ever used, so change notes
    /// it created are reproducible without any other backup.
    pub fn rho(&self, index: u64) -> PqDigest {
        derive_rho(&self.rho_seed, index)
    }

    /// The public pool-v2 payment address: `{owner_tag, ML-KEM-768 ek}`.
    pub fn address(&self) -> PqAddress {
        PqAddress {
            owner_tag: self.owner_tag(),
            kem_ek: self.kem.public_bytes(),
        }
    }
}

/// A pool-v2 payment address — everything a sender needs and nothing more:
///
/// - `owner_tag` (32 B) — binds the note to the recipient's `nsk`, so only
///   the recipient can derive the nullifier the spend circuit demands;
/// - `kem_ek` (1184 B) — the ML-KEM-768 encapsulation key the sender
///   encapsulates to when encrypting the note.
///
/// Both halves are required: a sender cannot build the note commitment
/// without the tag, and cannot encrypt to the recipient without the key.
/// 1216 bytes is the honest, unavoidable size of a lattice-KEM payment
/// address (Orchard's is 43 bytes because it is a curve point) — see
/// [`crate::hd`] and the address-encoding module docs for what that means
/// for the encoded string.
#[derive(Clone)]
pub struct PqAddress {
    owner_tag: PqDigest,
    kem_ek: [u8; KEM_PK_LEN],
}

impl PqAddress {
    /// Build an address from its two components. Returns `None` for the
    /// all-zero owner tag (the wire format's dummy-slot convention, which
    /// pool state refuses) or an ML-KEM key that fails FIPS 203 validation.
    pub fn new(owner_tag: PqDigest, kem_ek: [u8; KEM_PK_LEN]) -> Option<Self> {
        if owner_tag == PqDigest::ZERO {
            return None;
        }
        // Reject a malformed encapsulation key at PARSE time rather than at
        // send time: paying an address whose key fails `try_encaps` would
        // otherwise fail late, after the user believed the address good.
        use fips203::traits::SerDes;
        fips203::ml_kem_768::EncapsKey::try_from_bytes(kem_ek).ok()?;
        Some(PqAddress { owner_tag, kem_ek })
    }

    /// The recipient's owner tag.
    pub fn owner_tag(&self) -> PqDigest {
        self.owner_tag
    }

    /// The recipient's ML-KEM-768 encapsulation key.
    pub fn kem_ek(&self) -> &[u8; KEM_PK_LEN] {
        &self.kem_ek
    }

    /// The canonical [`PQ_ADDRESS_LEN`]-byte encoding: `owner_tag ‖ kem_ek`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PQ_ADDRESS_LEN);
        out.extend_from_slice(&self.owner_tag.to_bytes());
        out.extend_from_slice(&self.kem_ek);
        out
    }

    /// Parse the canonical encoding. `None` unless the input is exactly
    /// [`PQ_ADDRESS_LEN`] bytes carrying a canonical, non-zero owner tag and
    /// a valid ML-KEM-768 encapsulation key. Total: never panics, and the
    /// only allocation is bounded by the fixed address length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PQ_ADDRESS_LEN {
            return None;
        }
        let tag_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let owner_tag = PqDigest::from_bytes(&tag_bytes)?;
        let mut kem_ek = [0u8; KEM_PK_LEN];
        kem_ek.copy_from_slice(&bytes[32..]);
        PqAddress::new(owner_tag, kem_ek)
    }
}

// `[u8; 1184]` is beyond the arrays the standard library derives traits for,
// so equality/debug are written out. Equality is by the canonical encoding.
impl PartialEq for PqAddress {
    fn eq(&self, other: &Self) -> bool {
        self.owner_tag == other.owner_tag && self.kem_ek[..] == other.kem_ek[..]
    }
}
impl Eq for PqAddress {}

impl core::fmt::Debug for PqAddress {
    /// Debug prints the owner tag and a short fingerprint of the KEM key —
    /// never 1184 bytes of hex in a log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fp = blake3::hash(&self.kem_ek);
        write!(
            f,
            "PqAddress {{ owner_tag: {}, kem_ek#: {} }}",
            self.owner_tag.to_hex(),
            &fp.to_hex()[..16]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::encrypt_note;
    use crate::note::Note;

    const LEAF: [u8; 32] = [0x11; 32];

    #[test]
    fn derivation_is_deterministic_and_covers_every_component() {
        let a = PqShieldedKey::from_leaf_seed(&LEAF);
        let b = PqShieldedKey::from_leaf_seed(&LEAF);
        assert_eq!(a.owner_tag(), b.owner_tag());
        assert_eq!(a.address(), b.address());
        assert_eq!(a.auth_key().public_bytes(), b.auth_key().public_bytes());
        assert_eq!(a.rho(7), b.rho(7));
        // rho is per-index, not constant.
        assert_ne!(a.rho(7), a.rho(8));
    }

    #[test]
    fn a_different_leaf_gives_an_entirely_different_key_set() {
        let a = PqShieldedKey::from_leaf_seed(&LEAF);
        let b = PqShieldedKey::from_leaf_seed(&[0x12; 32]);
        assert_ne!(a.owner_tag(), b.owner_tag());
        assert_ne!(a.address(), b.address());
        assert_ne!(
            a.address().kem_ek()[..],
            b.address().kem_ek()[..],
            "the KEM key must move with the leaf"
        );
        assert_ne!(a.auth_key().public_bytes(), b.auth_key().public_bytes());
        assert_ne!(a.rho(0), b.rho(0));
    }

    #[test]
    fn the_five_subtree_secrets_are_independent() {
        // Same leaf, five domains: no two expansions may coincide.
        let outs: Vec<[u8; 32]> = [B3_HD_SPEND, B3_HD_KEM_D, B3_HD_KEM_Z, B3_HD_AUTH, B3_HD_RHO]
            .iter()
            .map(|d| *expand(d, &LEAF))
            .collect();
        for i in 0..outs.len() {
            assert_ne!(outs[i], LEAF, "an expansion leaked the leaf itself");
            for j in i + 1..outs.len() {
                assert_ne!(outs[i], outs[j], "HD domains {i} and {j} collided");
            }
        }
    }

    #[test]
    fn a_derived_key_decrypts_a_note_encrypted_to_its_address() {
        let key = PqShieldedKey::from_leaf_seed(&LEAF);
        let address = key.address();
        let note = Note::new(4_200, address.owner_tag(), key.rho(0)).expect("note");
        let ct = encrypt_note(address.kem_ek(), &note).expect("encrypt");
        assert_eq!(key.encryption_key().decrypt(&ct).expect("decrypt"), note);
        // A wallet restored from the same phrase decrypts it too.
        let restored = PqShieldedKey::from_leaf_seed(&LEAF);
        assert_eq!(
            restored.encryption_key().decrypt(&ct).expect("decrypt"),
            note
        );
    }

    #[test]
    fn address_roundtrips_and_rejects_malformed_bytes() {
        let key = PqShieldedKey::from_leaf_seed(&LEAF);
        let address = key.address();
        let bytes = address.to_bytes();
        assert_eq!(bytes.len(), PQ_ADDRESS_LEN);
        assert_eq!(PqAddress::from_bytes(&bytes), Some(address.clone()));

        // Wrong length (short, long, empty) — rejected, never panics.
        assert!(PqAddress::from_bytes(&[]).is_none());
        assert!(PqAddress::from_bytes(&bytes[..PQ_ADDRESS_LEN - 1]).is_none());
        let mut long = bytes.clone();
        long.push(0);
        assert!(PqAddress::from_bytes(&long).is_none());

        // Non-canonical owner tag (limb == p is out of range).
        let mut bad = bytes.clone();
        bad[..8].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
        assert!(PqAddress::from_bytes(&bad).is_none());

        // All-zero owner tag = the dummy convention; refused.
        let mut zero_tag = bytes.clone();
        zero_tag[..32].fill(0);
        assert!(PqAddress::from_bytes(&zero_tag).is_none());

        // A corrupted ML-KEM key is caught at parse time (FIPS 203 rejects
        // out-of-range coefficients), so a bad address can never be "paid".
        let mut bad_ek = bytes;
        for b in bad_ek[32..].iter_mut() {
            *b = 0xff;
        }
        assert!(PqAddress::from_bytes(&bad_ek).is_none());
    }

    #[test]
    fn debug_never_prints_the_whole_key_or_any_secret() {
        let key = PqShieldedKey::from_leaf_seed(&LEAF);
        let rendered = format!("{:?}", key.address());
        assert!(rendered.len() < 160, "Debug must stay a one-liner");
        assert!(!rendered.contains(&hex::encode(key.address().kem_ek())));
    }

    #[test]
    fn the_documented_path_template_matches_the_rendered_path() {
        assert_eq!(pq_hd_path(0, 0), "m/44'/5459798'/0'/0'/0'");
        assert_eq!(pq_hd_path(3, 7), "m/44'/5459798'/3'/0'/7'");
        assert_eq!(
            PQ_HD_PATH_TEMPLATE
                .replace("{account}", "3")
                .replace("{index}", "7"),
            pq_hd_path(3, 7)
        );
    }
}
