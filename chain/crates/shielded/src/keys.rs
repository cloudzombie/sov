//! Shielded keys and addresses, wrapping Orchard's key tree.
//!
//! A [`ShieldedKey`] is the root secret that controls a family of shielded
//! notes; its [`ShieldedAddress`] is the public payment address others send to.
//! Neither reveals balances or transaction history — observers cannot link a
//! payment to an address, which is the pseudonymity / untraceability property.

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::Address;

/// A shielded spending key: the root secret controlling a family of shielded
/// notes. Wraps Orchard's [`SpendingKey`]; it is never serialized or logged, so
/// secret material does not leak. Derive one deterministically from seed bytes
/// (e.g. an HD-wallet leaf) with [`ShieldedKey::from_seed`].
pub struct ShieldedKey {
    sk: SpendingKey,
}

impl ShieldedKey {
    /// Derive a shielded key from 32 bytes of seed material. Returns `None` for
    /// the negligible fraction of byte strings that are not valid Orchard keys
    /// (so callers must handle it rather than silently using a wrong key).
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        Option::from(SpendingKey::from_bytes(seed)).map(|sk| ShieldedKey { sk })
    }

    /// This key's full viewing key (crate-internal: used to build spends and to
    /// recover received notes).
    pub(crate) fn fvk(&self) -> FullViewingKey {
        FullViewingKey::from(&self.sk)
    }

    /// The underlying Orchard spending key (crate-internal: authorizes spends).
    pub(crate) fn spending_key(&self) -> &SpendingKey {
        &self.sk
    }

    /// The prepared incoming viewing key for the external scope (crate-internal:
    /// used to trial-decrypt received notes).
    pub(crate) fn prepared_ivk(&self) -> PreparedIncomingViewingKey {
        self.fvk().to_ivk(Scope::External).prepare()
    }

    /// The default external payment address for this key — the address a payer
    /// sends shielded value to.
    pub fn address(&self) -> ShieldedAddress {
        ShieldedAddress(self.fvk().address_at(0u32, Scope::External))
    }
}

/// A shielded payment address (Orchard): 43 raw bytes of diversifier plus
/// transmission key. It reveals nothing about balances or history, and two
/// addresses from the same key are unlinkable to an outside observer.
#[derive(Clone, Debug)]
pub struct ShieldedAddress(pub(crate) Address);

// Equality by raw 43-byte encoding (orchard::Address itself derives no Eq).
impl PartialEq for ShieldedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}
impl Eq for ShieldedAddress {}

impl ShieldedAddress {
    /// The 43-byte raw encoding of the address.
    pub fn to_bytes(&self) -> [u8; 43] {
        self.0.to_raw_address_bytes()
    }

    /// Parse a 43-byte raw address. Returns `None` if the bytes are not a valid
    /// Orchard address.
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        Option::from(Address::from_raw_address_bytes(bytes)).map(ShieldedAddress)
    }
}
