//! User-facing address encodings — the SOV analog of Zcash's address tiers.
//!
//! - **Transparent** — a **named account**, used as-is: `alice.actor.sov`.
//!   Self-describing, human-readable, and cryptographically bound to its
//!   controlling key on-chain — it needs no wrapper encoding.
//! - **Shielded** — `xus1…`: the 43-byte Orchard receiver under bech32m
//!   (BIP-350: the checksummed, QR-friendly, case-insensitive encoding
//!   Bitcoin taproot and Zcash unified addresses use; via the standard
//!   `bech32` crate — nothing hand-rolled). The chain's ticker (`xus`) is the
//!   prefix. Paying it routes value into the shielded pool,
//!   where sender, receiver, and amount are hidden by zero-knowledge proofs.
//! - **Unified** — `uxus1…`: one bech32m address carrying *both* receivers
//!   (the named account and the shielded receiver, TLV inside), so a sender's
//!   wallet automatically routes to the most private pool it supports —
//!   shielded when it can, the named account otherwise — with no manual
//!   address juggling.
//!
//! Display is canonical lowercase; per bech32m, the fully-uppercase forms
//! (`XUS1…`, `UXUS1…`) are equally valid and decode identically.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use sov_primitives::AccountId;

use crate::keys::ShieldedAddress;

/// Human-readable part of a shielded address (`xus1…`).
const HRP_SHIELDED: &str = "xus";
/// Human-readable part of a unified address (`uxus1…`).
const HRP_UNIFIED: &str = "uxus";

/// Unified-address TLV typecode: a transparent account id (UTF-8).
const UA_TYPE_TRANSPARENT: u8 = 0x00;
/// Unified-address TLV typecode: a 43-byte Orchard shielded receiver.
const UA_TYPE_SHIELDED: u8 = 0x01;

/// Why an address string failed to decode. Each variant names the exact
/// failure so wallet errors are diagnosable, not merely "invalid".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    /// Not valid bech32m (bad characters, mixed case, or checksum failure —
    /// the checksum catches typos and tampering).
    #[error("invalid bech32m encoding: {0}")]
    Encoding(String),
    /// Valid bech32m, but the human-readable prefix is for a different kind.
    #[error("wrong address kind: expected `{expected}1…`, got `{got}1…`")]
    WrongKind {
        /// The prefix this decoder expects.
        expected: &'static str,
        /// The prefix the string carried.
        got: String,
    },
    /// The payload bytes do not form a valid receiver of the declared kind.
    #[error("invalid {0} receiver payload")]
    Payload(&'static str),
    /// A unified address carried no receiver this implementation understands.
    #[error("unified address carries no known receiver")]
    NoKnownReceiver,
    /// A unified address carried the same receiver type twice.
    #[error("unified address duplicates receiver type {0:#04x}")]
    DuplicateReceiver(u8),
}

fn encode(hrp: &str, payload: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("static HRPs are valid");
    bech32::encode::<Bech32m>(hrp, payload).expect("payloads are within bech32 limits")
}

/// Strict bech32m decode (the Bech32m checksum specifically; plain bech32 is
/// rejected), returning the lowercase HRP and payload bytes.
fn decode(s: &str) -> Result<(String, Vec<u8>), AddressError> {
    let checked =
        CheckedHrpstring::new::<Bech32m>(s).map_err(|e| AddressError::Encoding(e.to_string()))?;
    let hrp = checked.hrp().to_lowercase();
    let payload = checked.byte_iter().collect();
    Ok((hrp, payload))
}

/// Encode a shielded receiver as `xus1…`.
pub fn encode_shielded(address: &ShieldedAddress) -> String {
    encode(HRP_SHIELDED, &address.to_bytes())
}

/// Decode a `xus1…` shielded address.
pub fn decode_shielded(s: &str) -> Result<ShieldedAddress, AddressError> {
    let (hrp, payload) = decode(s)?;
    if hrp != HRP_SHIELDED {
        return Err(AddressError::WrongKind {
            expected: HRP_SHIELDED,
            got: hrp,
        });
    }
    let bytes: [u8; 43] = payload
        .try_into()
        .map_err(|_| AddressError::Payload("shielded"))?;
    ShieldedAddress::from_bytes(&bytes).ok_or(AddressError::Payload("shielded"))
}

/// A unified address: one string carrying up to one receiver of each kind.
/// The sender's wallet picks the most private receiver it supports —
/// [`UnifiedAddress::preferred`] returns shielded when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedAddress {
    /// The transparent receiver — a named account, used as-is.
    pub transparent: Option<AccountId>,
    /// The shielded (Orchard) receiver, if included.
    pub shielded: Option<ShieldedAddress>,
}

/// The receiver a sending wallet should use, in privacy order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receiver {
    /// Route into the shielded pool (the private default).
    Shielded(ShieldedAddress),
    /// Pay the named account transparently.
    Transparent(AccountId),
}

impl UnifiedAddress {
    /// Build a unified address. At least one receiver must be present.
    pub fn new(
        transparent: Option<AccountId>,
        shielded: Option<ShieldedAddress>,
    ) -> Result<Self, AddressError> {
        if transparent.is_none() && shielded.is_none() {
            return Err(AddressError::NoKnownReceiver);
        }
        Ok(UnifiedAddress {
            transparent,
            shielded,
        })
    }

    /// Encode as `uxus1…`: a TLV sequence (`[type, len, value]…`) under bech32m.
    pub fn encode(&self) -> String {
        let mut payload = Vec::new();
        if let Some(account) = &self.transparent {
            let bytes = account.as_str().as_bytes();
            payload.push(UA_TYPE_TRANSPARENT);
            payload.push(bytes.len() as u8); // account ids are short by charset rule
            payload.extend_from_slice(bytes);
        }
        if let Some(address) = &self.shielded {
            payload.push(UA_TYPE_SHIELDED);
            payload.push(43);
            payload.extend_from_slice(&address.to_bytes());
        }
        encode(HRP_UNIFIED, &payload)
    }

    /// Decode a `uxus1…` unified address. Unknown receiver typecodes are skipped
    /// (forward compatibility: an old wallet can still pay a newer UA through
    /// the receivers it understands), duplicates are rejected, and at least
    /// one known receiver must be present.
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let (hrp, payload) = decode(s)?;
        if hrp != HRP_UNIFIED {
            return Err(AddressError::WrongKind {
                expected: HRP_UNIFIED,
                got: hrp,
            });
        }
        let mut transparent: Option<AccountId> = None;
        let mut shielded: Option<ShieldedAddress> = None;
        let mut i = 0usize;
        while i < payload.len() {
            if i + 2 > payload.len() {
                return Err(AddressError::Payload("unified"));
            }
            let (ty, len) = (payload[i], payload[i + 1] as usize);
            i += 2;
            if i + len > payload.len() {
                return Err(AddressError::Payload("unified"));
            }
            let value = &payload[i..i + len];
            i += len;
            match ty {
                UA_TYPE_TRANSPARENT => {
                    if transparent.is_some() {
                        return Err(AddressError::DuplicateReceiver(ty));
                    }
                    let name =
                        std::str::from_utf8(value).map_err(|_| AddressError::Payload("unified"))?;
                    transparent =
                        Some(AccountId::new(name).map_err(|_| AddressError::Payload("unified"))?);
                }
                UA_TYPE_SHIELDED => {
                    if shielded.is_some() {
                        return Err(AddressError::DuplicateReceiver(ty));
                    }
                    let bytes: [u8; 43] = value
                        .try_into()
                        .map_err(|_| AddressError::Payload("unified"))?;
                    shielded = Some(
                        ShieldedAddress::from_bytes(&bytes)
                            .ok_or(AddressError::Payload("unified"))?,
                    );
                }
                // Unknown receiver kinds from a future wallet: skip them.
                _ => {}
            }
        }
        UnifiedAddress::new(transparent, shielded)
    }

    /// The receiver a sender should pay: **shielded when present** (privacy
    /// by default), transparent otherwise.
    pub fn preferred(&self) -> Receiver {
        if let Some(address) = &self.shielded {
            Receiver::Shielded(address.clone())
        } else {
            Receiver::Transparent(
                self.transparent
                    .clone()
                    .expect("UnifiedAddress::new guarantees at least one receiver"),
            )
        }
    }
}

/// Any recipient a payment flow can accept: a bare named account, a `xus1…`
/// shielded address, or a `uxus1…` unified address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyAddress {
    /// A named account (`alice.actor.sov`) — the transparent tier.
    Transparent(AccountId),
    /// A `xus1…` shielded receiver.
    Shielded(ShieldedAddress),
    /// A `uxus1…` unified address.
    Unified(UnifiedAddress),
}

impl AnyAddress {
    /// Parse a recipient string of any tier. Order: `xus1…`/`uxus1…` prefixes
    /// are unambiguous (the shielded HRP `xus` is not a prefix of the unified
    /// HRP `uxus`, and a named account can never start with a digit-bearing
    /// `…1` HRP separator under bech32m); anything else must be a valid named
    /// account.
    pub fn parse(s: &str) -> Result<AnyAddress, AddressError> {
        let lower = s.to_lowercase();
        if lower.starts_with("xus1") {
            return decode_shielded(s).map(AnyAddress::Shielded);
        }
        if lower.starts_with("uxus1") {
            return UnifiedAddress::decode(s).map(AnyAddress::Unified);
        }
        AccountId::new(s)
            .map(AnyAddress::Transparent)
            .map_err(|_| AddressError::Payload("recipient"))
    }

    /// The receiver a sender should pay, privacy-first: shielded whenever the
    /// address carries one, the named account otherwise.
    pub fn receiver(&self) -> Receiver {
        match self {
            AnyAddress::Transparent(account) => Receiver::Transparent(account.clone()),
            AnyAddress::Shielded(address) => Receiver::Shielded(address.clone()),
            AnyAddress::Unified(ua) => ua.preferred(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ShieldedKey;

    fn z() -> ShieldedAddress {
        ShieldedKey::from_seed([7u8; 32]).unwrap().address()
    }
    fn t() -> AccountId {
        AccountId::new("alice.actor.sov").unwrap()
    }

    #[test]
    fn shielded_address_roundtrips_and_starts_with_xus1() {
        let s = encode_shielded(&z());
        assert!(s.starts_with("xus1"), "got {s}");
        assert_eq!(decode_shielded(&s).unwrap(), z());
        // bech32m is case-insensitive: the fully-uppercase form decodes too.
        assert_eq!(decode_shielded(&s.to_uppercase()).unwrap(), z());
    }

    #[test]
    fn unified_address_roundtrips_and_prefers_shielded() {
        let ua = UnifiedAddress::new(Some(t()), Some(z())).unwrap();
        let s = ua.encode();
        assert!(s.starts_with("uxus1"), "got {s}");
        let back = UnifiedAddress::decode(&s).unwrap();
        assert_eq!(back, ua);
        // Privacy by default: the routing rule picks the shielded receiver.
        assert_eq!(back.preferred(), Receiver::Shielded(z()));

        // Transparent-only UA routes transparently; empty UA is impossible.
        let t_only = UnifiedAddress::new(Some(t()), None).unwrap();
        let back = UnifiedAddress::decode(&t_only.encode()).unwrap();
        assert_eq!(back.preferred(), Receiver::Transparent(t()));
        assert_eq!(
            UnifiedAddress::new(None, None),
            Err(AddressError::NoKnownReceiver)
        );
    }

    #[test]
    fn tampering_and_wrong_kinds_are_rejected() {
        let s = encode_shielded(&z());
        // Flip one character: the bech32m checksum catches it.
        let mut chars: Vec<char> = s.chars().collect();
        let last = *chars.last().unwrap();
        *chars.last_mut().unwrap() = if last == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            decode_shielded(&tampered),
            Err(AddressError::Encoding(_))
        ));

        // A unified string is not a shielded address.
        let ua = UnifiedAddress::new(Some(t()), Some(z())).unwrap();
        assert!(matches!(
            decode_shielded(&ua.encode()),
            Err(AddressError::WrongKind { .. })
        ));
        // Garbage payload under the right HRP is rejected.
        assert!(matches!(
            decode_shielded(&encode("xus", &[0u8; 10])),
            Err(AddressError::Payload(_))
        ));
    }

    #[test]
    fn any_address_parses_all_three_tiers_and_routes_privacy_first() {
        // Named account.
        let a = AnyAddress::parse("alice.actor.sov").unwrap();
        assert_eq!(a.receiver(), Receiver::Transparent(t()));
        // xus1… shielded.
        let a = AnyAddress::parse(&encode_shielded(&z())).unwrap();
        assert_eq!(a.receiver(), Receiver::Shielded(z()));
        // uxus1… unified with both: routes SHIELDED (privacy by default).
        let ua = UnifiedAddress::new(Some(t()), Some(z())).unwrap();
        let a = AnyAddress::parse(&ua.encode()).unwrap();
        assert_eq!(a.receiver(), Receiver::Shielded(z()));
        // Garbage is rejected, not guessed at.
        assert!(AnyAddress::parse("not an address!").is_err());
        assert!(AnyAddress::parse("xus1garbage").is_err());
    }

    #[test]
    fn unified_decode_skips_unknown_receivers_and_rejects_duplicates() {
        // Forward compatibility: a UA with an unknown receiver type (0x7f)
        // plus a known transparent receiver still decodes via the known one.
        let acct = t();
        let bytes = acct.as_str().as_bytes();
        let mut payload = vec![0x7f, 3, 0xaa, 0xbb, 0xcc];
        payload.push(UA_TYPE_TRANSPARENT);
        payload.push(bytes.len() as u8);
        payload.extend_from_slice(bytes);
        let ua = UnifiedAddress::decode(&encode("uxus", &payload)).unwrap();
        assert_eq!(ua.transparent, Some(acct.clone()));

        // ONLY unknown receivers: rejected (nothing to pay).
        let only_unknown = encode("uxus", &[0x7f, 1, 0x00]);
        assert_eq!(
            UnifiedAddress::decode(&only_unknown),
            Err(AddressError::NoKnownReceiver)
        );

        // Duplicate known receivers: rejected.
        let mut dup = Vec::new();
        for _ in 0..2 {
            dup.push(UA_TYPE_TRANSPARENT);
            dup.push(bytes.len() as u8);
            dup.extend_from_slice(bytes);
        }
        assert_eq!(
            UnifiedAddress::decode(&encode("uxus", &dup)),
            Err(AddressError::DuplicateReceiver(UA_TYPE_TRANSPARENT))
        );
    }
}
