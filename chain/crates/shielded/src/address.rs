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

use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use sov_primitives::AccountId;
use sov_shielded_pq::{PqAddress, PQ_ADDRESS_LEN};

use crate::keys::ShieldedAddress;

/// Human-readable part of a shielded address (`xus1…`).
const HRP_SHIELDED: &str = "xus";
/// Human-readable part of a unified address (`uxus1…`).
const HRP_UNIFIED: &str = "uxus";
/// Human-readable part of a post-quantum (pool v2) shielded address
/// (`xusq1…`) — decision D8.
const HRP_SHIELDED_V2: &str = "xusq";

/// Unified-address TLV typecode: a transparent account id (UTF-8).
const UA_TYPE_TRANSPARENT: u8 = 0x00;
/// Unified-address TLV typecode: a 43-byte Orchard shielded receiver.
const UA_TYPE_SHIELDED: u8 = 0x01;
/// Unified-address TLV typecode: a [`PQ_ADDRESS_LEN`]-byte post-quantum
/// (pool v2) receiver, carried as [`UA_V2_CHUNKS`] consecutive records —
/// see [`UA_V2_CHUNK`] for why.
const UA_TYPE_SHIELDED_V2: u8 = 0x02;

/// Maximum bytes one unified-address TLV record can carry: the container's
/// length field is a single byte, and that container is already deployed.
///
/// A pool-v2 receiver is [`PQ_ADDRESS_LEN`] (1216) bytes — a 32-byte owner
/// tag plus a 1184-byte ML-KEM-768 encapsulation key. That does not fit one
/// record, and widening the length field is **not** an option: an
/// already-shipped parser reads exactly one length byte, so a wider field
/// would desync it and break forward-compatibility law F3 (older parsers
/// must SKIP a receiver they do not understand, not choke on it).
///
/// So the v2 receiver is split across consecutive records that all carry
/// typecode [`UA_TYPE_SHIELDED_V2`]. An older parser sees several unknown
/// typecodes and skips each one correctly — its duplicate-receiver check
/// only applies to the typecodes it knows — which is exactly what F3
/// requires. A v2-aware parser concatenates them in order.
///
/// The chunking is canonical: every record but the last is exactly
/// [`UA_V2_CHUNK`] bytes, the last carries the remainder, and there are
/// exactly [`UA_V2_CHUNKS`] of them. Any other shape is rejected, so
/// `encode(decode(s)) == s` for every accepted `s`.
const UA_V2_CHUNK: usize = 255;

/// Number of TLV records one v2 receiver occupies.
const UA_V2_CHUNKS: usize = PQ_ADDRESS_LEN.div_ceil(UA_V2_CHUNK);

/// Bech32m with the code-length restriction lifted — the same choice Zcash
/// makes for unified addresses (ZIP-316).
///
/// The `bech32` crate refuses strings longer than 1023 characters, because
/// beyond the BCH code length the checksum stops *guaranteeing* detection of
/// up to 4 errors. A pool-v2 address is 1216 bytes of key material, i.e.
/// ~1950 characters, so that bound cannot be met by any encoding of it: the
/// size is inherent to a lattice KEM, not a choice.
///
/// This type reuses the crate's Bech32m checksum engine verbatim — the same
/// generator polynomial and target residue, nothing hand-rolled — and only
/// raises `CODE_LENGTH`. What is kept: a 30-bit checksum, so a corrupted
/// address is accepted with probability ~2^-30, and the character set,
/// case-insensitivity and HRP separation are unchanged. What is given up:
/// the *guaranteed* 4-error detection distance. Tests exercise every
/// single-character substitution position on a full-length v2 address and
/// assert every one is rejected.
struct Bech32mLong;

impl Checksum for Bech32mLong {
    type MidstateRepr = <Bech32m as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = <Bech32m as Checksum>::CHECKSUM_LENGTH;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = <Bech32m as Checksum>::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = <Bech32m as Checksum>::TARGET_RESIDUE;
}

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
    /// The pool-v2 receiver's chunk sequence was not the canonical one.
    #[error("non-canonical pool-v2 receiver chunking in a unified address")]
    V2Chunking,
}

fn encode(hrp: &str, payload: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("static HRPs are valid");
    bech32::encode::<Bech32mLong>(hrp, payload).expect("Bech32mLong imposes no length bound")
}

/// Strict bech32m decode (the Bech32m checksum specifically; plain bech32 is
/// rejected), returning the lowercase HRP and payload bytes.
///
/// Uses [`Bech32mLong`], which is byte-for-byte the Bech32m checksum with the
/// 1023-character code-length cap lifted (see that type's docs). Every string
/// the stock decoder accepts is accepted here identically; the only strings
/// this additionally admits are ones longer than 1023 characters, which
/// only a pool-v2 receiver produces.
fn decode(s: &str) -> Result<(String, Vec<u8>), AddressError> {
    let checked = CheckedHrpstring::new::<Bech32mLong>(s)
        .map_err(|e| AddressError::Encoding(e.to_string()))?;
    let hrp = checked.hrp().to_lowercase();
    let payload = checked.byte_iter().collect();
    Ok((hrp, payload))
}

/// Append a pool-v2 receiver to a unified-address payload as the canonical
/// [`UA_V2_CHUNKS`] TLV records.
fn push_v2_receiver(payload: &mut Vec<u8>, address: &PqAddress) {
    let bytes = address.to_bytes();
    debug_assert_eq!(bytes.len(), PQ_ADDRESS_LEN);
    for chunk in bytes.chunks(UA_V2_CHUNK) {
        payload.push(UA_TYPE_SHIELDED_V2);
        payload.push(chunk.len() as u8); // <= UA_V2_CHUNK = 255
        payload.extend_from_slice(chunk);
    }
}

/// Encode a pool-v2 receiver as a standalone `xusq1…` address (D8).
pub fn encode_shielded_v2(address: &PqAddress) -> String {
    encode(HRP_SHIELDED_V2, &address.to_bytes())
}

/// Decode an `xusq1…` post-quantum shielded address.
pub fn decode_shielded_v2(s: &str) -> Result<PqAddress, AddressError> {
    let (hrp, payload) = decode(s)?;
    if hrp != HRP_SHIELDED_V2 {
        return Err(AddressError::WrongKind {
            expected: HRP_SHIELDED_V2,
            got: hrp,
        });
    }
    PqAddress::from_bytes(&payload).ok_or(AddressError::Payload("shielded-v2"))
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
    /// The post-quantum (pool v2) receiver, if included (D8).
    pub shielded_v2: Option<PqAddress>,
}

/// The receiver a sending wallet should use, in privacy order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receiver {
    /// Route into the post-quantum shielded pool (pool v2).
    ///
    /// BOXED deliberately: a `PqAddress` carries ML-KEM key material and is
    /// ~1216 bytes, so holding it inline would make every `Receiver` that
    /// large — including a transparent one, which is 32 bytes. Boxing keeps
    /// the common routes cheap.
    ShieldedV2(Box<PqAddress>),
    /// Route into the shielded pool (the private default).
    Shielded(ShieldedAddress),
    /// Pay the named account transparently.
    Transparent(AccountId),
}

impl UnifiedAddress {
    /// Build a unified address with the transparent and pool-v1 receivers.
    /// At least one receiver must be present.
    ///
    /// Kept at two arguments so every existing caller compiles unchanged;
    /// add a pool-v2 receiver with [`with_shielded_v2`](Self::with_shielded_v2).
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
            shielded_v2: None,
        })
    }

    /// Build a unified address from any combination of the three receivers.
    /// At least one must be present.
    pub fn with_receivers(
        transparent: Option<AccountId>,
        shielded: Option<ShieldedAddress>,
        shielded_v2: Option<PqAddress>,
    ) -> Result<Self, AddressError> {
        if transparent.is_none() && shielded.is_none() && shielded_v2.is_none() {
            return Err(AddressError::NoKnownReceiver);
        }
        Ok(UnifiedAddress {
            transparent,
            shielded,
            shielded_v2,
        })
    }

    /// Attach a pool-v2 receiver, consuming and returning the address.
    pub fn with_shielded_v2(mut self, address: PqAddress) -> Self {
        self.shielded_v2 = Some(address);
        self
    }

    /// Encode as `uxus1…`: a TLV sequence (`[type, len, value]…`) under bech32m.
    ///
    /// Receivers are emitted in ascending typecode order — transparent
    /// (`0x00`), pool v1 (`0x01`), then pool v2 (`0x02`, as
    /// [`UA_V2_CHUNKS`] consecutive records). The order is fixed so the
    /// encoding is canonical and `encode(decode(s)) == s`.
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
        if let Some(address) = &self.shielded_v2 {
            push_v2_receiver(&mut payload, address);
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
        // Accumulated pool-v2 chunks. Bounded to PQ_ADDRESS_LEN: the buffer
        // is pre-sized to the ONE legal size (a constant, not a length read
        // from the input), and any chunk that would overflow it is rejected
        // immediately, so a hostile address cannot drive unbounded work or
        // memory here.
        let mut v2_bytes: Vec<u8> = Vec::with_capacity(PQ_ADDRESS_LEN);
        let mut v2_chunks = 0usize;
        let mut v2_complete = false;
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
                UA_TYPE_SHIELDED_V2 => {
                    // Canonical chunking: exactly UA_V2_CHUNKS records, each
                    // of the exact expected length, appearing consecutively.
                    if v2_complete || v2_chunks >= UA_V2_CHUNKS {
                        return Err(AddressError::V2Chunking);
                    }
                    let expected = core::cmp::min(UA_V2_CHUNK, PQ_ADDRESS_LEN - v2_bytes.len());
                    if len != expected {
                        return Err(AddressError::V2Chunking);
                    }
                    v2_bytes.extend_from_slice(value);
                    v2_chunks += 1;
                    v2_complete = v2_bytes.len() == PQ_ADDRESS_LEN;
                }
                // Unknown receiver kinds from a future wallet: skip them.
                _ => {}
            }
        }
        // A partial v2 receiver is a malformed address, not a skippable one:
        // the chunks are ours, so we must not silently drop half of them.
        if v2_chunks != 0 && !v2_complete {
            return Err(AddressError::V2Chunking);
        }
        let shielded_v2 = if v2_complete {
            Some(PqAddress::from_bytes(&v2_bytes).ok_or(AddressError::Payload("unified"))?)
        } else {
            None
        };
        UnifiedAddress::with_receivers(transparent, shielded, shielded_v2)
    }

    /// The receiver a sender should pay: **shielded when present** (privacy
    /// by default), transparent otherwise.
    ///
    /// This is the pool-v2-**unaware** route, and it is deliberately
    /// unchanged: pool v2 is dormant (signal bit 2 is defined but not
    /// armed), so a wallet that routed to it today would build a payment no
    /// chain can execute. Once the deployment is Active, sending paths use
    /// [`preferred_pq`](Self::preferred_pq), which implements the D8 order.
    pub fn preferred(&self) -> Receiver {
        if let Some(address) = &self.shielded {
            return Receiver::Shielded(address.clone());
        }
        if let Some(account) = &self.transparent {
            return Receiver::Transparent(account.clone());
        }
        // Only a v2 receiver is present: there is nothing else to route to,
        // so surface it rather than inventing a receiver. The caller must
        // reject it while the deployment is dormant.
        Receiver::ShieldedV2(Box::new(
            self.shielded_v2
                .clone()
                .expect("UnifiedAddress guarantees at least one receiver"),
        ))
    }

    /// The receiver a **pool-v2-aware** sender should pay, in the D8 privacy
    /// order: post-quantum shielded, then shielded v1, then transparent.
    ///
    /// Only call this once the `shielded-v2` deployment is Active on the
    /// chain being paid; before then use [`preferred`](Self::preferred).
    pub fn preferred_pq(&self) -> Receiver {
        if let Some(address) = &self.shielded_v2 {
            return Receiver::ShieldedV2(Box::new(address.clone()));
        }
        self.preferred()
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
    /// A `xusq1…` post-quantum (pool v2) receiver.
    ShieldedV2(PqAddress),
    /// A `uxus1…` unified address.
    Unified(UnifiedAddress),
}

impl AnyAddress {
    /// Parse a recipient string of any tier. The three bech32m prefixes are
    /// unambiguous — `xusq1…` is tested before `xus1…` (`xus` is a prefix of
    /// `xusq`, but `xus1` is not a prefix of `xusq1`, and testing the longer
    /// HRP first makes that independent of the reader's care), `uxus` starts
    /// with a different letter, and a named account can never contain the
    /// `…1` HRP separator in those positions. Anything else must be a valid
    /// named account.
    pub fn parse(s: &str) -> Result<AnyAddress, AddressError> {
        let lower = s.to_lowercase();
        if lower.starts_with("xusq1") {
            return decode_shielded_v2(s).map(AnyAddress::ShieldedV2);
        }
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
    /// address carries one, the named account otherwise. Pool-v2-unaware —
    /// see [`UnifiedAddress::preferred`].
    pub fn receiver(&self) -> Receiver {
        match self {
            AnyAddress::Transparent(account) => Receiver::Transparent(account.clone()),
            AnyAddress::Shielded(address) => Receiver::Shielded(address.clone()),
            AnyAddress::ShieldedV2(address) => Receiver::ShieldedV2(Box::new(address.clone())),
            AnyAddress::Unified(ua) => ua.preferred(),
        }
    }

    /// The receiver a **pool-v2-aware** sender should pay, in the D8 order
    /// (v2 > v1 > transparent). Only for chains where the `shielded-v2`
    /// deployment is Active — see [`UnifiedAddress::preferred_pq`].
    pub fn receiver_pq(&self) -> Receiver {
        match self {
            AnyAddress::Unified(ua) => ua.preferred_pq(),
            other => other.receiver(),
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
