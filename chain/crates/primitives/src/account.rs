//! Human-readable account identifiers.
//!
//! SOV uses named accounts rather than raw public-key addresses, enabling
//! institutional identities like `usa.reserve.sov` or `val01.node.sov`. An
//! [`AccountId`] is a validated, normalized string; construction is the only
//! way to obtain one, so any `AccountId` in the system is guaranteed well-formed.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A validated account identifier.
///
/// Rules (checked by [`AccountId::new`]):
/// - length in `[MIN_LEN, MAX_LEN]`;
/// - characters limited to `a-z`, `0-9`, and the separators `-`, `_`, `.`;
/// - separators may not lead, trail, or be adjacent to one another.
///
/// The `.` separator is significant: it denotes hierarchy, so `reserve.sov` is
/// a sub-account namespace under the top-level `sov` registrar.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct AccountId(String);

impl AccountId {
    /// Minimum identifier length, in bytes.
    pub const MIN_LEN: usize = 2;
    /// Maximum identifier length, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validate and construct an account id.
    pub fn new(raw: impl Into<String>) -> Result<Self, AccountIdError> {
        let id = raw.into();
        Self::validate(&id)?;
        Ok(AccountId(id))
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The top-level segment after the final `.`, e.g. `sov` in `reserve.sov`.
    /// Returns the whole id if there is no separator.
    pub fn top_level(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    /// Whether this is an *implicit* (key-derived) account id: exactly 64
    /// lowercase hex characters.
    ///
    /// Implicit ids are reserved. An implicit account may only ever be
    /// key-bound to the key whose hash **is** the id — consensus enforces this
    /// at `Action::RotateKey`, so an implicit account can never be
    /// name-squatted. A miner's coinbase pays an implicit id, so mined
    /// funds are claimable solely by the holder of the mining key. Human-named
    /// accounts (`usa.reserve.sov`) never collide with this pattern, so they
    /// keep first-come registration for fresh, unfunded names.
    pub fn is_implicit(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// Whether this id is a **registrable name** for the on-chain name registry:
    /// a human-readable `*.sov` id (a non-empty label before the `.sov`
    /// top level) that is not a reserved implicit (64-hex) id. A registered name
    /// is an ENS/SNS-style alias that *resolves* to an account; it does not hold
    /// funds itself. Whether a given name is actually *claimable* (unregistered,
    /// not shadowing an existing keyed account) is a consensus check that needs
    /// the ledger — this only validates the name's shape. See
    /// [`Action::RegisterName`](../../sov_types/enum.Action.html).
    pub fn is_registrable_name(&self) -> bool {
        !self.is_implicit() && self.0.ends_with(".sov")
    }

    fn validate(id: &str) -> Result<(), AccountIdError> {
        let len = id.len();
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&len) {
            return Err(AccountIdError::Length { len });
        }

        let bytes = id.as_bytes();
        let is_sep = |b: u8| b == b'-' || b == b'_' || b == b'.';

        // Cannot lead or trail with a separator.
        if is_sep(bytes[0]) || is_sep(bytes[len - 1]) {
            return Err(AccountIdError::EdgeSeparator);
        }

        let mut prev_sep = false;
        for &b in bytes {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || is_sep(b);
            if !ok {
                return Err(AccountIdError::InvalidChar { ch: b as char });
            }
            if is_sep(b) {
                if prev_sep {
                    return Err(AccountIdError::AdjacentSeparators);
                }
                prev_sep = true;
            } else {
                prev_sep = false;
            }
        }
        Ok(())
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({:?})", self.0)
    }
}

impl Serialize for AccountId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = <String as Deserialize>::deserialize(d)?;
        AccountId::new(raw).map_err(de::Error::custom)
    }
}

/// Error returned when an account id fails validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountIdError {
    /// Length outside `[MIN_LEN, MAX_LEN]`.
    #[error("account id length {len} is outside [{min}, {max}]", min = AccountId::MIN_LEN, max = AccountId::MAX_LEN)]
    Length {
        /// The offending length.
        len: usize,
    },
    /// A disallowed character was present.
    #[error("invalid character {ch:?} in account id")]
    InvalidChar {
        /// The offending character.
        ch: char,
    },
    /// A separator appeared at the start or end.
    #[error("account id may not start or end with a separator")]
    EdgeSeparator,
    /// Two separators appeared back to back.
    #[error("account id may not contain adjacent separators")]
    AdjacentSeparators,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_ids() {
        for id in [
            "usa.reserve.sov",
            "val01.node.sov",
            "treasury.sov",
            "ab",
            "a-b_c",
        ] {
            assert!(AccountId::new(id).is_ok(), "{id} should be valid");
        }
    }

    #[test]
    fn rejects_malformed_ids() {
        assert!(matches!(
            AccountId::new("a"),
            Err(AccountIdError::Length { len: 1 })
        ));
        assert!(matches!(
            AccountId::new(".sov"),
            Err(AccountIdError::EdgeSeparator)
        ));
        assert!(matches!(
            AccountId::new("sov."),
            Err(AccountIdError::EdgeSeparator)
        ));
        assert!(matches!(
            AccountId::new("a..b"),
            Err(AccountIdError::AdjacentSeparators)
        ));
        assert!(matches!(
            AccountId::new("USA.sov"),
            Err(AccountIdError::InvalidChar { ch: 'U' })
        ));
        assert!(matches!(
            AccountId::new("a b"),
            Err(AccountIdError::InvalidChar { ch: ' ' })
        ));
    }

    #[test]
    fn implicit_ids_are_exactly_64_lowercase_hex() {
        // A 64-char lowercase-hex id (what a key hash encodes to) is implicit.
        let hexish = "0123456789abcdef".repeat(4);
        assert_eq!(hexish.len(), 64);
        assert!(AccountId::new(&hexish).unwrap().is_implicit());

        // Human-named accounts never match the implicit pattern.
        for named in ["usa.reserve.sov", "val01.node.sov", "treasury.sov", "ab"] {
            assert!(!AccountId::new(named).unwrap().is_implicit(), "{named}");
        }
        // Right length but a non-hex char (`g`, or the `.` separator) is not implicit.
        assert!(!AccountId::new("g".to_string() + &"0".repeat(63))
            .unwrap()
            .is_implicit());
        let dotted = "a".repeat(31) + "." + &"b".repeat(32);
        assert_eq!(dotted.len(), 64);
        assert!(!AccountId::new(&dotted).unwrap().is_implicit());
    }

    #[test]
    fn registrable_names_are_dot_sov_and_not_implicit() {
        for name in ["treasury.sov", "josh.sov", "usa.reserve.sov", "a.sov"] {
            assert!(
                AccountId::new(name).unwrap().is_registrable_name(),
                "{name} should be a registrable name"
            );
        }
        // Not ending in .sov, or an implicit 64-hex id, is not a name.
        for non in ["treasury", "josh.eth", "ab", "sov"] {
            assert!(
                !AccountId::new(non).unwrap().is_registrable_name(),
                "{non} should NOT be a registrable name"
            );
        }
        let hexish = "0123456789abcdef".repeat(4);
        assert!(!AccountId::new(&hexish).unwrap().is_registrable_name());
    }

    #[test]
    fn top_level_segment() {
        assert_eq!(
            AccountId::new("usa.reserve.sov").unwrap().top_level(),
            "sov"
        );
        assert_eq!(AccountId::new("treasury").unwrap().top_level(), "treasury");
    }

    #[test]
    fn json_roundtrip() {
        let id = AccountId::new("ecb.reserve.sov").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"ecb.reserve.sov\"");
        assert_eq!(serde_json::from_str::<AccountId>(&json).unwrap(), id);
    }

    #[test]
    fn deserialize_rejects_invalid() {
        assert!(serde_json::from_str::<AccountId>("\"BAD\"").is_err());
    }
}
