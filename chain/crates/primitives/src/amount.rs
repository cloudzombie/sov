//! Token amounts and the protocol supply cap.
//!
//! SOV amounts are integer counts of the smallest indivisible unit, the
//! *grain*. One SOV = 10^[`DECIMALS`] grains. Using an integer (`u128`) base
//! type makes arithmetic exact — no floating point ever touches a balance — and
//! all arithmetic is checked, so an overflow or an underflow surfaces as an
//! error rather than silently corrupting state.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Number of decimal places: 1 SOV = 10^8 grains — the exact precision of
/// Bitcoin (satoshi) and Zcash (zatoshi), i.e. units of `1.00000000`.
pub const DECIMALS: u32 = 8;

/// Grains per whole SOV.
pub const GRAINS_PER_SOV: u128 = 10u128.pow(DECIMALS);

/// The hard cap on total supply, in whole SOV. Per the blueprint, SOV targets
/// ultra-scarcity; the cap is fixed at the upper bound of the 10–21M range and
/// enforced by the protocol — no code path may mint beyond it.
pub const MAX_SUPPLY_SOV: u128 = 21_000_000;

/// The hard cap on total supply, in grains.
pub const MAX_SUPPLY_GRAINS: u128 = MAX_SUPPLY_SOV * GRAINS_PER_SOV;

/// A quantity of SOV, measured in grains.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, BorshSerialize, BorshDeserialize,
)]
pub struct Balance(u128);

impl Balance {
    /// Zero grains.
    pub const ZERO: Balance = Balance(0);

    /// The maximum representable supply, as a balance.
    pub const MAX_SUPPLY: Balance = Balance(MAX_SUPPLY_GRAINS);

    /// Construct from a raw grain count.
    pub const fn from_grains(grains: u128) -> Self {
        Balance(grains)
    }

    /// Construct from a whole number of SOV, erroring if it would exceed the
    /// representable range.
    pub fn from_sov(sov: u128) -> Result<Self, BalanceError> {
        sov.checked_mul(GRAINS_PER_SOV)
            .map(Balance)
            .ok_or(BalanceError::Overflow)
    }

    /// The raw grain count.
    pub const fn grains(self) -> u128 {
        self.0
    }

    /// Checked addition; `None` on overflow.
    pub fn checked_add(self, rhs: Balance) -> Option<Balance> {
        self.0.checked_add(rhs.0).map(Balance)
    }

    /// Checked subtraction; `None` if `rhs > self` (would underflow).
    pub fn checked_sub(self, rhs: Balance) -> Option<Balance> {
        self.0.checked_sub(rhs.0).map(Balance)
    }

    /// Whether this amount is within the protocol supply cap.
    pub const fn within_cap(self) -> bool {
        self.0 <= MAX_SUPPLY_GRAINS
    }
}

impl fmt::Display for Balance {
    /// Render as a decimal XUS value (the ticker), trimming trailing zeros.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / GRAINS_PER_SOV;
        let frac = self.0 % GRAINS_PER_SOV;
        if frac == 0 {
            write!(f, "{whole} XUS")
        } else {
            let frac_str = format!("{frac:0width$}", width = DECIMALS as usize);
            write!(f, "{whole}.{} XUS", frac_str.trim_end_matches('0'))
        }
    }
}

impl fmt::Debug for Balance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Balance({} grains)", self.0)
    }
}

// JSON/RPC encoding: a decimal string of grains. Balance is a u128 whose range
// far exceeds JavaScript's safe-integer limit (2^53), so encoding as a number
// could silently corrupt values in JS clients like the explorer; a string is
// always exact. Borsh (consensus) is handled by the derives above and uses the
// exact 16-byte integer.
impl Serialize for Balance {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Balance {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        let grains = s.parse::<u128>().map_err(de::Error::custom)?;
        Ok(Balance(grains))
    }
}

/// Error returned by fallible balance arithmetic.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BalanceError {
    /// An operation overflowed the representable range.
    #[error("balance arithmetic overflowed")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sov_to_grains() {
        assert_eq!(Balance::from_sov(1).unwrap().grains(), GRAINS_PER_SOV);
        assert_eq!(Balance::from_sov(0).unwrap(), Balance::ZERO);
    }

    #[test]
    fn checked_arithmetic() {
        let a = Balance::from_sov(5).unwrap();
        let b = Balance::from_sov(3).unwrap();
        assert_eq!(a.checked_add(b).unwrap(), Balance::from_sov(8).unwrap());
        assert_eq!(a.checked_sub(b).unwrap(), Balance::from_sov(2).unwrap());
        // Underflow is rejected, not wrapped.
        assert_eq!(b.checked_sub(a), None);
        // Overflow is rejected, not wrapped.
        assert_eq!(
            Balance::from_grains(u128::MAX).checked_add(Balance::from_grains(1)),
            None
        );
    }

    #[test]
    fn supply_cap_invariant() {
        assert!(Balance::MAX_SUPPLY.within_cap());
        assert!(!Balance::from_grains(MAX_SUPPLY_GRAINS + 1).within_cap());
    }

    #[test]
    fn display_trims_fraction() {
        assert_eq!(Balance::from_sov(7).unwrap().to_string(), "7 XUS");
        // 1.5 XUS
        assert_eq!(
            Balance::from_grains(GRAINS_PER_SOV + GRAINS_PER_SOV / 2).to_string(),
            "1.5 XUS"
        );
    }

    #[test]
    fn from_sov_overflow() {
        assert_eq!(Balance::from_sov(u128::MAX), Err(BalanceError::Overflow));
    }

    #[test]
    fn json_is_decimal_string() {
        // One whole SOV = 10^8 grains (Bitcoin/Zcash precision), encoded as a string.
        let one = Balance::from_sov(1).unwrap();
        assert_eq!(serde_json::to_string(&one).unwrap(), "\"100000000\"");
        assert_eq!(
            serde_json::from_str::<Balance>("\"100000000\"").unwrap(),
            one
        );
    }

    #[test]
    fn hard_cap_is_21m_with_8_decimals() {
        assert_eq!(DECIMALS, 8);
        assert_eq!(GRAINS_PER_SOV, 100_000_000);
        assert_eq!(MAX_SUPPLY_SOV, 21_000_000);
        // 21,000,000 * 1.00000000 = 2,100,000,000,000,000 grains.
        assert_eq!(MAX_SUPPLY_GRAINS, 2_100_000_000_000_000);
    }

    #[test]
    fn json_roundtrips_full_cap() {
        // The entire 21M supply must survive a JSON round-trip without loss.
        let cap = Balance::MAX_SUPPLY;
        let json = serde_json::to_string(&cap).unwrap();
        assert_eq!(serde_json::from_str::<Balance>(&json).unwrap(), cap);
    }
}
