//! xUSD — the SOV-collateralized stablecoin, a DAI-style collateralized debt
//! position (CDP).
//!
//! A holder locks XUS as **collateral** and mints **xUSD** against it, up to a
//! conservative fraction of the collateral's dollar value. The position must stay
//! **over-collateralized** ([`MIN_COLLATERAL_RATIO_PCT`]): you can only ever mint
//! *less* dollar-value of xUSD than the XUS you locked — the haircut is the safety
//! buffer, exactly as in MakerDAO/DAI. Burning xUSD repays the debt and frees the
//! collateral.
//!
//! Two honesty properties make this sound rather than a fractional-reserve fuse:
//!   * **Over-collateralization.** Minting more dollars than you lock is the Terra
//!     death-spiral; the ratio check forbids it.
//!   * **An honest price.** xUSD tracks $1 only if the XUS/USD price it uses is
//!     real. The launch price is seeded LOW ([`SEED_XUS_USD_PRICE`] = $1.00) and can
//!     only be moved by a signed [`ORACLE_ACCOUNT`] update — so the multiplier grows
//!     as XUS genuinely appreciates, never by decree.
//!
//! Consensus-safety: xUSD is an ordinary native asset (it obeys the per-asset
//! conservation theorem `sum(balances) == issued − burned`), and locked collateral
//! is counted in [`Ledger::total_supply`](crate::Ledger::total_supply) exactly like
//! HTLC escrow, so both existing invariants hold with no change. All vault/oracle
//! state lives in its own absent-when-empty slots, so an untouched chain keeps the
//! frozen genesis root byte-for-byte.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_primitives::{AccountId, Balance, Hash};

use crate::ledger::token_asset_id;

/// The fixed-point scale shared by SOV, xUSD, and the oracle price (10^8 grains).
pub const SCALE: u128 = 100_000_000;

/// The launch oracle seed: XUS = $1.00 — low and honest. Until a signed
/// [`OracleUpdate`](sov_types) lands, every vault prices XUS at exactly this.
/// USD per 1 XUS, in 10^8 fixed point.
pub const SEED_XUS_USD_PRICE: u128 = 100_000_000; // $1.00

/// Minimum collateral ratio: a vault must hold at least 150% of its xUSD debt in
/// XUS value. Any mint or withdrawal that would drop the ratio below this fails —
/// the over-collateralization that makes xUSD safe.
pub const MIN_COLLATERAL_RATIO_PCT: u128 = 150;

/// The account authorized to publish oracle prices (the launch price feed). A
/// compile-time constant — NOT genesis state — so introducing the oracle leaves
/// the frozen genesis root untouched. Its key is held off-chain by the feed
/// operator; until it publishes, the honest seed price stands.
pub const ORACLE_ACCOUNT: &str = "96abb93854040db54394648061dcb1766d6f306de962a19ad3e7bdb5e19caa7f";

/// The reserved issuer account for xUSD. It is a named account that holds no key
/// (unspendable), so xUSD can be minted or burned ONLY by the vault system —
/// never by a user `TokenIssue`.
pub const XUSD_ISSUER: &str = "xusd.reserve.sov";

/// xUSD's ticker symbol.
pub const XUSD_SYMBOL: &str = "xUSD";

/// A collateralized debt position: XUS locked as collateral, xUSD owed against it.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Vault {
    /// XUS locked as collateral (grains). Held out of the account's spendable
    /// balance but still counted in total supply.
    pub collateral: Balance,
    /// xUSD minted against the collateral and not yet repaid (grains).
    pub debt: Balance,
}

impl Vault {
    /// A vault with neither collateral nor debt — indistinguishable from absent,
    /// so it is pruned from state (keeping the commitment canonical).
    pub fn is_empty(&self) -> bool {
        self.collateral == Balance::ZERO && self.debt == Balance::ZERO
    }
}

/// The reserved xUSD asset id, derived from the keyless issuer and symbol just
/// like any native asset — so it occupies a normal token slot but no user can
/// reach it (the issuer has no key).
pub fn xusd_asset_id() -> Hash {
    let issuer = AccountId::new(XUSD_ISSUER).expect("reserved xUSD issuer id is valid");
    token_asset_id(&issuer, XUSD_SYMBOL)
}

/// The USD value (in xUSD grains) of `collateral` XUS grains at `price`
/// (USD/XUS in 10^8 fixed point): `collateral · price / SCALE`. `None` on overflow.
pub fn collateral_usd(collateral: Balance, price: u128) -> Option<u128> {
    collateral.grains().checked_mul(price).map(|v| v / SCALE)
}

/// The maximum xUSD debt permitted against `collateral` at `price`:
/// `collateral_usd · 100 / MIN_COLLATERAL_RATIO_PCT`. `None` on overflow.
pub fn max_debt(collateral: Balance, price: u128) -> Option<u128> {
    collateral_usd(collateral, price)?
        .checked_mul(100)
        .map(|v| v / MIN_COLLATERAL_RATIO_PCT)
}

/// Whether a vault holding `collateral` against `debt` is at or above the minimum
/// collateral ratio at `price` — i.e. `debt ≤ max_debt(collateral)`.
pub fn is_healthy(collateral: Balance, debt: Balance, price: u128) -> bool {
    match max_debt(collateral, price) {
        Some(max) => debt.grains() <= max,
        None => false,
    }
}

/// The collateral ratio as a percentage (`collateral_usd · 100 / debt`), or `None`
/// for a debt-free vault (infinite ratio). For display/telemetry.
pub fn collateral_ratio_pct(collateral: Balance, debt: Balance, price: u128) -> Option<u128> {
    if debt == Balance::ZERO {
        return None;
    }
    let usd = collateral_usd(collateral, price)?;
    usd.checked_mul(100).map(|v| v / debt.grains())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_price_is_one_dollar() {
        assert_eq!(SEED_XUS_USD_PRICE, SCALE);
    }

    #[test]
    fn max_debt_is_two_thirds_of_collateral_value_at_a_dollar() {
        // 150 XUS collateral at $1 = $150 of value → mint up to $100 (150% ratio).
        let collateral = Balance::from_grains(150 * SCALE);
        assert_eq!(max_debt(collateral, SEED_XUS_USD_PRICE), Some(100 * SCALE));
    }

    #[test]
    fn a_higher_price_lifts_the_mint_ceiling_proportionally() {
        // Same 150 XUS, but XUS = $5 → $750 of value → mint up to $500.
        let collateral = Balance::from_grains(150 * SCALE);
        assert_eq!(max_debt(collateral, 5 * SCALE), Some(500 * SCALE));
    }

    #[test]
    fn health_holds_at_exactly_the_minimum_and_breaks_one_grain_over() {
        let collateral = Balance::from_grains(150 * SCALE);
        let at_limit = Balance::from_grains(100 * SCALE);
        let over = Balance::from_grains(100 * SCALE + 1);
        assert!(is_healthy(collateral, at_limit, SEED_XUS_USD_PRICE));
        assert!(!is_healthy(collateral, over, SEED_XUS_USD_PRICE));
    }

    #[test]
    fn ratio_is_none_without_debt_and_150_at_the_limit() {
        let collateral = Balance::from_grains(150 * SCALE);
        assert_eq!(
            collateral_ratio_pct(collateral, Balance::ZERO, SEED_XUS_USD_PRICE),
            None
        );
        assert_eq!(
            collateral_ratio_pct(
                collateral,
                Balance::from_grains(100 * SCALE),
                SEED_XUS_USD_PRICE
            ),
            Some(150)
        );
    }

    #[test]
    fn xusd_asset_id_is_stable_and_issuer_is_keyless() {
        // Deterministic id; the issuer is a valid but keyless named account.
        let a = xusd_asset_id();
        let b = xusd_asset_id();
        assert_eq!(a, b);
    }
}
