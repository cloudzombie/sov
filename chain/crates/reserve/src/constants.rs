//! Protocol constants, read from the real protocol types.
//!
//! [`ProtocolConstants`] is a snapshot of the fixed facts a reserve model is built
//! on. Crucially, it is *derived*, never hand-copied: the supply cap and unit
//! scale come from [`sov_primitives`], and the emission parameters come from the
//! caller's real [`MiningPolicy`] — proof-of-work is the only emission source.
//! Nothing here is a magic number invented for modeling.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_mining::MiningPolicy;
use sov_primitives::{Balance, DECIMALS, GRAINS_PER_SOV, MAX_SUPPLY_GRAINS, MAX_SUPPLY_SOV};

/// The fixed protocol facts a reserve projection rests on, derived from the real
/// protocol types rather than restated.
///
/// Construct with [`ProtocolConstants::from_policies`], passing the very
/// [`MiningPolicy`] the chain runs. Every field is a protocol fact (provenance
/// [`Source::Protocol`](crate::Source::Protocol)).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ProtocolConstants {
    /// The hard supply cap, in grains. Read from [`MAX_SUPPLY_GRAINS`].
    pub max_supply_grains: u128,
    /// The hard supply cap, in whole SOV. Read from [`MAX_SUPPLY_SOV`].
    pub max_supply_sov: u128,
    /// Grains per whole SOV. Read from [`GRAINS_PER_SOV`].
    pub grains_per_sov: u128,
    /// Decimal places of one SOV. Read from [`DECIMALS`].
    pub decimals: u32,
    /// The real mining emission policy this model projects from — the chain's
    /// only emission source.
    pub mining: MiningPolicy,
}

impl ProtocolConstants {
    /// Derive the constants from the chain's real policy.
    ///
    /// The supply cap, unit scale, and decimals come straight from
    /// [`sov_primitives`]; the emission parameters are the supplied policy
    /// itself. This is the only intended way to build a [`ProtocolConstants`]:
    /// it guarantees the model and the chain agree by construction.
    pub fn from_policies(mining: MiningPolicy) -> Self {
        ProtocolConstants {
            max_supply_grains: MAX_SUPPLY_GRAINS,
            max_supply_sov: MAX_SUPPLY_SOV,
            grains_per_sov: GRAINS_PER_SOV,
            decimals: DECIMALS,
            mining,
        }
    }

    /// The supply cap as a [`Balance`].
    pub const fn cap(&self) -> Balance {
        Balance::from_grains(self.max_supply_grains)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_mirror_primitives_exactly() {
        let c = ProtocolConstants::from_policies(MiningPolicy::test());
        // Read from the real primitives, not restated here.
        assert_eq!(c.max_supply_grains, MAX_SUPPLY_GRAINS);
        assert_eq!(c.max_supply_sov, MAX_SUPPLY_SOV);
        assert_eq!(c.grains_per_sov, GRAINS_PER_SOV);
        assert_eq!(c.decimals, DECIMALS);
        assert_eq!(c.cap(), Balance::MAX_SUPPLY);
        // The derived cap is internally consistent with the unit scale.
        assert_eq!(c.max_supply_grains, c.max_supply_sov * c.grains_per_sov);
    }

    #[test]
    fn carries_the_supplied_policy_verbatim() {
        let mining = MiningPolicy::mainnet_like();
        let c = ProtocolConstants::from_policies(mining.clone());
        assert_eq!(c.mining, mining);
    }
}
