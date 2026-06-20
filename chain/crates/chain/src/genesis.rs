//! Genesis: the trusted initial state and block 0.
//!
//! Genesis establishes the **supply cap** — and, on mainnet, allocates
//! **nothing**: [`GenesisConfig::build`] sums every initial balance (liquid +
//! vesting-locked) plus the entire mining budget and refuses to proceed if the
//! total exceeds [`MAX_SUPPLY_GRAINS`](sov_primitives::MAX_SUPPLY_GRAINS).
//! Under the mainnet policy the mining budget IS the full cap, so **any genesis
//! balance whatsoever fails this check — no pre-mine is arithmetically
//! possible**. Every coin that will ever exist enters through a block coinbase
//! (50 SOV halving every 210,000 blocks, Bitcoin's standard), and because no
//! later code path mints outside the coinbase, the cap holds for all time by
//! induction.
//!
//! Consensus is **pure proof-of-work** (Bitcoin's model): there are no
//! validators, no committee, and no operators — only miners with hashpower. The
//! resulting [`Ledger`] and genesis [`Block`] are everything the chain needs to
//! start; the genesis block's `proposer` (a cosmetic coinbase field, since
//! genesis mints nothing) is the canonical-first funded account.

use sov_crypto::PublicKey;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance, BlockHeight, Hash, MAX_SUPPLY_GRAINS};
use sov_state::{Account, Ledger};
use sov_types::{receipts_root, Block};

/// One funded account in the genesis state.
#[derive(Clone, Debug)]
pub struct GenesisAccount {
    /// The account id.
    pub account: AccountId,
    /// The account's controlling key.
    pub key: PublicKey,
    /// Initial liquid balance.
    pub balance: Balance,
}

/// A vesting lockup applied to an early allocation: `amount` SOV held for
/// `account`, claimable to its liquid balance only at or after `unlock_height`.
#[derive(Clone, Debug)]
pub struct VestingGrant {
    /// The account receiving the locked allocation (must appear in `accounts`).
    pub account: AccountId,
    /// Amount locked.
    pub amount: Balance,
    /// Block height at or after which the funds may be claimed.
    pub unlock_height: u64,
}

/// The full description of the chain's starting point.
#[derive(Clone, Debug)]
pub struct GenesisConfig {
    /// Human-readable network identifier (e.g. `sov-mainnet`).
    pub chain_id: String,
    /// Genesis timestamp, Unix milliseconds.
    pub timestamp_ms: u64,
    /// Funded accounts and founding operators.
    pub accounts: Vec<GenesisAccount>,
    /// Mining difficulty and emission policy (consensus-critical: all nodes must
    /// agree, so it is fixed at genesis).
    pub mining: MiningPolicy,
    /// Vesting lockups for early allocations.
    pub vesting: Vec<VestingGrant>,
}

/// The artifacts produced from a [`GenesisConfig`].
pub struct Genesis {
    /// Initial world state.
    pub ledger: Ledger,
    /// Block 0.
    pub block: Block,
    /// The genesis block's coinbase account (canonical-first funded account) —
    /// the chain's default coinbase recipient until a miner identity is set.
    pub coinbase: AccountId,
}

impl GenesisConfig {
    /// Validate the configuration and construct the genesis artifacts.
    pub fn build(&self) -> Result<Genesis, GenesisError> {
        if self.accounts.is_empty() {
            return Err(GenesisError::Empty);
        }

        // Enforce the supply cap across every liquid + vesting balance.
        let mut total: u128 = 0;
        for a in &self.accounts {
            total = total
                .checked_add(a.balance.grains())
                .ok_or(GenesisError::Overflow)?;
        }
        for v in &self.vesting {
            total = total
                .checked_add(v.amount.grains())
                .ok_or(GenesisError::Overflow)?;
        }
        // Genesis allocations plus the entire mining budget must fit under the
        // hard cap. Proof-of-work issuance is the ONLY emission source, and on
        // mainnet the budget equals the cap — so this single check is also the
        // NO-PRE-MINE rule: a mainnet genesis with any funded balance fails.
        total = total
            .checked_add(self.mining.mining_budget_grains)
            .ok_or(GenesisError::Overflow)?;
        if total > MAX_SUPPLY_GRAINS {
            return Err(GenesisError::SupplyCapExceeded {
                total,
                cap: MAX_SUPPLY_GRAINS,
            });
        }

        // Tax fractions are basis points and may not exceed 100% individually or
        // in sum, or the coinbase/fee split would pay out more than was collected
        // (and the miner's remainder would underflow).
        for (what, bps) in [
            ("tax_primary_bps", self.mining.tax_primary_bps),
            ("tax_secondary_bps", self.mining.tax_secondary_bps),
        ] {
            if bps > 10_000 {
                return Err(GenesisError::InvalidFeeParameter { what, bps });
            }
        }
        if u32::from(self.mining.tax_primary_bps) + u32::from(self.mining.tax_secondary_bps)
            > 10_000
        {
            return Err(GenesisError::InvalidFeeParameter {
                what: "tax_primary_bps + tax_secondary_bps",
                bps: 10_001,
            });
        }

        // Build the ledger.
        let mut ledger = Ledger::new();
        for a in &self.accounts {
            ledger.set_account(&a.account, Account::new(a.key, a.balance));
        }

        // Apply vesting lockups to their (existing) accounts.
        for v in &self.vesting {
            if !ledger.exists(&v.account) {
                return Err(GenesisError::VestingUnknownAccount {
                    account: v.account.to_string(),
                });
            }
            let mut account = ledger.account(&v.account);
            account.locked = account
                .locked
                .checked_add(v.amount)
                .ok_or(GenesisError::Overflow)?;
            account.unlock_height = v.unlock_height;
            ledger.set_account(&v.account, account);
        }

        // Block 0: no transactions, committing to the genesis state root. The
        // `proposer` is the canonical-first funded account — deterministic across
        // nodes. Genesis mints nothing (no pre-mine), so this is only the header's
        // cosmetic coinbase field and the chain's default coinbase recipient.
        let coinbase = self.accounts[0].account.clone();
        let proposer = coinbase.clone();
        let mut block = Block::assemble(
            BlockHeight::GENESIS,
            Hash::ZERO,
            ledger.state_root(),
            receipts_root(&[]),
            self.timestamp_ms,
            proposer,
            Vec::new(),
        );
        // Commit the genesis difficulty in the header (Bitcoin's nBits): every
        // later block's `bits` is checked against the retarget rule seeded here.
        block.header.bits = self.mining.sha256d_target.to_compact();

        Ok(Genesis {
            ledger,
            block,
            coinbase,
        })
    }
}

/// Errors building genesis.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenesisError {
    /// No accounts were configured.
    #[error("genesis has no accounts")]
    Empty,
    /// A vesting grant referenced an account not present in `accounts`.
    #[error("vesting grant for unknown account {account}")]
    VestingUnknownAccount {
        /// The referenced account.
        account: String,
    },
    /// Initial supply exceeds the protocol cap.
    #[error("genesis supply {total} grains exceeds the cap of {cap} grains")]
    SupplyCapExceeded {
        /// The configured total, in grains.
        total: u128,
        /// The protocol cap, in grains.
        cap: u128,
    },
    /// A balance sum overflowed `u128`.
    #[error("genesis balance overflow")]
    Overflow,
    /// A fee split fraction exceeds 100% (10,000 basis points).
    #[error("invalid fee parameter {what}: {bps} basis points exceeds 10000")]
    InvalidFeeParameter {
        /// Which parameter was out of range.
        what: &'static str,
        /// The configured basis points.
        bps: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;

    fn acct(name: &str, seed: u8, balance: u128) -> GenesisAccount {
        GenesisAccount {
            account: AccountId::new(name).unwrap(),
            key: Keypair::from_seed([seed; 32]).public_key(),
            balance: Balance::from_sov(balance).unwrap(),
        }
    }

    #[test]
    fn rejects_out_of_range_fee_bps() {
        let mut mining = MiningPolicy::test();
        mining.tax_primary_bps = 10_001; // > 100%
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 0,
            accounts: vec![acct("val01.node.sov", 1, 0)],
            mining,
            vesting: vec![],
        };
        assert!(matches!(
            config.build(),
            Err(GenesisError::InvalidFeeParameter {
                what: "tax_primary_bps",
                ..
            })
        ));
    }

    #[test]
    fn builds_valid_genesis() {
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 1_700_000_000_000,
            accounts: vec![
                acct("val01.node.sov", 1, 1_000_000),
                acct("usa.reserve.sov", 2, 500_000),
            ],
            mining: MiningPolicy::test(),
            vesting: vec![],
        };
        let genesis = config.build().unwrap();
        assert!(genesis.block.is_genesis());
        // The coinbase default is the canonical-first funded account.
        assert_eq!(genesis.coinbase, AccountId::new("val01.node.sov").unwrap());
        assert_eq!(
            genesis.ledger.total_supply().unwrap(),
            Balance::from_sov(1_500_000).unwrap()
        );
        assert_eq!(genesis.block.header.state_root, genesis.ledger.state_root());
    }

    #[test]
    fn rejects_supply_over_cap() {
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 0,
            accounts: vec![
                acct("val01.node.sov", 1, 1),
                acct("whale.sov", 2, 21_000_000), // 21M + 1 liquid > cap
            ],
            mining: MiningPolicy::test(),
            vesting: vec![],
        };
        assert!(matches!(
            config.build(),
            Err(GenesisError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn mainnet_policy_forbids_any_premine() {
        // The no-pre-mine theorem: under the real mainnet policy the mining
        // budget is the FULL 21M cap, so a genesis that allocates even one
        // grain fails the cap check. Zero-balance accounts (keys only) are the
        // only valid mainnet genesis.
        let premine = GenesisConfig {
            chain_id: "sov-mainnet".into(),
            timestamp_ms: 0,
            accounts: vec![
                acct("val01.node.sov", 1, 0),
                GenesisAccount {
                    account: AccountId::new("insider.sov").unwrap(),
                    key: Keypair::from_seed([9; 32]).public_key(),
                    balance: Balance::from_grains(1), // one grain of pre-mine
                },
            ],
            mining: MiningPolicy::mainnet_like(),
            vesting: vec![],
        };
        assert!(matches!(
            premine.build(),
            Err(GenesisError::SupplyCapExceeded { .. })
        ));

        // Vesting grants are pre-mine too and are equally rejected.
        let vested = GenesisConfig {
            chain_id: "sov-mainnet".into(),
            timestamp_ms: 0,
            accounts: vec![acct("val01.node.sov", 1, 0)],
            mining: MiningPolicy::mainnet_like(),
            vesting: vec![VestingGrant {
                account: AccountId::new("val01.node.sov").unwrap(),
                amount: Balance::from_grains(1),
                unlock_height: 10,
            }],
        };
        assert!(matches!(
            vested.build(),
            Err(GenesisError::SupplyCapExceeded { .. })
        ));

        // The clean mainnet genesis: keys only, zero balances. Total supply at
        // genesis is exactly ZERO — every coin will be mined.
        let clean = GenesisConfig {
            chain_id: "sov-mainnet".into(),
            timestamp_ms: 0,
            accounts: vec![acct("val01.node.sov", 1, 0)],
            mining: MiningPolicy::mainnet_like(),
            vesting: vec![],
        };
        let genesis = clean.build().unwrap();
        assert_eq!(genesis.ledger.total_supply().unwrap(), Balance::ZERO);
    }

    #[test]
    fn rejects_empty_accounts() {
        let config = GenesisConfig {
            chain_id: "sov-test".into(),
            timestamp_ms: 0,
            accounts: vec![],
            mining: MiningPolicy::test(),
            vesting: vec![],
        };
        assert!(matches!(config.build(), Err(GenesisError::Empty)));
    }
}
