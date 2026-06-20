//! The account model.
//!
//! SOV is an account-based chain (like Ethereum/NEAR, unlike Bitcoin's UTXOs):
//! each [`AccountId`](sov_primitives::AccountId) maps to one [`Account`] holding
//! a liquid balance, a nonce, and the public key authorized to act for it.
//!
//! Invariants that make the account safe:
//! - the **nonce** is the count of transactions sent; requiring a transaction's
//!   nonce to equal the account nonce prevents replay and totally orders an
//!   account's transactions;
//! - the **controlling key** binds spending authority to a specific Ed25519 key.
//!   An account with no key (`None`) can receive funds but cannot originate
//!   transactions — so value can never leave an account without a signature from
//!   its registered key.
//!
//! Beyond the liquid `balance`, an account may hold one kind of non-spendable
//! funds: `locked` — a vesting lockup (e.g. an early allocation), claimable to
//! the liquid balance only at or after `unlock_height`. Only `balance` is
//! transferable; locked funds still count toward total holdings (and thus
//! supply) but cannot be moved out until they vest. (There is no staking and no
//! staked balance — SOV has no proof-of-stake of any kind.)

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::PublicKey;
use sov_primitives::Balance;

/// The on-chain state of a single account.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Account {
    /// Number of transactions sent; the nonce expected on the next one.
    pub nonce: u64,
    /// Liquid, transferable balance.
    pub balance: Balance,
    /// Vesting lockup: held but non-spendable until `unlock_height`.
    pub locked: Balance,
    /// Block height at or after which `locked` may be claimed to `balance`.
    pub unlock_height: u64,
    /// The public key authorized to send transactions for this account. `None`
    /// means the account can receive but not spend.
    pub key: Option<PublicKey>,
    /// Deployed WebAssembly contract code, if this account is a contract. `None`
    /// for ordinary accounts. Committed to the state root with the rest of the
    /// account, and per-contract key/value storage lives alongside in the ledger.
    pub code: Option<Vec<u8>>,
}

impl Account {
    /// A keyed account holding `balance`, nothing locked, nonce 0.
    pub fn new(key: PublicKey, balance: Balance) -> Self {
        Account {
            balance,
            key: Some(key),
            ..Account::default()
        }
    }

    /// A keyless account holding `balance`. It can receive but not originate
    /// transactions until a key is assigned. Useful as a transfer recipient and
    /// in tests.
    pub fn with_balance(balance: Balance) -> Self {
        Account {
            balance,
            ..Account::default()
        }
    }

    /// Total holdings: liquid + vesting-locked. `None` only on `u128`
    /// overflow, which the supply cap makes unreachable for real accounts.
    pub fn total(&self) -> Option<Balance> {
        self.balance.checked_add(self.locked)
    }

    /// The amount that may be transferred right now: the liquid balance only.
    pub fn spendable(&self) -> Balance {
        self.balance
    }

    /// Whether vesting-locked funds can be claimed at `height`.
    pub fn can_claim_vesting(&self, height: u64) -> bool {
        self.locked != Balance::ZERO && height >= self.unlock_height
    }

    /// Whether this account is authorized by `key`.
    pub fn is_controlled_by(&self, key: &PublicKey) -> bool {
        self.key.as_ref() == Some(key)
    }

    /// Whether this account has deployed contract code.
    pub fn is_contract(&self) -> bool {
        self.code.is_some()
    }

    /// Whether this account has never been touched (default state).
    pub fn is_empty(&self) -> bool {
        *self == Account::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;

    fn key(seed: u8) -> PublicKey {
        Keypair::from_seed([seed; 32]).public_key()
    }

    #[test]
    fn default_is_empty_and_keyless() {
        let a = Account::default();
        assert!(a.is_empty());
        assert_eq!(a.nonce, 0);
        assert_eq!(a.balance, Balance::ZERO);
        assert!(a.key.is_none());
    }

    #[test]
    fn controlling_key_check() {
        let a = Account::new(key(1), Balance::from_sov(10).unwrap());
        assert!(a.is_controlled_by(&key(1)));
        assert!(!a.is_controlled_by(&key(2)));
        // A keyless account is controlled by no one.
        assert!(!Account::with_balance(Balance::from_sov(1).unwrap()).is_controlled_by(&key(1)));
    }

    #[test]
    fn total_sums_liquid_and_locked() {
        let a = Account {
            nonce: 3,
            balance: Balance::from_sov(10).unwrap(),
            locked: Balance::from_sov(100).unwrap(),
            key: Some(key(1)),
            ..Account::default()
        };
        assert_eq!(a.total().unwrap(), Balance::from_sov(110).unwrap());
        // Only the liquid balance is spendable.
        assert_eq!(a.spendable(), Balance::from_sov(10).unwrap());
        assert!(!a.is_empty());
    }

    #[test]
    fn vesting_gating() {
        let vesting = Account {
            locked: Balance::from_sov(5).unwrap(),
            unlock_height: 50,
            ..Account::default()
        };
        assert!(!vesting.can_claim_vesting(49));
        assert!(vesting.can_claim_vesting(50));
    }

    #[test]
    fn borsh_roundtrip() {
        let a = Account::new(key(7), Balance::from_sov(7).unwrap());
        let bytes = borsh::to_vec(&a).unwrap();
        assert_eq!(borsh::from_slice::<Account>(&bytes).unwrap(), a);
    }
}
