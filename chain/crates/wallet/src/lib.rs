//! # sov-wallet
//!
//! Key management and transaction construction. A [`Wallet`] holds the signing
//! keypairs for one or more accounts and turns high-level intents ("transfer 5
//! SOV from A to B") into correctly-formed, signed [`SignedTransaction`]s ready
//! for the mempool.
//!
//! Keys are the most sensitive material in the system, so the wallet is careful
//! with them: a [`Keypair`] is never `Clone` or serializable, the wallet never
//! logs secret bytes, and it refuses to build a transaction for an account whose
//! key it does not hold. Encrypted at-rest storage is a deliberate next step
//! layered on this in-memory core; nothing here fabricates keys or balances.

#![forbid(unsafe_code)]

pub mod hd;
pub use hd::{generate_mnemonic, HdError, HdWallet, SOV_COIN_TYPE};

use std::collections::HashMap;

use sov_crypto::{Keypair, PublicKey};
use sov_primitives::{AccountId, Balance, SigningDomain};
use sov_types::{Action, SignedTransaction, Transaction};

/// An in-memory holder of account keypairs and a builder of signed transactions.
#[derive(Default)]
pub struct Wallet {
    keys: HashMap<AccountId, Keypair>,
}

impl Wallet {
    /// An empty wallet.
    pub fn new() -> Self {
        Wallet::default()
    }

    /// Import an existing keypair for `account`.
    pub fn import(&mut self, account: AccountId, keypair: Keypair) {
        self.keys.insert(account, keypair);
    }

    /// Generate a fresh keypair for `account` and return its public key. The
    /// secret never leaves the wallet.
    pub fn generate(&mut self, account: AccountId) -> Result<PublicKey, WalletError> {
        let keypair = Keypair::generate().map_err(|_| WalletError::KeyGeneration)?;
        let public = keypair.public_key();
        self.keys.insert(account, keypair);
        Ok(public)
    }

    /// Whether the wallet holds a key for `account`.
    pub fn manages(&self, account: &AccountId) -> bool {
        self.keys.contains_key(account)
    }

    /// The public key for a managed account.
    pub fn public_key(&self, account: &AccountId) -> Option<PublicKey> {
        self.keys.get(account).map(Keypair::public_key)
    }

    /// Number of managed accounts.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the wallet manages no accounts.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Build and sign a transfer of `amount` from a managed account `from` to
    /// `to`, with the given `nonce` (the account's current nonce in state).
    ///
    /// Signs the legacy (un-bound) way — correct while the `tx-domain` hard fork
    /// is dormant. Once the fork is active on the target network, use
    /// [`transfer_in`](Self::transfer_in) with the domain the node reports via
    /// `sov_getSigningDomain` (`RpcClient::signing_domain`).
    pub fn transfer(
        &self,
        from: &AccountId,
        to: AccountId,
        amount: Balance,
        nonce: u64,
    ) -> Result<SignedTransaction, WalletError> {
        self.transfer_in(from, to, amount, nonce, None)
    }

    /// Build and sign a transfer under an optional network [`SigningDomain`].
    ///
    /// `None` produces the legacy signature (byte-identical to
    /// [`transfer`](Self::transfer)); `Some(domain)` binds the signature to that
    /// network — required once the miner-signaled `tx-domain` fork is active.
    /// This wallet is offline (it holds keys, not a node connection), so the
    /// domain is the caller's to supply: query it from the node you will submit
    /// to (`sov_getSigningDomain`) and pass it through.
    pub fn transfer_in(
        &self,
        from: &AccountId,
        to: AccountId,
        amount: Balance,
        nonce: u64,
        domain: Option<&SigningDomain>,
    ) -> Result<SignedTransaction, WalletError> {
        let keypair = self
            .keys
            .get(from)
            .ok_or_else(|| WalletError::UnknownAccount {
                account: from.to_string(),
            })?;
        let tx = Transaction {
            signer: from.clone(),
            public_key: keypair.public_key(),
            nonce,
            action: Action::Transfer { to, amount },
        };
        // sign cannot mismatch: we built the tx with this keypair's public key.
        SignedTransaction::sign_in(tx, keypair, domain).map_err(|_| WalletError::Signing)
    }
}

/// Errors from wallet operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WalletError {
    /// No key is held for the requested account.
    #[error("wallet does not manage account {account}")]
    UnknownAccount {
        /// The requested account.
        account: String,
    },
    /// OS entropy was unavailable while generating a key.
    #[error("key generation failed")]
    KeyGeneration,
    /// Signing failed (key/transaction mismatch — unreachable via this API).
    #[error("signing failed")]
    Signing,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    #[test]
    fn generate_then_build_signed_transfer() {
        let mut wallet = Wallet::new();
        let pk = wallet.generate(id("usa.reserve.sov")).unwrap();
        assert!(wallet.manages(&id("usa.reserve.sov")));
        assert_eq!(wallet.public_key(&id("usa.reserve.sov")), Some(pk));

        let stx = wallet
            .transfer(
                &id("usa.reserve.sov"),
                id("ecb.reserve.sov"),
                Balance::from_sov(5).unwrap(),
                0,
            )
            .unwrap();
        assert!(stx.verify_signature());
        assert_eq!(stx.transaction.public_key, pk);
        assert_eq!(stx.transaction.signer, id("usa.reserve.sov"));
    }

    #[test]
    fn import_keypair_and_match_public_key() {
        let mut wallet = Wallet::new();
        let kp = Keypair::from_seed([3; 32]);
        let expected = kp.public_key();
        wallet.import(id("treasury.sov"), kp);
        assert_eq!(wallet.public_key(&id("treasury.sov")), Some(expected));
    }

    #[test]
    fn unknown_account_is_an_error() {
        let wallet = Wallet::new();
        assert_eq!(
            wallet.transfer(
                &id("ghost.sov"),
                id("ecb.reserve.sov"),
                Balance::from_sov(1).unwrap(),
                0
            ),
            Err(WalletError::UnknownAccount {
                account: "ghost.sov".into()
            })
        );
    }

    #[test]
    fn domain_bound_transfer_verifies_only_under_that_domain() {
        use sov_primitives::Hash;
        let mut wallet = Wallet::new();
        wallet.generate(id("usa.reserve.sov")).unwrap();
        let domain = SigningDomain::new("sov-mainnet", Hash::digest(b"test-genesis"));
        let bound = wallet
            .transfer_in(
                &id("usa.reserve.sov"),
                id("ecb.reserve.sov"),
                Balance::from_sov(1).unwrap(),
                0,
                Some(&domain),
            )
            .unwrap();
        // The bound signature verifies under its domain, NOT as a legacy sig,
        // and not under a different network's domain (the anti-replay point).
        assert!(bound.verify_signature_in(Some(&domain)));
        assert!(!bound.verify_signature());
        let other = SigningDomain::new("sov-testnet", Hash::digest(b"test-genesis"));
        assert!(!bound.verify_signature_in(Some(&other)));

        // `transfer` (legacy) stays the un-bound signature: dormant-path unchanged.
        let legacy = wallet
            .transfer(
                &id("usa.reserve.sov"),
                id("ecb.reserve.sov"),
                Balance::from_sov(1).unwrap(),
                0,
            )
            .unwrap();
        assert!(legacy.verify_signature());
        // The tx id is domain-independent: same body ⇒ same id either way.
        assert_eq!(bound.id(), legacy.id());
    }

    #[test]
    fn generated_keys_are_distinct() {
        let mut wallet = Wallet::new();
        let a = wallet.generate(id("a.sov")).unwrap();
        let b = wallet.generate(id("b.sov")).unwrap();
        assert_ne!(a, b);
        assert_eq!(wallet.len(), 2);
    }
}
