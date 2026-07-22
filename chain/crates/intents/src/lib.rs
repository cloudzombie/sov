//! # sov-intents
//!
//! NEAR-style **intents**: a user signs *one* declarative intent — "give X of
//! asset A, receive at least Y of asset B" — and **solvers** compete to fill it.
//! The user never picks a route, a venue, or a counterparty; they sign their
//! desired outcome and the best solver wins.
//!
//! This crate is the on-chain core: the signed [`Intent`], a solver's
//! [`Settlement`], and [`settle`] — which verifies the intent and atomically
//! swaps the two assets between owner and solver. Solver *competition* (who finds
//! the best fill) happens off-chain; settlement and its verification are on-chain
//! and trustless.
//!
//! **Wired into consensus** (Phase 17, `Action::IntentSettle`/`IntentCancel`):
//! the runtime verifies the owner's signature against their registered
//! on-chain key, consumes each intent id exactly once (replay exclusion), and
//! settles native-SOV and on-chain-asset ([`Asset::Token`]) legs atomically
//! with compliance gates — see Part X of `docs/proofs.md`. Cross-chain swaps
//! use the trustless HTLC path (there is no committee-attested cross-chain
//! pool — consensus is pure proof-of-work).

#![forbid(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, SigningDomain, TxDomainMode};

/// An asset an intent can give or want: native SOV or an on-chain native asset
/// (token).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Asset {
    /// Native SOV.
    Sov,
    /// An on-chain native asset, by its 32-byte asset id (see the chain's
    /// `token_asset_id` derivation).
    Token(sov_primitives::Hash),
}

/// JSON (de)serialization of `u128` as a decimal string — `serde_json::Value`
/// (the JSON-RPC param carrier) cannot represent raw 128-bit integers, and a
/// string keeps JS clients precision-safe, matching `Balance`'s convention.
mod u128_string {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// A user's declarative swap intent.
///
/// Amounts are in each asset's smallest unit (SOV grains, or the external
/// asset's base unit). The user commits to giving exactly `give_amount` of
/// `give_asset` and requires *at least* `min_receive` of `want_asset` — solvers
/// may deliver more to win, never less.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Intent {
    /// The account whose funds back the intent.
    pub owner: AccountId,
    /// The owner's controlling public key (verifies the signature).
    pub public_key: sov_crypto::PublicKey,
    /// Per-owner uniqueness/replay protection for intents.
    pub nonce: u64,
    /// Asset the owner gives.
    pub give_asset: Asset,
    /// Exact amount given.
    #[serde(with = "u128_string")]
    pub give_amount: u128,
    /// Asset the owner wants.
    pub want_asset: Asset,
    /// Minimum amount the owner will accept (slippage floor).
    #[serde(with = "u128_string")]
    pub min_receive: u128,
    /// Last block height at which the intent may be settled.
    pub expiry_height: u64,
}

/// Domain tag for intent signatures under the miner-signaled `tx-domain` hard
/// fork: `"sov:intent:v1" ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh(Intent)`.
/// Distinct from the transaction tag `sov:tx:v1`, so a signature over one can
/// never be reinterpreted as the other.
pub const INTENT_SIGNING_DOMAIN_TAG: &[u8] = b"sov:intent:v1";

impl Intent {
    /// Canonical signing bytes: the deterministic Borsh encoding.
    pub fn signing_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialization of an Intent is infallible")
    }

    /// The signing preimage under an optional network [`SigningDomain`]. `None`
    /// reproduces [`signing_bytes`](Self::signing_bytes) exactly (pre-fork,
    /// byte-identical); `Some(domain)` binds the signature to that network,
    /// closing cross-network intent replay. The intent *id* is unaffected.
    pub fn signing_bytes_in(&self, domain: Option<&SigningDomain>) -> Vec<u8> {
        match domain {
            None => self.signing_bytes(),
            Some(d) => d.frame(INTENT_SIGNING_DOMAIN_TAG, &self.signing_bytes()),
        }
    }

    /// The intent's id: the Blake3 hash of its canonical signing bytes —
    /// stable, signature-independent, and unique per (owner, nonce, terms).
    /// On-chain settlement consumes this id exactly once (replay exclusion).
    pub fn id(&self) -> sov_primitives::Hash {
        sov_primitives::Hash::digest(&self.signing_bytes())
    }

    /// Sign this intent with `keypair` (whose public key must match `public_key`).
    pub fn sign(self, keypair: &Keypair) -> Result<SignedIntent, IntentError> {
        self.sign_in(keypair, None)
    }

    /// Sign this intent under an optional network [`SigningDomain`] (`None` =
    /// legacy, byte-identical to [`sign`](Self::sign)).
    pub fn sign_in(
        self,
        keypair: &Keypair,
        domain: Option<&SigningDomain>,
    ) -> Result<SignedIntent, IntentError> {
        if keypair.public_key() != self.public_key {
            return Err(IntentError::KeyMismatch);
        }
        let signature = keypair.sign(&self.signing_bytes_in(domain));
        Ok(SignedIntent {
            intent: self,
            signature,
        })
    }
}

/// An intent plus the owner's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SignedIntent {
    /// The signed intent.
    pub intent: Intent,
    /// Owner's signature over [`Intent::signing_bytes`].
    pub signature: Signature,
}

impl SignedIntent {
    /// Whether the signature verifies against the intent's committed key
    /// (legacy, un-bound preimage).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_in(None)
    }

    /// Whether the signature verifies under an optional network [`SigningDomain`].
    /// `None` is byte-identical to [`verify`](Self::verify); `Some(domain)`
    /// requires the signature to bind to that network, rejecting a legacy or
    /// cross-network-replayed intent once the `tx-domain` fork is active.
    #[must_use]
    pub fn verify_in(&self, domain: Option<&SigningDomain>) -> bool {
        self.intent
            .public_key
            .verify(&self.intent.signing_bytes_in(domain), &self.signature)
    }

    /// Whether the signature verifies under a resolved [`TxDomainMode`] — the
    /// three-state (`Legacy` / `Grace` / `Bound`) regime of the `tx-domain`
    /// fork's grace window. Intents share the transaction resolver, so they get
    /// the exact same grace treatment: `Legacy` is byte-identical to
    /// [`verify_in`](Self::verify_in)`(None)`; `Grace(d)` accepts a legacy OR a
    /// `d`-bound intent signature; `Bound(d)` accepts only a bound one.
    #[must_use]
    pub fn verify_mode(&self, mode: &TxDomainMode) -> bool {
        mode.verifies(|domain| self.verify_in(domain))
    }
}

/// A solver's proposal to fill an intent: deliver `deliver_amount` of the
/// wanted asset (≥ the intent's `min_receive`) in exchange for the given asset.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Settlement {
    /// The intent being filled.
    pub intent: SignedIntent,
    /// The solver fulfilling it.
    pub solver: AccountId,
    /// Amount of the wanted asset the solver delivers (≥ `min_receive`).
    #[serde(with = "u128_string")]
    pub deliver_amount: u128,
}

/// Asset balances the settlement engine operates over. Implemented for a test
/// ledger here and, on the chain, over native SOV plus the consensus pool.
pub trait Balances {
    /// Current balance of `asset` held by `account`.
    fn balance(&self, account: &AccountId, asset: Asset) -> u128;
    /// Move `amount` of `asset` from `from` to `to`. Returns `false` (moving
    /// nothing) if `from` lacks the balance.
    fn transfer(&mut self, from: &AccountId, to: &AccountId, asset: Asset, amount: u128) -> bool;
}

/// Verify and atomically execute a `settlement` at block `height`.
///
/// On success the owner has given `give_amount` of `give_asset` to the solver
/// and received `deliver_amount` of `want_asset` in return. Either both legs
/// happen or none do.
pub fn settle(
    settlement: &Settlement,
    height: u64,
    balances: &mut impl Balances,
) -> Result<(), IntentError> {
    let intent = &settlement.intent.intent;

    if !settlement.intent.verify() {
        return Err(IntentError::BadSignature);
    }
    if height > intent.expiry_height {
        return Err(IntentError::Expired);
    }
    if settlement.deliver_amount < intent.min_receive {
        return Err(IntentError::InsufficientDelivery {
            offered: settlement.deliver_amount,
            required: intent.min_receive,
        });
    }
    if intent.give_asset == intent.want_asset {
        return Err(IntentError::DegenerateSwap);
    }

    // Both legs must be funded before either moves (atomicity).
    if balances.balance(&intent.owner, intent.give_asset) < intent.give_amount {
        return Err(IntentError::OwnerUnderfunded);
    }
    if balances.balance(&settlement.solver, intent.want_asset) < settlement.deliver_amount {
        return Err(IntentError::SolverUnderfunded);
    }

    if !balances.transfer(
        &intent.owner,
        &settlement.solver,
        intent.give_asset,
        intent.give_amount,
    ) {
        return Err(IntentError::OwnerUnderfunded);
    }
    if !balances.transfer(
        &settlement.solver,
        &intent.owner,
        intent.want_asset,
        settlement.deliver_amount,
    ) {
        return Err(IntentError::SolverUnderfunded);
    }
    Ok(())
}

/// Reasons an intent cannot be signed or settled.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IntentError {
    /// The signing key did not match the intent's `public_key`.
    #[error("signing key does not match the intent's public key")]
    KeyMismatch,
    /// The intent's signature did not verify.
    #[error("invalid intent signature")]
    BadSignature,
    /// The intent has expired.
    #[error("intent has expired")]
    Expired,
    /// Give and want assets are the same — not a swap.
    #[error("give and want assets are identical")]
    DegenerateSwap,
    /// The solver offered less than the intent's minimum.
    #[error("solver delivers {offered} but the intent requires at least {required}")]
    InsufficientDelivery {
        /// Amount the solver offered.
        offered: u128,
        /// Minimum the intent demanded.
        required: u128,
    },
    /// The owner cannot cover the asset they offered to give.
    #[error("owner cannot cover the given amount")]
    OwnerUnderfunded,
    /// The solver cannot cover the asset they offered to deliver.
    #[error("solver cannot cover the delivered amount")]
    SolverUnderfunded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A simple in-memory balance sheet for tests.
    #[derive(Default)]
    struct TestBalances {
        map: HashMap<(AccountId, Asset), u128>,
    }
    impl TestBalances {
        fn give(&mut self, who: &str, asset: Asset, amount: u128) {
            *self.map.entry((id(who), asset)).or_default() += amount;
        }
    }
    impl Balances for TestBalances {
        fn balance(&self, account: &AccountId, asset: Asset) -> u128 {
            self.map
                .get(&(account.clone(), asset))
                .copied()
                .unwrap_or(0)
        }
        fn transfer(
            &mut self,
            from: &AccountId,
            to: &AccountId,
            asset: Asset,
            amount: u128,
        ) -> bool {
            if self.balance(from, asset) < amount {
                return false;
            }
            *self.map.get_mut(&(from.clone(), asset)).unwrap() -= amount;
            *self.map.entry((to.clone(), asset)).or_default() += amount;
            true
        }
    }

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    /// A non-SOV on-chain token used as the counter-asset in swap tests.
    fn token() -> Asset {
        Asset::Token(sov_primitives::Hash::digest(b"wrapped-asset"))
    }

    /// An intent: give `give` SOV, want ≥ `want` of a token, expiring at `expiry`.
    fn sov_for_token(seed: u8, give: u128, want: u128, expiry: u64) -> SignedIntent {
        let kp = Keypair::from_seed([seed; 32]);
        Intent {
            owner: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            give_asset: Asset::Sov,
            give_amount: give,
            want_asset: token(),
            min_receive: want,
            expiry_height: expiry,
        }
        .sign(&kp)
        .unwrap()
    }

    #[test]
    fn intent_domain_binding_closes_cross_network_replay() {
        use sov_primitives::{Hash, SigningDomain};
        // Legacy (dormant) path is byte-identical, and the id is domain-independent.
        let kp = Keypair::from_seed([1; 32]);
        let intent = Intent {
            owner: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            give_asset: Asset::Sov,
            give_amount: 1_000,
            want_asset: token(),
            min_receive: 5,
            expiry_height: 100,
        };
        assert_eq!(intent.signing_bytes(), intent.signing_bytes_in(None));

        // Bind to one network; a signature made for it verifies ONLY under it.
        let mainnet = SigningDomain::new("sov-mainnet", Hash::digest(b"genesis-main"));
        let testnet = SigningDomain::new("sov-testnet", Hash::digest(b"genesis-test"));
        let signed = intent.clone().sign_in(&kp, Some(&mainnet)).unwrap();
        assert!(signed.verify_in(Some(&mainnet)));
        // Cross-network replay, a legacy verifier, and a legacy signature are all rejected.
        assert!(!signed.verify_in(Some(&testnet)));
        assert!(!signed.verify_in(None));
        let legacy = intent.sign(&kp).unwrap();
        assert!(legacy.verify()); // valid while dormant
        assert!(!legacy.verify_in(Some(&mainnet))); // rejected once active — no fallback
                                                    // The bound preimage never collides with the transaction domain (distinct tags).
        assert!(signed
            .intent
            .signing_bytes_in(Some(&mainnet))
            .starts_with(INTENT_SIGNING_DOMAIN_TAG));
    }

    #[test]
    fn intent_grace_window_accepts_either_preimage_then_binds() {
        // Intents share the transaction resolver's three-state mode, so they get
        // the same grace treatment: Legacy = legacy-only (dormant, pre-fork
        // byte-identical); Grace = legacy OR bound; Bound = bound-only.
        use sov_primitives::{Hash, SigningDomain, TxDomainMode};
        let kp = Keypair::from_seed([1; 32]);
        let intent = Intent {
            owner: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            give_asset: Asset::Sov,
            give_amount: 1_000,
            want_asset: token(),
            min_receive: 5,
            expiry_height: 100,
        };
        let mainnet = SigningDomain::new("sov-mainnet", Hash::digest(b"genesis-main"));
        let legacy = intent.clone().sign(&kp).unwrap();
        let bound = intent.sign_in(&kp, Some(&mainnet)).unwrap();

        let l = TxDomainMode::Legacy;
        let g = TxDomainMode::Grace(mainnet.clone());
        let b = TxDomainMode::Bound(mainnet.clone());
        assert!(legacy.verify_mode(&l) && !bound.verify_mode(&l));
        assert!(legacy.verify_mode(&g) && bound.verify_mode(&g));
        assert!(!legacy.verify_mode(&b) && bound.verify_mode(&b));
    }

    #[test]
    fn solver_settles_a_valid_intent() {
        let intent = sov_for_token(1, 1_000, 5, 100);
        let settlement = Settlement {
            intent,
            solver: id("solver.sov"),
            deliver_amount: 6,
        };

        let mut bal = TestBalances::default();
        bal.give("usa.reserve.sov", Asset::Sov, 1_000);
        bal.give("solver.sov", token(), 10);

        settle(&settlement, 50, &mut bal).unwrap();

        // Owner gave 1000 SOV, received 6 BTC; solver took the SOV, paid 6 BTC.
        assert_eq!(bal.balance(&id("usa.reserve.sov"), Asset::Sov), 0);
        assert_eq!(bal.balance(&id("usa.reserve.sov"), token()), 6);
        assert_eq!(bal.balance(&id("solver.sov"), Asset::Sov), 1_000);
        assert_eq!(bal.balance(&id("solver.sov"), token()), 4);
    }

    #[test]
    fn rejects_expired_intent() {
        let intent = sov_for_token(1, 1_000, 5, 10);
        let settlement = Settlement {
            intent,
            solver: id("solver.sov"),
            deliver_amount: 6,
        };
        let mut bal = TestBalances::default();
        assert_eq!(settle(&settlement, 11, &mut bal), Err(IntentError::Expired));
    }

    #[test]
    fn rejects_under_minimum_delivery() {
        let intent = sov_for_token(1, 1_000, 5, 100);
        let settlement = Settlement {
            intent,
            solver: id("solver.sov"),
            deliver_amount: 4,
        };
        let mut bal = TestBalances::default();
        assert!(matches!(
            settle(&settlement, 1, &mut bal),
            Err(IntentError::InsufficientDelivery {
                offered: 4,
                required: 5
            })
        ));
    }

    #[test]
    fn rejects_tampered_intent() {
        let mut signed = sov_for_token(1, 1_000, 5, 100);
        signed.intent.give_amount = 1; // tamper after signing
        let settlement = Settlement {
            intent: signed,
            solver: id("solver.sov"),
            deliver_amount: 6,
        };
        let mut bal = TestBalances::default();
        assert_eq!(
            settle(&settlement, 1, &mut bal),
            Err(IntentError::BadSignature)
        );
    }

    #[test]
    fn rejects_underfunded_owner_and_solver() {
        let intent = sov_for_token(1, 1_000, 5, 100);
        let settlement = Settlement {
            intent,
            solver: id("solver.sov"),
            deliver_amount: 6,
        };
        // Owner has no SOV.
        let mut bal = TestBalances::default();
        bal.give("solver.sov", token(), 10);
        assert_eq!(
            settle(&settlement, 1, &mut bal),
            Err(IntentError::OwnerUnderfunded)
        );

        // Owner funded, solver has no BTC.
        let intent2 = sov_for_token(1, 1_000, 5, 100);
        let settlement2 = Settlement {
            intent: intent2,
            solver: id("solver.sov"),
            deliver_amount: 6,
        };
        let mut bal2 = TestBalances::default();
        bal2.give("usa.reserve.sov", Asset::Sov, 1_000);
        assert_eq!(
            settle(&settlement2, 1, &mut bal2),
            Err(IntentError::SolverUnderfunded)
        );
    }

    #[test]
    fn signature_roundtrip_and_key_mismatch() {
        let intent = sov_for_token(1, 1, 1, 1);
        assert!(intent.verify());
        // Signing with a non-matching key is refused.
        let kp = Keypair::from_seed([2; 32]);
        let bad = Intent {
            owner: id("x.sov"),
            public_key: Keypair::from_seed([3; 32]).public_key(),
            nonce: 0,
            give_asset: Asset::Sov,
            give_amount: 1,
            want_asset: token(),
            min_receive: 1,
            expiry_height: 1,
        };
        assert_eq!(bad.sign(&kp), Err(IntentError::KeyMismatch));
    }
}
