//! Conformance tests for the State Transition Specification (Phase 7, p7-i0).
//!
//! Each test pins one normative rule from `chain/docs/state-transition.md`
//! against the REAL runtime, driven through a real [`Blockchain`] — so the
//! specification is machine-checked, not merely prose. Test names carry the
//! rule ID from that document.

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance};
use sov_types::{Action, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn chain() -> Blockchain {
    let config = GenesisConfig {
        chain_id: "sov-conformance".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::from_seed([2; 32]).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    };
    Blockchain::new(&config).unwrap()
}

fn usa_transfer(to: &str, sov: u128, nonce: u64) -> SignedTransaction {
    let kp = Keypair::from_seed([2; 32]);
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer {
            to: id(to),
            amount: Balance::from_sov(sov).unwrap(),
        },
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

fn bal(c: &Blockchain, a: &str) -> Balance {
    c.ledger().account(&id(a)).balance
}

/// STF-TRANSFER: a transfer debits the sender and credits the recipient by
/// exactly `amount`, conserving total supply.
#[test]
fn stf_transfer_is_exact_and_conserves() {
    let mut c = chain();
    let before = c.ledger().total_supply().unwrap();
    let blk = c
        .produce_block(vec![usa_transfer("ecb.reserve.sov", 250, 0)], 2_000)
        .unwrap();
    c.import_block(blk).unwrap();
    assert_eq!(bal(&c, "usa.reserve.sov"), Balance::from_sov(750).unwrap());
    assert_eq!(bal(&c, "ecb.reserve.sov"), Balance::from_sov(250).unwrap());
    assert_eq!(c.ledger().total_supply().unwrap(), before);
}

/// STF-NONCE (replay protection): a transaction whose nonce is not the signer's
/// current nonce takes no effect — it cannot be replayed to move funds twice.
#[test]
fn stf_stale_nonce_cannot_replay() {
    let mut c = chain();
    let blk = c
        .produce_block(vec![usa_transfer("ecb.reserve.sov", 10, 0)], 2_000)
        .unwrap();
    c.import_block(blk).unwrap();
    assert_eq!(bal(&c, "ecb.reserve.sov"), Balance::from_sov(10).unwrap());

    // Re-submitting nonce 0 must not move funds again — whether it is rejected at
    // production or recorded as a failed receipt.
    if let Ok(replay) = c.produce_block(vec![usa_transfer("ecb.reserve.sov", 10, 0)], 3_000) {
        let _ = c.import_block(replay);
    }
    assert_eq!(
        bal(&c, "ecb.reserve.sov"),
        Balance::from_sov(10).unwrap(),
        "a replayed (stale-nonce) transfer must not double-credit"
    );
}

/// STF-NONCE-CONSUME: an admitted transaction consumes its nonce even when the
/// action fails, so a failed payment cannot be replayed and the signer's next
/// nonce advances by exactly one.
#[test]
fn stf_failed_action_still_consumes_nonce() {
    let mut c = chain();
    // nonce 0: transfer more than the balance -> action fails, nonce consumed.
    let blk = c
        .produce_block(vec![usa_transfer("ecb.reserve.sov", 5_000, 0)], 2_000)
        .unwrap();
    c.import_block(blk).unwrap();
    assert_eq!(
        bal(&c, "ecb.reserve.sov"),
        Balance::ZERO,
        "an overspend must transfer nothing"
    );

    // The signer's nonce is now 1: a valid transfer at nonce 1 must succeed
    // (which is only possible if the failed tx consumed nonce 0).
    let blk = c
        .produce_block(vec![usa_transfer("ecb.reserve.sov", 100, 1)], 3_000)
        .unwrap();
    c.import_block(blk).unwrap();
    assert_eq!(bal(&c, "ecb.reserve.sov"), Balance::from_sov(100).unwrap());
    assert_eq!(bal(&c, "usa.reserve.sov"), Balance::from_sov(900).unwrap());
}
