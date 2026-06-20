//! Fault injection / adversarial rejection (Phase 7, p7-i8 — the buildable part).
//!
//! These inject faults a malicious peer or buggy node could produce and assert
//! the chain *rejects* them: forged state/tx roots, broken links, tampered
//! signatures, and validator equivocation (double-signing) leading to slashing.
//! The chain validates every block — peer or self-produced — through the same
//! path, so "trust nothing, re-check everything" is enforced here.
//!
//! Honest boundary: *continuous, live-network* chaos/fault injection (p7-i8's
//! other half) needs the Phase 8 node daemon and a running testnet; this is the
//! deterministic, unit-level adversarial suite that runs on every CI.

use sov_chain::{Blockchain, ChainError, GenesisAccount, GenesisConfig};
use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::{Action, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn fresh_chain() -> Blockchain {
    let config = GenesisConfig {
        chain_id: "sov-fault".into(),
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
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    };
    Blockchain::new(&config).unwrap()
}

fn transfer(to: &str, sov: u128, nonce: u64) -> SignedTransaction {
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

#[test]
fn forged_state_root_is_rejected() {
    let mut chain = fresh_chain();
    let mut block = chain
        .produce_block(vec![transfer("ecb.reserve.sov", 10, 0)], 2_000)
        .unwrap();
    // Forge the committed state root, then RE-MINE valid proof-of-work over the
    // tampered header (the header commits to the state root, so forging alone
    // would already break the PoW seal — re-mining proves the *re-execution*
    // gate independently catches the lie).
    block.header.state_root = Hash::digest(b"forged");
    let target = chain.sha256d_difficulty().to_target();
    for nonce in 0.. {
        block.header.nonce = nonce;
        if target.is_met_by(&block.header.pow_hash()) {
            break;
        }
    }
    assert!(matches!(
        chain.import_block(block),
        Err(ChainError::StateRootMismatch)
    ));
    assert_eq!(
        chain.height(),
        0,
        "a rejected block must not advance the chain"
    );
}

#[test]
fn forged_tx_root_is_rejected() {
    let mut chain = fresh_chain();
    let mut block = chain
        .produce_block(vec![transfer("ecb.reserve.sov", 10, 0)], 2_000)
        .unwrap();
    // Forge the committed tx root, then re-mine valid PoW over the tampered
    // header so the import reaches the tx-root consistency check (forging alone
    // already breaks the PoW seal, since the header commits to the tx root).
    block.header.tx_root = Hash::digest(b"forged");
    let target = chain.sha256d_difficulty().to_target();
    for nonce in 0.. {
        block.header.nonce = nonce;
        if target.is_met_by(&block.header.pow_hash()) {
            break;
        }
    }
    assert!(matches!(
        chain.import_block(block),
        Err(ChainError::TxRootMismatch)
    ));
    assert_eq!(chain.height(), 0);
}

#[test]
fn broken_parent_link_is_rejected() {
    let mut chain = fresh_chain();
    let mut block = chain.produce_block(vec![], 2_000).unwrap();
    block.header.prev_hash = Hash::digest(b"not the head");
    assert!(matches!(
        chain.import_block(block),
        Err(ChainError::PrevHashMismatch)
    ));
    assert_eq!(chain.height(), 0);
}

#[test]
fn tampered_signature_is_rejected() {
    let mut chain = fresh_chain();
    let mut block = chain
        .produce_block(vec![transfer("ecb.reserve.sov", 10, 0)], 2_000)
        .unwrap();
    // Replace the transaction's signature with an all-zero (invalid) one. The
    // tx id (and thus tx_root) is over the unsigned transaction, so this slips
    // past the root check and must be caught by signature verification.
    block.transactions[0].signature = Signature::from_bytes([0u8; 64]);
    assert!(matches!(
        chain.import_block(block),
        Err(ChainError::BadSignatures)
    ));
    assert_eq!(chain.height(), 0);
}

#[test]
fn competing_blocks_at_one_height_resolve_by_work_not_votes() {
    // The Nakamoto answer to "equivocation": two valid candidate blocks at the
    // same height are not a punishable offense — they are a fork, and fork
    // choice resolves it. Importing both leaves exactly one on the active
    // chain (first-seen at equal work), the other stored as a side branch with
    // no confirmations and no finality.
    let mut chain = fresh_chain();
    let block_a = chain
        .produce_block(vec![transfer("ecb.reserve.sov", 1, 0)], 2_000)
        .unwrap();
    let block_b = chain.produce_block(vec![], 3_000).unwrap();
    assert_ne!(block_a.hash(), block_b.hash());

    chain.import_block(block_a.clone()).unwrap();
    chain.import_block(block_b.clone()).unwrap();

    // First-seen wins at equal work; the rival is stored but inert.
    assert_eq!(chain.head().hash(), block_a.hash());
    assert_eq!(chain.confirmations(&block_a.hash()), Some(1));
    assert_eq!(
        chain.confirmations(&block_b.hash()),
        None,
        "a side-branch block accrues no confirmations"
    );
    assert!(!chain.is_final(&block_b.hash()));
}
