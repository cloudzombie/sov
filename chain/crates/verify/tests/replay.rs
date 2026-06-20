//! Deterministic replay + cross-node state-root agreement (Phase 7, p7-i4).
//!
//! This drives a *real* [`Blockchain`] through a sequence of blocks — every one
//! a real PoW-mined block with a real coinbase, plus transfers — and at every step
//! checks the Phase 7 invariants ([`check_transition`] / [`check_ledger`]) over
//! genuine execution. It then **replays** the exact same blocks into a second,
//! independent chain built from the identical genesis and asserts the two reach
//! byte-identical `state_root`s at every height. That is what "cross-node
//! agreement" means: any node re-executing the same blocks lands on the same
//! authenticated state, deterministically — no floats, no ambiguity.

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance};
use sov_types::{Action, SignedTransaction, Transaction};
use sov_verify::{check_ledger, check_transition};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn signed(seed: u8, signer: &str, nonce: u64, action: Action) -> SignedTransaction {
    let kp = Keypair::from_seed([seed; 32]);
    let tx = Transaction {
        signer: id(signer),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

fn genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: "sov-verify-test".into(),
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
        mining: {
            // Real coinbase issuance ON for this suite (the test preset's
            // base_reward is zero): every mined block mints a constant 50 SOV
            // to its miner, so the emission invariants are exercised by real
            // block flow.
            let mut m = MiningPolicy::test();
            m.base_reward = Balance::from_sov(50).unwrap();
            m.halving_interval_blocks = 210_000; // constant 50 across this short run
            m
        },
        vesting: vec![],
    }
}

#[test]
fn invariants_hold_over_real_blocks_and_replay_agrees_cross_node() {
    let config = genesis();
    let mining = config.mining.clone();

    let mut node_a = Blockchain::new(&config).unwrap();

    // The blocks we produce, captured for replay into an independent node.
    let mut blocks = Vec::new();
    // node_a's state root after each imported block, the agreement target.
    let mut roots = Vec::new();

    // Build the per-block transaction batches. Timestamps are spaced by exactly
    // the policy's target_block_ms so difficulty stays stable across the run.
    // Every block's coinbase is a real PoW mint (Nakamoto issuance); the
    // batches add 1) an empty block, 2) a transfer, 3) a second transfer.
    let batches: Vec<Vec<SignedTransaction>> = vec![
        vec![],
        vec![signed(
            2,
            "usa.reserve.sov",
            0,
            Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(100).unwrap(),
            },
        )],
        vec![signed(
            2,
            "usa.reserve.sov",
            1,
            Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(50).unwrap(),
            },
        )],
    ];

    for (i, batch) in batches.into_iter().enumerate() {
        let ts = 2_000 + (i as u64) * 1_000;
        let block = node_a.produce_block(batch, ts).unwrap();
        blocks.push(block.clone());

        let before = node_a.ledger().clone();
        node_a.import_block(block).unwrap();
        let after = node_a.ledger();

        // The transition invariant must hold across every real block: all new
        // supply is exactly the coinbase emission, nothing created or lost.
        check_transition(&before, after)
            .unwrap_or_else(|e| panic!("transition invariant violated at block {}: {e}", i + 1));
        // And the state invariants must hold on the resulting ledger.
        check_ledger(after, &mining)
            .unwrap_or_else(|e| panic!("ledger invariant violated at block {}: {e}", i + 1));

        roots.push(after.state_root());
    }

    // Real mints actually happened: three blocks, three 50-SOV coinbases.
    assert_eq!(
        node_a.ledger().mined_emitted(),
        Balance::from_sov(150).unwrap(),
        "three block coinbases of the 50 SOV base reward"
    );
    // Cross-node agreement: a second, independent node built from the identical
    // genesis and fed the identical blocks reproduces the exact same authenticated
    // state root at every height — deterministic replay.
    let mut node_b = Blockchain::new(&config).unwrap();
    for (i, block) in blocks.into_iter().enumerate() {
        node_b.import_block(block).unwrap();
        assert_eq!(
            node_b.ledger().state_root(),
            roots[i],
            "state roots diverged at height {} across independent nodes",
            i + 1
        );
    }
    assert_eq!(node_b.ledger().state_root(), node_a.ledger().state_root());
}
