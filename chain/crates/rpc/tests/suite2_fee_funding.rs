//! Existing pool notes can fund a direct activated withdrawal's normal fee.
#![cfg(feature = "zk-suite2")]

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_governance::{Deployment, Threshold};
use sov_mining::MiningPolicy;
use sov_node::{Node, NodeError};
use sov_primitives::{AccountId, Balance, BlockHeight};
use sov_runtime::{apply_transaction, BlockContext, ExecutionError, ShieldedV2Error};
use sov_shielded_pq::carrier::CarrierContext;
use sov_shielded_pq::wallet::{authorize_for_carrier, build_shield, build_spend_suite2};
use sov_shielded_pq::wire::{encode_bundle, encode_bundle_for_suite};
use sov_shielded_pq::{PqNoteStore, PqShieldedKey};
use sov_types::{Action, Block, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn node() -> Node {
    let mut policy = MiningPolicy::test();
    policy.gas_price = Balance::from_grains(1);
    policy.deshield_window_blocks = 0;
    let config = GenesisConfig {
        chain_id: "sov-suite2-rehearsal-fee-funding".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: id("funding.sov"),
                key: Keypair::hybrid_from_seed([92; 32]).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
            GenesisAccount {
                account: id("miner.sov"),
                key: Keypair::hybrid_from_seed([93; 32]).public_key(),
                balance: Balance::ZERO,
            },
        ],
        mining: policy,
        vesting: vec![],
    };
    let mut chain = Blockchain::new(&config).unwrap();
    let deployment = |name: &str, bit, start, active| {
        Deployment::new(
            name,
            bit,
            BlockHeight::new(start),
            BlockHeight::new(start + 100),
            4,
            Threshold::new(3, 4).unwrap(),
            BlockHeight::new(active),
            false,
        )
        .unwrap()
    };
    chain.set_shielded_v2_deployment(deployment("shielded-v2", 2, 4, 12));
    chain.set_shielded_v2_suite2_deployment(deployment("shielded-v2-suite2", 5, 16, 24));
    chain.set_signal_mask((1 << 2) | (1 << 5));
    let mut node = Node::new(chain, 128, 32);
    node.set_coinbase(id("miner.sov"));
    node
}

fn mine(node: &mut Node, txs: Vec<SignedTransaction>) -> Block {
    let block = node
        .chain()
        .produce_block(txs, (node.chain().height() + 2) * 1_000)
        .unwrap();
    node.import_block(block.clone()).unwrap();
    block
}

fn signed(key: &Keypair, signer: AccountId, bundle: Vec<u8>, nonce: u64) -> SignedTransaction {
    SignedTransaction::sign(
        Transaction {
            signer,
            public_key: key.public_key(),
            nonce,
            action: Action::ShieldedV2 { bundle },
        },
        key,
    )
    .unwrap()
}

#[test]
fn empty_transparent_wallet_pays_exact_fee_from_verified_withdrawal_and_replays() {
    let mut source = node();
    let mut blocks = Vec::new();
    for _ in 0..12 {
        blocks.push(mine(&mut source, vec![]));
    }
    let old = PqShieldedKey::from_leaf_seed(&[91; 32]);
    let domain = source.chain().chain_domain();
    let genesis = domain.genesis();
    let gross = 500_000_000;
    let mut deposit = build_shield(&old, &old.address(), gross, 0).unwrap();
    authorize_for_carrier(
        &mut deposit,
        &old,
        domain.chain_id(),
        genesis.as_bytes(),
        "funding.sov",
        0,
    )
    .unwrap();
    let deposit_tx = signed(
        &Keypair::hybrid_from_seed([92; 32]),
        id("funding.sov"),
        encode_bundle(&deposit),
        0,
    );
    let deposited = mine(&mut source, vec![deposit_tx]);
    assert_eq!(deposited.transactions.len(), 1);
    let mut store = PqNoteStore::new(0);
    store.ingest_block(&old, 13, *deposited.hash().as_bytes(), &[&deposit]);
    blocks.push(deposited);
    while source.chain().height() < 23 {
        blocks.push(mine(&mut source, vec![]));
    }

    let payout_key = Keypair::hybrid_from_seed([94; 32]);
    let payout = payout_key.public_key().implicit_account_id();
    assert!(!source.chain().ledger().exists(&payout));
    assert_eq!(
        source.chain().ledger().account(&payout).balance,
        Balance::ZERO
    );
    let built = build_spend_suite2(
        &old,
        &store,
        None,
        gross,
        0,
        &PqShieldedKey::from_leaf_seed_suite2(&[91; 32]).address(),
        &CarrierContext {
            chain_id: domain.chain_id().as_bytes(),
            genesis: genesis.as_bytes(),
            signer: payout.as_str().as_bytes(),
            nonce: 0,
        },
    )
    .unwrap();
    let bytes = encode_bundle_for_suite(2, &built.bundle).unwrap();
    let tx = signed(&payout_key, payout.clone(), bytes.clone(), 0);
    let gas = sov_runtime::gas_for(&tx.transaction.action)
        + sov_runtime::gas::envelope_gas(&tx.transaction.public_key);
    let exact_fee = Balance::from_grains(u128::from(gas));
    assert!(exact_fee.grains() > 0 && exact_fee.grains() < u128::from(gross));
    let snapshot = source.chain().ledger().to_snapshot_bytes();

    // A signed carrier with an invalid proof must not obtain provisional
    // balance, consume a nonce, publish a nullifier or enter the mempool.
    let mut broken_proof = bytes.clone();
    // Version 2 retains the bounded public-input header: proof bytes begin
    // after version, digests, flags, public legs and the proof length (421).
    // The signed carrier's public inputs and ML-DSA authorization stay intact.
    broken_proof[421 + 20] ^= 1;
    let rejected_proof = signed(&payout_key, payout.clone(), broken_proof, 0);
    assert!(matches!(
        source.submit(rejected_proof),
        Err(NodeError::Suite2FeeFunding(ExecutionError::ShieldedV2(
            ShieldedV2Error::MalformedBundle(_) | ShieldedV2Error::InvalidProof(_)
        )))
    ));
    assert_eq!(source.mempool_len(), 0);
    assert_eq!(source.chain().ledger().to_snapshot_bytes(), snapshot);

    let mut broken = bytes;
    let final_byte = broken.len() - 1;
    broken[final_byte] ^= 1; // corrupt the independently checked ML-DSA authorization
    let rejected = signed(&payout_key, payout.clone(), broken, 0);
    assert!(source.submit(rejected).is_err());
    assert_eq!(source.mempool_len(), 0);
    assert_eq!(source.chain().ledger().to_snapshot_bytes(), snapshot);

    // The same genuine proof cannot create fee credit before bit 5, or cover
    // a fee larger than its verified payout. Policy changes here are isolated
    // execution fixtures, not an additional real-network activation schedule.
    let mut ledger = source.chain().ledger().clone();
    let mut policy = source.chain().mining_policy().clone();
    policy.gas_price = Balance::from_grains(100);
    let mut ctx = BlockContext {
        height: 24,
        prev_hash: source.chain().head().hash(),
        block_time_ms: 25_000,
        mining: &policy,
        gas_price: policy.gas_price,
        miner: id("miner.sov"),
        pq: None,
        tx_domain: source.chain().resolved_tx_domain_mode(24),
        fee_auction_active: false,
        shielded_v2_active: true,
        shielded_v2_suite2_active: true,
        tx_timestamp_active: false,
        chain_domain: domain.clone(),
    };
    assert!(matches!(
        apply_transaction(&mut ledger, &tx, &ctx),
        Err(ExecutionError::CannotAffordFee { .. })
    ));
    assert_eq!(ledger.to_snapshot_bytes(), snapshot);
    ctx.shielded_v2_suite2_active = false;
    assert!(apply_transaction(&mut ledger, &tx, &ctx).is_err());
    assert_eq!(ledger.to_snapshot_bytes(), snapshot);

    let pool_before = source.chain().ledger().shielded_v2_value();
    let supply_before = source.chain().ledger().total_supply().unwrap();
    let miner_before = source.chain().ledger().account(&id("miner.sov")).balance;
    let reward = source.chain().mint_reward();
    source.submit(tx.clone()).unwrap();
    assert_eq!(source.mempool_len(), 1);
    assert_eq!(source.chain().ledger().to_snapshot_bytes(), snapshot);
    let produced = source.produce(25_000).unwrap();
    assert_eq!(produced.block.transactions, vec![tx]);
    assert_eq!(produced.receipts[0].gas_used, gas);
    assert!(produced.receipts[0].succeeded());
    assert_eq!(source.mempool_len(), 0);
    assert_eq!(
        source.chain().ledger().shielded_v2_value(),
        pool_before
            .checked_sub(Balance::from_grains(u128::from(gross)))
            .unwrap()
    );
    assert_eq!(source.chain().ledger().shielded_v2().nullifier_count(), 1);
    assert_eq!(
        source.chain().ledger().account(&payout).balance,
        Balance::from_grains(u128::from(gross))
            .checked_sub(exact_fee)
            .unwrap()
    );
    assert_eq!(
        source.chain().ledger().account(&id("miner.sov")).balance,
        miner_before
            .checked_add(reward)
            .unwrap()
            .checked_add(exact_fee)
            .unwrap()
    );
    assert_eq!(
        source.chain().ledger().total_supply().unwrap(),
        supply_before.checked_add(reward).unwrap()
    );
    blocks.push(produced.block);

    // Independent nodes and a cold replay derive exactly the same pool, nonce,
    // miner fee, receiver net payout and whole-ledger commitment.
    for _ in 0..2 {
        let mut replay = node();
        for block in &blocks {
            replay.import_block(block.clone()).unwrap();
        }
        assert_eq!(replay.chain().head().hash(), source.chain().head().hash());
        assert_eq!(
            replay.chain().ledger().to_snapshot_bytes(),
            source.chain().ledger().to_snapshot_bytes()
        );
    }
}
