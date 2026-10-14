//! Real isolated activation, RPC submission, legacy-note recovery and replay.
#![cfg(feature = "zk-suite2")]

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_governance::{Deployment, Threshold};
use sov_mining::MiningPolicy;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, BlockHeight};
use sov_rpc::{RpcClient, RpcServer};
use sov_shielded_pq::carrier::CarrierContext;
use sov_shielded_pq::wallet::{authorize_for_carrier, build_shield, build_spend_suite2};
use sov_shielded_pq::wire::{decode_bundle_for_suite, encode_bundle, encode_bundle_for_suite};
use sov_shielded_pq::{PqNoteStore, PqShieldedKey};
use sov_types::{Action, Block, SignedTransaction, Transaction};
use std::sync::{Arc, Mutex};

fn account() -> AccountId {
    AccountId::new("owner.sov").unwrap()
}
fn config() -> GenesisConfig {
    GenesisConfig {
        chain_id: "sov-suite2-rehearsal-recovery".into(),
        timestamp_ms: 1_000,
        accounts: vec![GenesisAccount {
            account: account(),
            key: Keypair::hybrid_from_seed([82; 32]).public_key(),
            balance: Balance::from_sov(1_000).unwrap(),
        }],
        mining: MiningPolicy::test(),
        vesting: vec![],
    }
}
fn chain(recovery: bool) -> Blockchain {
    let mut chain = Blockchain::new(&config()).unwrap();
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
    chain.set_tx_domain_deployment(deployment("tx-domain", 0, 4, 12));
    chain.set_tx_domain_grace_blocks(0);
    chain.set_shielded_v2_deployment(deployment("shielded-v2", 2, 4, 12));
    if recovery {
        chain.set_shielded_v2_suite2_deployment(
            Deployment::new(
                "shielded-v2-suite2",
                5,
                BlockHeight::new(4),
                BlockHeight::new(16),
                4,
                Threshold::new(3, 4).unwrap(),
                BlockHeight::new(12),
                false,
            )
            .unwrap(),
        );
        chain.set_shielded_v2_suite2_recovery_deployment(deployment(
            "shielded-v2-suite2-recovery",
            6,
            16,
            20,
        ));
    } else {
        chain.set_shielded_v2_suite2_deployment(deployment("shielded-v2-suite2", 5, 16, 24));
    }
    chain.set_pq_deployment(sov_chain::blockchain::PqDeploymentConfig {
        deployment: deployment("pq-sunset", 4, 24, 32),
        sunset_delay_blocks: 8,
        threshold_grains: 0,
    });
    chain.set_signal_mask((1 << 0) | (1 << 2) | (1 << 4) | (1 << if recovery { 6 } else { 5 }));
    chain
}
fn mine(node: &mut Node, txs: Vec<SignedTransaction>) -> Block {
    let block = node
        .chain()
        .produce_block(txs, (node.chain().height() + 2) * 1_000)
        .unwrap();
    node.import_block(block.clone()).unwrap();
    block
}
fn signed(node: &Node, bundle: Vec<u8>, nonce: u64) -> SignedTransaction {
    let key = Keypair::hybrid_from_seed([82; 32]);
    let domain = node.chain().resolved_tx_domain(node.chain().height() + 1);
    SignedTransaction::sign_in(
        Transaction {
            signer: account(),
            public_key: key.public_key(),
            nonce,
            action: Action::ShieldedV2 { bundle },
        },
        &key,
        domain.as_ref(),
    )
    .unwrap()
}
fn scan(key: &PqShieldedKey, blocks: &[Block]) -> PqNoteStore {
    let mut store = PqNoteStore::new(0);
    for block in blocks {
        let bundles: Vec<_> = block
            .transactions
            .iter()
            .filter_map(|tx| match &tx.transaction.action {
                Action::ShieldedV2 { bundle } => {
                    Some(decode_bundle_for_suite(bundle[0], bundle).unwrap())
                }
                _ => None,
            })
            .collect();
        let refs: Vec<_> = bundles.iter().collect();
        store.ingest_block(
            key,
            block.header.height.get(),
            *block.hash().as_bytes(),
            &refs,
        );
    }
    store
}

#[test]
fn legacy_deposit_recovers_through_hiding_rpc_spends_after_activation_and_sunset() {
    exercise_legacy_recovery(false);
}

#[test]
fn failed_original_window_recovers_legacy_notes_through_distinct_bit6_and_cold_replay() {
    exercise_legacy_recovery(true);
}

fn exercise_legacy_recovery(recovery: bool) {
    let node = Arc::new(Mutex::new(Node::new(chain(recovery), 128, 32)));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .unwrap();
    let client = RpcClient::new(handle.local_addr().to_string());
    let old = PqShieldedKey::from_leaf_seed(&[81; 32]);
    let fresh = PqShieldedKey::from_leaf_seed_suite2(&[81; 32]);
    assert_ne!(old.owner_tag(), fresh.owner_tag());
    let mut blocks = Vec::new();
    for _ in 0..12 {
        blocks.push(mine(&mut node.lock().unwrap(), vec![]));
    }
    // This is an imported historical deposit fixture, not a new legacy RPC
    // exception. Deposit-only history has never published this input NSK.
    let domain = node.lock().unwrap().chain().chain_domain();
    let mut deposit = build_shield(&old, &old.address(), 500_000_000, 0).unwrap();
    authorize_for_carrier(
        &mut deposit,
        &old,
        domain.chain_id(),
        domain.genesis().as_bytes(),
        "owner.sov",
        0,
    )
    .unwrap();
    let tx = signed(&node.lock().unwrap(), encode_bundle(&deposit), 0);
    assert!(
        client.submit_transaction(&tx).is_err(),
        "no legacy write-policy bypass"
    );
    blocks.push(mine(&mut node.lock().unwrap(), vec![tx]));
    let old_store = scan(&old, &blocks);
    assert_eq!(old_store.balance(), 500_000_000);
    let genesis = domain.genesis();
    let carrier = CarrierContext {
        chain_id: domain.chain_id().as_bytes(),
        genesis: genesis.as_bytes(),
        signer: b"owner.sov",
        nonce: 1,
    };
    let first = build_spend_suite2(
        &old,
        &old_store,
        None,
        200_000_000,
        0,
        &fresh.address(),
        &carrier,
    )
    .unwrap();
    let bytes = encode_bundle_for_suite(2, &first.bundle).unwrap();
    let tx = signed(&node.lock().unwrap(), bytes, 1);
    assert!(
        tx.serialized_size() > sov_types::MAX_TX_WEIGHT as usize,
        "exercise new admission size path"
    );
    assert!(
        client.submit_transaction(&tx).is_err(),
        "replacement proof is not active yet"
    );
    for _ in 13..19 {
        blocks.push(mine(&mut node.lock().unwrap(), vec![]));
    }
    let locked = client
        .call("sov_getShieldedV2Info", serde_json::json!({}))
        .unwrap();
    let chosen_bit = if recovery { 6 } else { 5 };
    let locked_deployment = locked["suite2Deployments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["bit"] == chosen_bit)
        .unwrap();
    assert_eq!(locked["height"], 19);
    assert_eq!(locked["evaluatedHeight"], 20);
    assert_eq!(locked["suite2NextBlockActive"], false);
    assert_eq!(locked_deployment["state"], "Started");
    assert_eq!(locked_deployment["nextState"], "LockedIn");
    assert_eq!(locked_deployment["activationHeight"], 24);
    for _ in 19..23 {
        blocks.push(mine(&mut node.lock().unwrap(), vec![]));
    }
    assert!(node.lock().unwrap().chain().shielded_v2_suite2_active(24));
    let info = client
        .call("sov_getShieldedV2Info", serde_json::json!({}))
        .unwrap();
    assert_eq!(info["height"], 23);
    assert_eq!(info["evaluatedHeight"], 24);
    assert_eq!(info["suite2CurrentActive"], false);
    assert_eq!(info["suite2NextBlockActive"], true);
    assert_eq!(info["suite2Active"], true);
    assert_eq!(info["spendsAllowed"], true);
    assert_eq!(info["acceptedNewProofVersions"], serde_json::json!([2]));
    let deployments = client
        .call("sov_getDeployments", serde_json::json!({}))
        .unwrap();
    let suite_deployments = info["suite2Deployments"].as_array().unwrap();
    let chosen = suite_deployments
        .iter()
        .find(|d| d["bit"] == chosen_bit)
        .unwrap();
    assert_eq!(chosen["state"], "LockedIn");
    assert_eq!(chosen["nextState"], "Active");
    assert_eq!(chosen["activationHeight"], 24);
    assert_eq!(chosen["earliestActivationHeight"], 24);
    assert_eq!(chosen["requiredSignalingBlocks"], 3);
    assert_eq!(chosen["windowSignalingBlocks"], 4);
    assert!(deployments["deployments"]
        .as_array()
        .unwrap()
        .contains(chosen));
    if recovery {
        let old = suite_deployments.iter().find(|d| d["bit"] == 5).unwrap();
        assert_eq!(old["state"], "Failed");
        assert_eq!(old["nextState"], "Failed");
        assert_eq!(old["activationHeight"], serde_json::Value::Null);
    }
    client.submit_transaction(&tx).unwrap();
    blocks.push(mine(&mut node.lock().unwrap(), vec![tx]));
    assert_eq!(blocks.last().unwrap().transactions.len(), 1);
    assert_eq!(
        node.lock()
            .unwrap()
            .chain()
            .ledger()
            .shielded_v2_value()
            .grains(),
        300_000_000
    );
    assert_eq!(scan(&old, &blocks).balance(), 0);
    let fresh_store = scan(&fresh, &blocks);
    assert_eq!(
        fresh_store.balance(),
        300_000_000,
        "change pays independent new spending key"
    );
    for _ in 24..31 {
        blocks.push(mine(&mut node.lock().unwrap(), vec![]));
    }
    assert!(node.lock().unwrap().chain().resolved_pq(32).is_some());
    let carrier = CarrierContext {
        nonce: 2,
        ..carrier
    };
    let second = build_spend_suite2(
        &fresh,
        &fresh_store,
        None,
        300_000_000,
        0,
        &fresh.address(),
        &carrier,
    )
    .unwrap();
    let tx = signed(
        &node.lock().unwrap(),
        encode_bundle_for_suite(2, &second.bundle).unwrap(),
        2,
    );
    client.submit_transaction(&tx).unwrap();
    blocks.push(mine(&mut node.lock().unwrap(), vec![tx]));
    assert_eq!(
        blocks.last().unwrap().transactions.len(),
        1,
        "new suite remains spendable at PQ retirement"
    );
    assert_eq!(
        node.lock().unwrap().chain().ledger().shielded_v2_value(),
        Balance::ZERO
    );
    assert_eq!(
        node.lock()
            .unwrap()
            .chain()
            .ledger()
            .shielded_v2()
            .nullifier_count(),
        2
    );
    for _ in 32..40 {
        blocks.push(mine(&mut node.lock().unwrap(), vec![]));
    }
    let expected = node.lock().unwrap().chain().head().clone();
    let expected_supply = node.lock().unwrap().chain().ledger().total_supply();
    for _ in 0..2 {
        let mut replay = chain(recovery);
        for block in &blocks {
            replay.import_block(block.clone()).unwrap();
        }
        assert_eq!(replay.head(), &expected);
        assert_eq!(replay.ledger().total_supply(), expected_supply);
        assert_eq!(replay.ledger().shielded_v2_value(), Balance::ZERO);
    }
    handle.shutdown();
}
