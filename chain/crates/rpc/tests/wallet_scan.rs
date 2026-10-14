//! Wallet scan pages over the real HTTP server: full authenticated inputs,
//! bounded contiguous pagination, stable snapshots, and explicit reorg failure.

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance};
use sov_rpc::{RpcClient, RpcServer};
use sov_types::{Action, Block, Receipt, SignedTransaction, Transaction};
use std::sync::{Arc, Mutex};

fn node() -> Node {
    let key = Keypair::from_seed([82; 32]);
    let config = GenesisConfig {
        chain_id: "sov-wallet-scan-test".into(),
        timestamp_ms: 1_000,
        accounts: vec![GenesisAccount {
            account: AccountId::new("owner.sov").unwrap(),
            key: key.public_key(),
            balance: Balance::from_sov(1_000).unwrap(),
        }],
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    };
    let mut node = Node::new(Blockchain::new(&config).unwrap(), 128, 128);
    node.set_coinbase(AccountId::new("miner.sov").unwrap());
    node
}

#[test]
fn wallet_scan_pages_match_existing_blocks_and_receipts_through_a_growing_tip() {
    let mut node = node();
    let key = Keypair::from_seed([82; 32]);
    node.submit(
        SignedTransaction::sign(
            Transaction {
                signer: AccountId::new("owner.sov").unwrap(),
                public_key: key.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: AccountId::new("recipient.sov").unwrap(),
                    amount: Balance::from_sov(1).unwrap(),
                },
            },
            &key,
        )
        .unwrap(),
    )
    .unwrap();
    for height in 1..=260 {
        node.produce(1_000 + height * 1_000).unwrap();
    }
    let snapshot_hash = node.chain().head().hash();
    let genesis_hash = node.chain().block_by_height(0).unwrap().hash();
    let node = Arc::new(Mutex::new(node));
    let server = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .unwrap();
    let client = RpcClient::new(server.local_addr().to_string());
    let mut params = json!({
        "fromHeight": 0, "limit": u64::MAX,
        "snapshotHeight": 260, "snapshotHash": snapshot_hash.to_hex(),
    });
    let first: Value = client
        .call("sov_getWalletScanBlocks", params.clone())
        .unwrap();
    assert_eq!(first["chainId"], "sov-wallet-scan-test");
    assert_eq!(first["genesisHash"], genesis_hash.to_hex());
    assert_eq!(first["snapshotHeight"], 260);
    assert_eq!(first["snapshotHash"], snapshot_hash.to_hex());
    assert_eq!(first["fromHeight"], 0);
    assert_eq!(first["nextHeight"], 256);
    assert_eq!(first["complete"], false);
    assert_eq!(first["blocks"].as_array().unwrap().len(), 256);
    assert!(serde_json::to_vec(&first).unwrap().len() <= 8 * 1024 * 1024);
    let entry = &first["blocks"][1];
    let old_block: Value = client
        .call("sov_getBlockByHeight", json!({"height": 1}))
        .unwrap();
    let old_receipts: Value = client
        .call("sov_getBlockReceipts", json!({"height": 1}))
        .unwrap();
    assert_eq!(entry["block"], old_block);
    assert_eq!(entry["receipts"], old_receipts);
    assert_eq!(entry["receipts"].as_array().unwrap().len(), 1);
    let block: Block = serde_json::from_value(entry["block"].clone()).unwrap();
    let receipts: Vec<Receipt> = serde_json::from_value(entry["receipts"].clone()).unwrap();
    assert!(block.tx_root_matches());
    assert_eq!(
        sov_types::receipts_root(&receipts),
        block.header.receipts_root
    );

    // Mining during a scan neither invalidates an unchanged snapshot nor
    // silently extends the range past the root the wallet initially captured.
    node.lock().unwrap().produce(262_000).unwrap();
    params["fromHeight"] = first["nextHeight"].clone();
    let last: Value = client
        .call("sov_getWalletScanBlocks", params.clone())
        .unwrap();
    assert_eq!(last["nextHeight"], 261);
    assert_eq!(last["complete"], true);
    let heights: Vec<u64> = first["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .chain(last["blocks"].as_array().unwrap())
        .map(|entry| entry["block"]["header"]["height"].as_u64().unwrap())
        .collect();
    assert_eq!(heights, (0..=260).collect::<Vec<_>>());
    params["fromHeight"] = json!(261);
    let complete: Value = client.call("sov_getWalletScanBlocks", params).unwrap();
    assert_eq!(complete["blocks"], json!([]));
    assert_eq!(complete["nextHeight"], 261);
    assert_eq!(complete["complete"], true);
    server.shutdown();
}

#[test]
fn wallet_scan_refuses_replaced_snapshot_and_bad_ranges() {
    let mut primary = node();
    primary.produce(2_000).unwrap();
    let old_snapshot = primary.chain().head().hash();
    let node = Arc::new(Mutex::new(primary));
    let server = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .unwrap();
    let client = RpcClient::new(server.local_addr().to_string());
    let params = json!({
        "fromHeight": 0, "limit": 1,
        "snapshotHeight": 1, "snapshotHash": old_snapshot.to_hex(),
    });
    let _: Value = client
        .call("sov_getWalletScanBlocks", params.clone())
        .unwrap();
    for (key, bad) in [
        ("fromHeight", json!(3)),
        ("limit", json!(0)),
        ("limit", json!("256")),
        ("snapshotHash", json!("invalid")),
        ("snapshotHeight", json!(u64::MAX)),
    ] {
        let mut malformed = params.clone();
        malformed[key] = bad;
        assert!(matches!(
            client.call("sov_getWalletScanBlocks", malformed),
            Err(sov_rpc::RpcClientError::Rpc { code: -32602, .. })
        ));
    }
    let mut rival = self::node();
    let first = rival.produce(2_100).unwrap().block;
    let second = rival.produce(3_100).unwrap().block;
    {
        let mut node = node.lock().unwrap();
        node.import_block(first).unwrap();
        node.import_block(second).unwrap();
        assert_ne!(
            node.chain().block_by_height(1).unwrap().hash(),
            old_snapshot
        );
    }
    assert!(matches!(
        client.call("sov_getWalletScanBlocks", params),
        Err(sov_rpc::RpcClientError::Rpc { code: -32000, .. })
    ));
    server.shutdown();
}

#[test]
fn transaction_status_distinguishes_rejection_nonce_gap_unknown_and_confirmation() {
    let mut node = node();
    let key = Keypair::from_seed([82; 32]);
    let tx = |nonce| {
        SignedTransaction::sign(
            Transaction {
                signer: AccountId::new("owner.sov").unwrap(),
                public_key: key.public_key(),
                nonce,
                action: Action::Transfer {
                    to: AccountId::new("recipient.sov").unwrap(),
                    amount: Balance::from_sov(1).unwrap(),
                },
            },
            &key,
        )
        .unwrap()
    };
    let first = tx(0);
    let second = tx(1);
    node.submit(first.clone()).unwrap();
    node.submit(second.clone()).unwrap();
    let node = Arc::new(Mutex::new(node));
    let server = RpcServer::new(node.clone())
        .start("127.0.0.1:0", 2)
        .unwrap();
    let client = RpcClient::new(server.local_addr().to_string());
    let status = |id: sov_primitives::Hash| {
        client
            .call("sov_getTransactionStatus", json!({"txId": id.to_hex()}))
            .unwrap()
    };
    assert_eq!(status(first.id())["state"], "pending");
    node.lock()
        .unwrap()
        .reject_tx(first.id(), "input 0: nullifier already spent".into());
    let rejected = status(first.id());
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(rejected["nodeLocal"], true);
    assert_eq!(rejected["observedHeight"], 0);
    assert!(rejected["reason"]
        .as_str()
        .unwrap()
        .contains("already spent"));
    assert_eq!(status(second.id())["state"], "queued");
    assert_eq!(
        status(sov_primitives::Hash::digest(b"unknown"))["state"],
        "unknown"
    );
    // A later accepted inclusion takes precedence over old node-local observations.
    node.lock().unwrap().submit(first.clone()).unwrap();
    node.lock().unwrap().produce(2_000).unwrap();
    let included = status(first.id());
    assert_eq!(included["state"], "included");
    assert_eq!(included["nodeLocal"], false);
    assert_eq!(included["receipt"]["status"]["status"], "success");
    server.shutdown();
}
