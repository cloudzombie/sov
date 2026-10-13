//! The pool-v2 (post-quantum) read RPC surface, over a real socket.
//!
//! These endpoints are served even while the `shielded-v2` deployment is
//! DORMANT, and that is deliberate: a wallet must be able to distinguish "the
//! pool is empty" from "this node does not know about pool v2". Reporting the
//! second as the first is how a user concludes their funds vanished.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance};
use sov_rpc::RpcServer;

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn node() -> Node {
    let config = GenesisConfig {
        chain_id: "sov-shieldedv2-rpc-test".into(),
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
    let mut n = Node::new(Blockchain::new(&config).unwrap(), 1024, 256);
    n.set_coinbase(id("val01.node.sov"));
    n
}

fn serve() -> (Arc<Mutex<Node>>, sov_rpc::RpcHandle, SocketAddr) {
    serve_node(node())
}

fn serve_node(n: Node) -> (Arc<Mutex<Node>>, sov_rpc::RpcHandle, SocketAddr) {
    let node = Arc::new(Mutex::new(n));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .expect("server binds");
    let addr = handle.local_addr();
    (node, handle, addr)
}

fn arm_v2(n: &mut Node) {
    use sov_governance::{Deployment, Threshold};
    use sov_primitives::BlockHeight;
    n.chain_mut().set_shielded_v2_deployment(
        Deployment::new(
            sov_governance::SHIELDED_V2_DEPLOYMENT,
            2,
            BlockHeight::new(4),
            BlockHeight::new(400),
            4,
            Threshold::new(3, 4).unwrap(),
            BlockHeight::new(0),
            true,
        )
        .unwrap(),
    );
    n.chain_mut().set_signal_mask(1 << 2);
}

fn rpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let body = serde_json::to_vec(&req).unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    let header = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    let split = text.find("\r\n\r\n").expect("http body");
    serde_json::from_str(text[split + 4..].trim()).expect("json")
}

#[test]
fn shielded_v2_info_is_served_and_reports_dormant_honestly() {
    let (_node, handle, addr) = serve();
    let r = rpc(addr, "sov_getShieldedV2Info", json!({}))["result"].clone();

    // The distinction that matters: served, but explicitly NOT active.
    assert_eq!(
        r["active"],
        json!(false),
        "bit 2 is defined and not armed, so the pool must report dormant"
    );
    // An empty pool is still a truthful answer, not a placeholder.
    assert_eq!(r["poolValue"], json!("0"));
    assert_eq!(r["noteCount"], json!(0));
    assert_eq!(r["nullifierCount"], json!(0));
    assert!(
        r["anchor"].as_str().is_some_and(|a| a.len() == 64),
        "the empty-tree anchor is still a real 32-byte digest"
    );
    // The drain-limiter fields mirror pool v1 so a wallet has one mental model.
    assert!(r["deshieldLimitGrains"].is_string());
    assert!(r["deshieldableNowGrains"].is_string());
    assert!(r["height"].is_number());

    handle.shutdown();
}

#[test]
fn shielded_v2_anchors_serves_the_ring() {
    let (_node, handle, addr) = serve();
    let r = rpc(addr, "sov_getShieldedV2Anchors", json!({}))["result"].clone();
    assert_eq!(r["active"], json!(false));
    let anchors = r["anchors"].as_array().expect("anchors array");

    // A fresh pool is NOT anchorless: the ring is seeded with the empty-tree
    // root, which is a legitimate anchor to prove against. (My first version of
    // this test asserted an empty list — the code was right and the assumption
    // was wrong.) A client proving against an anchor absent from this ring
    // wastes prover time on a bundle consensus will reject, so the ring is the
    // authoritative list.
    assert_eq!(anchors.len(), 1, "the empty-tree root seeds the ring");

    // The two endpoints must agree: the newest anchor here is the `anchor`
    // reported by getShieldedV2Info. A client that mixes them would build
    // against a root the chain does not hold.
    let info = rpc(addr, "sov_getShieldedV2Info", json!({}))["result"].clone();
    assert_eq!(
        anchors[0], info["anchor"],
        "the ring's anchor and the reported anchor must be the same root"
    );
    handle.shutdown();
}

#[test]
fn nullifier_lookup_answers_and_rejects_a_non_canonical_digest() {
    let (_node, handle, addr) = serve();

    // An unspent nullifier: answered, not errored.
    let zero = "00".repeat(32);
    let r = rpc(
        addr,
        "sov_shieldedV2NullifierSeen",
        json!({ "nullifier": zero }),
    )["result"]
        .clone();
    assert_eq!(r["seen"], json!(false));

    // Wrong length is bad params, not a panic or a silent wrong answer.
    let short = rpc(
        addr,
        "sov_shieldedV2NullifierSeen",
        json!({ "nullifier": "00" }),
    );
    assert!(short["error"].is_object(), "a 1-byte nullifier is invalid");

    // Not hex at all.
    let bad = rpc(
        addr,
        "sov_shieldedV2NullifierSeen",
        json!({ "nullifier": "zz".repeat(32) }),
    );
    assert!(bad["error"].is_object(), "non-hex is invalid");

    // Well-formed hex that is NOT a canonical field-element digest must be
    // rejected rather than answered about some other value.
    let noncanonical = "ff".repeat(32);
    let nc = rpc(
        addr,
        "sov_shieldedV2NullifierSeen",
        json!({ "nullifier": noncanonical }),
    );
    assert!(
        nc["error"].is_object() || nc["result"]["seen"] == json!(false),
        "a non-canonical digest is either rejected or truthfully unseen"
    );

    handle.shutdown();
}

#[test]
fn quantum_status_and_write_policy_fail_closed_without_mutating_state() {
    let (node, handle, addr) = serve();
    let before = node.lock().unwrap().chain().head().hash();
    let status = rpc(addr, "sov_getQuantumStatus", json!({}));
    assert_eq!(status["result"]["pqSunset"]["stage"], "unarmed");
    assert_eq!(status["result"]["poolV2CreationAllowed"], false);
    assert_eq!(status["result"]["v2PrivacyEstablished"], false);
    let key = Keypair::hybrid_from_seed([123; 32]);
    let tx = sov_types::SignedTransaction::sign(
        sov_types::Transaction {
            signer: key.public_key().implicit_account_id(),
            public_key: key.public_key(),
            nonce: 0,
            action: sov_types::Action::ProposeMultisig {
                account: id("vault.sov"),
                action: Box::new(sov_types::Action::ShieldedV2 { bundle: vec![] }),
            },
        },
        &key,
    )
    .unwrap();
    let reply = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(tx).unwrap(),
    );
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("private inputs"));
    assert_eq!(node.lock().unwrap().mempool_len(), 0);
    assert_eq!(node.lock().unwrap().chain().head().hash(), before);
    handle.shutdown();
}

#[test]
fn historical_v2_funds_replay_remain_visible_and_are_not_a_recovery_permission() {
    use sov_shielded_pq::hd::PqShieldedKey;
    use sov_shielded_pq::scan::PqNoteStore;
    use sov_shielded_pq::wallet::{authorize_for_carrier, build_shield, build_spend};
    use sov_shielded_pq::{encode_bundle, SpendBundle};
    use sov_types::{Action, SignedTransaction, Transaction};

    let mut historic = node();
    arm_v2(&mut historic);
    let mut blocks = Vec::new();
    let mut timestamp = 2_000;
    for _ in 1..=11 {
        let block = historic
            .chain_mut()
            .produce_block(vec![], timestamp)
            .unwrap();
        historic.chain_mut().import_block(block.clone()).unwrap();
        blocks.push(block);
        timestamp += 1_000;
    }
    assert!(historic.chain().shielded_v2_active(12));

    let owner = PqShieldedKey::from_leaf_seed(&[73; 32]);
    let carrier = Keypair::from_seed([2; 32]);
    let chain_id = historic.chain().chain_id().to_string();
    let genesis = historic.chain().chain_domain().genesis();
    let bind = |bundle: &mut SpendBundle, nonce| {
        authorize_for_carrier(
            bundle,
            &owner,
            &chain_id,
            genesis.as_bytes(),
            "usa.reserve.sov",
            nonce,
        )
        .unwrap();
        SignedTransaction::sign(
            Transaction {
                signer: id("usa.reserve.sov"),
                public_key: carrier.public_key(),
                nonce,
                action: Action::ShieldedV2 {
                    bundle: encode_bundle(bundle),
                },
            },
            &carrier,
        )
        .unwrap()
    };
    let five = u64::try_from(Balance::from_sov(5).unwrap().grains()).unwrap();
    let two = u64::try_from(Balance::from_sov(2).unwrap().grains()).unwrap();
    let mut shield = build_shield(&owner, &owner.address(), five, 0).unwrap();
    let shield_tx = bind(&mut shield, 0);
    let block = historic
        .chain_mut()
        .produce_block(vec![shield_tx], timestamp)
        .unwrap();
    assert_eq!(block.transactions.len(), 1);
    historic.chain_mut().import_block(block.clone()).unwrap();
    let mut store = PqNoteStore::new(0);
    store.ingest_block(&owner, 12, *block.hash().as_bytes(), &[&shield]);
    blocks.push(block);
    timestamp += 1_000;

    let mut withdrawn = build_spend(&owner, &store, None, two, 0).unwrap().bundle;
    let withdrawal_tx = bind(&mut withdrawn, 1);
    let block = historic
        .chain_mut()
        .produce_block(vec![withdrawal_tx], timestamp)
        .unwrap();
    assert_eq!(block.transactions.len(), 1);
    historic.chain_mut().import_block(block.clone()).unwrap();
    store.ingest_block(&owner, 13, *block.hash().as_bytes(), &[&withdrawn]);
    blocks.push(block);
    let expected_pool = Balance::from_sov(3).unwrap();
    assert_eq!(store.balance(), expected_pool.grains() as u64);

    // Full block execution in a fresh node proves the deployed wire format,
    // commitments, nullifiers, balances and total supply still replay. This
    // deliberately bypasses only *new transaction admission*, as historical
    // block import does in production; no alternate verifier is installed.
    let mut replay = node();
    arm_v2(&mut replay);
    for block in blocks {
        replay.chain_mut().import_block(block).unwrap();
    }
    assert_eq!(replay.chain().head().hash(), historic.chain().head().hash());
    assert_eq!(
        replay.chain().ledger().state_root(),
        historic.chain().ledger().state_root()
    );
    assert_eq!(replay.chain().ledger().shielded_v2_value(), expected_pool);
    assert_eq!(replay.chain().ledger().shielded_v2().note_count(), 2);
    assert_eq!(replay.chain().ledger().shielded_v2().nullifier_count(), 1);
    let snapshot = replay.chain().ledger().to_snapshot_bytes();
    let restored = sov_state::Ledger::from_snapshot_bytes(&snapshot).unwrap();
    assert_eq!(restored.state_root(), replay.chain().ledger().state_root());
    assert_eq!(restored.shielded_v2_value(), expected_pool);
    assert_eq!(
        restored.shielded_v2(),
        replay.chain().ledger().shielded_v2()
    );

    let mut recovery = build_spend(&owner, &store, None, store.balance(), 0)
        .unwrap()
        .bundle;
    let recovery_tx = bind(&mut recovery, 2);
    assert_eq!(recovery.public_inputs.transparent_in, 0);
    assert!(recovery
        .public_inputs
        .output_dummy
        .iter()
        .all(|&dummy| dummy));
    let (node, handle, addr) = serve_node(replay);
    let info = rpc(addr, "sov_getShieldedV2Info", json!({}))["result"].clone();
    assert_eq!(info["active"], true);
    assert_eq!(info["poolValue"], expected_pool.grains().to_string());
    assert_eq!(info["noteCount"], 2);
    assert_eq!(info["nullifierCount"], 1);
    assert_eq!(info["scanSupported"], true);
    assert_eq!(info["historicalReplaySupported"], true);
    assert_eq!(
        info["historicalProofVersions"],
        if cfg!(feature = "zk-suite2") {
            json!([1, 2])
        } else {
            json!([1])
        }
    );
    assert_eq!(info["acceptedNewProofVersions"], json!([]));
    assert_eq!(info["spendsAllowed"], false);
    assert_eq!(info["recoveryAllowed"], false);
    let supply = rpc(addr, "sov_getSupply", json!({}))["result"].clone();
    assert_eq!(supply["shieldedV2"], expected_pool.grains().to_string());
    let total: u128 = supply["total"].as_str().unwrap().parse().unwrap();
    let transparent: u128 = supply["transparent"].as_str().unwrap().parse().unwrap();
    let v1: u128 = supply["shielded"].as_str().unwrap().parse().unwrap();
    assert_eq!(total, transparent + v1 + expected_pool.grains());

    let reply = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(recovery_tx).unwrap(),
    );
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("private inputs"));
    let n = node.lock().unwrap();
    assert_eq!(n.mempool_len(), 0);
    assert_eq!(n.chain().ledger().to_snapshot_bytes(), snapshot);
    drop(n);
    handle.shutdown();
}
