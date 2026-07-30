//! `sov_getReceiptProof` over a real socket — the endpoint that lets a light
//! client verify a receipt, and the creation time committed inside it, WITHOUT
//! trusting the node that served it.
//!
//! The point of committing transaction timing to the receipt (rather than
//! keeping it in a node-local index) is exactly this: the client re-derives the
//! Merkle root from the receipt plus the returned sibling path and compares it
//! with the `receiptsRoot` in a block header it already trusts. A node that
//! invents a receipt, alters a creation time, or serves a path from a different
//! block fails that check.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, BlockHeight, Hash};
use sov_rpc::RpcServer;
use sov_types::{Action, Receipt, ReceiptProof, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// The `tx-timestamp` deployment used here: bit 3, signaling opens at 4,
/// window 4, 3-of-4 threshold — a chain signaling every block is LockedIn at 8
/// and Active at 12, the same shape the `sov-chain` activation tests use.
fn tx_timestamp_deployment() -> sov_governance::Deployment {
    sov_governance::Deployment::new(
        sov_governance::TX_TIMESTAMP_DEPLOYMENT,
        sov_governance::BIT_TX_TIMESTAMP,
        BlockHeight::new(4),
        BlockHeight::new(400),
        4,
        sov_governance::Threshold::new(3, 4).unwrap(),
        BlockHeight::new(0),
        false,
    )
    .unwrap()
}

fn node() -> Node {
    let config = GenesisConfig {
        chain_id: "sov-receipt-proof-test".into(),
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
    let mut chain = Blockchain::new(&config).unwrap();
    chain.set_tx_timestamp_deployment(tx_timestamp_deployment());
    chain.set_signal_mask(1 << sov_governance::BIT_TX_TIMESTAMP);
    let mut n = Node::new(chain, 1024, 256);
    n.set_coinbase(id("val01.node.sov"));
    n
}

fn serve(node: Node) -> (Arc<Mutex<Node>>, sov_rpc::RpcHandle, SocketAddr) {
    let node = Arc::new(Mutex::new(node));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .expect("server binds");
    let addr = handle.local_addr();
    (node, handle, addr)
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

fn transfer(nonce: u64, action: Action) -> SignedTransaction {
    let kp = Keypair::from_seed([2; 32]);
    SignedTransaction::sign(
        Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            action,
        },
        &kp,
    )
    .unwrap()
}

fn plain(nonce: u64) -> SignedTransaction {
    transfer(
        nonce,
        Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(1).unwrap(),
        },
    )
}

fn timestamped(created_at_ms: u64, nonce: u64) -> SignedTransaction {
    transfer(
        nonce,
        Action::Timestamped {
            created_at_ms,
            inner: Box::new(Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            }),
        },
    )
}

/// Mine `n` empty blocks so the deployment signals its way to Active, returning
/// the next timestamp to use.
fn mine_to_activation(node: &mut Node) -> u64 {
    let mut ts = 2_000u64;
    for _ in 1..=11 {
        let produced = node.produce(ts).expect("produce");
        node.commit_mined(produced.block).expect("commit");
        ts += 1_000;
    }
    assert!(
        node.chain().tx_timestamp_active(12),
        "bit 3 is Active at 12"
    );
    ts
}

/// End to end: mine a timestamped transaction, fetch its proof over JSON-RPC,
/// and verify it with NO further help from the node — that the receipt is
/// committed under the block's `receiptsRoot`, that `created_at_ms == T`, and
/// that `block.timestampMs - created_at_ms == X`.
#[test]
fn a_light_client_verifies_creation_time_from_the_proof_alone() {
    const WAITED_MS: u64 = 5_000;
    let mut n = node();
    let ts = mine_to_activation(&mut n);
    let created_at = ts - WAITED_MS;

    // Two transactions, so the receipt tree has a real sibling path.
    let stamped = timestamped(created_at, 0);
    let stamped_id = stamped.id();
    n.submit(stamped).expect("timestamped tx is admitted");
    n.submit(plain(1)).expect("plain tx is admitted");
    let produced = n.produce(ts).expect("produce");
    assert_eq!(produced.block.transactions.len(), 2);
    let header = produced.block.header.clone();
    n.commit_mined(produced.block).expect("commit");
    let height = header.height.get();

    let (_node, handle, addr) = serve(n);
    let r = rpc(
        addr,
        "sov_getReceiptProof",
        json!({ "txId": stamped_id.to_hex() }),
    )["result"]
        .clone();

    // The node's own claims, which we are about to check rather than trust.
    assert_eq!(r["height"], json!(height));
    assert_eq!(r["timestampMs"], json!(header.timestamp_ms));
    assert_eq!(r["waitedMs"], json!(WAITED_MS));

    // ── Everything below is what a light client does ────────────────────────
    // Inputs: the JSON above, and a block header the client already trusts.
    let receipt: Receipt = serde_json::from_value(r["receipt"].clone()).expect("receipt decodes");
    let proof = ReceiptProof {
        index: r["index"].as_u64().expect("index") as u32,
        siblings: serde_json::from_value(r["siblings"].clone()).expect("siblings decode"),
    };
    // The served root must equal the header's — a client uses ITS OWN header.
    let served_root: Hash =
        serde_json::from_value(r["receiptsRoot"].clone()).expect("root decodes");
    assert_eq!(served_root, header.receipts_root);

    assert!(
        sov_types::verify_receipt_proof(&receipt, &proof, &header.receipts_root),
        "the receipt must verify against the trusted header's receipts_root"
    );
    let timing = receipt.timing.expect("a timestamped tx commits its timing");
    assert_eq!(timing.created_at_ms, created_at, "created at T");
    assert_eq!(
        header.timestamp_ms - timing.created_at_ms,
        WAITED_MS,
        "confirmed at T + X, derived from committed values only"
    );

    // NEGATIVE: a node that lies about the creation time is caught, because the
    // timing is inside the hashed leaf. (Here it understates the wait by a
    // second — the smallest interesting lie, not an absurd one.)
    let mut forged = receipt.clone();
    forged.timing = Some(sov_types::ReceiptTiming {
        created_at_ms: created_at + 1_000,
    });
    assert!(
        !sov_types::verify_receipt_proof(&forged, &proof, &header.receipts_root),
        "a forged creation time must fail"
    );
    // NEGATIVE: a tampered sibling is caught.
    let mut bad = proof.clone();
    bad.siblings[0].sibling = Hash::digest(b"forged sibling");
    assert!(!sov_types::verify_receipt_proof(
        &receipt,
        &bad,
        &header.receipts_root
    ));

    // Addressing by height+index returns the identical proof.
    let by_index = rpc(
        addr,
        "sov_getReceiptProof",
        json!({ "height": height, "index": proof.index }),
    )["result"]
        .clone();
    assert_eq!(by_index["receipt"], r["receipt"]);
    assert_eq!(by_index["siblings"], r["siblings"]);
    assert_eq!(by_index["receiptsRoot"], r["receiptsRoot"]);

    handle.shutdown();
}

/// Every receipt in a block proves, and an ordinary (untimed) one reports no
/// timing rather than a fabricated zero.
#[test]
fn every_receipt_in_the_block_proves_and_untimed_ones_report_no_timing() {
    let mut n = node();
    let ts = mine_to_activation(&mut n);
    n.submit(timestamped(ts - 1_000, 0)).unwrap();
    n.submit(plain(1)).unwrap();
    n.submit(plain(2)).unwrap();
    let produced = n.produce(ts).expect("produce");
    let header = produced.block.header.clone();
    assert_eq!(produced.block.transactions.len(), 3);
    n.commit_mined(produced.block).expect("commit");
    let height = header.height.get();

    let (_node, handle, addr) = serve(n);
    let mut untimed = 0;
    for index in 0..3u64 {
        let r = rpc(
            addr,
            "sov_getReceiptProof",
            json!({ "height": height, "index": index }),
        )["result"]
            .clone();
        let receipt: Receipt = serde_json::from_value(r["receipt"].clone()).unwrap();
        let proof = ReceiptProof {
            index: r["index"].as_u64().unwrap() as u32,
            siblings: serde_json::from_value(r["siblings"].clone()).unwrap(),
        };
        assert!(
            sov_types::verify_receipt_proof(&receipt, &proof, &header.receipts_root),
            "receipt {index} must prove"
        );
        if receipt.timing.is_none() {
            untimed += 1;
            assert_eq!(
                r["waitedMs"],
                Value::Null,
                "no committed timing means no derived wait — never a made-up 0"
            );
            assert!(
                !r["receipt"].as_object().unwrap().contains_key("timing"),
                "an untimed receipt's JSON is unchanged: no `timing` key at all"
            );
        }
    }
    assert_eq!(untimed, 2, "the two plain transfers commit no timing");

    handle.shutdown();
}

/// Unknown transactions, out-of-range heights and indexes answer `null` — the
/// same shape `sov_getReceipt` uses — rather than erroring or inventing a proof.
#[test]
fn unknown_targets_answer_null() {
    let mut n = node();
    let ts = mine_to_activation(&mut n);
    n.submit(plain(0)).unwrap();
    let produced = n.produce(ts).expect("produce");
    let height = produced.block.header.height.get();
    n.commit_mined(produced.block).expect("commit");

    let (_node, handle, addr) = serve(n);
    assert_eq!(
        rpc(
            addr,
            "sov_getReceiptProof",
            json!({ "txId": Hash::digest(b"never mined").to_hex() })
        )["result"],
        Value::Null
    );
    assert_eq!(
        rpc(
            addr,
            "sov_getReceiptProof",
            json!({ "height": height, "index": 99 })
        )["result"],
        Value::Null
    );
    assert_eq!(
        rpc(
            addr,
            "sov_getReceiptProof",
            json!({ "height": 9_999_999u64, "index": 0 })
        )["result"],
        Value::Null
    );
    // A call with neither addressing form is an invalid-params ERROR, not null:
    // the client asked a malformed question.
    assert!(rpc(addr, "sov_getReceiptProof", json!({}))["error"].is_object());

    handle.shutdown();
}
