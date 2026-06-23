//! Integration test for the JSON-RPC server (Phase 8, p8-i2).
//!
//! Spins up the real server over a real [`Node`] on an ephemeral port and drives
//! it with raw HTTP/1.1 JSON-RPC requests — querying live chain state and
//! submitting a genuinely-signed transaction — then shuts it down.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance};
use sov_rpc::RpcServer;
use sov_types::{Action, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn node() -> Node {
    let config = GenesisConfig {
        chain_id: "sov-rpc-test".into(),
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
    Node::new(Blockchain::new(&config).unwrap(), 1024, 256)
}

/// One JSON-RPC call over a fresh connection; returns the full response object.
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

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    let split = text
        .find("\r\n\r\n")
        .expect("response has a header/body split");
    serde_json::from_str(&text[split + 4..]).expect("response body is JSON")
}

#[test]
fn rejects_oversized_request_body() {
    let node = Arc::new(Mutex::new(node()));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 1)
        .expect("server binds");
    let addr = handle.local_addr();

    // Claim a body far larger than the cap and send only the headers: the server
    // must refuse with 413 *before* allocating or reading the body.
    let mut stream = TcpStream::connect(addr).unwrap();
    let header = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        50 * 1024 * 1024
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 413"),
        "oversized body must be rejected with 413, got: {:?}",
        text.lines().next()
    );

    handle.shutdown();
}

#[test]
fn rpc_server_serves_real_chain_state_and_accepts_transactions() {
    let node = Arc::new(Mutex::new(node()));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .expect("server binds");
    let addr = handle.local_addr();

    // --- queries reflect real genesis state ---
    assert_eq!(
        rpc(addr, "sov_chainId", json!({}))["result"],
        "sov-rpc-test"
    );
    assert_eq!(rpc(addr, "sov_getHeight", json!({}))["result"], 0);
    // Balance is encoded as a decimal-grain string (JS-safe). 1000 SOV = 1e11 grains.
    assert_eq!(
        rpc(
            addr,
            "sov_getBalance",
            json!({"account": "usa.reserve.sov"})
        )["result"],
        "100000000000"
    );
    assert_eq!(
        rpc(addr, "sov_getNonce", json!({"account": "usa.reserve.sov"}))["result"],
        0
    );
    // A funded account serializes to an object; an unknown one is null (not faked).
    assert!(rpc(
        addr,
        "sov_getAccount",
        json!({"account": "usa.reserve.sov"})
    )["result"]
        .is_object());
    assert!(rpc(addr, "sov_getAccount", json!({"account": "nobody.sov"}))["result"].is_null());
    // Genesis block is retrievable and self-consistent.
    let head = rpc(addr, "sov_getHead", json!({}));
    assert_eq!(head["result"]["header"]["height"], 0);
    assert_eq!(
        rpc(addr, "sov_getBlockByHeight", json!({"height": 0}))["result"]["header"]["height"],
        0
    );
    assert!(rpc(addr, "sov_getBlockByHeight", json!({"height": 99}))["result"].is_null());

    // --- submit a genuinely-signed transfer; it lands in the mempool ---
    assert_eq!(rpc(addr, "sov_getMempoolSize", json!({}))["result"], 0);
    let kp = Keypair::from_seed([2; 32]);
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(250).unwrap(),
        },
    };
    let stx = SignedTransaction::sign(tx, &kp).unwrap();
    let submitted = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(&stx).unwrap(),
    );
    assert_eq!(submitted["result"]["accepted"], true);
    assert_eq!(submitted["result"]["txId"], stx.id().to_hex());
    assert_eq!(rpc(addr, "sov_getMempoolSize", json!({}))["result"], 1);

    // --- mining endpoints (real, empty at genesis) ---
    assert_eq!(
        rpc(addr, "sov_getMiners", json!({}))["result"],
        json!([]),
        "no miners until someone mines"
    );

    // --- block digest carries the new prevHash / stateRoot (for the block-detail view) ---
    let digest = rpc(addr, "sov_getBlockDigest", json!({"height": 0}));
    assert!(digest["result"]["prevHash"].is_string(), "digest has prevHash");
    assert!(
        digest["result"]["stateRoot"].is_string(),
        "digest has stateRoot"
    );

    // --- fee estimate is the REAL gas × price (single source of truth) ---
    // With a V1 (Ed25519) signer the envelope surcharge is zero, so a transfer's gas
    // is exactly the 21,000 intrinsic; a shielded send costs strictly more (proof
    // verification). The fee itself is gas × the node's live gas price.
    let v1_pk = serde_json::to_value(kp.public_key()).unwrap();
    let est = rpc(
        addr,
        "sov_estimateFee",
        json!({"kind": "transfer", "publicKey": v1_pk}),
    );
    assert_eq!(est["result"]["gasUsed"], 21_000, "V1 transfer = intrinsic only");
    assert!(
        est["result"]["feeGrains"].is_string(),
        "feeGrains is a JS-safe string"
    );
    let shielded = rpc(
        addr,
        "sov_estimateFee",
        json!({"kind": "shielded", "publicKey": v1_pk}),
    );
    assert!(
        shielded["result"]["gasUsed"].as_u64().unwrap() > 21_000,
        "a shielded send costs more than a bare transfer"
    );
    // Default (no key) prices the hybrid post-quantum envelope every station wallet
    // uses, so it costs strictly more than the V1 transfer.
    let hybrid = rpc(addr, "sov_estimateFee", json!({"kind": "transfer"}));
    assert!(hybrid["result"]["gasUsed"].as_u64().unwrap() > 21_000, "hybrid envelope > V1");
    // An unknown route is a parameter error, not a silent default.
    let bad_kind = rpc(addr, "sov_estimateFee", json!({"kind": "frobnicate"}));
    assert_eq!(bad_kind["error"]["code"], -32602);

    // --- errors are well-formed JSON-RPC ---
    let unknown = rpc(addr, "sov_nope", json!({}));
    assert_eq!(unknown["error"]["code"], -32601);
    let bad = rpc(addr, "sov_getBalance", json!({}));
    assert_eq!(bad["error"]["code"], -32602);

    // --- a duplicate submission (same nonce) is rejected with a server error ---
    let dup = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(&stx).unwrap(),
    );
    assert_eq!(dup["error"]["code"], -32000);

    handle.shutdown();
}
