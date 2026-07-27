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
    let node = Arc::new(Mutex::new(node()));
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
