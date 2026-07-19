//! Comprehensive integration suite for the v0.1.92 mining work-distribution RPCs:
//! `sov_getBlockTemplate` + `sov_submitBlock`.
//!
//! Spins up the real JSON-RPC server over a real [`Node`] (SHA-256d test policy, so
//! grinding is instant) and drives it with raw HTTP/1.1 JSON-RPC — exactly the way an
//! out-of-process miner (a Stratum bridge) would. Every scenario is a distinct test:
//! the happy round-trip (both submit forms), template-cache lifecycle (unknown id,
//! TTL expiry, eviction at capacity, distinct ids, double-submit), malformed inputs,
//! bad proof-of-work, coinbase override, timestamp rolling, mempool inclusion, and a
//! frozen-mainnet-genesis guard proving the additions never touched network identity.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::{ChainSpec, RpcServer};
use sov_types::{Action, BlockHeader, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// A fresh test chain (SHA-256d, trivial difficulty, zero reward, fees off) with the
/// node's own coinbase already configured — the same shape the existing rpc.rs
/// harness uses, so templates build without further setup.
fn node() -> Node {
    let config = GenesisConfig {
        chain_id: "sov-blocktemplate-test".into(),
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

/// Start the RPC server over a fresh node; returns (shared node, handle, address).
fn serve() -> (Arc<Mutex<Node>>, sov_rpc::RpcHandle, SocketAddr) {
    let node = Arc::new(Mutex::new(node()));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .expect("server binds");
    let addr = handle.local_addr();
    (node, handle, addr)
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

fn height(addr: SocketAddr) -> u64 {
    rpc(addr, "sov_getHeight", json!({}))["result"]
        .as_u64()
        .unwrap()
}

/// The pieces of a `sov_getBlockTemplate` response a miner actually uses.
struct Template {
    id: String,
    ts: u64,
    min_ts: u64,
    nonce_offset: usize,
    target: sov_mining::Target,
    blob: Vec<u8>,
}

fn get_template(addr: SocketAddr, params: Value) -> Template {
    let tmpl = rpc(addr, "sov_getBlockTemplate", params);
    let r = &tmpl["result"];
    assert!(r.is_object(), "getBlockTemplate failed: {tmpl}");
    Template {
        id: r["templateId"].as_str().unwrap().to_string(),
        ts: r["timestampMs"].as_u64().unwrap(),
        min_ts: r["minTimestampMs"].as_u64().unwrap(),
        nonce_offset: r["nonceOffset"].as_u64().unwrap() as usize,
        target: sov_mining::Target::from_hash(
            Hash::from_hex(r["target"].as_str().unwrap()).unwrap(),
        ),
        blob: hex::decode(r["blob"].as_str().unwrap()).unwrap(),
    }
}

/// Grind the trailing-u64 nonce in `preimage` until its SHA-256d seal meets `target`
/// (trivial at test difficulty), returning the winning nonce and leaving it spliced in.
fn grind(preimage: &mut [u8], offset: usize, target: &sov_mining::Target) -> u64 {
    for nonce in 0u64..50_000_000 {
        preimage[offset..offset + 8].copy_from_slice(&nonce.to_le_bytes());
        let seal = Hash::from_bytes(sov_pow::sha256d(preimage));
        if target.is_met_by(&seal) {
            return nonce;
        }
    }
    panic!("no valid nonce found within budget at test difficulty");
}

/// The opposite of [`grind`]: find a nonce whose seal does NOT meet the target
/// (immediate at any nontrivial difficulty), so a bad-work submit can be exercised
/// deterministically rather than by luck.
fn grind_failing(preimage: &mut [u8], offset: usize, target: &sov_mining::Target) -> u64 {
    for nonce in 0u64..50_000_000 {
        preimage[offset..offset + 8].copy_from_slice(&nonce.to_le_bytes());
        let seal = Hash::from_bytes(sov_pow::sha256d(preimage));
        if !target.is_met_by(&seal) {
            return nonce;
        }
    }
    panic!("every nonce met the target — target is trivial-all, cannot test bad work");
}

// ───────────────────────────── happy paths ─────────────────────────────

/// Happy path: template → off-node grind → submit by `templateId` → the block imports
/// through the validated path and the chain height advances by one.
#[test]
fn template_grind_submit_by_template_id_advances_height() {
    let (_node, handle, addr) = serve();
    assert_eq!(height(addr), 0);

    let mut t = get_template(addr, json!({}));
    let nonce = grind(&mut t.blob, t.nonce_offset, &t.target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce }),
    );
    let s = &submit["result"];
    assert_eq!(s["accepted"], true, "submit rejected: {submit}");
    assert_eq!(s["height"], 1);
    assert_eq!(s["hash"].as_str().unwrap().len(), 64);
    assert_eq!(height(addr), 1);

    handle.shutdown();
}

/// Happy path via the whole-header fallback form: the caller reconstructs the full
/// sealed header (Borsh-decoded from the ground blob) and submits it; the body is
/// recovered server-side from the cached candidate matched by `tx_root`.
#[test]
fn submit_via_whole_header_form_advances_height() {
    let (_node, handle, addr) = serve();

    let mut t = get_template(addr, json!({}));
    grind(&mut t.blob, t.nonce_offset, &t.target);
    let header: BlockHeader = borsh::from_slice(&t.blob).unwrap();
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "header": serde_json::to_value(&header).unwrap() }),
    );
    assert_eq!(
        submit["result"]["accepted"], true,
        "whole-header submit rejected: {submit}"
    );
    assert_eq!(height(addr), 1);

    handle.shutdown();
}

// ─────────────────────── template-cache lifecycle ───────────────────────

/// An unknown `templateId` is a clean JSON-RPC server error (`-32000`, with the
/// "unknown or expired" refetch hint) and the chain is untouched.
#[test]
fn unknown_template_id_is_clean_error_and_chain_untouched() {
    let (_node, handle, addr) = serve();

    let bad = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": Hash::ZERO.to_hex(), "nonce": 0 }),
    );
    assert_eq!(bad["error"]["code"], -32000, "expected server error: {bad}");
    assert!(
        bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown or expired"),
        "error tells the miner to refetch: {bad}"
    );
    assert_eq!(
        height(addr),
        0,
        "a rejected submit must not touch the chain"
    );

    handle.shutdown();
}

/// A template older than the 120 s TTL expires: submitting its (valid!) solution after
/// expiry is the same clean "unknown or expired" error and the chain is untouched.
/// Genuinely waits out the TTL against the wall clock — slow by design (the TTL is a
/// private constant with no test seam, which is itself a guarantee: nothing can extend
/// a stale template's life).
#[test]
fn expired_template_ttl_is_rejected_after_deadline() {
    let (_node, handle, addr) = serve();

    let mut t = get_template(addr, json!({}));
    let nonce = grind(&mut t.blob, t.nonce_offset, &t.target);

    // TEMPLATE_TTL is 120 s; sleep just past it so the entry is expired, not merely old.
    std::thread::sleep(Duration::from_secs(121));

    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce }),
    );
    assert_eq!(
        submit["error"]["code"], -32000,
        "expired template must be a server error: {submit}"
    );
    assert!(
        submit["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown or expired"),
        "error tells the miner to refetch: {submit}"
    );
    assert_eq!(height(addr), 0);

    handle.shutdown();
}

/// The cache is bounded at MAX_CACHED_TEMPLATES (64): requesting a 65th template
/// evicts the single oldest, whose solution then fails with the refetch error, while
/// the newest template is still live and submittable — the bound costs a miner one
/// refetch, never a stuck chain.
#[test]
fn cache_eviction_at_capacity_drops_only_the_oldest() {
    let (_node, handle, addr) = serve();

    // Oldest template first. Consecutive templates differ only by their clamped
    // wall-clock timestamp, so space the calls a few ms apart to guarantee distinct
    // headers (= distinct template ids / cache keys).
    let mut oldest = get_template(addr, json!({}));
    let oldest_nonce = grind(&mut oldest.blob, oldest.nonce_offset, &oldest.target);

    // 64 more templates: inserts 2..=64 fill the cache to capacity; insert 65 evicts
    // the oldest (MAX_CACHED_TEMPLATES = 64 in sov-rpc).
    let mut ids = vec![oldest.id.clone()];
    let mut newest = None;
    for _ in 0..64 {
        std::thread::sleep(Duration::from_millis(3));
        let t = get_template(addr, json!({}));
        ids.push(t.id.clone());
        newest = Some(t);
    }
    let distinct: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        distinct.len(),
        65,
        "all 65 templates must be distinct cache entries for the eviction count to hold"
    );

    // The oldest was evicted: its perfectly valid solution now needs a refetch.
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": oldest.id, "nonce": oldest_nonce }),
    );
    assert_eq!(
        submit["error"]["code"], -32000,
        "evicted template must error: {submit}"
    );
    assert!(submit["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown or expired"));
    assert_eq!(height(addr), 0);

    // The newest survived eviction and still round-trips to an imported block.
    let mut newest = newest.unwrap();
    let nonce = grind(&mut newest.blob, newest.nonce_offset, &newest.target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": newest.id, "nonce": nonce }),
    );
    assert_eq!(
        submit["result"]["accepted"], true,
        "newest template must still be live: {submit}"
    );
    assert_eq!(height(addr), 1);

    handle.shutdown();
}

/// Two `sov_getBlockTemplate` calls yield distinct `templateId`s (the id is the
/// unsealed header hash; the clamped wall-clock timestamp moves between calls), and
/// both stay individually submittable — concurrent miners never collide on one entry.
#[test]
fn two_get_block_template_calls_yield_distinct_template_ids() {
    let (_node, handle, addr) = serve();

    let a = get_template(addr, json!({}));
    std::thread::sleep(Duration::from_millis(5));
    let b = get_template(addr, json!({}));
    assert_ne!(a.id, b.id, "consecutive templates must have distinct ids");

    // The first id is still live in the cache alongside the second: solving it wins.
    let mut a = a;
    let nonce = grind(&mut a.blob, a.nonce_offset, &a.target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": a.id, "nonce": nonce }),
    );
    assert_eq!(submit["result"]["accepted"], true, "{submit}");

    handle.shutdown();
}

/// Double-submitting the same winning solution is handled cleanly — IDEMPOTENTLY:
/// `import_block` short-circuits an already-indexed block hash to an empty Ok (no
/// re-execution, no state change), so the second submit reports the same accepted
/// block (same hash, same height) and the chain never double-advances. This is the
/// friendly behavior for a pool retrying over a flaky link.
#[test]
fn double_submit_of_the_same_solution_is_idempotent() {
    let (_node, handle, addr) = serve();

    let mut t = get_template(addr, json!({}));
    let nonce = grind(&mut t.blob, t.nonce_offset, &t.target);
    let first = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce }),
    );
    assert_eq!(first["result"]["accepted"], true, "{first}");
    assert_eq!(height(addr), 1);
    let first_hash = first["result"]["hash"].as_str().unwrap().to_string();

    // Same template, same nonce, again. The template is still cached (submission does
    // not remove it) and the block hash is already indexed: import is a no-op Ok.
    let second = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce }),
    );
    assert_eq!(
        second["result"]["accepted"], true,
        "a duplicate submit is an idempotent accept, not an error: {second}"
    );
    assert_eq!(
        second["result"]["hash"].as_str().unwrap(),
        first_hash,
        "both submits name the SAME block: {second}"
    );
    assert_eq!(height(addr), 1, "height must not double-advance");
    // And the balance sheet was not re-applied: the chain still has exactly one
    // block-1 in its history (a re-execution would have failed loudly or forked).
    let blk = rpc(addr, "sov_getBlockByHeight", json!({ "height": 1 }));
    assert_eq!(blk["result"]["header"]["height"], 1);
    assert!(rpc(addr, "sov_getBlockByHeight", json!({ "height": 2 }))["result"].is_null());

    handle.shutdown();
}

// ───────────────────────── malformed submissions ─────────────────────────

/// Malformed `nonce` values (bad hex, non-numeric JSON, oversized hex, negative,
/// fractional, missing) are `-32602` invalid-params errors — never a panic, and the
/// server keeps serving afterwards.
#[test]
fn malformed_nonce_is_invalid_params_not_a_panic() {
    let (_node, handle, addr) = serve();

    // A REAL cached template id, so the failure under test is the nonce, not the id.
    let t = get_template(addr, json!({}));

    let cases: Vec<(Value, &str)> = vec![
        (json!("zzzz"), "non-hex string"),
        (json!("0x1ffffffffffffffffff"), "hex overflowing u64"),
        (json!({}), "object"),
        (json!([1, 2]), "array"),
        (json!(-1), "negative"),
        (json!(1.5), "fractional"),
        (Value::Null, "null (treated as missing)"),
    ];
    for (bad, label) in cases {
        let resp = rpc(
            addr,
            "sov_submitBlock",
            json!({ "templateId": t.id, "nonce": bad }),
        );
        assert_eq!(
            resp["error"]["code"], -32602,
            "nonce case `{label}` must be invalid-params: {resp}"
        );
    }
    // Missing entirely.
    let resp = rpc(addr, "sov_submitBlock", json!({ "templateId": t.id }));
    assert_eq!(resp["error"]["code"], -32602, "missing nonce: {resp}");

    // A malformed `timestampMs` on an otherwise-valid submit is equally clean.
    let resp = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": 0, "timestampMs": "not-hex!" }),
    );
    assert_eq!(resp["error"]["code"], -32602, "bad timestampMs: {resp}");

    // The server survived every malformed request and the chain is untouched.
    assert_eq!(height(addr), 0);

    handle.shutdown();
}

/// A whole-header submit whose `tx_root` matches no cached candidate (corrupted or
/// invented) finds no template and is a clean refetch error — the chain is untouched.
#[test]
fn whole_header_submit_with_wrong_tx_root_finds_no_cache_match() {
    let (_node, handle, addr) = serve();

    let mut t = get_template(addr, json!({}));
    grind(&mut t.blob, t.nonce_offset, &t.target);
    let mut header: BlockHeader = borsh::from_slice(&t.blob).unwrap();
    header.tx_root = Hash::from_bytes([0xAB; 32]); // commits to a tx set nobody built

    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "header": serde_json::to_value(&header).unwrap() }),
    );
    assert_eq!(submit["error"]["code"], -32000, "{submit}");
    assert!(
        submit["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no cached template matches"),
        "error names the tx_root mismatch: {submit}"
    );
    assert_eq!(height(addr), 0);

    handle.shutdown();
}

/// A submission whose seal does NOT meet the proof-of-work target is refused before
/// import (clean error naming the target failure, in both submit forms) and the chain
/// is untouched — bad work can never advance the chain.
#[test]
fn seal_not_meeting_target_is_rejected_and_chain_untouched() {
    let (_node, handle, addr) = serve();

    let mut t = get_template(addr, json!({}));
    let bad_nonce = grind_failing(&mut t.blob, t.nonce_offset, &t.target);

    // Form (a): templateId + failing nonce.
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": bad_nonce }),
    );
    assert_eq!(submit["error"]["code"], -32000, "{submit}");
    assert!(
        submit["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not meet the proof-of-work target"),
        "error names the failed work: {submit}"
    );

    // Form (b): the whole header carrying the failing nonce (tx_root matches, so the
    // cache lookup succeeds — the SEAL check is what refuses it).
    let header: BlockHeader = borsh::from_slice(&t.blob).unwrap();
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "header": serde_json::to_value(&header).unwrap() }),
    );
    assert_eq!(submit["error"]["code"], -32000, "{submit}");
    assert!(
        submit["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not meet the proof-of-work target"),
        "{submit}"
    );

    assert_eq!(height(addr), 0, "bad work must never advance the chain");

    handle.shutdown();
}

// ─────────────────── coinbase override + timestamp rolling ───────────────────

/// `coinbaseAccount` directs the block reward: the template's proposer is the override
/// AND the block actually imported at height 1 carries it in `header.proposer` —
/// proven by reading the block back, not by trusting the template.
#[test]
fn coinbase_account_override_is_the_imported_blocks_proposer() {
    let (_node, handle, addr) = serve();

    let tmpl = rpc(
        addr,
        "sov_getBlockTemplate",
        json!({ "coinbaseAccount": "usa.reserve.sov" }),
    );
    assert_eq!(
        tmpl["result"]["proposer"], "usa.reserve.sov",
        "template honors the override: {tmpl}"
    );
    let mut t = Template {
        id: tmpl["result"]["templateId"].as_str().unwrap().to_string(),
        ts: tmpl["result"]["timestampMs"].as_u64().unwrap(),
        min_ts: tmpl["result"]["minTimestampMs"].as_u64().unwrap(),
        nonce_offset: tmpl["result"]["nonceOffset"].as_u64().unwrap() as usize,
        target: sov_mining::Target::from_hash(
            Hash::from_hex(tmpl["result"]["target"].as_str().unwrap()).unwrap(),
        ),
        blob: hex::decode(tmpl["result"]["blob"].as_str().unwrap()).unwrap(),
    };
    let nonce = grind(&mut t.blob, t.nonce_offset, &t.target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce }),
    );
    assert_eq!(submit["result"]["accepted"], true, "{submit}");

    // Read the imported block back: its header credits the overridden account.
    let blk = rpc(addr, "sov_getBlockByHeight", json!({ "height": 1 }));
    assert_eq!(
        blk["result"]["header"]["proposer"], "usa.reserve.sov",
        "imported block must credit the override, not the node coinbase: {blk}"
    );

    // And an invalid override is refused up front (invalid-params, nothing built).
    let bad = rpc(
        addr,
        "sov_getBlockTemplate",
        json!({ "coinbaseAccount": "NOT a valid id!!" }),
    );
    assert_eq!(bad["error"]["code"], -32602, "{bad}");

    handle.shutdown();
}

/// Timestamp rolling, accept side: a miner may roll the header timestamp (extra nonce
/// space) as long as it stays >= the template's `minTimestampMs` AND within the same
/// difficulty window; the rolled value is what the imported block carries.
///
/// NOTE (contract subtlety this suite surfaced): the required `bits` is a function of
/// the block's OWN timestamp — the Emergency Difficulty Adjustment (v0.1.85) relaxes
/// difficulty per 15-minute stall interval. Rolling the timestamp far from the value
/// the template was built with (e.g. all the way down to `minTimestampMs` when the
/// parent is old) crosses EDA intervals, changes the required `bits`, and import
/// correctly rejects with "difficulty bits mismatch". A miner must keep rolls small
/// (seconds) or refetch — which is exactly what the template's own `timestampMs` and
/// short TTL steer it to. Small forward rolls, as here, are always safe.
#[test]
fn timestamp_rolling_forward_within_window_is_accepted() {
    let (_node, handle, addr) = serve();

    let t = get_template(addr, json!({}));
    // Roll the timestamp 5 s FORWARD of the template's own value (well above the
    // consensus floor and within the same EDA interval), then grind those exact bytes.
    let rolled = t.ts + 5_000;
    assert!(
        rolled >= t.min_ts,
        "forward roll is trivially above the floor"
    );
    let mut header: BlockHeader = borsh::from_slice(&t.blob).unwrap();
    header.timestamp_ms = rolled;
    let mut blob = borsh::to_vec(&header).unwrap();
    let offset = blob.len() - 8;
    let nonce = grind(&mut blob, offset, &t.target);

    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce, "timestampMs": rolled }),
    );
    assert_eq!(
        submit["result"]["accepted"], true,
        "a small forward roll above the floor must be accepted: {submit}"
    );
    assert_eq!(height(addr), 1);
    let blk = rpc(addr, "sov_getBlockByHeight", json!({ "height": 1 }));
    assert_eq!(
        blk["result"]["header"]["timestamp_ms"],
        json!(rolled),
        "the imported block carries the rolled timestamp: {blk}"
    );

    handle.shutdown();
}

/// Timestamp rolling, reject side: a timestamp BELOW `minTimestampMs` passes the seal
/// check (the miner really did the work over those bytes) but the validated import
/// path refuses it — `accepted: false` with a reason, chain untouched. The RPC layer
/// holds no consensus authority.
#[test]
fn timestamp_below_min_timestamp_is_rejected_by_import() {
    let (_node, handle, addr) = serve();

    let t = get_template(addr, json!({}));
    let below = t.min_ts - 1; // == parent timestamp: not strictly after it
    let mut header: BlockHeader = borsh::from_slice(&t.blob).unwrap();
    header.timestamp_ms = below;
    let mut blob = borsh::to_vec(&header).unwrap();
    let offset = blob.len() - 8;
    let nonce = grind(&mut blob, offset, &t.target);

    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": t.id, "nonce": nonce, "timestampMs": below }),
    );
    assert_eq!(
        submit["result"]["accepted"], false,
        "a below-floor timestamp must be refused by import: {submit}"
    );
    assert!(
        submit["result"]["error"]
            .as_str()
            .unwrap()
            .contains("import rejected"),
        "rejection names the import: {submit}"
    );
    assert_eq!(
        height(addr),
        0,
        "the refused block must not touch the chain"
    );

    handle.shutdown();
}

// ───────────────────────────── mempool inclusion ─────────────────────────────

/// A template reflects the live mempool: empty mempool → coinbase-only tx set; after a
/// real signed transfer is admitted the template's `txRoot` changes, and mining that
/// template applies the transfer (recipient credited, mempool drained).
#[test]
fn template_reflects_empty_vs_non_empty_mempool_and_applies_the_tx() {
    let (_node, handle, addr) = serve();

    let empty = get_template(addr, json!({}));
    let empty_tx_root = {
        let header: BlockHeader = borsh::from_slice(&empty.blob).unwrap();
        header.tx_root
    };

    // Admit a genuinely-signed transfer.
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
    assert_eq!(submitted["result"]["accepted"], true, "{submitted}");
    assert_eq!(rpc(addr, "sov_getMempoolSize", json!({}))["result"], 1);

    // The new template commits to a different tx set.
    std::thread::sleep(Duration::from_millis(3));
    let mut full = get_template(addr, json!({}));
    let full_tx_root = {
        let header: BlockHeader = borsh::from_slice(&full.blob).unwrap();
        header.tx_root
    };
    assert_ne!(
        empty_tx_root, full_tx_root,
        "a mempool tx must change the template's tx_root"
    );

    // Mine it: the transfer applies and the mempool drains.
    let nonce = grind(&mut full.blob, full.nonce_offset, &full.target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": full.id, "nonce": nonce }),
    );
    assert_eq!(submit["result"]["accepted"], true, "{submit}");
    assert_eq!(height(addr), 1);
    assert_eq!(
        rpc(
            addr,
            "sov_getBalance",
            json!({"account": "ecb.reserve.sov"})
        )["result"],
        "25000000000",
        "250 SOV landed via the mined block"
    );
    assert_eq!(
        rpc(addr, "sov_getMempoolSize", json!({}))["result"],
        0,
        "the included tx left the mempool"
    );

    handle.shutdown();
}

// ───────────────────────────── frozen-genesis guard ─────────────────────────────

/// Guard: the v0.1.92 work-distribution additions change NOTHING about network
/// identity. The embedded mainnet chain-spec still builds the frozen genesis
/// `cb0272ff…` byte-for-byte, the binary constant still pins it, and the verified
/// constructor still passes — the KAT the whole network's handshake binds to.
#[test]
fn mainnet_genesis_is_still_frozen() {
    /// The frozen mainnet genesis hash, restated LITERALLY here (not read from the
    /// constant) so a drift in either the spec, the builder, or the constant fails.
    const FROZEN: &str = "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d";

    // The binary-hardcoded pin is unchanged.
    assert_eq!(ChainSpec::MAINNET_GENESIS_HASH, FROZEN);
    assert_eq!(
        ChainSpec::hardcoded_genesis_pin("sov-mainnet"),
        Some(FROZEN)
    );

    // The committed mainnet spec still BUILDS that exact genesis block.
    let spec = ChainSpec::from_json(include_str!("../../../specs/mainnet.json"))
        .expect("committed mainnet spec parses");
    assert_eq!(spec.chain_id, "sov-mainnet");
    let cfg = spec
        .to_genesis_config_verified()
        .expect("verified constructor passes: spec still produces the frozen genesis");
    let genesis = cfg.build().expect("genesis builds").block;
    assert_eq!(
        genesis.hash().to_hex(),
        FROZEN,
        "MAINNET GENESIS DRIFTED — the work-distribution additions must be additive"
    );
    assert_eq!(genesis.header.height.get(), 0);
}
