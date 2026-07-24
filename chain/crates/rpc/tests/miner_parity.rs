//! Response-shape suite for the v0.1.99 ADDITIVE read-only miner-parity RPCs —
//! the four enhancements the XUS Miner's mempool.space-style strip consumes:
//!
//! 1. `sov_getMempoolHistogram` (NEW) — pending txs bucketed by effective tip
//!    (the v0.1.98 auction's ordering key) + the live auction floors;
//! 2. `sov_getBlockTemplate` — NEW `txIds` + `txCount` beside the untouched
//!    template fields;
//! 3. `sov_getBlockByHeight` / `sov_getBlockByHash` — NEW `header.hash` (the
//!    blake3 block id) beside the untouched `{header, transactions}` reply;
//! 4. `sov_estimateFee` — NEW `floorGrains` (+ `tipFloorGrains`) beside the
//!    untouched fee fields.
//!
//! Every test pins the EXACT JSON contract the miner parses AND asserts the
//! pre-existing fields are byte-for-byte unaffected (the additive-only law,
//! F5). Plus the standing frozen-mainnet-genesis guard: these are serialization
//! changes with zero consensus surface.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::{ChainSpec, RpcServer};
use sov_types::{Action, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// A fresh test chain (SHA-256d, trivial difficulty, fees off) with a funded
/// account and the node coinbase configured — the same shape the block_template
/// harness uses. `max_block_txs` is explicit so the next-block auction floor can
/// be driven to a NONZERO value with a tiny pool.
fn node(max_block_txs: usize) -> Node {
    let config = GenesisConfig {
        chain_id: "sov-miner-parity-test".into(),
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
    let mut n = Node::new(Blockchain::new(&config).unwrap(), 1024, max_block_txs);
    n.set_coinbase(id("val01.node.sov"));
    n
}

fn serve(max_block_txs: usize) -> (Arc<Mutex<Node>>, sov_rpc::RpcHandle, SocketAddr) {
    let node = Arc::new(Mutex::new(node(max_block_txs)));
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

/// A genuinely-signed transfer from `usa.reserve.sov` at `nonce`, tipped with
/// `tip_grains` when nonzero (a top-level `Action::Tipped` fee-auction envelope,
/// exactly what `effective_tip` reads), else a plain legacy transfer bidding 0.
fn reserve_tx(nonce: u64, tip_grains: u128) -> SignedTransaction {
    let kp = Keypair::from_seed([2; 32]);
    let transfer = Action::Transfer {
        to: id("ecb.reserve.sov"),
        amount: Balance::from_sov(1).unwrap(),
    };
    let action = if tip_grains == 0 {
        transfer
    } else {
        Action::Tipped {
            tip: Balance::from_grains(tip_grains),
            inner: Box::new(transfer),
        }
    };
    let t = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    SignedTransaction::sign(t, &kp).unwrap()
}

fn submit_tx(addr: SocketAddr, stx: &SignedTransaction) {
    let resp = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(stx).unwrap(),
    );
    assert_eq!(resp["result"]["accepted"], true, "admission failed: {resp}");
}

/// Grind the trailing-u64 nonce in `preimage` until its SHA-256d seal meets
/// `target` (trivial at test difficulty).
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

/// Fetch a template and mine one block through `sov_submitBlock`, returning the
/// accepted block's hash hex.
fn mine_one(addr: SocketAddr) -> String {
    let tmpl = rpc(addr, "sov_getBlockTemplate", json!({}));
    let r = &tmpl["result"];
    assert!(r.is_object(), "getBlockTemplate failed: {tmpl}");
    let mut blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
    let offset = r["nonceOffset"].as_u64().unwrap() as usize;
    let target =
        sov_mining::Target::from_hash(Hash::from_hex(r["target"].as_str().unwrap()).unwrap());
    let nonce = grind(&mut blob, offset, &target);
    let submit = rpc(
        addr,
        "sov_submitBlock",
        json!({ "templateId": r["templateId"], "nonce": nonce }),
    );
    assert_eq!(submit["result"]["accepted"], true, "{submit}");
    submit["result"]["hash"].as_str().unwrap().to_string()
}

// ───────────────── 1. sov_getMempoolHistogram ─────────────────

/// The empty-pool histogram is the exact zero shape: no buckets, zero counts,
/// zero floors — and the method exists (no `-32601`).
#[test]
fn histogram_empty_pool_is_the_zero_shape() {
    let (_node, handle, addr) = serve(256);

    let resp = rpc(addr, "sov_getMempoolHistogram", json!({}));
    let r = &resp["result"];
    assert!(r.is_object(), "method must exist: {resp}");
    assert_eq!(r["txCount"], 0);
    assert_eq!(r["floorGrains"], "0");
    assert_eq!(r["poolFloorGrains"], "0");
    assert_eq!(r["maxBlockTxs"], 256);
    assert_eq!(r["buckets"], json!([]), "empty pool → no buckets: {resp}");

    handle.shutdown();
}

/// Real pending txs bucket by EFFECTIVE TIP, highest first, with per-bucket
/// count + serialized bytes — and with 1-tx blocks the next-block floor is the
/// marginal selected bid (the head of the sender's nonce package), NONZERO.
#[test]
fn histogram_buckets_by_tip_high_to_low_and_reports_the_live_floor() {
    // max_block_txs = 1: the next block holds ONE tx, so with work pending the
    // "make the next block" floor is the top package-head bid.
    let (_node, handle, addr) = serve(1);

    // Nonce 0 bids 7_000 grains (a Tipped envelope); nonce 1 bids 0 (legacy).
    submit_tx(addr, &reserve_tx(0, 7_000));
    submit_tx(addr, &reserve_tx(1, 0));

    let resp = rpc(addr, "sov_getMempoolHistogram", json!({}));
    let r = &resp["result"];
    assert_eq!(r["txCount"], 2, "{resp}");
    let buckets = r["buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 2, "two distinct tips → two buckets: {resp}");
    // Ordered high → low, each with the exact miner-parser shape.
    assert_eq!(buckets[0]["feeRateGrains"], "7000");
    assert_eq!(buckets[0]["txCount"], 1);
    assert!(buckets[0]["totalBytes"].as_u64().unwrap() > 0);
    assert_eq!(buckets[1]["feeRateGrains"], "0");
    assert_eq!(buckets[1]["txCount"], 1);
    assert!(buckets[1]["totalBytes"].as_u64().unwrap() > 0);
    // The auction floors: the next 1-tx block goes to the 7_000-grain head
    // (select's marginal bid), while the 1024-slot pool itself is nowhere near
    // full, so pool ADMISSION is still free.
    assert_eq!(r["floorGrains"], "7000", "{resp}");
    assert_eq!(r["poolFloorGrains"], "0", "{resp}");
    assert_eq!(r["maxBlockTxs"], 1);

    handle.shutdown();
}

// ───────────────── 2. sov_getBlockTemplate txIds/txCount ─────────────────

/// The template ADDITIVELY reports the ids of the txs it already selected:
/// empty mempool → `txCount` 0 / `txIds` [] (the coinbase is the header's
/// implicit `proposer` claim, not a listed tx); after a real admitted transfer
/// the new template lists exactly its id — and every pre-existing template
/// field is still present and typed as before.
#[test]
fn template_reports_tx_ids_and_count_beside_untouched_fields() {
    let (_node, handle, addr) = serve(256);

    let empty = rpc(addr, "sov_getBlockTemplate", json!({}));
    let e = &empty["result"];
    assert_eq!(e["txCount"], 0, "{empty}");
    assert_eq!(e["txIds"], json!([]), "{empty}");

    let stx = reserve_tx(0, 0);
    let tx_id = stx.id().to_hex();
    submit_tx(addr, &stx);
    std::thread::sleep(std::time::Duration::from_millis(3));

    let tmpl = rpc(addr, "sov_getBlockTemplate", json!({}));
    let r = &tmpl["result"];
    assert_eq!(r["txCount"], 1, "{tmpl}");
    assert_eq!(r["txIds"], json!([tx_id]), "{tmpl}");

    // ADDITIVE proof: the existing miner contract is untouched — every v0.1.92
    // field is still present with its shape.
    for key in [
        "templateId",
        "prevHash",
        "txRoot",
        "stateRoot",
        "receiptsRoot",
        "target",
        "powKey",
        "blob",
        "proposer",
        "powAlgo",
    ] {
        assert!(r[key].is_string(), "existing field `{key}` drifted: {tmpl}");
    }
    for key in [
        "height",
        "timestampMs",
        "minTimestampMs",
        "bits",
        "versionBits",
        "nonceOffset",
    ] {
        assert!(r[key].is_u64(), "existing field `{key}` drifted: {tmpl}");
    }

    handle.shutdown();
}

// ───────────────── 3. header.hash on block reads ─────────────────

/// `sov_getBlockByHeight` and `sov_getBlockByHash` carry the block's own id as
/// `header.hash` — the SAME id `sov_submitBlock` replied with (and that
/// `sov_getBlockByHash` was keyed by) — while the pre-existing `{header,
/// transactions}` reply is untouched.
#[test]
fn block_reads_carry_header_hash_beside_untouched_reply() {
    let (_node, handle, addr) = serve(256);

    submit_tx(addr, &reserve_tx(0, 0));
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mined_hash = mine_one(addr);

    let by_height = rpc(addr, "sov_getBlockByHeight", json!({ "height": 1 }));
    let b = &by_height["result"];
    assert_eq!(
        b["header"]["hash"].as_str().unwrap(),
        mined_hash,
        "header.hash must be the submit-reply block id: {by_height}"
    );
    // The pre-existing reply shape is intact.
    assert_eq!(b["header"]["height"], 1);
    assert!(b["header"]["prev_hash"].is_string(), "{by_height}");
    assert!(b["header"]["tx_root"].is_string(), "{by_height}");
    assert_eq!(b["transactions"].as_array().unwrap().len(), 1);

    // The parallel read is identical through the hash key.
    let by_hash = rpc(addr, "sov_getBlockByHash", json!({ "hash": mined_hash }));
    assert_eq!(
        by_hash["result"], *b,
        "byHash and byHeight must serialize the same block identically"
    );

    // Genesis carries its own id too, and a missing height is still null.
    let genesis = rpc(addr, "sov_getBlockByHeight", json!({ "height": 0 }));
    assert_eq!(
        genesis["result"]["header"]["hash"].as_str().unwrap().len(),
        64
    );
    assert!(rpc(addr, "sov_getBlockByHeight", json!({ "height": 99 }))["result"].is_null());

    handle.shutdown();
}

// ───────────────── 4. sov_estimateFee floorGrains ─────────────────

/// `sov_estimateFee` ADDITIVELY reports the live auction floor: with an
/// uncontested mempool `floorGrains == feeGrains` (tip floor 0); with 1-tx
/// blocks and a tipped bid pending, `floorGrains = feeGrains + tipFloorGrains`.
/// The four pre-existing fields are unchanged.
#[test]
fn estimate_fee_adds_the_auction_floor_beside_untouched_fields() {
    let (_node, handle, addr) = serve(1);

    // Uncontested: the floor IS the base estimate.
    let quiet = rpc(addr, "sov_estimateFee", json!({ "kind": "transfer" }));
    let q = &quiet["result"];
    assert_eq!(q["kind"], "transfer");
    assert!(q["gasUsed"].is_u64(), "{quiet}");
    assert!(q["gasPriceGrains"].is_string(), "{quiet}");
    assert!(q["feeGrains"].is_string(), "{quiet}");
    assert_eq!(q["tipFloorGrains"], "0", "{quiet}");
    assert_eq!(
        q["floorGrains"], q["feeGrains"],
        "empty mempool → floor equals the base estimate: {quiet}"
    );

    // Contested: a 7_000-grain bid holds the single next-block slot, so the
    // all-in floor is base fee (0 on the fee-free test policy) + 7_000.
    submit_tx(addr, &reserve_tx(0, 7_000));
    let loaded = rpc(addr, "sov_estimateFee", json!({ "kind": "transfer" }));
    let l = &loaded["result"];
    assert_eq!(l["tipFloorGrains"], "7000", "{loaded}");
    assert_eq!(l["floorGrains"], "7000", "{loaded}");
    assert_eq!(
        l["feeGrains"], q["feeGrains"],
        "the pre-existing base estimate must not move with mempool load: {loaded}"
    );

    handle.shutdown();
}

// ───────────────── frozen-genesis guard ─────────────────

/// Guard: the miner-parity additions change NOTHING about network identity. The
/// embedded mainnet chain-spec still builds the frozen genesis `cb0272ff…`
/// byte-for-byte and the binary constant still pins it.
#[test]
fn mainnet_genesis_is_still_frozen() {
    const FROZEN: &str = "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d";

    assert_eq!(ChainSpec::MAINNET_GENESIS_HASH, FROZEN);
    assert_eq!(
        ChainSpec::hardcoded_genesis_pin("sov-mainnet"),
        Some(FROZEN)
    );

    let spec = ChainSpec::from_json(include_str!("../../../specs/mainnet.json"))
        .expect("committed mainnet spec parses");
    let cfg = spec
        .to_genesis_config_verified()
        .expect("verified constructor passes: spec still produces the frozen genesis");
    let genesis = cfg.build().expect("genesis builds").block;
    assert_eq!(
        genesis.hash().to_hex(),
        FROZEN,
        "MAINNET GENESIS DRIFTED — the miner-parity additions must be additive"
    );
}
