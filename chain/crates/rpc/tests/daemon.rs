//! Daemon persistence + resume integration test (Phase 8, p8-i0 / p8-i4).
//!
//! Boots a daemon, submits a transaction over the real RPC server, produces a
//! block, then drops the daemon and starts a fresh one on the same data
//! directory — asserting it **replays the block log and resumes the exact state**
//! (height, balances, state root). Also checks chain-spec JSON → genesis.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;

use serde_json::{json, Value};
use sov_chain::Blockchain;
use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::{ChainSpec, Daemon};
use sov_types::{Action, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sov-daemon-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Chain-spec JSON an operator would write. Public key is `Keypair::from_seed`'s.
fn chain_spec_json() -> String {
    let val_pk = hex::encode(Keypair::from_seed([1; 32]).public_key().as_bytes());
    let usa_pk = hex::encode(Keypair::from_seed([2; 32]).public_key().as_bytes());
    // 1,000 SOV = 1e11 grains; balances are decimal-grain strings.
    format!(
        r#"{{
            "chain_id": "sov-daemon-test",
            "timestamp_ms": 1000,
            "policy": "test",
            "accounts": [
                {{ "account": "val01.node.sov", "public_key": "{val_pk}", "operator": true }},
                {{ "account": "usa.reserve.sov", "public_key": "{usa_pk}", "balance": "100000000000" }}
            ]
        }}"#
    )
}

fn rpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let body = serde_json::to_vec(&req).unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    let header = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    let split = text.find("\r\n\r\n").unwrap();
    serde_json::from_str(&text[split + 4..]).unwrap()
}

#[test]
fn chain_spec_json_builds_genesis() {
    let spec = ChainSpec::from_json(&chain_spec_json()).unwrap();
    let genesis = spec.to_genesis_config().unwrap();
    assert_eq!(genesis.chain_id, "sov-daemon-test");
    let chain = Blockchain::new(&genesis).unwrap();
    assert_eq!(
        chain.ledger().account(&id("usa.reserve.sov")).balance,
        Balance::from_sov(1_000).unwrap()
    );
    assert_eq!(chain.height(), 0);
}

#[test]
fn pq_native_genesis_boots_finalizes_and_transacts_on_hybrid_keys() {
    // The launch posture: the chain is born post-quantum — every genesis key
    // (validator AND user) is hybrid Ed25519+ML-DSA-65, exactly what
    // `sov-testnet gen` now emits. No key migration ever needed.
    let dir = unique_dir("pq-native");
    let _ = std::fs::remove_dir_all(&dir);

    let val = Keypair::hybrid_from_seed([1; 32]);
    let usa = Keypair::hybrid_from_seed([2; 32]);
    let val_pk = serde_json::to_value(val.public_key()).unwrap();
    let usa_pk = serde_json::to_value(usa.public_key()).unwrap();
    assert!(val_pk.as_str().unwrap().starts_with("hybrid65:0x"));
    let spec = format!(
        r#"{{
            "chain_id": "sov-pq-native",
            "timestamp_ms": 1000,
            "policy": "test",
            "accounts": [
                {{ "account": "val01.node.sov", "public_key": {val_pk}, "operator": true }},
                {{ "account": "usa.reserve.sov", "public_key": {usa_pk}, "balance": "100000000000" }}
            ]
        }}"#
    );
    let genesis = ChainSpec::from_json(&spec)
        .unwrap()
        .to_genesis_config()
        .unwrap();

    // The miner/node identity uses its hybrid key (dual signatures).
    let d = Daemon::new(
        &genesis,
        &dir,
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::hybrid_from_seed([1; 32]))],
    )
    .unwrap();
    let rpc_handle = d.serve_rpc("127.0.0.1:0", 1).unwrap();
    let addr = rpc_handle.local_addr();

    // A hybrid-signed transfer over real RPC.
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: usa.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(100).unwrap(),
        },
    };
    let stx = SignedTransaction::sign(tx, &usa).unwrap();
    let submitted = rpc(
        addr,
        "sov_submitTransaction",
        serde_json::to_value(&stx).unwrap(),
    );
    assert_eq!(submitted["result"]["accepted"], true);

    assert!(d.produce_once(2_000).unwrap());
    assert_eq!(d.height(), 1);
    assert_eq!(
        d.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(100).unwrap()
    );
    rpc_handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn daemon_persists_blocks_and_resumes_state_after_restart() {
    let dir = unique_dir("resume");
    let _ = std::fs::remove_dir_all(&dir);
    let genesis = ChainSpec::from_json(&chain_spec_json())
        .unwrap()
        .to_genesis_config()
        .unwrap();
    let miner_keys = || vec![(id("val01.node.sov"), Keypair::from_seed([1; 32]))];

    // --- first run: submit a transfer over RPC, produce a block, persist it ---
    let root_after;
    {
        let d1 = Daemon::new(&genesis, &dir, 1024, 256, miner_keys()).unwrap();
        assert_eq!(d1.resumed_blocks(), 0);
        assert_eq!(d1.height(), 0);

        let rpc_handle = d1.serve_rpc("127.0.0.1:0", 1).unwrap();
        let addr = rpc_handle.local_addr();

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

        // Deterministically produce the block holding the tx.
        assert!(d1.produce_once(2_000).unwrap());
        assert_eq!(d1.height(), 1);
        assert_eq!(
            d1.balance(&id("usa.reserve.sov")),
            Balance::from_sov(750).unwrap()
        );
        assert_eq!(
            d1.balance(&id("ecb.reserve.sov")),
            Balance::from_sov(250).unwrap()
        );
        root_after = d1.state_root_hex();

        rpc_handle.shutdown();
    }

    // --- second run: same data dir; the block log is replayed to resume state ---
    let d2 = Daemon::new(&genesis, &dir, 1024, 256, miner_keys()).unwrap();
    assert_eq!(
        d2.resumed_blocks(),
        1,
        "the persisted block must be replayed"
    );
    assert_eq!(d2.height(), 1);
    assert_eq!(
        d2.balance(&id("usa.reserve.sov")),
        Balance::from_sov(750).unwrap()
    );
    assert_eq!(
        d2.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(250).unwrap()
    );
    // Byte-identical authenticated state across the restart.
    assert_eq!(d2.state_root_hex(), root_after);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn daemon_fast_resumes_from_chainstate_snapshot() {
    // The normal restart path: a daemon checkpoints its chainstate, then a fresh
    // daemon on the same data dir resumes from that snapshot (tier 1) — reproducing
    // the exact head + state root WITHOUT replaying the block log from genesis.
    let dir = unique_dir("snapshot-resume");
    let _ = std::fs::remove_dir_all(&dir);
    let genesis = ChainSpec::from_json(&chain_spec_json())
        .unwrap()
        .to_genesis_config()
        .unwrap();
    let miner_keys = || vec![(id("val01.node.sov"), Keypair::from_seed([1; 32]))];

    let root_after;
    {
        let d1 = Daemon::new(&genesis, &dir, 1024, 256, miner_keys()).unwrap();
        assert!(
            !d1.resumed_from_snapshot(),
            "first boot has no snapshot to resume from"
        );
        // Produce three blocks (a transfer in the first to populate the receipt index).
        let kp = Keypair::from_seed([2; 32]);
        for i in 0..3u64 {
            let tx = Transaction {
                signer: id("usa.reserve.sov"),
                public_key: kp.public_key(),
                nonce: i,
                action: Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(10).unwrap(),
                },
            };
            d1.node()
                .lock()
                .unwrap()
                .submit(SignedTransaction::sign(tx, &kp).unwrap())
                .unwrap();
            assert!(d1.produce_once(2_000 + i * 1_000).unwrap());
        }
        assert_eq!(d1.height(), 3);
        root_after = d1.state_root_hex();
        // Explicit checkpoint (what the app does on quit / the run loop does on shutdown).
        d1.write_snapshot_now().unwrap();
    }

    // Fresh daemon, same data dir: must resume FROM THE SNAPSHOT, not a replay.
    let d2 = Daemon::new(&genesis, &dir, 1024, 256, miner_keys()).unwrap();
    assert!(
        d2.resumed_from_snapshot(),
        "second boot resumes from the chainstate snapshot (tier 1)"
    );
    assert_eq!(d2.height(), 3);
    assert_eq!(d2.state_root_hex(), root_after);
    assert_eq!(
        d2.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(30).unwrap()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn boot_streams_indexing_progress_on_replay() {
    // When a node re-indexes its block log on boot (no snapshot yet), it must STREAM
    // progress so a UI shows a live "indexing N/total" counter instead of appearing to
    // hang. This drives the real boot via `new_with_progress` and asserts the callback
    // fired, ending at total/total.
    let dir = unique_dir("progress");
    let _ = std::fs::remove_dir_all(&dir);
    let genesis = ChainSpec::from_json(&chain_spec_json())
        .unwrap()
        .to_genesis_config()
        .unwrap();
    let miner_keys = || vec![(id("val01.node.sov"), Keypair::from_seed([1; 32]))];

    // Build three blocks (no snapshot is written by the produce_once path), then drop.
    {
        let d1 = Daemon::new(&genesis, &dir, 1024, 256, miner_keys()).unwrap();
        let kp = Keypair::from_seed([2; 32]);
        for i in 0..3u64 {
            let tx = Transaction {
                signer: id("usa.reserve.sov"),
                public_key: kp.public_key(),
                nonce: i,
                action: Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(1).unwrap(),
                },
            };
            d1.node()
                .lock()
                .unwrap()
                .submit(SignedTransaction::sign(tx, &kp).unwrap())
                .unwrap();
            assert!(d1.produce_once(2_000 + i * 1_000).unwrap());
        }
        assert_eq!(d1.height(), 3);
    }

    // Restart with no snapshot present → the REPLAY tier, which streams progress.
    let mut updates: Vec<(u64, u64)> = Vec::new();
    let d2 = Daemon::new_with_progress(&genesis, &dir, 1024, 256, miner_keys(), &mut |done, total| {
        updates.push((done, total))
    })
    .unwrap();
    assert!(!d2.resumed_from_snapshot(), "no snapshot existed — replay path");
    assert_eq!(d2.height(), 3);
    assert!(!updates.is_empty(), "the replay streamed indexing progress");
    assert_eq!(
        updates.last().copied(),
        Some((3, 3)),
        "progress ends at total/total (fully indexed)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn confirmations_survive_restart() {
    // Nakamoto finality is a function of chain state alone, so a restart that
    // replays the block log reproduces the exact same confirmation depths —
    // there is no separate finality store to lose.
    let dir = unique_dir("finality");
    let _ = std::fs::remove_dir_all(&dir);
    let genesis = ChainSpec::from_json(&chain_spec_json())
        .unwrap()
        .to_genesis_config()
        .unwrap();

    // --- first run: mine FINALITY_DEPTH blocks so block 1 crosses the line ---
    let first_hash;
    {
        let d1 = Daemon::new(
            &genesis,
            &dir,
            1024,
            256,
            vec![(id("val01.node.sov"), Keypair::from_seed([1; 32]))],
        )
        .unwrap();

        let kp = Keypair::from_seed([2; 32]);
        for i in 0..sov_chain::FINALITY_DEPTH {
            let tx = Transaction {
                signer: id("usa.reserve.sov"),
                public_key: kp.public_key(),
                nonce: i,
                action: Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(10).unwrap(),
                },
            };
            d1.node()
                .lock()
                .unwrap()
                .submit(SignedTransaction::sign(tx, &kp).unwrap())
                .unwrap();
            assert!(d1.produce_once(2_000 + i * 1_000).unwrap());
        }
        assert_eq!(d1.height(), sov_chain::FINALITY_DEPTH);

        let node = d1.node();
        let n = node.lock().unwrap();
        first_hash = n.chain().block_by_height(1).unwrap().hash();
        assert!(
            n.chain().is_final(&first_hash),
            "block 1 is FINALITY_DEPTH deep on the mining node"
        );
    }

    // --- restart from the block log alone: same head, same confirmations ---
    let d2 = Daemon::new(&genesis, &dir, 1024, 256, vec![]).unwrap();
    assert_eq!(d2.height(), sov_chain::FINALITY_DEPTH);
    let node = d2.node();
    let n = node.lock().unwrap();
    assert_eq!(n.chain().block_by_height(1).unwrap().hash(), first_hash);
    assert_eq!(
        n.chain().confirmations(&first_hash),
        Some(sov_chain::FINALITY_DEPTH)
    );
    assert!(
        n.chain().is_final(&first_hash),
        "confirmation-depth finality was re-derived from the replayed block log"
    );
    drop(n);

    let _ = std::fs::remove_dir_all(&dir);
}
