//! End-to-end protocol tests: the REAL `sov-stratum` binary, spawned against a
//! mock SOV node (an HTTP/1.1 JSON-RPC server speaking the exact wire shape
//! `RpcClient` expects), driven by a scripted Stratum miner over loopback TCP.
//!
//! Templates are Sha256d so the seal math is instant; the code paths exercised
//! (template poll, job issue, submit verify/classify/forward, error surfaces)
//! are byte-identical to the RandomX configuration — the algorithm is a
//! template parameter, not a code path fork.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sov_primitives::{AccountId, BlockHeight, Hash};
use sov_types::BlockHeader;

/// A real (Borsh-exact) header preimage for the mock node's template, so the
/// blob/nonceOffset relationship in play is the one mainnet templates carry.
fn template_blob() -> Vec<u8> {
    BlockHeader {
        height: BlockHeight::new(101),
        prev_hash: Hash::digest(b"it-parent"),
        tx_root: Hash::digest(b"it-txs"),
        receipts_root: Hash::digest(b"it-receipts"),
        state_root: Hash::digest(b"it-state"),
        timestamp_ms: 1_753_000_000_777,
        proposer: AccountId::new("sov-pool").unwrap(),
        version_bits: 0,
        bits: 0x1d00_ffff,
        nonce: 0,
    }
    .pow_preimage()
}

const TEMPLATE_ID: &str = "abababababababababababababababababababababababababababababababab";
const FROZEN_TIMESTAMP: u64 = 1_753_000_000_777;

/// The mock node's `sov_getBlockTemplate` result for a given network target.
fn template_json(target_hex: &str) -> Value {
    let blob = template_blob();
    json!({
        "templateId": TEMPLATE_ID,
        "height": 101u64,
        "prevHash": "cd".repeat(32),
        "timestampMs": FROZEN_TIMESTAMP,
        "target": target_hex,
        "powAlgo": "Sha256d",
        "powKey": "",
        "blob": hex::encode(&blob),
        "nonceOffset": blob.len() - 8,
    })
}

/// A network target only the all-zero hash could meet — shares never become
/// blocks against it.
fn unreachable_target() -> String {
    "00".repeat(32)
}

/// The real seal (as the bridge recomputes it) for `nonce` on the test template.
fn seal_hex(nonce: u64) -> String {
    let mut blob = template_blob();
    let off = blob.len() - 8;
    blob[off..].copy_from_slice(&nonce.to_le_bytes());
    hex::encode(sov_pow::sha256d(&blob))
}

fn nonce_wire(nonce: u64) -> String {
    hex::encode(nonce.to_le_bytes())
}

/// A mock SOV node: HTTP/1.1 + JSON-RPC 2.0, connection-per-request (the
/// `Connection: close` discipline `RpcClient` uses). Records every
/// `sov_submitBlock` params object it receives.
struct MockNode {
    addr: String,
    submits: Arc<Mutex<Vec<Value>>>,
}

fn spawn_mock_node(template: Value) -> MockNode {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock node");
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let submits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&submits);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let header_end = loop {
                match conn.read(&mut tmp) {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(pos);
                        }
                    }
                }
            };
            let Some(pos) = header_end else { continue };
            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
            let clen: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = buf[pos + 4..].to_vec();
            while body.len() < clen {
                match conn.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            let Ok(req) = serde_json::from_slice::<Value>(&body) else {
                continue;
            };
            let result = match req["method"].as_str() {
                Some("sov_getHeight") => json!(100u64),
                Some("sov_getBlockTemplate") => template.clone(),
                Some("sov_submitBlock") => {
                    recorded.lock().unwrap().push(req["params"].clone());
                    json!({"accepted": true, "height": 101u64, "hash": "aa".repeat(32)})
                }
                _ => Value::Null,
            };
            let body =
                json!({"jsonrpc": "2.0", "id": req["id"].clone(), "result": result}).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes());
        }
    });
    MockNode { addr, submits }
}

/// The spawned bridge binary; killed on drop so no test leaves a stray daemon.
struct Bridge {
    child: Child,
    addr: String,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_bridge(node_addr: &str, extra: &[&str]) -> Bridge {
    // Reserve a port by binding :0 and releasing it — the bridge takes it next.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_sov-stratum"))
        .args([
            "--node",
            node_addr,
            "--bind",
            &addr,
            "--poll-ms",
            "250",
            "--refresh-secs",
            "3600", // one template for the whole test: fully deterministic
        ])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sov-stratum binary");
    Bridge { child, addr }
}

/// A scripted Stratum miner connection.
struct MinerConn {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    next_id: u64,
}

impl MinerConn {
    fn connect(addr: &str) -> MinerConn {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match TcpStream::connect(addr) {
                Ok(s) => break s,
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "bridge never listened on {addr}: {e}"
                    );
                    thread::sleep(Duration::from_millis(50));
                }
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        MinerConn {
            stream,
            reader,
            next_id: 0,
        }
    }

    fn send_raw(&mut self, line: &str) {
        self.stream.write_all(line.as_bytes()).unwrap();
        self.stream.write_all(b"\n").unwrap();
        self.stream.flush().unwrap();
    }

    /// Read replies until the one matching `id` arrives, skipping unsolicited
    /// `job` notifications (the bridge may push work at any time).
    fn read_reply(&mut self, id: &Value) -> Value {
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).expect("read from bridge");
            assert!(n > 0, "bridge closed the connection unexpectedly");
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(line.trim()).expect("bridge always sends JSON");
            if v.get("method").is_some() {
                continue; // job push, not a reply
            }
            if &v["id"] == id {
                return v;
            }
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = json!(self.next_id);
        self.send_raw(
            &json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params}).to_string(),
        );
        self.read_reply(&id)
    }

    /// `login`, retrying until the bridge's poller has fetched work.
    fn login(&mut self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let reply = self.call(
                "login",
                json!({"login": "wallet.worker1", "pass": "x", "agent": "sov-test-miner/1.0"}),
            );
            if reply["error"].is_null() {
                return reply["result"].clone();
            }
            assert!(
                Instant::now() < deadline,
                "bridge never produced work: {reply}"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn error_message(reply: &Value) -> String {
    reply["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn full_share_pipeline_over_loopback() {
    // Network target unreachable ⇒ everything stays a share; start-diff 1 ⇒
    // every submitted nonce is a valid share.
    let node = spawn_mock_node(template_json(&unreachable_target()));
    let bridge = spawn_bridge(&node.addr, &["--start-diff", "1", "--min-diff", "1"]);
    let mut miner = MinerConn::connect(&bridge.addr);

    // -- login: session id + a complete Monero-dialect job --------------------
    let login = miner.login();
    assert!(
        !login["id"].as_str().unwrap_or_default().is_empty(),
        "login must issue a session id"
    );
    assert_eq!(login["status"], json!("OK"));
    let job = login["job"].clone();
    assert_eq!(job["blob"], json!(hex::encode(template_blob())));
    assert_eq!(job["algo"], json!("sha256d"));
    assert_eq!(job["height"], json!(101u64));
    assert_eq!(job["target"], json!("ffffffff")); // difficulty 1
    assert_eq!(job["nonce_size"], json!(8u64));
    assert_eq!(job["nonce_offset"], json!(template_blob().len() as u64 - 8));
    assert_eq!(job["target_full"], json!("ff".repeat(32)));

    // -- keepalived -----------------------------------------------------------
    let ka = miner.call("keepalived", json!({"id": login["id"]}));
    assert_eq!(ka["result"]["status"], json!("KEEPALIVED"));

    // -- getjob issues a fresh, distinct job ----------------------------------
    let job2 = miner.call("getjob", json!({}));
    assert!(job2["error"].is_null());
    let job2 = job2["result"].clone();
    assert_ne!(job2["job_id"], job["job_id"], "every job id is unique");
    let job_id = job2["job_id"].as_str().unwrap().to_string();

    // -- a valid share, result cross-checked ----------------------------------
    let ok = miner.call(
        "submit",
        json!({"job_id": job_id, "nonce": nonce_wire(42), "result": seal_hex(42)}),
    );
    assert!(ok["error"].is_null(), "valid share rejected: {ok}");
    assert_eq!(ok["result"]["status"], json!("OK"));

    // -- the same nonce again: duplicate, not double-counted ------------------
    let dup = miner.call(
        "submit",
        json!({"job_id": job_id, "nonce": nonce_wire(42), "result": seal_hex(42)}),
    );
    assert!(
        error_message(&dup).contains("duplicate"),
        "duplicate submit must be rejected: {dup}"
    );

    // -- a LYING result hash: the bridge recomputes and catches it ------------
    let lie = miner.call(
        "submit",
        json!({"job_id": job_id, "nonce": nonce_wire(43), "result": "00".repeat(32)}),
    );
    assert!(
        error_message(&lie).contains("mismatch"),
        "lying result must be rejected: {lie}"
    );

    // -- result field is optional (some miners omit it) -----------------------
    let ok2 = miner.call("submit", json!({"job_id": job_id, "nonce": nonce_wire(44)}));
    assert_eq!(ok2["result"]["status"], json!("OK"));

    // -- stale / unknown job --------------------------------------------------
    let stale = miner.call(
        "submit",
        json!({"job_id": "ffffffffffffffff", "nonce": nonce_wire(1)}),
    );
    assert!(error_message(&stale).contains("stale"), "{stale}");

    // -- malformed submits: typed errors, session stays alive -----------------
    for (params, code) in [
        (json!({}), -32602i64),
        (json!({"job_id": job_id}), -32602),
        (json!({"job_id": job_id, "nonce": "xyz"}), -32602),
        (json!({"job_id": job_id, "nonce": 7}), -32602),
        (json!({"job_id": job_id, "nonce": "010203"}), -32602),
    ] {
        let reply = miner.call("submit", params.clone());
        assert_eq!(
            reply["error"]["code"],
            json!(code),
            "params {params} → {reply}"
        );
    }

    // -- unknown method / missing method --------------------------------------
    let unknown = miner.call("mining.subscribe", json!({}));
    assert_eq!(unknown["error"]["code"], json!(-32601));
    miner.send_raw(&json!({"id": 999, "params": {}}).to_string());
    let no_method = miner.read_reply(&json!(999));
    assert_eq!(no_method["error"]["code"], json!(-32600));

    // -- garbage JSON: parse error reply, no panic, no disconnect -------------
    miner.send_raw("this is not json {{{");
    let parse_err = miner.read_reply(&Value::Null);
    assert_eq!(parse_err["error"]["code"], json!(-32700));

    // -- a huge (1 MiB) field: bounded handling, then business as usual -------
    let huge = "A".repeat(1 << 20);
    let big = miner.call("login", json!({"login": huge, "pass": "x"}));
    assert!(big.is_object(), "bridge must reply to an oversized login");
    let ka = miner.call("keepalived", json!({}));
    assert_eq!(
        ka["result"]["status"],
        json!("KEEPALIVED"),
        "session must survive adversarial input"
    );

    // -- a second session cannot submit against the first session's job -------
    let mut thief = MinerConn::connect(&bridge.addr);
    thief.login();
    let theft = thief.call("submit", json!({"job_id": job_id, "nonce": nonce_wire(50)}));
    assert!(
        error_message(&theft).contains("different session"),
        "cross-session submit must be rejected: {theft}"
    );

    // Nothing in this test cleared network difficulty — the node must never
    // have been asked to import a block.
    assert!(
        node.submits.lock().unwrap().is_empty(),
        "no sov_submitBlock may have been forwarded"
    );
}

#[test]
fn low_difficulty_shares_are_rejected_at_high_share_difficulty() {
    // Share difficulty 2^32 ⇒ the share target has four leading zero bytes; a
    // counted handful of nonces virtually cannot meet it (P ≈ 2⁻³² each), and
    // each rejection must name "low difficulty", not kill the session.
    let node = spawn_mock_node(template_json(&unreachable_target()));
    let bridge = spawn_bridge(
        &node.addr,
        &["--start-diff", "4294967296", "--min-diff", "4294967296"],
    );
    let mut miner = MinerConn::connect(&bridge.addr);
    let login = miner.login();
    let job_id = login["job"]["job_id"].as_str().unwrap().to_string();
    // The issued compact target reflects the 2^32 difficulty (64-bit form).
    assert_eq!(login["job"]["target"], json!("ffffffff00000000"));

    // Belt and braces: only submit nonces whose real seal misses the target,
    // so the assertion is deterministic, not merely 1 − 2⁻³² likely.
    let share_target = {
        let mut t = [0xffu8; 32];
        t[..4].fill(0); // (2^256 − 1) >> 32
        t
    };
    let mut submitted = 0u64;
    for nonce in 0..1_000u64 {
        let seal = hex::decode(seal_hex(nonce)).unwrap();
        if seal.as_slice() > share_target.as_slice() {
            let reply = miner.call(
                "submit",
                json!({"job_id": job_id, "nonce": nonce_wire(nonce)}),
            );
            assert!(
                error_message(&reply).contains("low difficulty"),
                "weak share must be rejected as low difficulty: {reply}"
            );
            submitted += 1;
            if submitted == 3 {
                break;
            }
        }
    }
    assert_eq!(submitted, 3, "three weak nonces must exist in 1000 tries");

    // The session survives a run of rejections.
    let ka = miner.call("keepalived", json!({}));
    assert_eq!(ka["result"]["status"], json!("KEEPALIVED"));
    assert!(node.submits.lock().unwrap().is_empty());
}

#[test]
fn network_difficulty_share_is_forwarded_to_the_node_exactly_once() {
    // An all-ones network target: the FIRST share clears network difficulty and
    // must be forwarded via sov_submitBlock with the job's frozen timestamp.
    let node = spawn_mock_node(template_json(&"ff".repeat(32)));
    let bridge = spawn_bridge(&node.addr, &["--start-diff", "1", "--min-diff", "1"]);
    let mut miner = MinerConn::connect(&bridge.addr);
    let login = miner.login();
    let job_id = login["job"]["job_id"].as_str().unwrap().to_string();

    let ok = miner.call(
        "submit",
        json!({"job_id": job_id, "nonce": nonce_wire(7), "result": seal_hex(7)}),
    );
    assert_eq!(ok["result"]["status"], json!("OK"), "{ok}");

    // The forward happens synchronously inside submit handling, but poll for it
    // with a deadline anyway (never trust scheduling).
    let deadline = Instant::now() + Duration::from_secs(5);
    let forwarded = loop {
        {
            let submits = node.submits.lock().unwrap();
            if !submits.is_empty() {
                break submits[0].clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "block was never forwarded to the node"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(forwarded["templateId"], json!(TEMPLATE_ID));
    assert_eq!(forwarded["nonce"], json!(7u64));
    assert_eq!(
        forwarded["timestampMs"],
        json!(FROZEN_TIMESTAMP),
        "sov_submitBlock must carry the job's FROZEN timestamp"
    );

    // Replaying the winning nonce is a duplicate — the node is not asked twice.
    let dup = miner.call(
        "submit",
        json!({"job_id": job_id, "nonce": nonce_wire(7), "result": seal_hex(7)}),
    );
    assert!(error_message(&dup).contains("duplicate"), "{dup}");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        node.submits.lock().unwrap().len(),
        1,
        "exactly one sov_submitBlock forward"
    );
}
