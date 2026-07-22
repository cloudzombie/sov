use serde_json::{json, Value};
use sov_pow::{pow_seal, PowAlgo};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_message(reader: &mut BufReader<std::net::TcpStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read miner message");
    assert!(!line.is_empty(), "miner disconnected before sending JSON");
    serde_json::from_str(&line).expect("miner sent valid JSON")
}

fn read_submit_for(reader: &mut BufReader<std::net::TcpStream>, job_id: &str) -> Value {
    for _ in 0..10_000 {
        let message = read_message(reader);
        if message["method"] == json!("submit") && message["params"]["job_id"] == json!(job_id) {
            return message;
        }
    }
    panic!("miner never submitted a share for job {job_id}");
}

fn assert_valid_submit(submit: &Value, job_id: &str, blob: &[u8]) {
    assert_eq!(submit["params"]["job_id"], json!(job_id));
    let nonce_bytes = hex::decode(submit["params"]["nonce"].as_str().unwrap()).unwrap();
    assert_eq!(nonce_bytes.len(), 8);
    let nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());
    let mut expected_blob = blob.to_vec();
    expected_blob[56..].copy_from_slice(&nonce.to_le_bytes());
    let expected = pow_seal(PowAlgo::Sha256d, &[], &expected_blob);
    assert_eq!(submit["params"]["result"], json!(hex::encode(expected)));
    assert!(
        expected
            <= [
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]
    );
}

fn accept_share(stream: &mut std::net::TcpStream, submit: &Value) {
    writeln!(
        stream,
        "{}",
        json!({
            "id": submit["id"],
            "jsonrpc": "2.0",
            "error": Value::Null,
            "result": {"status": "OK"},
        })
    )
    .unwrap();
    stream.flush().unwrap();
}

fn job(job_id: &str, height: u64, blob: &[u8]) -> Value {
    json!({
        "job_id": job_id,
        "blob": hex::encode(blob),
        "target": "ffff0000",
        // Roughly one share per 2^16 SHA-256d hashes: quick in a test without
        // flooding the socket with a difficulty-one share for every nonce.
        "target_full": format!("0000{}", "ff".repeat(30)),
        "algo": "sha256d",
        "height": height,
        "seed_hash": "",
        "nonce_offset": 56,
        "nonce_size": 8,
    })
}

#[test]
fn external_process_logs_in_hashes_and_submits_a_valid_share() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Stratum pool");
    let address = listener.local_addr().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_xus-miner"))
        .args([
            "--headless",
            "--json-events",
            "--password-stdin",
            "--pool",
            &address.to_string(),
            "--user",
            "integration-worker",
            "--workers",
            "1",
            "--reconnect-secs",
            "1",
            "--report-secs",
            "60",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn xus-miner");
    child
        .stdin
        .take()
        .expect("miner password stdin")
        .write_all(b"integration-secret")
        .expect("write miner password");
    let stdout = child.stdout.take().expect("miner telemetry stdout");
    let (telemetry_tx, telemetry_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                if telemetry_tx.send(value).is_err() {
                    break;
                }
            }
        }
    });
    let _child = ChildGuard(child);

    let (mut stream, _) = listener.accept().expect("accept miner");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let login = read_message(&mut reader);
    assert_eq!(login["method"], json!("login"));
    assert_eq!(login["params"]["login"], json!("integration-worker"));
    assert_eq!(login["params"]["pass"], json!("integration-secret"));
    assert!(login["params"]["agent"]
        .as_str()
        .unwrap_or_default()
        .starts_with("xus-miner/"));

    let blob = vec![0u8; 64];
    let first_job = job("integration-job", 999, &blob);
    writeln!(
        stream,
        "{}",
        json!({
            "id": 1,
            "jsonrpc": "2.0",
            "error": Value::Null,
            "result": {"id": "session", "job": first_job, "status": "OK"}
        })
    )
    .unwrap();
    stream.flush().unwrap();

    let submit = read_submit_for(&mut reader, "integration-job");
    assert_valid_submit(&submit, "integration-job", &blob);

    let mut event_names = Vec::new();
    for _ in 0..4 {
        let event = telemetry_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("GUI telemetry event");
        event_names.push(
            event["event"]
                .as_str()
                .expect("telemetry event name")
                .to_owned(),
        );
    }
    assert_eq!(
        event_names,
        ["startup", "connecting", "pool_connected", "job"]
    );
    // Until the pool answers, the one-worker client must not queue a second
    // share. This is the backpressure that prevents stale-share floods.
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut unexpected = String::new();
    let error = reader
        .read_line(&mut unexpected)
        .expect_err("a second share was queued before the first response");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    accept_share(&mut stream, &submit);

    // A server-pushed replacement job must supersede the old work immediately.
    let pushed_blob = vec![0x5au8; 64];
    writeln!(
        stream,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "method": "job",
            "params": job("pushed-job", 1000, &pushed_blob),
        })
    )
    .unwrap();
    stream.flush().unwrap();
    let pushed_submit = read_submit_for(&mut reader, "pushed-job");
    assert_valid_submit(&pushed_submit, "pushed-job", &pushed_blob);
    accept_share(&mut stream, &pushed_submit);

    // Closing the pool connection must make the long-running client reconnect
    // and log in again, rather than silently leaving its workers on stale work.
    drop(reader);
    drop(stream);
    let (mut stream, _) = listener.accept().expect("accept reconnecting miner");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let second_login = read_message(&mut reader);
    assert_eq!(second_login["method"], json!("login"));

    let reconnected_blob = vec![0xa5u8; 64];
    writeln!(
        stream,
        "{}",
        json!({
            "id": 1,
            "jsonrpc": "2.0",
            "error": Value::Null,
            "result": {
                "id": "session-2",
                "job": job("reconnected-job", 1001, &reconnected_blob),
                "status": "OK"
            }
        })
    )
    .unwrap();
    stream.flush().unwrap();
    let reconnected_submit = read_submit_for(&mut reader, "reconnected-job");
    assert_valid_submit(&reconnected_submit, "reconnected-job", &reconnected_blob);
    accept_share(&mut stream, &reconnected_submit);
}
