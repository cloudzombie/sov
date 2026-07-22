#![forbid(unsafe_code)]

mod gui;

use borsh::BorshDeserialize;
use serde_json::{json, Value};
use sov_pow::{pow_seal_mining, PowAlgo};
use sov_types::BlockHeader;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_BLOB_BYTES: usize = 1024 * 1024;
const WORK_BATCH: u64 = 256;
const LOGIN_ID: u64 = 1;
const KEEPALIVE_ID: u64 = 2;
const FIRST_SUBMIT_ID: u64 = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    pool: String,
    user: String,
    password: String,
    workers: u64,
    reconnect_secs: u64,
    report_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pool: "127.0.0.1:3333".into(),
            user: "xus-miner".into(),
            password: "x".into(),
            // sov-pow currently owns one full RandomX dataset per worker thread.
            // Defaulting to one avoids surprising multi-gigabyte allocations.
            workers: 1,
            reconnect_secs: 5,
            report_secs: 10,
        }
    }
}

fn usage() -> &'static str {
    "xus-miner — native GUI and standalone SOV/XUS Stratum CPU miner\n\n\
     USAGE: xus-miner [--gui]\n\
            xus-miner --headless [OPTIONS]\n\n\
       --gui                    Open the native operator console [default with no args]\n\
       --headless               Run as a terminal/server process\n\
       --pool <host:port>       SOV node RPC (:8645) or Stratum pool [127.0.0.1:3333]\n\
       --user <label>           Public account/worker label [xus-miner]\n\
       --password <value>       Stratum password [x]\n\
       --password-stdin         Read the Stratum password from standard input\n\
       --workers <n>            Mining threads [1; each may use ~2.3 GiB]\n\
       --reconnect-secs <n>     Delay after disconnect [5]\n\
       --report-secs <n>        Hashrate reporting interval [10]\n\
       --help                   Show this help\n\n\
     No wallet seed or private key is used by this program."
}

fn parse_u64(flag: &str, raw: &str, min: u64, max: u64) -> u64 {
    let parsed = raw.parse::<u64>().unwrap_or_else(|_| {
        eprintln!("error: {flag} expects an integer, got `{raw}`");
        process::exit(2);
    });
    if !(min..=max).contains(&parsed) {
        eprintln!("error: {flag} must be in {min}..={max}, got {parsed}");
        process::exit(2);
    }
    parsed
}

fn parse_args_from<I>(args: I) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut cfg = Config::default();
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = |flag: &str, args: &mut I::IntoIter| {
            args.next().unwrap_or_else(|| {
                eprintln!("error: {flag} requires a value");
                process::exit(2);
            })
        };
        match flag.as_str() {
            "--pool" => cfg.pool = value("--pool", &mut args),
            "--user" => cfg.user = value("--user", &mut args),
            "--password" => cfg.password = value("--password", &mut args),
            "--workers" => {
                cfg.workers = parse_u64("--workers", &value("--workers", &mut args), 1, 64)
            }
            "--reconnect-secs" => {
                cfg.reconnect_secs = parse_u64(
                    "--reconnect-secs",
                    &value("--reconnect-secs", &mut args),
                    1,
                    3600,
                )
            }
            "--report-secs" => {
                cfg.report_secs =
                    parse_u64("--report-secs", &value("--report-secs", &mut args), 1, 3600)
            }
            "--help" | "-h" => {
                println!("{}", usage());
                process::exit(0);
            }
            other => {
                eprintln!("error: unknown option `{other}`\n\n{}", usage());
                process::exit(2);
            }
        }
    }
    if cfg.pool.trim().is_empty() || cfg.user.trim().is_empty() {
        eprintln!("error: --pool and --user cannot be empty");
        process::exit(2);
    }
    cfg
}

#[derive(Clone, Debug)]
struct Job {
    id: String,
    blob: Vec<u8>,
    nonce_offset: usize,
    target: [u8; 32],
    algo: PowAlgo,
    pow_key: Vec<u8>,
    height: u64,
    timestamp_ms: Option<u64>,
    /// Reward destination disclosed by the node/pool for this exact job.
    coinbase: Option<String>,
}

impl Job {
    fn from_stratum(value: &Value) -> Result<Self, String> {
        let string = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("job missing non-empty string `{name}`"))
        };
        let number = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("job missing integer `{name}`"))
        };

        let id = string("job_id")?.to_owned();
        if id.len() > 256 {
            return Err("job_id exceeds 256 bytes".into());
        }
        let blob = hex::decode(string("blob")?).map_err(|e| format!("invalid blob hex: {e}"))?;
        if blob.len() < 8 || blob.len() > MAX_BLOB_BYTES {
            return Err(format!(
                "blob length {} outside 8..={MAX_BLOB_BYTES}",
                blob.len()
            ));
        }
        let nonce_offset = usize::try_from(number("nonce_offset")?)
            .map_err(|_| "nonce_offset does not fit this platform".to_string())?;
        if number("nonce_size")? != 8 {
            return Err("SOV jobs require nonce_size 8".into());
        }
        if nonce_offset != blob.len() - 8 {
            return Err(format!(
                "nonce_offset {nonce_offset} does not identify the trailing u64 in {}-byte blob",
                blob.len()
            ));
        }

        let target_bytes = hex::decode(string("target_full")?)
            .map_err(|e| format!("invalid target_full hex: {e}"))?;
        let target: [u8; 32] = target_bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("target_full is {} bytes, want 32", v.len()))?;

        let algo = match string("algo")? {
            "rx/0" => PowAlgo::RandomX,
            "sha256d" => PowAlgo::Sha256d,
            other => return Err(format!("unsupported algorithm `{other}`")),
        };
        let seed = value
            .get("seed_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "job missing string `seed_hash`".to_string())?;
        let pow_key = hex::decode(seed).map_err(|e| format!("invalid seed_hash hex: {e}"))?;
        if algo == PowAlgo::RandomX && pow_key.is_empty() {
            return Err("RandomX seed_hash cannot be empty".into());
        }

        Ok(Self {
            id,
            blob,
            nonce_offset,
            target,
            algo,
            pow_key,
            height: number("height")?,
            timestamp_ms: None,
            coinbase: value
                .get("coinbase")
                .or_else(|| value.get("coinbase_account"))
                .and_then(Value::as_str)
                .filter(|account| !account.is_empty())
                .map(str::to_owned),
        })
    }

    fn from_rpc(value: &Value) -> Result<Self, String> {
        let string = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("template missing string `{name}`"))
        };
        let number = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("template missing integer `{name}`"))
        };
        let template_id = string("templateId")?.to_owned();
        let height = number("height")?;
        let timestamp_ms = number("timestampMs")?;
        let blob =
            hex::decode(string("blob")?).map_err(|e| format!("invalid template blob: {e}"))?;
        let nonce_offset = number("nonceOffset")? as usize;
        if blob.len() < 8 || nonce_offset != blob.len() - 8 {
            return Err("node returned an incompatible nonce offset".into());
        }
        let target: [u8; 32] = hex::decode(string("target")?)
            .map_err(|e| format!("invalid template target: {e}"))?
            .try_into()
            .map_err(|v: Vec<u8>| format!("template target is {} bytes, want 32", v.len()))?;
        let algo = match string("powAlgo")? {
            "RandomX" => PowAlgo::RandomX,
            "Sha256d" => PowAlgo::Sha256d,
            other => return Err(format!("unsupported node PoW algorithm `{other}`")),
        };
        let pow_key =
            hex::decode(string("powKey")?).map_err(|e| format!("invalid template powKey: {e}"))?;
        let coinbase = string("proposer")?.trim().to_owned();
        if coinbase.is_empty() {
            return Err("template proposer cannot be empty".into());
        }
        let header = BlockHeader::try_from_slice(&blob)
            .map_err(|e| format!("template blob is not a valid SOV block header: {e}"))?;
        if header.proposer.as_str() != coinbase {
            return Err(format!(
                "template proposer `{coinbase}` does not match encoded header coinbase `{}`",
                header.proposer.as_str()
            ));
        }
        if header.height.get() != height {
            return Err(format!(
                "template height {height} does not match encoded header height {}",
                header.height.get()
            ));
        }
        if header.timestamp_ms != timestamp_ms {
            return Err(format!(
                "template timestamp {timestamp_ms} does not match encoded header timestamp {}",
                header.timestamp_ms
            ));
        }
        let encoded_template_id = header.hash().to_hex();
        if encoded_template_id != template_id {
            return Err(format!(
                "template ID `{template_id}` does not match encoded header ID `{encoded_template_id}`"
            ));
        }
        Ok(Self {
            id: template_id,
            blob,
            nonce_offset,
            target,
            algo,
            pow_key,
            height,
            timestamp_ms: Some(timestamp_ms),
            // `proposer` is encoded into the header preimage. Requiring it here
            // makes the displayed reward account a property of the work being
            // hashed, not an unverified copy of the user's input.
            coinbase: Some(coinbase),
        })
    }

    fn seal_blob(&self, blob: &[u8]) -> [u8; 32] {
        pow_seal_mining(self.algo, &self.pow_key, blob)
    }
}

/// Expected independent hashes before a uniformly distributed 256-bit seal is
/// at or below this inclusive big-endian target. This is `(2^256)/(target+1)`.
fn expected_hashes_for_target(target: &[u8; 32]) -> f64 {
    let mut success_probability = 2.0_f64.powi(-256); // the inclusive `+ 1`
    for (index, byte) in target.iter().enumerate() {
        success_probability += f64::from(*byte) * 2.0_f64.powi(-8 * (index as i32 + 1));
    }
    success_probability.recip()
}

struct State {
    job: RwLock<Option<Arc<Job>>>,
    connection: RwLock<Option<Arc<Connection>>>,
    rpc_endpoint: RwLock<Option<String>>,
    generation: AtomicU64,
    next_request: AtomicU64,
    interval_hashes: AtomicU64,
    total_hashes: AtomicU64,
    submitted: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    mempool_size: AtomicU64,
    mempool_known: AtomicBool,
    confirmed_coinbase: RwLock<Option<String>>,
    json_events: bool,
}

impl State {
    fn new(json_events: bool) -> Self {
        Self {
            job: RwLock::new(None),
            connection: RwLock::new(None),
            rpc_endpoint: RwLock::new(None),
            generation: AtomicU64::new(0),
            next_request: AtomicU64::new(FIRST_SUBMIT_ID),
            interval_hashes: AtomicU64::new(0),
            total_hashes: AtomicU64::new(0),
            submitted: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            mempool_known: AtomicBool::new(false),
            confirmed_coinbase: RwLock::new(None),
            json_events,
        }
    }

    fn emit(&self, event: Value) {
        if self.json_events {
            println!("{event}");
        }
    }

    fn install_job(&self, job: Job) {
        eprintln!("job {}: height {} ({:?})", job.id, job.height, job.algo);
        if let Some(account) = job.coinbase.as_deref() {
            let mut confirmed = self
                .confirmed_coinbase
                .write()
                .expect("confirmed coinbase lock");
            if confirmed.as_deref() != Some(account) {
                eprintln!(
                    "COINBASE CONFIRMED by block template: {account} | block reward destination for height {}",
                    job.height
                );
                *confirmed = Some(account.to_owned());
            }
        }
        let expected_hashes = expected_hashes_for_target(&job.target);
        self.emit(json!({
            "event": "job",
            "job_id": job.id,
            "height": job.height,
            "algorithm": match job.algo {
                PowAlgo::RandomX => "RandomX",
                PowAlgo::Sha256d => "SHA-256d",
            },
            "coinbase": job.coinbase,
            "network_target": hex::encode(job.target),
            "expected_hashes": expected_hashes,
        }));
        *self.job.write().expect("job lock") = Some(Arc::new(job));
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn clear_connection(&self, connection: &Arc<Connection>) {
        let mut current = self.connection.write().expect("connection lock");
        if current
            .as_ref()
            .is_some_and(|existing| Arc::ptr_eq(existing, connection))
        {
            *current = None;
            *self.job.write().expect("job lock") = None;
            *self
                .confirmed_coinbase
                .write()
                .expect("confirmed coinbase lock") = None;
            self.generation.fetch_add(1, Ordering::Release);
        }
    }
}

struct Connection {
    writer: Mutex<TcpStream>,
    pending: AtomicU64,
    max_pending: u64,
}

impl Connection {
    fn reserve_share(&self) -> bool {
        self.pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                (pending < self.max_pending).then_some(pending + 1)
            })
            .is_ok()
    }

    fn finish_share(&self) {
        let _ = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                Some(pending.saturating_sub(1))
            });
    }
}

fn write_json(connection: &Connection, value: &Value) -> io::Result<()> {
    let mut payload = value.to_string();
    payload.push('\n');
    if payload.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound JSON exceeds line limit",
        ));
    }
    let mut stream = connection.writer.lock().expect("socket writer lock");
    stream.write_all(payload.as_bytes())?;
    stream.flush()
}

fn read_json_line(reader: &mut BufReader<TcpStream>) -> io::Result<Option<Value>> {
    let mut bytes = Vec::new();
    let count = reader
        .by_ref()
        .take((MAX_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_LINE_BYTES || !bytes.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stratum line exceeds 64 KiB or is unterminated",
        ));
    }
    let value = serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON: {e}")))?;
    Ok(Some(value))
}

fn install_job_value(state: &State, value: &Value) -> io::Result<()> {
    let job =
        Job::from_stratum(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    state.install_job(job);
    Ok(())
}

fn handle_message(state: &State, connection: &Connection, message: &Value) -> io::Result<()> {
    if message.get("method").and_then(Value::as_str) == Some("job") {
        let params = message
            .get("params")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "job push has no params"))?;
        return install_job_value(state, params);
    }

    let id = message.get("id").and_then(Value::as_u64);
    if id == Some(LOGIN_ID) {
        if !message.get("error").is_none_or(Value::is_null) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("pool rejected login: {}", message["error"]),
            ));
        }
        let job = message
            .pointer("/result/job")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "login reply has no job"))?;
        return install_job_value(state, job);
    }

    if id.is_some_and(|id| id >= FIRST_SUBMIT_ID) {
        connection.finish_share();
        if message.get("error").is_none_or(Value::is_null) {
            state.accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            let rejected = state.rejected.fetch_add(1, Ordering::Relaxed) + 1;
            if rejected <= 5 || rejected.is_multiple_of(100) {
                eprintln!("share rejected #{rejected}: {}", message["error"]);
            }
        }
        state.emit(json!({
            "event": "share",
            "submitted": state.submitted.load(Ordering::Relaxed),
            "accepted": state.accepted.load(Ordering::Relaxed),
            "rejected": state.rejected.load(Ordering::Relaxed),
        }));
    }
    Ok(())
}

fn pool_address(raw: &str) -> &str {
    raw.strip_prefix("stratum+tcp://")
        .or_else(|| raw.strip_prefix("tcp://"))
        .unwrap_or(raw)
}

fn endpoint_address(raw: &str) -> &str {
    raw.strip_prefix("rpc://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or_else(|| pool_address(raw))
        .trim_end_matches('/')
}

fn is_direct_rpc(raw: &str) -> bool {
    raw.starts_with("rpc://")
        || raw.starts_with("http://")
        || endpoint_address(raw)
            .rsplit_once(':')
            .is_some_and(|(_, port)| port == "8645")
}

fn rpc_call(endpoint: &str, method: &str, params: Value) -> io::Result<Value> {
    let address = endpoint_address(endpoint);
    let mut stream = connect(address).map_err(|e| {
        if e.kind() == io::ErrorKind::ConnectionRefused {
            io::Error::new(e.kind(), format!(
                "SOV node refused {address}. On SOV Station enable ‘Expose node RPC on LAN’, then restart its node ({e})"
            ))
        } else { e }
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let request = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params});
    let body = request.to_string();
    let host = address.split(':').next().unwrap_or("sov-node");
    write!(stream,
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "node returned malformed HTTP")
        })?;
    let value: Value = serde_json::from_slice(&response[split + 4..]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("node returned invalid JSON: {e}"),
        )
    })?;
    if !value.get("error").is_none_or(Value::is_null) {
        return Err(io::Error::other(format!(
            "node RPC {method} failed: {}",
            value["error"]
        )));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "node RPC reply has no result"))
}

fn requested_coinbase(user: &str) -> Option<&str> {
    let user = user.trim();
    (!user.is_empty() && user != "xus-miner").then_some(user)
}

fn validate_rpc_coinbase(requested: Option<&str>, job: &Job) -> Result<(), String> {
    let actual = job
        .coinbase
        .as_deref()
        .ok_or_else(|| "node template did not disclose a coinbase/proposer".to_string())?;
    if let Some(expected) = requested {
        if actual != expected {
            return Err(format!(
                "SECURITY: node template coinbase mismatch: requested `{expected}`, but the block header pays `{actual}`; refusing to hash"
            ));
        }
    }
    Ok(())
}

fn run_rpc_session(cfg: &Config, state: &Arc<State>) -> io::Result<()> {
    *state.rpc_endpoint.write().expect("rpc endpoint lock") = Some(cfg.pool.clone());
    let result = (|| {
        let mut previous_id = String::new();
        let mut chain_height = None;
        let mut announced = false;
        let mut refreshed = Instant::now() - Duration::from_secs(31);
        loop {
            // One lightweight health call supplies both values used by the dashboard;
            // mempool visualization adds no extra polling or node lock acquisition.
            let health = rpc_call(&cfg.pool, "sov_health", json!({}))?;
            let current_height = health
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sov_health result has no integer height",
                    )
                })?;
            let mempool_size = health
                .get("mempool")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sov_health result has no integer mempool size",
                    )
                })?;
            state.mempool_size.store(mempool_size, Ordering::Relaxed);
            state.mempool_known.store(true, Ordering::Release);
            if !announced {
                state.emit(json!({"event":"node_connected"}));
                announced = true;
            }
            if previous_id.is_empty()
                || chain_height != Some(current_height)
                || refreshed.elapsed() >= Duration::from_secs(30)
            {
                let requested = requested_coinbase(&cfg.user);
                let params = requested
                    .map_or_else(|| json!({}), |account| json!({"coinbaseAccount": account}));
                let value = rpc_call(&cfg.pool, "sov_getBlockTemplate", params)?;
                let job = Job::from_rpc(&value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                validate_rpc_coinbase(requested, &job)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if let Ok(network) = rpc_call(&cfg.pool, "sov_getDifficulty", json!({})) {
                    state.emit(json!({
                        "event": "network",
                        "hashrate": network.get("hashrate").cloned().unwrap_or(Value::Null),
                        "target_block_ms": network.get("targetBlockMs").cloned().unwrap_or(Value::Null),
                        "difficulty": network.get("sha256d").cloned().unwrap_or(Value::Null),
                    }));
                }
                previous_id = job.id.clone();
                state.install_job(job);
                chain_height = Some(current_height);
                refreshed = Instant::now();
            }
            thread::sleep(Duration::from_secs(2));
        }
    })();
    *state.rpc_endpoint.write().expect("rpc endpoint lock") = None;
    *state
        .confirmed_coinbase
        .write()
        .expect("confirmed coinbase lock") = None;
    state.mempool_known.store(false, Ordering::Release);
    *state.job.write().expect("job lock") = None;
    state.generation.fetch_add(1, Ordering::Release);
    result
}

fn connect(pool: &str) -> io::Result<TcpStream> {
    let address = pool_address(pool);
    let mut last = None;
    for socket in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "pool resolved to no addresses",
        )
    }))
}

fn run_session(cfg: &Config, state: &Arc<State>) -> io::Result<()> {
    let stream = connect(&cfg.pool)?;
    state.emit(json!({"event": "pool_connected"}));
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let connection = Arc::new(Connection {
        writer: Mutex::new(stream.try_clone()?),
        pending: AtomicU64::new(0),
        // Bound memory/socket growth and stale work: each worker may have at
        // most one share awaiting a pool response on this connection.
        max_pending: cfg.workers,
    });
    *state.connection.write().expect("connection lock") = Some(Arc::clone(&connection));

    write_json(
        &connection,
        &json!({
            "id": LOGIN_ID,
            "jsonrpc": "2.0",
            "method": "login",
            "params": {
                "login": cfg.user,
                "pass": cfg.password,
                "agent": format!("xus-miner/{VERSION}"),
            }
        }),
    )?;

    let result = (|| {
        let mut reader = BufReader::new(stream);
        loop {
            match read_json_line(&mut reader) {
                Ok(Some(message)) => handle_message(state, &connection, &message)?,
                Ok(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "pool closed connection",
                    ))
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    write_json(
                        &connection,
                        &json!({
                            "id": KEEPALIVE_ID,
                            "jsonrpc": "2.0",
                            "method": "keepalived",
                            "params": {}
                        }),
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
    })();
    state.clear_connection(&connection);
    result
}

fn nonce_wire(nonce: u64) -> String {
    hex::encode(nonce.to_le_bytes())
}

fn worker_loop(state: Arc<State>, worker: u64) {
    let mut generation = u64::MAX;
    let mut job: Option<Arc<Job>> = None;
    let mut blob = Vec::new();
    let mut nonce = worker << 56;
    let mut initialized = false;

    loop {
        let latest_generation = state.generation.load(Ordering::Acquire);
        if latest_generation != generation {
            generation = latest_generation;
            job = state.job.read().expect("job lock").clone();
            if let Some(current) = &job {
                blob.clone_from(&current.blob);
                nonce = worker << 56;
            }
        }

        let Some(current) = &job else {
            thread::sleep(Duration::from_millis(200));
            continue;
        };

        let mut completed = 0u64;
        for _ in 0..WORK_BATCH {
            if state.generation.load(Ordering::Acquire) != generation {
                break;
            }
            blob[current.nonce_offset..current.nonce_offset + 8]
                .copy_from_slice(&nonce.to_le_bytes());
            if !initialized {
                eprintln!("worker {worker}: initializing RandomX dataset (~2.3 GiB); hashrate appears when ready");
                state.emit(json!({"event":"worker_initializing", "worker":worker}));
            }
            let seal = current.seal_blob(&blob);
            if !initialized {
                initialized = true;
                eprintln!("worker {worker}: RandomX dataset ready; hashing");
                state.emit(json!({"event":"worker_ready", "worker":worker}));
            }
            completed += 1;
            if seal <= current.target && state.generation.load(Ordering::Acquire) == generation {
                if let Some(endpoint) = state
                    .rpc_endpoint
                    .read()
                    .expect("rpc endpoint lock")
                    .clone()
                {
                    state.submitted.fetch_add(1, Ordering::Relaxed);
                    let params = json!({
                        "templateId": current.id,
                        "nonce": nonce,
                        "timestampMs": current.timestamp_ms,
                    });
                    match rpc_call(&endpoint, "sov_submitBlock", params) {
                        Ok(_) => {
                            state.accepted.fetch_add(1, Ordering::Relaxed);
                            state.emit(json!({"event":"share", "submitted":state.submitted.load(Ordering::Relaxed), "accepted":state.accepted.load(Ordering::Relaxed), "rejected":state.rejected.load(Ordering::Relaxed)}));
                            state.generation.fetch_add(1, Ordering::Release);
                        }
                        Err(error) => {
                            state.rejected.fetch_add(1, Ordering::Relaxed);
                            eprintln!("block submission rejected: {error}");
                        }
                    }
                    nonce = nonce.wrapping_add(1);
                    continue;
                }
                let request_id = state.next_request.fetch_add(1, Ordering::Relaxed);
                let message = json!({
                    "id": request_id,
                    "jsonrpc": "2.0",
                    "method": "submit",
                    "params": {
                        "job_id": current.id,
                        "nonce": nonce_wire(nonce),
                        "result": hex::encode(seal),
                    }
                });
                if let Some(connection) = state
                    .connection
                    .read()
                    .expect("connection lock")
                    .clone()
                    .filter(|connection| connection.reserve_share())
                {
                    match write_json(&connection, &message) {
                        Ok(()) => {
                            state.submitted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            connection.finish_share();
                            eprintln!("submit failed: {error}");
                        }
                    }
                }
            }
            nonce = nonce.wrapping_add(1);
        }
        state
            .interval_hashes
            .fetch_add(completed, Ordering::Relaxed);
        state.total_hashes.fetch_add(completed, Ordering::Relaxed);
    }
}

fn reporter_loop(state: Arc<State>, every: Duration) {
    let mut previous = Instant::now();
    loop {
        thread::sleep(every);
        let elapsed = previous.elapsed().as_secs_f64();
        previous = Instant::now();
        let hashes = state.interval_hashes.swap(0, Ordering::Relaxed);
        let rate = hashes as f64 / elapsed.max(f64::EPSILON);
        let height = state
            .job
            .read()
            .expect("job lock")
            .as_ref()
            .map_or_else(|| "-".into(), |job| job.height.to_string());
        eprintln!(
            "height {height} | {rate:.2} H/s | total {} | shares {}/{}/{} submitted/accepted/rejected",
            state.total_hashes.load(Ordering::Relaxed),
            state.submitted.load(Ordering::Relaxed),
            state.accepted.load(Ordering::Relaxed),
            state.rejected.load(Ordering::Relaxed),
        );
        state.emit(json!({
            "event": "metrics",
            "hashrate": rate,
            "height": state
                .job
                .read()
                .expect("job lock")
                .as_ref()
                .map(|job| job.height),
            "total_hashes": state.total_hashes.load(Ordering::Relaxed),
            "submitted": state.submitted.load(Ordering::Relaxed),
            "accepted": state.accepted.load(Ordering::Relaxed),
            "rejected": state.rejected.load(Ordering::Relaxed),
            "mempool_size": state.mempool_known.load(Ordering::Acquire)
                .then(|| state.mempool_size.load(Ordering::Relaxed)),
        }));
    }
}

fn run_headless(cfg: Config, json_events: bool) {
    eprintln!(
        "xus-miner {VERSION} | pool {} | user {} | workers {}",
        cfg.pool, cfg.user, cfg.workers
    );
    if cfg.workers > 1 {
        eprintln!(
            "warning: each worker may allocate a full ~2.3 GiB RandomX dataset; monitor memory"
        );
    }

    let state = Arc::new(State::new(json_events));
    state.emit(json!({
        "event": "startup",
        "version": VERSION,
        "pool": cfg.pool,
        "user": cfg.user,
        "workers": cfg.workers,
    }));
    for worker in 0..cfg.workers {
        let worker_state = Arc::clone(&state);
        thread::Builder::new()
            .name(format!("xus-worker-{worker}"))
            .spawn(move || worker_loop(worker_state, worker))
            .expect("spawn mining worker");
    }
    {
        let report_state = Arc::clone(&state);
        let interval = Duration::from_secs(cfg.report_secs);
        thread::Builder::new()
            .name("xus-reporter".into())
            .spawn(move || reporter_loop(report_state, interval))
            .expect("spawn reporter");
    }

    loop {
        eprintln!("connecting to {}", cfg.pool);
        state.emit(json!({"event": "connecting", "pool": cfg.pool}));
        let direct = is_direct_rpc(&cfg.pool);
        if direct {
            eprintln!("direct SOV node RPC mode");
        }
        let session = if direct {
            run_rpc_session(&cfg, &state)
        } else {
            run_session(&cfg, &state)
        };
        if let Err(error) = session {
            eprintln!(
                "{} session ended: {error}",
                if direct { "node RPC" } else { "pool" }
            );
            state.emit(json!({
                "event": "session_error",
                "message": error.to_string(),
                "retry_in_secs": cfg.reconnect_secs,
            }));
        }
        thread::sleep(Duration::from_secs(cfg.reconnect_secs));
    }
}

fn main() {
    let mut raw: Vec<String> = env::args().skip(1).collect();
    if raw.is_empty() || raw.iter().any(|arg| arg == "--gui") {
        if let Err(error) = gui::run() {
            eprintln!("{error}");
            process::exit(1);
        }
        return;
    }

    let json_events = raw.iter().any(|arg| arg == "--json-events");
    let password_stdin = raw.iter().any(|arg| arg == "--password-stdin");
    raw.retain(|arg| {
        !matches!(
            arg.as_str(),
            "--headless" | "--json-events" | "--password-stdin"
        )
    });
    let mut cfg = parse_args_from(raw);
    if password_stdin {
        let mut password = String::new();
        io::stdin()
            .take(4_097)
            .read_to_string(&mut password)
            .unwrap_or_else(|error| {
                eprintln!("error: cannot read password from stdin: {error}");
                process::exit(2);
            });
        if password.len() > 4_096 {
            eprintln!("error: password from stdin exceeds 4096 bytes");
            process::exit(2);
        }
        cfg.password = password;
    }
    run_headless(cfg, json_events);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_primitives::{AccountId, BlockHeight, Hash};

    fn valid_job() -> Value {
        json!({
            "job_id": "job-1",
            "blob": "00".repeat(64),
            "target_full": "ff".repeat(32),
            "algo": "sha256d",
            "height": 42,
            "seed_hash": "",
            "nonce_offset": 56,
            "nonce_size": 8,
        })
    }

    fn valid_rpc_template() -> Value {
        let header = BlockHeader {
            height: BlockHeight::new(43),
            prev_hash: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            state_root: Hash::ZERO,
            timestamp_ms: 1_700_000_000_000_u64,
            proposer: AccountId::new("sov-coinbase-account").unwrap(),
            version_bits: 0,
            bits: 0,
            nonce: 0,
        };
        let blob = borsh::to_vec(&header).unwrap();
        json!({
            "templateId": header.hash().to_hex(),
            "blob": hex::encode(&blob),
            "target": "ff".repeat(32),
            "powAlgo": "Sha256d",
            "powKey": "",
            "height": 43,
            "timestampMs": 1_700_000_000_000_u64,
            "nonceOffset": blob.len() - 8,
            "proposer": "sov-coinbase-account",
        })
    }

    #[test]
    fn parses_complete_sov_job() {
        let job = Job::from_stratum(&valid_job()).unwrap();
        assert_eq!(job.id, "job-1");
        assert_eq!(job.height, 42);
        assert_eq!(job.nonce_offset, 56);
        assert_eq!(job.target, [0xff; 32]);
        assert_eq!(job.algo, PowAlgo::Sha256d);
    }

    #[test]
    fn rpc_template_confirms_header_coinbase() {
        let job = Job::from_rpc(&valid_rpc_template()).unwrap();
        assert_eq!(job.coinbase.as_deref(), Some("sov-coinbase-account"));
        assert!(validate_rpc_coinbase(None, &job).is_ok());
        assert!(validate_rpc_coinbase(Some("sov-coinbase-account"), &job).is_ok());
    }

    #[test]
    fn rpc_template_refuses_missing_or_mismatched_coinbase() {
        let mut missing = valid_rpc_template();
        missing.as_object_mut().unwrap().remove("proposer");
        assert!(Job::from_rpc(&missing).unwrap_err().contains("proposer"));

        let mut dishonest = valid_rpc_template();
        dishonest["proposer"] = json!("different-account");
        assert!(Job::from_rpc(&dishonest)
            .unwrap_err()
            .contains("does not match encoded header coinbase"));

        let job = Job::from_rpc(&valid_rpc_template()).unwrap();
        let error = validate_rpc_coinbase(Some("different-account"), &job).unwrap_err();
        assert!(error.contains("refusing to hash"));
        assert!(error.contains("different-account"));
        assert!(error.contains("sov-coinbase-account"));
    }

    #[test]
    fn target_to_expected_hashes_uses_inclusive_big_endian_probability() {
        assert!((expected_hashes_for_target(&[0xff; 32]) - 1.0).abs() < f64::EPSILON);

        let mut one_in_256 = [0xff; 32];
        one_in_256[0] = 0;
        assert!((expected_hashes_for_target(&one_in_256) - 256.0).abs() < 1e-10);

        let impossible_except_zero = [0; 32];
        assert_eq!(
            expected_hashes_for_target(&impossible_except_zero),
            2.0_f64.powi(256)
        );
    }

    #[test]
    fn refuses_layout_target_algorithm_and_seed_drift() {
        let mut value = valid_job();
        value["nonce_offset"] = json!(55);
        assert!(Job::from_stratum(&value).unwrap_err().contains("trailing"));

        let mut value = valid_job();
        value["nonce_size"] = json!(4);
        assert!(Job::from_stratum(&value)
            .unwrap_err()
            .contains("nonce_size"));

        let mut value = valid_job();
        value["target_full"] = json!("ff".repeat(31));
        assert!(Job::from_stratum(&value).unwrap_err().contains("want 32"));

        let mut value = valid_job();
        value["algo"] = json!("rx/wow");
        assert!(Job::from_stratum(&value)
            .unwrap_err()
            .contains("unsupported"));

        let mut value = valid_job();
        value["algo"] = json!("rx/0");
        assert!(Job::from_stratum(&value)
            .unwrap_err()
            .contains("cannot be empty"));
    }

    #[test]
    fn nonce_wire_is_full_little_endian_u64() {
        assert_eq!(nonce_wire(1), "0100000000000000");
        assert_eq!(nonce_wire(0x0123_4567_89ab_cdef), "efcdab8967452301");
    }

    #[test]
    fn sha_job_hashes_the_exact_spliced_blob() {
        let job = Job::from_stratum(&valid_job()).unwrap();
        let nonce: u64 = 0x0123_4567_89ab_cdef;
        let mut blob = job.blob.clone();
        blob[job.nonce_offset..].copy_from_slice(&nonce.to_le_bytes());
        assert_eq!(
            job.seal_blob(&blob),
            sov_pow::pow_seal(PowAlgo::Sha256d, &[], &blob)
        );
    }

    #[test]
    #[ignore = "allocates the full ~2 GiB RandomX mining dataset"]
    fn randomx_mainnet_job_uses_the_exact_sov_mining_seal() {
        let mut value = valid_job();
        value["algo"] = json!("rx/0");
        value["seed_hash"] =
            json!("cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d");
        let job = Job::from_stratum(&value).unwrap();
        let nonce: u64 = 0xfeed_face_cafe_beef;
        let mut blob = job.blob.clone();
        blob[job.nonce_offset..].copy_from_slice(&nonce.to_le_bytes());
        assert_eq!(
            job.seal_blob(&blob),
            sov_pow::pow_seal(PowAlgo::RandomX, &job.pow_key, &blob)
        );
    }

    #[test]
    fn pool_url_prefixes_are_optional() {
        assert_eq!(pool_address("127.0.0.1:3333"), "127.0.0.1:3333");
        assert_eq!(pool_address("tcp://host:1"), "host:1");
        assert_eq!(pool_address("stratum+tcp://host:2"), "host:2");
    }
}
