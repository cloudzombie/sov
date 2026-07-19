//! # sov-stratum — the SOV RandomX Stratum bridge
//!
//! A TCP daemon that speaks **Monero-lineage Stratum** (login/job/submit/keepalived
//! over line-delimited JSON-RPC — the dialect xmrig-class RandomX miners speak) to
//! miners on one side, and `sov_getBlockTemplate` / `sov_submitBlock` JSON-RPC to a
//! SOV node on the other. It is a **work-distribution layer only**: it adds no
//! consensus rule and can only relay a nonce the node independently re-seals and
//! fully re-validates on import (`.github/RELEASE-0.1.92.md`, Phase 2).
//!
//! Architecture (std threads, no async runtime — mirrors the other `tools/` crates):
//!
//! * a **poller** thread watches the node's height and refetches a template on tip
//!   change or refresh, then pushes a fresh job to every session;
//! * one **reader** thread per connection handles the four Stratum methods;
//! * a single **verifier** thread owns seal recomputation, so exactly one light
//!   RandomX VM (~256 MiB) exists no matter how many miners connect;
//! * optional **worker** threads (`--workers N`) grind the current template with
//!   the fast (full-dataset) VM — the built-in SOV-native miner path, so pool
//!   mining works day one with no third-party miner (each worker thread keeps its
//!   own RandomX VM; budget ~2.3 GiB per worker in fast mode).
//!
//! Every submitted share is re-sealed with the REAL `pow_seal` — the miner's
//! `result` field is cross-checked, never trusted. A seal that also clears the
//! network target is forwarded via `sov_submitBlock` with the job's **frozen**
//! `timestampMs` (the timestamp is inside the hashed blob, so miners never roll it).
//!
//! No secret material is handled anywhere in this process (the coinbase account id
//! is public), so there is nothing to zeroize — deliberate, see the README.

mod job;
mod share;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sov_rpc::client::RpcClient;

use job::{parse_nonce_hex, Template};
use share::{
    classify_seal, difficulty_to_target256, effective_share_target, next_difficulty,
    stratum_target_hex, ShareOutcome, VardiffConfig,
};

/// How many issued jobs stay submittable at once (across all sessions). Old jobs
/// are evicted oldest-first; the whole book is cleared whenever the template
/// changes, so a submit against a superseded template is rejected as stale.
const MAX_LIVE_JOBS: usize = 4096;
/// Hard cap on concurrent miner connections. Past this the listener sheds new
/// connections instead of spawning unbounded threads — a flood on the (public-facing)
/// Stratum port cannot exhaust the bridge's threads/memory. Firewall :3333 too.
const MAX_CONNECTIONS: usize = 512;
static ACTIVE_CONNS: AtomicUsize = AtomicUsize::new(0);
/// Reader-side idle cutoff: xmrig sends `keepalived` every 60 s, so a session
/// silent for this long is dead and its thread should exit.
const READ_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Write timeout on miner sockets — a wedged peer must never block a broadcast
/// (the same lesson as the v0.1.75 p2p SO_SNDTIMEO fix).
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Nonces a built-in worker grinds between checks for a superseded template.
const WORKER_BATCH: u64 = 64;

/// Runtime configuration, from CLI flags (see `usage`).
#[derive(Clone, Debug)]
struct Config {
    /// The SOV node's JSON-RPC endpoint, `host:port`.
    node: String,
    /// The Stratum listen address, `host:port`.
    bind: String,
    /// Coinbase account passed to `sov_getBlockTemplate` (None = the node's own).
    coinbase: Option<String>,
    /// Starting per-session share difficulty (vardiff tunes it from here).
    start_diff: u64,
    /// Vardiff knobs.
    vardiff: VardiffConfig,
    /// Node poll interval (height watch), milliseconds.
    poll_ms: u64,
    /// Template refresh interval even without a tip change (fresh timestamp +
    /// fresh mempool; also keeps templates far inside the node's 120 s cache TTL).
    refresh_secs: u64,
    /// Built-in SOV-native worker threads (0 = bridge only).
    workers: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            node: "127.0.0.1:8645".into(),
            bind: "0.0.0.0:3333".into(),
            coinbase: None,
            start_diff: 5_000,
            vardiff: VardiffConfig::default(),
            poll_ms: 2_000,
            refresh_secs: 30,
            workers: 0,
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "sov-stratum — Monero-lineage RandomX Stratum bridge for SOV\n\n\
         USAGE: sov-stratum [FLAGS]\n\n\
         FLAGS (all optional):\n\
           --node <host:port>        SOV node JSON-RPC endpoint     [127.0.0.1:8645]\n\
           --bind <host:port>        Stratum listen address         [0.0.0.0:3333]\n\
           --coinbase <account-id>   mine to this account (else the node's configured one)\n\
           --start-diff <n>          initial per-session share difficulty [5000]\n\
           --min-diff <n>            vardiff floor                  [100]\n\
           --max-diff <n>            vardiff ceiling                [2^62]\n\
           --share-secs <n>          vardiff ideal seconds/share    [10]\n\
           --retarget-secs <n>       vardiff window seconds         [30]\n\
           --poll-ms <n>             node height poll interval, ms  [2000]\n\
           --refresh-secs <n>        template refresh interval, s   [30]\n\
           --workers <n>             built-in SOV-native miner threads [0]\n\
           --help                    this text"
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = |flag: &str| -> String {
            args.next().unwrap_or_else(|| {
                eprintln!("error: {flag} requires a value\n");
                usage()
            })
        };
        let parse_u64 = |flag: &str, raw: String| -> u64 {
            raw.parse().unwrap_or_else(|_| {
                eprintln!("error: {flag} wants an unsigned integer, got `{raw}`\n");
                usage()
            })
        };
        match flag.as_str() {
            "--node" => cfg.node = strip_http(&value("--node")),
            "--bind" => cfg.bind = value("--bind"),
            "--coinbase" => cfg.coinbase = Some(value("--coinbase")),
            "--start-diff" => cfg.start_diff = parse_u64("--start-diff", value("--start-diff")),
            "--min-diff" => cfg.vardiff.min_diff = parse_u64("--min-diff", value("--min-diff")),
            "--max-diff" => cfg.vardiff.max_diff = parse_u64("--max-diff", value("--max-diff")),
            "--share-secs" => {
                cfg.vardiff.target_share_secs =
                    parse_u64("--share-secs", value("--share-secs")) as f64
            }
            "--retarget-secs" => {
                cfg.vardiff.retarget_secs =
                    parse_u64("--retarget-secs", value("--retarget-secs")) as f64
            }
            "--poll-ms" => cfg.poll_ms = parse_u64("--poll-ms", value("--poll-ms")).max(250),
            "--refresh-secs" => {
                cfg.refresh_secs = parse_u64("--refresh-secs", value("--refresh-secs")).max(1)
            }
            "--workers" => cfg.workers = parse_u64("--workers", value("--workers")),
            "--help" | "-h" => usage(),
            other => {
                eprintln!("error: unknown flag `{other}`\n");
                usage()
            }
        }
    }
    if cfg.vardiff.min_diff == 0 || cfg.vardiff.min_diff > cfg.vardiff.max_diff {
        eprintln!("error: --min-diff must be nonzero and <= --max-diff\n");
        usage()
    }
    cfg.start_diff = cfg
        .start_diff
        .clamp(cfg.vardiff.min_diff, cfg.vardiff.max_diff);
    cfg
}

/// `RpcClient` wants `host:port`; tolerate a pasted `http://host:port/` URL.
fn strip_http(raw: &str) -> String {
    raw.trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

/// The exact `sov_submitBlock` params for a network-difficulty share: the cached
/// template's id, the winning nonce, and the job's FROZEN timestamp (it is inside
/// the hashed blob — forwarding anything else would describe a different preimage).
fn submit_params(template: &Template, nonce: u64) -> Value {
    json!({
        "templateId": template.template_id,
        "nonce": nonce,
        "timestampMs": template.timestamp_ms,
    })
}

/// One issued Stratum job: which template it grinds, which session it belongs
/// to, and the share difficulty it was issued at (retargets issue a NEW job, so
/// accounting stays bound to the difficulty the work was actually done under).
#[derive(Clone)]
struct JobEntry {
    template: Arc<Template>,
    miner_id: u64,
    difficulty: u64,
    share_target: [u8; 32],
    /// Nonces already submitted against this job (shared across clones of the
    /// entry). A repeat is rejected *before* seal recomputation, so a duplicate
    /// can neither be double-counted (share credit, and the eventual PPLNS
    /// weights), double-forwarded to `sov_submitBlock`, nor used to spin the
    /// verifier's RandomX VM on work it has already done.
    submitted: Arc<Mutex<HashSet<u64>>>,
}

/// Per-session vardiff measurement window.
struct ShareWindow {
    since: Instant,
    shares: u64,
}

/// One connected miner session.
struct Miner {
    id: u64,
    session: String,
    peer: String,
    /// Write half (a `try_clone` of the socket) — the poller pushes jobs here.
    writer: Mutex<TcpStream>,
    difficulty: AtomicU64,
    window: Mutex<ShareWindow>,
    accepted: AtomicU64,
    rejected: AtomicU64,
    logged_in: AtomicBool,
    alive: AtomicBool,
}

/// A seal-recomputation request for the single verifier thread.
struct VerifyReq {
    template: Arc<Template>,
    nonce: u64,
    reply: mpsc::Sender<[u8; 32]>,
}

/// Shared pool state.
struct Pool {
    cfg: Config,
    rpc: RpcClient,
    /// The template all current jobs grind (None until the first successful poll).
    current: RwLock<Option<Arc<Template>>>,
    /// The live job book: id → entry, plus insertion order for eviction.
    jobs: Mutex<(HashMap<String, JobEntry>, VecDeque<String>)>,
    job_seq: AtomicU64,
    miner_seq: AtomicU64,
    miners: Mutex<Vec<Arc<Miner>>>,
    verify_tx: mpsc::Sender<VerifyReq>,
    blocks_found: AtomicU64,
}

impl Pool {
    /// Recompute a seal on the dedicated verifier thread (one light RandomX VM
    /// process-wide, regardless of connection count).
    fn seal(&self, template: &Arc<Template>, nonce: u64) -> Result<[u8; 32], String> {
        let (tx, rx) = mpsc::channel();
        self.verify_tx
            .send(VerifyReq {
                template: Arc::clone(template),
                nonce,
                reply: tx,
            })
            .map_err(|_| "verifier thread is gone".to_string())?;
        rx.recv().map_err(|_| "verifier thread is gone".to_string())
    }

    /// Issue a fresh job for `miner` against the current template (None while the
    /// bridge has no work — e.g. the node is unreachable at startup).
    fn new_job_for(&self, miner: &Miner) -> Option<Value> {
        let template = self.current.read().expect("current lock").clone()?;
        let difficulty = miner.difficulty.load(Ordering::Relaxed);
        let share_target = effective_share_target(
            difficulty_to_target256(difficulty),
            &template.network_target,
        );
        let job_id = format!("{:016x}", self.job_seq.fetch_add(1, Ordering::Relaxed));
        {
            let (map, order) = &mut *self.jobs.lock().expect("jobs lock");
            map.insert(
                job_id.clone(),
                JobEntry {
                    template: Arc::clone(&template),
                    miner_id: miner.id,
                    difficulty,
                    share_target,
                    submitted: Arc::new(Mutex::new(HashSet::new())),
                },
            );
            order.push_back(job_id.clone());
            while order.len() > MAX_LIVE_JOBS {
                if let Some(old) = order.pop_front() {
                    map.remove(&old);
                }
            }
        }
        Some(json!({
            // The Monero-dialect fields xmrig-class miners consume.
            "job_id": job_id,
            "blob": hex::encode(&template.blob),
            "target": stratum_target_hex(difficulty),
            "algo": template.stratum_algo(),
            "height": template.height,
            "seed_hash": template.seed_hash,
            // SOV extensions (unknown fields are ignored by stock miners): where
            // the nonce really lives, and the full big-endian share threshold for
            // miners that check the seal the way SOV consensus does.
            "nonce_offset": template.nonce_offset,
            "nonce_size": 8,
            "target_full": hex::encode(share_target),
        }))
    }

    /// Push `line`-encoded JSON to one miner; a failed write marks it dead.
    fn push(&self, miner: &Miner, msg: &Value) {
        let mut writer = miner.writer.lock().expect("writer lock");
        let mut payload = msg.to_string();
        payload.push('\n');
        if writer.write_all(payload.as_bytes()).is_err() || writer.flush().is_err() {
            miner.alive.store(false, Ordering::Relaxed);
        }
    }

    /// Broadcast a fresh job to every logged-in session and prune dead ones.
    fn broadcast_jobs(&self) {
        let miners: Vec<Arc<Miner>> = self.miners.lock().expect("miners lock").clone();
        for m in &miners {
            if !m.alive.load(Ordering::Relaxed) || !m.logged_in.load(Ordering::Relaxed) {
                continue;
            }
            if let Some(job) = self.new_job_for(m) {
                self.push(
                    m,
                    &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
                );
            }
        }
        self.miners
            .lock()
            .expect("miners lock")
            .retain(|m| m.alive.load(Ordering::Relaxed));
    }

    /// Forward a network-difficulty seal to the node. The node re-validates the
    /// whole block on import — the bridge's word counts for nothing, by design.
    fn submit_block(&self, template: &Template, nonce: u64, seal: &[u8; 32]) {
        log(&format!(
            "BLOCK CANDIDATE height {} nonce {:#x} seal {} — forwarding to {}",
            template.height,
            nonce,
            hex::encode(seal),
            self.cfg.node
        ));
        match self
            .rpc
            .call("sov_submitBlock", submit_params(template, nonce))
        {
            Ok(v) => {
                if v.get("accepted").and_then(Value::as_bool) == Some(true) {
                    self.blocks_found.fetch_add(1, Ordering::Relaxed);
                    log(&format!(
                        "BLOCK ACCEPTED height {} hash {}",
                        v.get("height").and_then(Value::as_u64).unwrap_or_default(),
                        v.get("hash").and_then(Value::as_str).unwrap_or("?")
                    ));
                } else {
                    log(&format!(
                        "block import rejected: {}",
                        v.get("error").and_then(Value::as_str).unwrap_or("unknown")
                    ));
                }
            }
            Err(e) => log(&format!("sov_submitBlock failed: {e}")),
        }
    }
}

fn log(msg: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    println!("[{secs}] {msg}");
}

/// The single verifier thread: owns the light RandomX VM via `pow_seal`'s
/// thread-local storage (the key is genesis-constant, so the VM builds once).
fn spawn_verifier() -> mpsc::Sender<VerifyReq> {
    let (tx, rx) = mpsc::channel::<VerifyReq>();
    thread::Builder::new()
        .name("seal-verifier".into())
        .spawn(move || {
            for req in rx {
                let seal = req.template.seal_for_nonce(req.nonce);
                let _ = req.reply.send(seal);
            }
        })
        .expect("spawn verifier thread");
    tx
}

/// The poller: watch the node's height; refetch a template on tip change or
/// refresh interval; broadcast fresh jobs when the template changes.
fn poll_loop(pool: Arc<Pool>) {
    let mut last_height: Option<u64> = None;
    let mut last_fetch = Instant::now()
        .checked_sub(Duration::from_secs(pool.cfg.refresh_secs))
        .unwrap_or_else(Instant::now);
    let mut have_template = false;
    loop {
        let height = match pool.rpc.height() {
            Ok(h) => Some(h),
            Err(e) => {
                log(&format!("node poll failed ({}): {e}", pool.cfg.node));
                None
            }
        };
        let tip_moved = height.is_some() && height != last_height;
        let refresh_due = last_fetch.elapsed() >= Duration::from_secs(pool.cfg.refresh_secs);
        if height.is_some() && (tip_moved || refresh_due || !have_template) {
            let params = match &pool.cfg.coinbase {
                Some(cb) => json!({ "coinbaseAccount": cb }),
                None => json!({}),
            };
            match pool.rpc.call("sov_getBlockTemplate", params) {
                Ok(v) => match Template::from_rpc(&v) {
                    Ok(t) => {
                        last_fetch = Instant::now();
                        last_height = height;
                        have_template = true;
                        let t = Arc::new(t);
                        *pool.current.write().expect("current lock") = Some(Arc::clone(&t));
                        // The old template's jobs are superseded: clear the book so
                        // late submits against them are rejected as stale.
                        {
                            let (map, order) = &mut *pool.jobs.lock().expect("jobs lock");
                            map.clear();
                            order.clear();
                        }
                        let sessions = pool.miners.lock().expect("miners lock").len();
                        log(&format!(
                            "new work: height {} prev {} algo {:?} ({} session{})",
                            t.height,
                            &t.prev_hash[..16.min(t.prev_hash.len())],
                            t.algo,
                            sessions,
                            if sessions == 1 { "" } else { "s" }
                        ));
                        pool.broadcast_jobs();
                    }
                    Err(e) => log(&format!("bad template from node: {e}")),
                },
                Err(e) => log(&format!("sov_getBlockTemplate failed: {e}")),
            }
        }
        thread::sleep(Duration::from_millis(pool.cfg.poll_ms));
    }
}

/// Handle one `submit`. Returns the Stratum `result` value, or `(code, message)`
/// for the error reply.
fn handle_submit(pool: &Pool, miner: &Miner, params: &Value) -> Result<Value, (i64, String)> {
    let job_id = params
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing string param `job_id`".to_string()))?;
    let nonce_hex = params
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing string param `nonce`".to_string()))?;
    let nonce = parse_nonce_hex(nonce_hex).map_err(|e| (-32602, e))?;
    let entry = pool
        .jobs
        .lock()
        .expect("jobs lock")
        .0
        .get(job_id)
        .cloned()
        .ok_or((
            -1,
            "block expired — stale job, wait for the next".to_string(),
        ))?;
    if entry.miner_id != miner.id {
        return Err((-1, "job belongs to a different session".to_string()));
    }
    // Duplicate check BEFORE the (expensive) seal recomputation: each nonce is
    // considered exactly once per job, whatever its outcome, so a replayed
    // submit can neither inflate share counts nor grind the verifier.
    if !entry
        .submitted
        .lock()
        .expect("submitted lock")
        .insert(nonce)
    {
        miner.rejected.fetch_add(1, Ordering::Relaxed);
        return Err((-1, "duplicate share".to_string()));
    }

    // Recompute the seal with the REAL pow_seal — never trust the miner's word.
    let seal = pool.seal(&entry.template, nonce).map_err(|e| (-1, e))?;
    if let Some(result_hex) = params.get("result").and_then(Value::as_str) {
        if !result_hex.eq_ignore_ascii_case(&hex::encode(seal)) {
            miner.rejected.fetch_add(1, Ordering::Relaxed);
            return Err((
                -1,
                "result hash mismatch — miner sealed different bytes".to_string(),
            ));
        }
    }
    match classify_seal(&seal, &entry.share_target, &entry.template.network_target) {
        ShareOutcome::TooWeak => {
            miner.rejected.fetch_add(1, Ordering::Relaxed);
            Err((-1, "low difficulty share".to_string()))
        }
        outcome => {
            let accepted = miner.accepted.fetch_add(1, Ordering::Relaxed) + 1;
            // NOTE(Phase 3): this per-session tally is where PPLNS share weights
            // will accrue once the decentralized sharechain lands — see
            // `.github/RELEASE-0.1.92.md` Sections 3–4. Not implemented here.
            if outcome == ShareOutcome::Block {
                pool.submit_block(&entry.template, nonce, &seal);
            }
            log(&format!(
                "share OK from {} (diff {}, total {}{})",
                miner.peer,
                entry.difficulty,
                accepted,
                if outcome == ShareOutcome::Block {
                    ", NETWORK difficulty — block submitted"
                } else {
                    ""
                }
            ));
            maybe_retarget(pool, miner);
            Ok(json!({ "status": "OK" }))
        }
    }
}

/// Vardiff bookkeeping after an accepted share: retarget when the window has run
/// its course (or the session is drastically outrunning it) and, if difficulty
/// changed, push a fresh job at the new target immediately.
fn maybe_retarget(pool: &Pool, miner: &Miner) {
    let cfg = &pool.cfg.vardiff;
    let mut changed = false;
    {
        let mut w = miner.window.lock().expect("window lock");
        w.shares += 1;
        let elapsed = w.since.elapsed().as_secs_f64();
        // Early exit while the window is still measuring — unless the session is
        // flooding (≫ the ideal rate), which warrants an immediate clamp-up.
        let flooding = (w.shares as f64) >= 4.0 * cfg.max_adjust;
        if elapsed < cfg.retarget_secs && !flooding {
            return;
        }
        let current = miner.difficulty.load(Ordering::Relaxed);
        let next = next_difficulty(current, w.shares, elapsed, cfg);
        if next != current {
            miner.difficulty.store(next, Ordering::Relaxed);
            log(&format!(
                "vardiff: {} {} -> {} ({} share(s) in {:.1}s)",
                miner.peer, current, next, w.shares, elapsed
            ));
            changed = true;
        }
        w.shares = 0;
        w.since = Instant::now();
    }
    if changed {
        if let Some(job) = pool.new_job_for(miner) {
            pool.push(
                miner,
                &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
            );
        }
    }
}

/// One Stratum session: read line-delimited JSON-RPC requests until EOF/timeout.
fn serve_conn(pool: Arc<Pool>, stream: TcpStream) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            log(&format!("{peer}: cannot clone socket: {e}"));
            return;
        }
    };
    let id = pool.miner_seq.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let miner = Arc::new(Miner {
        id,
        session: format!("{id:08x}{nanos:08x}"),
        peer: peer.clone(),
        writer: Mutex::new(writer),
        difficulty: AtomicU64::new(pool.cfg.start_diff),
        window: Mutex::new(ShareWindow {
            since: Instant::now(),
            shares: 0,
        }),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        logged_in: AtomicBool::new(false),
        alive: AtomicBool::new(true),
    });
    pool.miners
        .lock()
        .expect("miners lock")
        .push(Arc::clone(&miner));
    log(&format!("{peer}: connected (session {})", miner.session));

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // EOF, reset, or idle timeout — the session is over.
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                reply_err(
                    &pool,
                    &miner,
                    Value::Null,
                    -32700,
                    &format!("parse error: {e}"),
                );
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        match req.get("method").and_then(Value::as_str) {
            Some("login") => {
                // `params.login` carries the miner's wallet/worker label; the
                // coinbase is pool-level config here, so it is logged, not obeyed.
                if let Some(who) = params.get("login").and_then(Value::as_str) {
                    log(&format!("{peer}: login `{who}`"));
                }
                miner.logged_in.store(true, Ordering::Relaxed);
                match pool.new_job_for(&miner) {
                    Some(job) => reply_ok(
                        &pool,
                        &miner,
                        id,
                        json!({
                            "id": miner.session,
                            "job": job,
                            "extensions": [],
                            "status": "OK",
                        }),
                    ),
                    None => reply_err(&pool, &miner, id, -1, "no work yet — node unreachable?"),
                }
            }
            Some("getjob") => match pool.new_job_for(&miner) {
                Some(job) => reply_ok(&pool, &miner, id, job),
                None => reply_err(&pool, &miner, id, -1, "no work yet — node unreachable?"),
            },
            Some("submit") => match handle_submit(&pool, &miner, &params) {
                Ok(result) => reply_ok(&pool, &miner, id, result),
                Err((code, msg)) => reply_err(&pool, &miner, id, code, &msg),
            },
            Some("keepalived") => reply_ok(&pool, &miner, id, json!({ "status": "KEEPALIVED" })),
            Some(other) => reply_err(
                &pool,
                &miner,
                id,
                -32601,
                &format!("unknown method `{other}`"),
            ),
            None => reply_err(&pool, &miner, id, -32600, "request has no method"),
        }
        if !miner.alive.load(Ordering::Relaxed) {
            break;
        }
    }

    miner.alive.store(false, Ordering::Relaxed);
    pool.miners
        .lock()
        .expect("miners lock")
        .retain(|m| m.id != miner.id);
    log(&format!(
        "{peer}: disconnected (accepted {}, rejected {})",
        miner.accepted.load(Ordering::Relaxed),
        miner.rejected.load(Ordering::Relaxed)
    ));
}

fn reply_ok(pool: &Pool, miner: &Miner, id: Value, result: Value) {
    pool.push(
        miner,
        &json!({ "id": id, "jsonrpc": "2.0", "error": Value::Null, "result": result }),
    );
}

fn reply_err(pool: &Pool, miner: &Miner, id: Value, code: i64, message: &str) {
    pool.push(
        miner,
        &json!({
            "id": id,
            "jsonrpc": "2.0",
            "error": { "code": code, "message": message },
            "result": Value::Null,
        }),
    );
}

/// A built-in SOV-native worker: grind the current template with the fast VM,
/// abandoning the batch the moment the template is superseded. Workers bypass
/// share accounting (they are the operator's own hashrate) and submit network-
/// difficulty seals directly.
fn worker_loop(pool: Arc<Pool>, index: u64) {
    log(&format!("worker {index}: online"));
    let mut current: Option<Arc<Template>> = None;
    // Once a block is found on a template, the template is SPENT for this worker:
    // grinding (or worse, resubmitting) it again is wasted work — park until the
    // poller hands out the next one (which the found block itself triggers).
    let mut spent: Option<Arc<Template>> = None;
    let mut nonce: u64 = 0;
    loop {
        let latest = pool.current.read().expect("current lock").clone();
        let Some(template) = latest else {
            thread::sleep(Duration::from_millis(500));
            continue;
        };
        if let Some(s) = &spent {
            if Arc::ptr_eq(s, &template) {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            spent = None;
        }
        let fresh = match &current {
            Some(t) => !Arc::ptr_eq(t, &template),
            None => true,
        };
        if fresh {
            // Partition the nonce space so workers never duplicate effort.
            nonce = index << 56;
            current = Some(Arc::clone(&template));
        }
        for _ in 0..WORKER_BATCH {
            let seal = template.seal_for_nonce_mining(nonce);
            if seal <= template.network_target {
                pool.submit_block(&template, nonce, &seal);
                spent = Some(Arc::clone(&template));
                break; // abandon this template; the poller will bring the next
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

fn main() {
    let cfg = parse_args();
    log(&format!(
        "sov-stratum: node {} | stratum {} | start diff {} | coinbase {} | workers {}",
        cfg.node,
        cfg.bind,
        cfg.start_diff,
        cfg.coinbase.as_deref().unwrap_or("(node's own)"),
        cfg.workers
    ));

    let listener = match TcpListener::bind(&cfg.bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };

    let pool = Arc::new(Pool {
        rpc: RpcClient::new(cfg.node.clone()).with_timeout(Duration::from_secs(15)),
        cfg: cfg.clone(),
        current: RwLock::new(None),
        jobs: Mutex::new((HashMap::new(), VecDeque::new())),
        job_seq: AtomicU64::new(0),
        miner_seq: AtomicU64::new(0),
        miners: Mutex::new(Vec::new()),
        verify_tx: spawn_verifier(),
        blocks_found: AtomicU64::new(0),
    });

    {
        let pool = Arc::clone(&pool);
        thread::Builder::new()
            .name("template-poller".into())
            .spawn(move || poll_loop(pool))
            .expect("spawn poller thread");
    }
    for index in 0..cfg.workers {
        let pool = Arc::clone(&pool);
        thread::Builder::new()
            .name(format!("worker-{index}"))
            .spawn(move || worker_loop(pool, index))
            .expect("spawn worker thread");
    }

    log(&format!("listening for miners on {}", cfg.bind));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Shed load past the cap so a connection flood can't exhaust threads/memory.
                if ACTIVE_CONNS.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    log("connection cap reached — refusing new miner");
                    drop(s);
                    continue;
                }
                ACTIVE_CONNS.fetch_add(1, Ordering::Relaxed);
                let pool = Arc::clone(&pool);
                if thread::Builder::new()
                    .name("stratum-conn".into())
                    .spawn(move || {
                        serve_conn(pool, s);
                        ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
                    })
                    .is_err()
                {
                    ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
                    log("failed to spawn a connection thread");
                }
            }
            Err(e) => log(&format!("accept failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_pow::PowAlgo;

    #[test]
    fn submit_params_carry_the_frozen_job_timestamp() {
        // The timestamp is inside the hashed blob: sov_submitBlock must receive the
        // job's OWN timestampMs so the node reconstructs the identical preimage.
        let template = Template {
            template_id: "ab".repeat(32),
            height: 7,
            prev_hash: "cd".repeat(32),
            blob: vec![0; 176],
            nonce_offset: 168,
            network_target: [0xff; 32],
            algo: PowAlgo::Sha256d,
            pow_key: vec![],
            seed_hash: String::new(),
            timestamp_ms: 1_752_800_123_456,
        };
        let p = submit_params(&template, 42);
        assert_eq!(p["templateId"], json!("ab".repeat(32)));
        assert_eq!(p["nonce"], json!(42u64));
        assert_eq!(p["timestampMs"], json!(1_752_800_123_456u64));
    }

    #[test]
    fn strip_http_tolerates_pasted_urls() {
        assert_eq!(strip_http("http://127.0.0.1:8645/"), "127.0.0.1:8645");
        assert_eq!(
            strip_http("https://node.sovxus.org:8645"),
            "node.sovxus.org:8645"
        );
        assert_eq!(strip_http("64.225.10.34:8645"), "64.225.10.34:8645");
    }

    // ---- handler-level harness ---------------------------------------------
    //
    // These tests drive `new_job_for` / `handle_submit` / `maybe_retarget`
    // directly against a real `Pool` and a real socket-backed `Miner`, with
    // Sha256d templates (the same splice + `pow_seal` path RandomX rides —
    // the algo is a template parameter, so the logic under test is identical).

    /// An arbitrary Sha256d template. The blob need not be a valid header for
    /// share arithmetic — `pow_seal` hashes whatever bytes the node handed out.
    fn share_template(network_target: [u8; 32]) -> Template {
        Template {
            template_id: "ab".repeat(32),
            height: 100,
            prev_hash: "cd".repeat(32),
            blob: vec![0x5a; 64],
            nonce_offset: 56,
            network_target,
            algo: PowAlgo::Sha256d,
            pow_key: vec![],
            seed_hash: String::new(),
            timestamp_ms: 1_753_000_000_000,
        }
    }

    /// A network target no sha256d output will ever meet (only the all-zero
    /// hash would) — so every valid share stays a Share, never a Block.
    const UNREACHABLE: [u8; 32] = [0u8; 32];

    fn test_pool(node: &str, template: Option<Template>, start_diff: u64) -> Arc<Pool> {
        let mut cfg = Config {
            node: node.to_string(),
            start_diff,
            ..Config::default()
        };
        cfg.vardiff.min_diff = 1;
        Arc::new(Pool {
            rpc: RpcClient::new(node.to_string()).with_timeout(Duration::from_secs(5)),
            cfg,
            current: RwLock::new(template.map(Arc::new)),
            jobs: Mutex::new((HashMap::new(), VecDeque::new())),
            job_seq: AtomicU64::new(0),
            miner_seq: AtomicU64::new(0),
            miners: Mutex::new(Vec::new()),
            verify_tx: spawn_verifier(),
            blocks_found: AtomicU64::new(0),
        })
    }

    /// A registered miner whose writer is one end of a real loopback socket;
    /// the returned client end observes everything the pool pushes.
    fn test_miner(pool: &Pool, difficulty: u64) -> (Arc<Miner>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let id = pool.miner_seq.fetch_add(1, Ordering::Relaxed);
        let miner = Arc::new(Miner {
            id,
            session: format!("{id:08x}"),
            peer: format!("test-miner-{id}"),
            writer: Mutex::new(server),
            difficulty: AtomicU64::new(difficulty),
            window: Mutex::new(ShareWindow {
                since: Instant::now(),
                shares: 0,
            }),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            logged_in: AtomicBool::new(true),
            alive: AtomicBool::new(true),
        });
        pool.miners.lock().unwrap().push(Arc::clone(&miner));
        (miner, client)
    }

    fn nonce_wire(nonce: u64) -> String {
        hex::encode(nonce.to_le_bytes())
    }

    fn job_id_of(job: &Value) -> String {
        job["job_id"].as_str().expect("job_id").to_string()
    }

    #[test]
    fn new_job_for_issues_a_monero_dialect_job_and_registers_it() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job = pool.new_job_for(&miner).expect("template present");
        assert_eq!(job["blob"], json!(hex::encode(&template.blob)));
        assert_eq!(job["algo"], json!("sha256d"));
        assert_eq!(job["height"], json!(100u64));
        assert_eq!(job["target"], json!("ffffffff")); // difficulty 1
        assert_eq!(job["nonce_offset"], json!(56u64));
        assert_eq!(job["nonce_size"], json!(8u64));
        assert_eq!(job["target_full"], json!("ff".repeat(32))); // diff-1 share target
                                                                // The job is live in the book, keyed by its id.
        let jobs = pool.jobs.lock().unwrap();
        assert!(jobs.0.contains_key(&job_id_of(&job)));
        assert_eq!(jobs.1.len(), 1);
    }

    #[test]
    fn new_job_for_returns_none_without_a_template() {
        let pool = test_pool("127.0.0.1:1", None, 1);
        let (miner, _client) = test_miner(&pool, 1);
        assert!(pool.new_job_for(&miner).is_none());
    }

    #[test]
    fn handle_submit_accepts_a_share_and_rejects_every_duplicate() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        // Difficulty 1 accepts every hash — first submit is credited.
        let ok = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7)}),
        )
        .expect("first submit is a share");
        assert_eq!(ok, json!({"status": "OK"}));
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1);

        // The identical resubmit is rejected — no double credit, ever.
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7)}),
        )
        .expect_err("duplicate must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("duplicate"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1, "no double count");
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);

        // A duplicate dressed up with a correct `result` hash is still a duplicate.
        let seal = hex::encode(share_template(UNREACHABLE).seal_for_nonce(7));
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7), "result": seal}),
        )
        .expect_err("correct hash does not launder a duplicate");
        assert!(err.1.contains("duplicate"));

        // The u32 wire form of an already-seen nonce is the SAME nonce.
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": "07000000"}),
        )
        .expect_err("u32 encoding of nonce 7 is still nonce 7");
        assert!(err.1.contains("duplicate"));

        // A genuinely fresh nonce is credited again.
        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(8)}),
        )
        .expect("fresh nonce accepted");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn handle_submit_rejects_low_difficulty_shares() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1 << 32);
        let (miner, _client) = test_miner(&pool, 1 << 32);
        let job = pool.new_job_for(&miner).unwrap();
        // Difficulty 2^32 ⇒ share target (2^256−1)>>32: four leading zero bytes.
        let share_target = hex::decode(job["target_full"].as_str().unwrap()).unwrap();
        assert_eq!(&share_target[..4], &[0, 0, 0, 0]);
        // Find a nonce whose REAL seal misses that target (P(miss) ≈ 1 − 2⁻³²
        // per nonce, so the first candidate all but certainly fails).
        let weak_nonce = (0..1_000u64)
            .find(|&n| template.seal_for_nonce(n).as_slice() > share_target.as_slice())
            .expect("a weak nonce exists in 1000 tries");
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id_of(&job), "nonce": nonce_wire(weak_nonce)}),
        )
        .expect_err("weak seal must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("low difficulty"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_submit_rejects_a_lying_result_hash() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        // The miner claims a hash that is not the seal of these bytes.
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(9), "result": "00".repeat(32)}),
        )
        .expect_err("a lying result must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("mismatch"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);

        // An honest result — matched case-insensitively — is accepted.
        let honest = hex::encode(template.seal_for_nonce(10)).to_uppercase();
        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(10), "result": honest}),
        )
        .expect("honest uppercase result accepted");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_submit_rejects_stale_foreign_and_malformed_submissions() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner_a, _ca) = test_miner(&pool, 1);
        let (miner_b, _cb) = test_miner(&pool, 1);
        let job_a = job_id_of(&pool.new_job_for(&miner_a).unwrap());

        // A job id the pool never issued (or already evicted) is stale.
        let (code, msg) = handle_submit(
            &pool,
            &miner_a,
            &json!({"job_id": "beef000000000000", "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert_eq!(code, -1);
        assert!(msg.contains("stale"), "got `{msg}`");

        // Session B cannot ride session A's job (share-theft guard).
        let (_, msg) = handle_submit(
            &pool,
            &miner_b,
            &json!({"job_id": job_a, "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert!(msg.contains("different session"), "got `{msg}`");

        // Malformed parameter shapes: typed errors, never a panic or a credit.
        for (params, expect) in [
            (json!({}), "job_id"),
            (json!({"job_id": job_a}), "nonce"),
            (json!({"job_id": 7, "nonce": nonce_wire(1)}), "job_id"),
            (json!({"job_id": job_a, "nonce": 7}), "nonce"),
            (json!({"job_id": job_a, "nonce": "xyz"}), "hex"),
            (
                json!({"job_id": job_a, "nonce": "01020304050607"}),
                "16 hex",
            ),
            (
                json!({"job_id": job_a, "nonce": "0x".repeat(50_000)}),
                "hex",
            ),
        ] {
            let (code, msg) =
                handle_submit(&pool, &miner_a, &params).expect_err("malformed must fail");
            assert_eq!(code, -32602, "params {params} → wrong code");
            assert!(msg.contains(expect), "params {params} → `{msg}`");
        }
        assert_eq!(miner_a.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner_b.accepted.load(Ordering::Relaxed), 0);
    }

    /// A one-shot mock SOV node: accepts HTTP/1.1 JSON-RPC connections, records
    /// every `sov_submitBlock` params object, and answers `accepted: true`.
    fn spawn_mock_node() -> (String, Arc<Mutex<Vec<Value>>>) {
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
                // Read headers, then exactly Content-Length body bytes.
                let header_end = loop {
                    match std::io::Read::read(&mut conn, &mut tmp) {
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
                    match std::io::Read::read(&mut conn, &mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&tmp[..n]),
                    }
                }
                let Ok(req) = serde_json::from_slice::<Value>(&body) else {
                    continue;
                };
                let result = match req["method"].as_str() {
                    Some("sov_submitBlock") => {
                        recorded.lock().unwrap().push(req["params"].clone());
                        json!({"accepted": true, "height": 101u64, "hash": "aa".repeat(32)})
                    }
                    Some("sov_getHeight") => json!(100u64),
                    _ => Value::Null,
                };
                let body = json!({"jsonrpc": "2.0", "id": req["id"].clone(), "result": result})
                    .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes());
            }
        });
        (addr, submits)
    }

    #[test]
    fn network_difficulty_share_is_forwarded_exactly_once_with_the_frozen_timestamp() {
        let (node_addr, submits) = spawn_mock_node();
        // An all-ones network target: EVERY seal clears it, so the first share
        // is a Block and must be forwarded via sov_submitBlock.
        let template = share_template([0xff; 32]);
        let pool = test_pool(&node_addr, Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(3)}),
        )
        .expect("network-clearing share accepted");
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 1);
        {
            let recorded = submits.lock().unwrap();
            assert_eq!(recorded.len(), 1, "exactly one sov_submitBlock call");
            assert_eq!(recorded[0]["templateId"], json!(template.template_id));
            assert_eq!(recorded[0]["nonce"], json!(3u64));
            assert_eq!(
                recorded[0]["timestampMs"],
                json!(template.timestamp_ms),
                "the job's FROZEN timestamp must ride along"
            );
        }
        // Replaying the winner cannot double-submit the block to the node.
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(3)}),
        )
        .expect_err("replayed winner rejected");
        assert!(err.1.contains("duplicate"));
        assert_eq!(submits.lock().unwrap().len(), 1, "still exactly one submit");
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn job_book_evicts_oldest_jobs_beyond_capacity() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let first_job = job_id_of(&pool.new_job_for(&miner).unwrap());
        for _ in 0..MAX_LIVE_JOBS + 5 {
            pool.new_job_for(&miner).unwrap();
        }
        {
            let jobs = pool.jobs.lock().unwrap();
            assert_eq!(jobs.0.len(), MAX_LIVE_JOBS, "book capped at MAX_LIVE_JOBS");
            assert_eq!(jobs.1.len(), MAX_LIVE_JOBS);
            assert!(
                !jobs.0.contains_key(&first_job),
                "oldest job must have been evicted"
            );
        }
        // A submit against the evicted job is now stale — not a panic, not a credit.
        let (_, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": first_job, "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert!(msg.contains("stale"));
    }

    #[test]
    fn share_flood_triggers_an_immediate_vardiff_clamp_up_and_a_pushed_job() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, client) = test_miner(&pool, 1);
        // 16 distinct instant shares = 4 × max_adjust — the flood threshold in
        // `maybe_retarget`. Every submit needs its own job-independent nonce.
        for nonce in 0..16u64 {
            let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());
            handle_submit(
                &pool,
                &miner,
                &json!({"job_id": job_id, "nonce": nonce_wire(nonce)}),
            )
            .expect("diff-1 share accepted");
        }
        // The clamp is ×4 per retarget: difficulty 1 → 4, no further.
        assert_eq!(miner.difficulty.load(Ordering::Relaxed), 4);
        // And the retarget pushed a fresh job at the new difficulty to the
        // miner's socket, unprompted.
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).expect("pushed job line");
        let msg: Value = serde_json::from_str(line.trim()).expect("pushed job is JSON");
        assert_eq!(msg["method"], json!("job"));
        assert_eq!(
            msg["params"]["target"],
            json!(stratum_target_hex(4)),
            "pushed job carries the retargeted difficulty"
        );
    }

    #[test]
    fn a_dead_miner_socket_is_detected_and_pruned() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, client) = test_miner(&pool, 1);
        assert_eq!(pool.miners.lock().unwrap().len(), 1);
        // Kill the miner's end, then keep pushing until the OS surfaces the
        // failure (the first write after FIN can still land in the send buffer;
        // the RST that follows fails the next one).
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(10);
        while miner.alive.load(Ordering::Relaxed) {
            pool.push(&miner, &json!({"method": "job", "params": {"probe": true}}));
            assert!(
                Instant::now() < deadline,
                "push to a closed socket never failed"
            );
            thread::sleep(Duration::from_millis(25));
        }
        // broadcast_jobs prunes dead sessions from the roster.
        pool.broadcast_jobs();
        assert!(pool.miners.lock().unwrap().is_empty());
    }
}
