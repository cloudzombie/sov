//! # sov-rpc
//!
//! The JSON-RPC server a SOV node exposes — how miners, wallets, and the block
//! explorer talk to a running node (Phase 8, p8-i2). It is a real HTTP/1.1 +
//! JSON-RPC 2.0 server built on `std::net` only (no async runtime, no framework),
//! keeping the cross-platform, audit-light dependency promise the rest of the
//! chain makes.
//!
//! The node is shared as an `Arc<Mutex<`[`Node`]`>>`, so the same node a block-
//! production loop drives can also answer queries and accept transactions. Every
//! response is real chain state read from the live [`Blockchain`](sov_chain::Blockchain)
//! — nothing is mocked.
//!
//! ```no_run
//! use std::sync::{Arc, Mutex};
//! use sov_rpc::RpcServer;
//! # fn demo(node: sov_node::Node) -> std::io::Result<()> {
//! let node = Arc::new(Mutex::new(node));
//! let handle = RpcServer::new(node).start("127.0.0.1:8645", 4)?;
//! println!("RPC listening on {}", handle.local_addr());
//! // ... serve ...
//! handle.shutdown();
//! # Ok(())
//! # }
//! ```
//!
//! ## Methods
//! Reads: `sov_health`, `sov_version`, `sov_chainId`, `sov_getHeight`, `sov_getSupply`,
//! `sov_getAccount`, `sov_getBalance`, `sov_getNonce`, `sov_getBlockByHeight`,
//! `sov_getBlockByHash`, `sov_getBlockDigest`, `sov_getHead`,
//! `sov_getStateRoot`, `sov_getDifficulty`, `sov_estimateFee`,
//! `sov_getMempoolSize`, `sov_getPeerInfo` (live P2P/sync state),
//! `sov_getConfirmations`, `sov_isFinal`,
//! `sov_getMiners`, `sov_listTokens` (paged), `sov_getTokenInfo`,
//! `sov_getTokenBalances`, `sov_getHtlc`. SNS (Sovereign Name Service):
//! `sov_resolveName`, `sov_getName`, `sov_namesOf`, `sov_listNames` (paged).
//! NFTs: `sov_getNftClass`, `sov_getNft`, `sov_nftsOf`, `sov_listNfts` (paged).
//! `sov_getSupply` also reports shielded value + shielded % of supply.
//! Receipts (the recorded outcome of a transaction, incl. the exact failure
//! reason for an included-but-rejected tx): `sov_getReceipt` (by `txId`),
//! `sov_getBlockReceipts` (by `height`). Shielded pool + de-shield drain-limiter
//! state: `sov_getShieldedInfo`.
//! Write: `sov_submitTransaction`. Mining work-distribution (out-of-process /
//! Stratum): `sov_getBlockTemplate` (build + cache a candidate, return the header
//! preimage to grind) and `sov_submitBlock` (verify a submitted nonce's seal and
//! import through the validated path).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sov_chain::MiningCandidate;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::{Block, BlockHeader, SignedTransaction};

pub mod client;
pub use client::{RpcClient, RpcClientError};

pub mod daemon;
pub use daemon::{
    keystore_fingerprint_of, keystore_stored_fingerprint, BlockLog, ChainSpec, CheckpointSpec,
    Daemon, DaemonError, DaemonHandle, Keystore, KeystoreEntry, NodeConfig, PolicyPreset,
    SpecAccount,
};

pub mod p2p;
pub use p2p::{P2p, P2pConfig, P2pHandle};

pub mod sync_status;
pub use sync_status::SyncShared;

/// Maximum accepted request body (4 MiB) — large enough for a contract-deploy
/// transaction, small enough that a public bind cannot be memory-DoSed.
const MAX_RPC_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Maximum bytes for the HTTP request line and for any single header line. Bounds
/// each `read_line` allocation so a peer can't stream an endless no-newline line to
/// exhaust memory (a slowloris/OOM vector on a public bind) — the body cap above only
/// covers the body.
const MAX_REQUEST_LINE_BYTES: u64 = 16 * 1024;

/// Maximum number of header lines accepted, so the header section is bounded in count
/// as well as per-line size.
const MAX_REQUEST_HEADERS: usize = 64;

/// Maximum JSON-RPC batch length, so one request cannot fan out without bound.
const MAX_RPC_BATCH: usize = 100;

/// Per-IP RPC rate limit (token bucket). The RPC is bound on `0.0.0.0` so any state query
/// or `sov_submitTransaction` (which forces a hybrid PQ signature verify before it can be
/// rejected) is reachable by anyone; without a throttle an unauthenticated flood pins the
/// node's CPU and contends the node lock with mining/sync. These are generous for real
/// clients (20 req/s sustained, 100 burst) and loopback is exempt (local tooling).
const RPC_RATE_PER_SEC: f64 = 20.0;
const RPC_RATE_BURST: f64 = 100.0;
/// Prune the per-IP table once it exceeds this, dropping idle (full-bucket) entries so it
/// can't grow without bound across many distinct clients.
const RPC_RATE_MAX_TRACKED: usize = 8_192;

/// A per-IP token-bucket rate limiter for inbound RPC connections.
#[derive(Default)]
struct RpcRateLimiter {
    buckets:
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (f64, std::time::Instant)>>,
}

impl RpcRateLimiter {
    /// Spend one token for `ip`; returns `false` if the bucket is empty (refuse the
    /// connection). Loopback is always allowed.
    fn allow(&self, ip: std::net::IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let now = std::time::Instant::now();
        let mut b = self.buckets.lock().unwrap();
        if b.len() > RPC_RATE_MAX_TRACKED {
            // Drop idle entries (bucket refilled to full since last seen) to bound memory.
            b.retain(|_, (tokens, last)| {
                *tokens + now.duration_since(*last).as_secs_f64() * RPC_RATE_PER_SEC
                    < RPC_RATE_BURST
            });
        }
        let e = b.entry(ip).or_insert((RPC_RATE_BURST, now));
        let dt = now.duration_since(e.1).as_secs_f64();
        e.1 = now;
        e.0 = (e.0 + dt * RPC_RATE_PER_SEC).min(RPC_RATE_BURST);
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Hard cap on `sov_listTokens` page size, so a registry of any size yields a
/// bounded response (the client pages through with `offset`).
const MAX_TOKEN_PAGE: usize = 200;

/// How long a mining template cached by `sov_getBlockTemplate` remains submittable.
/// Generous relative to the 2.5-minute target block time, but short enough that a
/// stale template (built on a now-buried tip) expires rather than lingering: a miner
/// polls a fresh template each tip change, and an old one simply fails `sov_submitBlock`
/// with a clear "expired" error so the miner refetches.
const TEMPLATE_TTL: Duration = Duration::from_secs(120);

/// Maximum number of live templates cached at once. A template holds a full candidate
/// block (its transaction set), so the cache is bounded in count; the oldest is evicted
/// past this. Ample for many concurrent out-of-process miners polling one node.
const MAX_CACHED_TEMPLATES: usize = 64;

/// A bounded, short-TTL cache of built mining candidates, keyed by template id (the
/// unsealed header's hash). `sov_getBlockTemplate` inserts a candidate and returns its
/// id + the header preimage a miner grinds; `sov_submitBlock` looks the candidate back
/// up by id (or by `tx_root` for the whole-header submit form) so the full transaction
/// set never has to travel the wire. Purely a work-distribution convenience on top of
/// the existing template producer — it holds no consensus authority; every submitted
/// block is re-validated in full by the import path.
#[derive(Default)]
struct TemplateCache {
    inner: Mutex<HashMap<Hash, (Instant, MiningCandidate)>>,
}

impl TemplateCache {
    /// Cache `candidate` under `id`, first dropping expired entries and, if still at
    /// capacity, the single oldest — so the map is bounded in both age and count.
    fn insert(&self, id: Hash, candidate: MiningCandidate) {
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, (t, _)| now.duration_since(*t) < TEMPLATE_TTL);
        if m.len() >= MAX_CACHED_TEMPLATES {
            if let Some(oldest) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k) {
                m.remove(&oldest);
            }
        }
        m.insert(id, (now, candidate));
    }

    /// Fetch a still-live candidate by template id, expiring stale entries first.
    fn get(&self, id: &Hash) -> Option<MiningCandidate> {
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, (t, _)| now.duration_since(*t) < TEMPLATE_TTL);
        m.get(id).map(|(_, c)| c.clone())
    }

    /// Fetch a still-live candidate whose block commits to `tx_root` — the lookup the
    /// whole-header submit form uses (a caller that has the full header but not the
    /// template id it came from). Expires stale entries first.
    fn get_by_tx_root(&self, tx_root: &Hash) -> Option<MiningCandidate> {
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, (t, _)| now.duration_since(*t) < TEMPLATE_TTL);
        m.values()
            .find(|(_, c)| &c.block().header.tx_root == tx_root)
            .map(|(_, c)| c.clone())
    }
}

/// A JSON-RPC 2.0 error (code + message), mapped onto the standard code space.
#[derive(Debug, Clone)]
pub struct RpcError {
    /// JSON-RPC error code (`-32601` method not found, `-32602` invalid params,
    /// `-32603` internal, `-32000` server/application error, …).
    pub code: i64,
    /// Human-readable description.
    pub message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
        }
    }
    /// `-32601` — the method does not exist.
    fn method_not_found(m: &str) -> Self {
        Self::new(-32601, format!("method not found: {m}"))
    }
    /// `-32602` — the params are missing or malformed.
    fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, msg)
    }
    /// `-32000` — a valid request that the server could not fulfil.
    fn server(msg: impl Into<String>) -> Self {
        Self::new(-32000, msg)
    }
}

/// A JSON-RPC server bound to a shared [`Node`].
pub struct RpcServer {
    node: Arc<Mutex<Node>>,
    /// If set, a transaction accepted via `sov_submitTransaction` is GOSSIPED to
    /// peers over this transport, so it reaches every node's mempool and any miner
    /// can include it — not just the node it was submitted to. Without this a tx
    /// would live only on the originating node (the "only mined by its own client"
    /// bug); a real network must propagate transactions.
    gossip: Option<Arc<sov_network::TcpNode>>,
    /// Live peering/sync telemetry, so `sov_getPeerInfo` can report the real-time
    /// network picture (authenticated peers, best peer height, behind/IBD) over RPC.
    sync: Option<Arc<crate::SyncShared>>,
    /// If set, a block accepted via `sov_submitBlock` (out-of-process/Stratum mining) is
    /// appended + fsynced here for durability — exactly like a self-mined or peer block,
    /// never committed to memory alone (audit SOV-H001).
    block_log: Option<Arc<BlockLog>>,
}

/// The live network state the RPC handlers need beyond the node itself: the gossip
/// transport (broadcast accepted txs AND list connected peers) and the sync
/// telemetry. Threaded to the dispatch chain so `sov_submitTransaction` can gossip
/// and `sov_getPeerInfo` can expose peering/sync in real time.
#[derive(Clone, Default)]
struct RpcCtx {
    gossip: Option<Arc<sov_network::TcpNode>>,
    sync: Option<Arc<crate::SyncShared>>,
    /// Durable block log for `sov_submitBlock` (see [`RpcServer::block_log`]).
    block_log: Option<Arc<BlockLog>>,
    /// Server-side cache of built mining templates (`sov_getBlockTemplate` /
    /// `sov_submitBlock`), shared across worker threads via `Arc`.
    templates: Arc<TemplateCache>,
}

/// A running server: its bound address and the means to stop it gracefully.
pub struct RpcHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl RpcHandle {
    /// The address the server actually bound (useful when binding to port `0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Signal all workers to stop and wait for them to finish.
    pub fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for w in self.workers {
            let _ = w.join();
        }
    }
}

impl RpcServer {
    /// Wrap a shared node.
    pub fn new(node: Arc<Mutex<Node>>) -> Self {
        RpcServer {
            node,
            gossip: None,
            sync: None,
            block_log: None,
        }
    }

    /// Attach a P2P transport so accepted transactions are gossiped to peers (so any
    /// node can mine them, not just the one they were submitted to) and connected
    /// peers can be reported via `sov_getPeerInfo`.
    pub fn with_gossip(mut self, gossip: Option<Arc<sov_network::TcpNode>>) -> Self {
        self.gossip = gossip;
        self
    }

    /// Attach the sync telemetry so `sov_getPeerInfo` reports authenticated peers,
    /// the best peer height, and IBD/behind status in real time.
    pub fn with_sync_status(mut self, sync: Option<Arc<crate::SyncShared>>) -> Self {
        self.sync = sync;
        self
    }

    /// Attach the durable block log so a block accepted via `sov_submitBlock` is
    /// appended + fsynced (fail-closed) exactly like a self-mined or peer block — the
    /// out-of-process/Stratum mining path is then as durable as the in-process one.
    pub fn with_block_log(mut self, block_log: Arc<BlockLog>) -> Self {
        self.block_log = Some(block_log);
        self
    }

    /// Bind `addr` and start `workers` accept threads. Returns immediately with a
    /// [`RpcHandle`]; the server runs until [`RpcHandle::shutdown`].
    pub fn start(self, addr: impl ToSocketAddrs, workers: usize) -> io::Result<RpcHandle> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        // Non-blocking accept so workers can observe the shutdown flag instead of
        // parking forever in `accept`.
        listener.set_nonblocking(true)?;
        let listener = Arc::new(listener);
        let shutdown = Arc::new(AtomicBool::new(false));

        let ctx = RpcCtx {
            gossip: self.gossip.clone(),
            sync: self.sync.clone(),
            block_log: self.block_log.clone(),
            templates: Arc::new(TemplateCache::default()),
        };
        let limiter = Arc::new(RpcRateLimiter::default());
        let mut handles = Vec::new();
        for _ in 0..workers.max(1) {
            let listener = Arc::clone(&listener);
            let shutdown = Arc::clone(&shutdown);
            let node = Arc::clone(&self.node);
            let ctx = ctx.clone();
            let limiter = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                while !shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            // Throttle per source IP before doing any work (a rejected
                            // request still costs a PQ verify, so refuse the flood early).
                            if !limiter.allow(peer.ip()) {
                                continue;
                            }
                            let _ = handle_connection(stream, &node, &ctx);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            }));
        }
        Ok(RpcHandle {
            addr: local,
            shutdown,
            workers: handles,
        })
    }
}

/// Read one HTTP/1.1 request: returns `(method, path, body)`, or `None` if the
/// peer closed without sending anything.
fn read_request(stream: &TcpStream) -> io::Result<Option<(String, String, Vec<u8>)>> {
    let mut reader = BufReader::new(stream.try_clone()?);

    // Reject a too-long request/header line at the source: a header read that fills the
    // cap without a terminating newline is oversized (or a slowloris) — refuse it
    // instead of growing the buffer without bound. (`Take<&mut BufRead>` is `BufRead`.)
    let reject_oversized = |stream: &TcpStream| -> io::Result<Option<(String, String, Vec<u8>)>> {
        if let Ok(mut s) = stream.try_clone() {
            let _ = write_response(
                &mut s,
                "431 Request Header Fields Too Large",
                br#"{"error":"request header exceeds limit"}"#,
            );
        }
        Ok(None)
    };

    let mut request_line = String::new();
    let n = (&mut reader)
        .take(MAX_REQUEST_LINE_BYTES)
        .read_line(&mut request_line)?;
    if n == 0 {
        return Ok(None);
    }
    if !request_line.ends_with('\n') {
        return reject_oversized(stream); // no newline within the cap ⇒ oversized
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    let mut headers = 0usize;
    loop {
        if headers >= MAX_REQUEST_HEADERS {
            return reject_oversized(stream);
        }
        let mut line = String::new();
        let n = (&mut reader)
            .take(MAX_REQUEST_LINE_BYTES)
            .read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if !line.ends_with('\n') {
            return reject_oversized(stream); // header line exceeded the cap
        }
        headers += 1;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break; // end of headers
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    if content_length > MAX_RPC_BODY_BYTES {
        // Refuse oversized bodies before allocating — a public RPC must not be
        // memory-DoSable by a large Content-Length.
        let mut s = stream.try_clone()?;
        let _ = write_response(
            &mut s,
            "413 Payload Too Large",
            br#"{"error":"request body exceeds limit"}"#,
        );
        return Ok(None);
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some((method, path, body)))
}

/// Write an HTTP/1.1 response with a JSON body and `Connection: close`.
fn write_response(stream: &mut TcpStream, status: &str, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Handle a single connection: one request, one response, then close.
fn handle_connection(
    mut stream: TcpStream,
    node: &Arc<Mutex<Node>>,
    ctx: &RpcCtx,
) -> io::Result<()> {
    // The listener is non-blocking; accepted sockets must be blocking for the
    // timeout-bounded reads/writes below to behave.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let Some((method, path, body)) = read_request(&stream)? else {
        return Ok(());
    };

    let (status, payload): (&str, Vec<u8>) = if method == "GET" && path == "/health" {
        (
            "200 OK",
            serde_json::to_vec(&health(node)).unwrap_or_default(),
        )
    } else if method == "POST" {
        ("200 OK", dispatch(node, ctx, &body))
    } else {
        (
            "405 Method Not Allowed",
            br#"{"error":"only POST (JSON-RPC) and GET /health are supported"}"#.to_vec(),
        )
    };
    write_response(&mut stream, status, &payload)
}

fn health(node: &Arc<Mutex<Node>>) -> Value {
    match node.lock() {
        Ok(n) => {
            json!({"ok": true, "chainId": n.chain().chain_id(), "height": n.chain().height(), "mempool": n.mempool_len()})
        }
        Err(_) => json!({"ok": false, "error": "node lock poisoned"}),
    }
}

/// Parse the request body and produce the JSON-RPC response bytes (single or batch).
fn dispatch(node: &Arc<Mutex<Node>>, ctx: &RpcCtx, body: &[u8]) -> Vec<u8> {
    let parsed: Result<Value, _> = serde_json::from_slice(body);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_vec(&error_envelope(Value::Null, -32700, "Parse error"))
                .unwrap_or_default()
        }
    };

    let response = match value {
        Value::Array(reqs) if reqs.len() > MAX_RPC_BATCH => {
            error_envelope(Value::Null, -32600, "Invalid Request (batch too large)")
        }
        Value::Array(reqs) if !reqs.is_empty() => {
            Value::Array(reqs.iter().map(|r| handle_one(node, ctx, r)).collect())
        }
        Value::Array(_) => error_envelope(Value::Null, -32600, "Invalid Request (empty batch)"),
        single => handle_one(node, ctx, &single),
    };
    serde_json::to_vec(&response).unwrap_or_default()
}

fn error_envelope(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": id})
}

/// Dispatch one JSON-RPC request object into a full response object.
fn handle_one(node: &Arc<Mutex<Node>>, ctx: &RpcCtx, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return error_envelope(id, -32600, "Invalid Request (missing method)");
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    match call(node, ctx, method, &params) {
        Ok(result) => json!({"jsonrpc": "2.0", "result": result, "id": id}),
        Err(e) => {
            json!({"jsonrpc": "2.0", "error": {"code": e.code, "message": e.message}, "id": id})
        }
    }
}

// ---- parameter helpers ----------------------------------------------------

fn param_account(params: &Value) -> Result<AccountId, RpcError> {
    let s = params
        .get("account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing string param `account`"))?;
    AccountId::new(s).map_err(|e| RpcError::invalid_params(format!("invalid account: {e}")))
}

fn param_hash(params: &Value) -> Result<Hash, RpcError> {
    let s = params
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing string param `hash`"))?;
    Hash::from_hex(s).map_err(|e| RpcError::invalid_params(format!("invalid hash: {e}")))
}

fn param_tx_id(params: &Value) -> Result<Hash, RpcError> {
    let s = params
        .get("txId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing string param `txId`"))?;
    Hash::from_hex(s).map_err(|e| RpcError::invalid_params(format!("invalid txId: {e}")))
}

fn param_name(params: &Value) -> Result<String, RpcError> {
    params
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| RpcError::invalid_params("missing string param `name`"))
}

fn param_collection(params: &Value) -> Result<Hash, RpcError> {
    let s = params
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing string param `collection`"))?;
    Hash::from_hex(s).map_err(|e| RpcError::invalid_params(format!("invalid collection: {e}")))
}

fn param_token_id(params: &Value) -> Result<Vec<u8>, RpcError> {
    let s = params
        .get("tokenId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing string param `tokenId`"))?;
    hex::decode(s).map_err(|e| RpcError::invalid_params(format!("invalid tokenId hex: {e}")))
}

/// Parse a required `u64` param that may be given either as a JSON number or as a hex
/// string (`"0x…"` or bare hex) — the flexible form a miner sends a 64-bit nonce in.
fn param_u64_flexible(params: &Value, key: &str) -> Result<u64, RpcError> {
    match params.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| RpcError::invalid_params(format!("`{key}` must be a u64"))),
        Some(Value::String(s)) => {
            let t = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(t, 16)
                .map_err(|e| RpcError::invalid_params(format!("invalid `{key}` hex: {e}")))
        }
        _ => Err(RpcError::invalid_params(format!(
            "missing `{key}` (u64 or hex string)"
        ))),
    }
}

/// Like [`param_u64_flexible`], but the param is optional: `Ok(None)` when absent,
/// `Err` only when present-but-malformed.
fn opt_u64_flexible(params: &Value, key: &str) -> Result<Option<u64>, RpcError> {
    if params.get(key).map(Value::is_null).unwrap_or(true) {
        Ok(None)
    } else {
        param_u64_flexible(params, key).map(Some)
    }
}

/// Bound a list response with `offset`/`limit` so a read RPC can never return an
/// unbounded array (memory/DoS-safe). `limit` defaults to and is hard-capped at
/// [`MAX_TOKEN_PAGE`]; `offset` skips that many items. Applied uniformly to every
/// list-returning read, so callers can page through with `offset`.
fn paged(params: &Value, items: Vec<Value>) -> Vec<Value> {
    let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit = (params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_TOKEN_PAGE as u64) as usize)
        .clamp(1, MAX_TOKEN_PAGE);
    items.into_iter().skip(offset).take(limit).collect()
}

/// Render an NFT item as JSON. `token_id` is shown as hex plus, when it is valid
/// UTF-8 (e.g. an SNS name), a readable `tokenText`.
fn nft_json(
    collection: &Hash,
    token_id: &[u8],
    owner: &str,
    metadata: &[u8],
    minted: u64,
) -> Value {
    json!({
        "collection": collection.to_hex(),
        "tokenId": hex::encode(token_id),
        "tokenText": std::str::from_utf8(token_id).ok(),
        "owner": owner,
        "metadata": hex::encode(metadata),
        "mintedHeight": minted,
    })
}

fn to_value<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

// ---- method dispatch ------------------------------------------------------

fn call(
    node: &Arc<Mutex<Node>>,
    ctx: &RpcCtx,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    // A single lock serves the whole call: queries borrow the node immutably,
    // `sov_submitTransaction` mutably. Handlers are short, so contention is low.
    let mut node = node
        .lock()
        .map_err(|_| RpcError::server("node lock poisoned"))?;

    match method {
        "sov_health" => {
            let c = node.chain();
            Ok(
                json!({"ok": true, "chainId": c.chain_id(), "height": c.height(), "mempool": node.mempool_len()}),
            )
        }
        "sov_version" => Ok(json!({ "version": env!("SOV_VERSION") })),
        "sov_chainId" => Ok(json!(node.chain().chain_id())),
        "sov_getHeight" => Ok(json!(node.chain().height())),
        "sov_getSupply" => {
            let l = node.chain().ledger();
            let total = l
                .total_supply()
                .ok_or_else(|| RpcError::server("supply overflow"))?;
            let shielded = l.shielded_value();
            // Zcash-style "shielded supply": the fraction of the circulating
            // supply currently held in the shielded pool. SOV has no pre-mine, so
            // total supply IS the circulating supply (every coin was mined), and
            // total_supply already counts shielded value — so this is the share of
            // ALL coins that are shielded, exactly as Zcash reports it.
            let shielded_percent = if total.grains() == 0 {
                0.0
            } else {
                (shielded.grains() as f64 / total.grains() as f64) * 100.0
            };
            Ok(json!({
                "total": to_value(total),
                "circulating": to_value(total),
                "mined": to_value(l.mined_emitted()),
                "shielded": to_value(shielded),
                "transparent": to_value(total.checked_sub(shielded).unwrap_or(total)),
                "shieldedPercent": shielded_percent,
            }))
        }
        "sov_getAccount" => {
            let id = param_account(params)?;
            let ledger = node.chain().ledger();
            // Honest absence: an unfunded account is `null`, not a fabricated zero.
            if ledger.exists(&id) {
                Ok(to_value(ledger.account(&id)))
            } else {
                Ok(Value::Null)
            }
        }
        "sov_getVault" => {
            // The account's xUSD CDP vault, priced at the current oracle: locked
            // XUS collateral, xUSD debt, the health ratio, and how much MORE xUSD
            // can be safely minted right now. All real chain state — the webapp
            // reads this to show a mint limit and liquidation price honestly.
            let id = param_account(params)?;
            let ledger = node.chain().ledger();
            let vault = ledger.vault(&id);
            let price = ledger.oracle_price();
            let xusd = sov_state::vault::xusd_asset_id();
            let xusd_balance = ledger.token_balance(&xusd, &id);
            let max_debt = sov_state::vault::max_debt(vault.collateral, price).unwrap_or(0);
            let mintable = max_debt.saturating_sub(vault.debt.grains());
            let ratio = sov_state::vault::collateral_ratio_pct(vault.collateral, vault.debt, price);
            Ok(json!({
                "account": id,
                "collateralGrains": vault.collateral,
                "debtGrains": vault.debt,
                "xusdBalanceGrains": xusd_balance,
                "oraclePriceUsd1e8": price.to_string(),
                "minRatioPct": sov_state::vault::MIN_COLLATERAL_RATIO_PCT.to_string(),
                "maxDebtGrains": max_debt.to_string(),
                "mintableGrains": mintable.to_string(),
                "collateralRatioPct": ratio.map(|r| r.to_string()),
            }))
        }
        "sov_getOracle" => {
            // The xUSD system's price + parameters. `seeded` is true while the
            // honest $1.00 launch price still stands (no signed feed update yet).
            let ledger = node.chain().ledger();
            Ok(json!({
                "priceUsd1e8": ledger.oracle_price().to_string(),
                "seeded": ledger.oracle_is_seeded(),
                "minRatioPct": sov_state::vault::MIN_COLLATERAL_RATIO_PCT.to_string(),
                "xusdAsset": sov_state::vault::xusd_asset_id(),
                "oracleAccount": sov_state::vault::ORACLE_ACCOUNT,
            }))
        }
        "sov_getMultisigProposals" => {
            // Pending on-chain multisig proposals drawing from `account`, with each
            // spend decoded to a plain summary so a wallet can render an approval
            // inbox ("send N XUS to X — k of m") without understanding any codes.
            let account = param_account(params)?;
            let ledger = node.chain().ledger();
            let policy = ledger.multisig_of(&account);
            let threshold = policy.map(|p| p.threshold).unwrap_or(0);
            let signer_count = policy.map(|p| p.signers.len()).unwrap_or(0);
            let out: Vec<Value> = ledger
                .proposals_for(&account)
                .into_iter()
                .map(|(pid, prop)| {
                    let action = match borsh::from_slice::<sov_types::Action>(&prop.action) {
                        Ok(sov_types::Action::Transfer { to, amount }) => json!({
                            "type": "transfer",
                            "to": to.as_str(),
                            "amount": amount.grains().to_string(),
                        }),
                        _ => Value::Null,
                    };
                    json!({
                        "id": to_value(pid),
                        "account": prop.account.as_str(),
                        "approvers": prop.approvers,
                        "approved": prop.approvers.len(),
                        "threshold": threshold,
                        "signers": signer_count,
                        "action": action,
                    })
                })
                .collect();
            Ok(Value::Array(out))
        }
        "sov_getBalance" => {
            let id = param_account(params)?;
            Ok(to_value(node.chain().ledger().account(&id).balance))
        }
        "sov_getNonce" => {
            let id = param_account(params)?;
            Ok(json!(node.chain().ledger().account(&id).nonce))
        }
        "sov_getBlockByHeight" => {
            let h = params
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::invalid_params("missing integer param `height`"))?;
            Ok(node
                .chain()
                .block_by_height(h)
                .map_or(Value::Null, to_value))
        }
        "sov_getBlockByHash" => {
            let hash = param_hash(params)?;
            Ok(node
                .chain()
                .block_by_hash(&hash)
                .map_or(Value::Null, to_value))
        }
        "sov_getReceipt" => {
            // The recorded outcome of a transaction by its id: success, or the
            // exact failure reason for a transaction that was included but did not
            // apply (e.g. "de-shield rate limit exceeded for this window"). This is
            // what makes an on-chain failure visible instead of being inferred from
            // balances — `null` if no active block contains the transaction.
            let tx_id = param_tx_id(params)?;
            Ok(node
                .chain()
                .receipt(&tx_id)
                .map_or(Value::Null, |(height, r)| {
                    let mut v = to_value(r);
                    if let Value::Object(map) = &mut v {
                        map.insert("height".into(), json!(height));
                    }
                    v
                }))
        }
        "sov_getBlockReceipts" => {
            // Every transaction's receipt in the active block at `height`, in
            // transaction order: `null` if the height is beyond the chain, `[]` for
            // a block with no transactions.
            let h = params
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::invalid_params("missing integer param `height`"))?;
            Ok(node
                .chain()
                .receipts_at_height(h)
                .map_or(Value::Null, |rs| {
                    json!(rs.iter().map(to_value).collect::<Vec<_>>())
                }))
        }
        "sov_getShieldedInfo" => {
            // The shielded pool's value plus the live de-shield drain-limiter state,
            // so a wallet can show how much can be de-shielded right now and when the
            // window resets — making the circuit breaker transparent instead of a
            // silent transaction failure. The turnstile (pool value can never go
            // negative) is the Zcash-grade integrity guarantee; this limiter is an
            // additional, fully-visible circuit breaker on top of it.
            let c = node.chain();
            let l = c.ledger();
            let policy = c.mining_policy();
            let height = c.height();
            let (start, spent) = l.deshield_window();
            let window_blocks = policy.deshield_window_blocks;
            let limit = policy.deshield_limit_grains;
            // The window resets the next time a de-shield lands at/after this height.
            let elapsed = window_blocks != 0 && height.saturating_sub(start) >= window_blocks;
            let spent_now = if elapsed { 0u128 } else { spent.grains() };
            let deshieldable_now = if window_blocks == 0 {
                l.shielded_value().grains()
            } else {
                limit
                    .saturating_sub(spent_now)
                    .min(l.shielded_value().grains())
            };
            Ok(json!({
                "poolValue": to_value(l.shielded_value()),
                "deshieldLimitGrains": limit.to_string(),
                "deshieldWindowBlocks": window_blocks,
                "windowStartHeight": start,
                "windowSpentGrains": spent_now.to_string(),
                "deshieldableNowGrains": deshieldable_now.to_string(),
                "windowResetsAtHeight": if window_blocks == 0 { 0 } else { start.saturating_add(window_blocks) },
                "height": height,
            }))
        }
        "sov_getBlockDigest" => {
            // A block's id (its header hash) and its transactions' canonical ids are
            // computed from content, not stored in the serialized block — so the
            // explorer fetches them explicitly, in one round-trip per block.
            let h = params
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::invalid_params("missing integer param `height`"))?;
            let chain = node.chain();
            Ok(chain.block_by_height(h).map_or(Value::Null, |b| {
                // The COINBASE: every block's issuance, surfaced from the
                // authoritative source. The ENTIRE height-keyed subsidy goes to the
                // miner (the header's proposer) — no tax, nothing burned (pure
                // Nakamoto). Genesis (and any post-budget block) mints nothing.
                let reward = chain.coinbase_reward_at(h).grains();
                let coinbase = if reward == 0 {
                    Value::Null
                } else {
                    json!({
                        "reward": reward.to_string(),
                        "recipients": [
                            { "account": b.header.proposer.as_str(), "amount": reward.to_string(), "role": "miner" },
                        ],
                    })
                };
                json!({
                    "hash": to_value(b.hash()),
                    "prevHash": to_value(b.header.prev_hash),
                    "stateRoot": to_value(b.header.state_root),
                    "timestampMs": b.header.timestamp_ms,
                    "nonce": b.header.nonce,
                    "bits": b.header.bits,
                    "txIds": b
                        .transactions
                        .iter()
                        .map(|stx| to_value(stx.id()))
                        .collect::<Vec<_>>(),
                    "coinbase": coinbase,
                })
            }))
        }
        "sov_getHead" => Ok(to_value(node.chain().head())),
        "sov_getStateRoot" => Ok(json!(node.chain().ledger().state_root().to_hex())),
        "sov_getDifficulty" => {
            let c = node.chain();
            // The proof-of-work seal in force (SHA-256d on dev/test, RandomX on
            // mainnet) and the next-block difficulty, so a client can show exactly
            // how work is being proven without guessing from the chain id.
            Ok(json!({
                "sha256d": c.sha256d_difficulty().0.to_string(),
                "algo": format!("{:?}", c.mining_policy().pow_algo),
                "targetBlockMs": c.mining_policy().target_block_ms,
                // Measured network hash rate in hashes/second (Bitcoin's
                // getnetworkhashps), or null until there are enough blocks to measure.
                "hashrate": c.estimate_hashrate(),
            }))
        }
        "sov_estimateFee" => {
            // The EXACT fee the runtime would charge for one of the wallet's send
            // routes, using the same gas schedule (`sov_runtime::gas`) and the node's
            // live gas price — 0 on a fee-free testnet, the real cost once fees are on
            // (mainnet). The station shows this (and the resulting balance) in the
            // send-review modal so the spender sees the full cost before broadcast.
            use sov_runtime::gas::{
                envelope_gas, hybrid_envelope_gas, BOOKKEEPING_GAS, INTRINSIC_GAS,
                SHIELDED_VERIFY_GAS,
            };
            let kind = params
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("transfer");
            // Payload-independent intrinsic gas per route — mirrors `gas_for` (pinned by
            // `gas::tests::wallet_route_intrinsic_gas_is_stable`).
            let action_gas = match kind {
                "transfer" => INTRINSIC_GAS,
                "tokenTransfer" => INTRINSIC_GAS + BOOKKEEPING_GAS,
                "shielded" => INTRINSIC_GAS + SHIELDED_VERIFY_GAS,
                other => {
                    return Err(RpcError::invalid_params(format!(
                        "unknown action kind `{other}` (transfer | tokenTransfer | shielded)"
                    )))
                }
            };
            // Signature-envelope surcharge: exact for the signer's key when supplied,
            // else the hybrid (post-quantum) envelope every sov-station wallet uses.
            let envelope = match params.get("publicKey").and_then(Value::as_str) {
                Some(pk_hex) => {
                    let pk: sov_crypto::PublicKey =
                        serde_json::from_value(Value::String(pk_hex.to_string())).map_err(|e| {
                            RpcError::invalid_params(format!("invalid publicKey: {e}"))
                        })?;
                    envelope_gas(&pk)
                }
                None => hybrid_envelope_gas(),
            };
            let gas_used = action_gas + envelope;
            let gas_price = node.chain().mining_policy().gas_price.grains();
            let fee = u128::from(gas_used).saturating_mul(gas_price);
            Ok(json!({
                "kind": kind,
                "gasUsed": gas_used,
                "gasPriceGrains": gas_price.to_string(),
                "feeGrains": fee.to_string(),
            }))
        }
        "sov_getMintReward" => Ok(to_value(node.chain().mint_reward())),
        "sov_getMempoolSize" => Ok(json!(node.mempool_len())),
        // LIVE networking state — so an operator (or `curl`) can see EXACTLY why two
        // nodes do or don't see each other, without reading GUI logs. `chainId` +
        // `genesisHash` are what peers handshake on (a mismatch ⇒ they can NEVER
        // authenticate); `tcpLinks` is raw connections, `peers` is AUTHENTICATED peers,
        // `connectedPeers` their addresses. peers 0 + connectedPeers [] ⇒ no link
        // (check the seed peer / firewall); tcpLinks > 0 but peers 0 ⇒ handshake/
        // genesis mismatch. `behindBlocks`/`syncing` show catch-up state.
        "sov_getPeerInfo" => {
            let c = node.chain();
            let genesis = c
                .block_by_height(0)
                .map(|b| b.hash().to_hex())
                .unwrap_or_default();
            let (peers, best, behind) = ctx
                .sync
                .as_ref()
                .map(|s| (s.authed_peers(), s.best_peer_height(), s.behind_blocks()))
                .unwrap_or((0, 0, 0));
            // Real per-peer software versions (v0.1.86 Version handshake): the network is
            // now version-aware, so an operator sees exactly what each peer is running.
            let peer_versions: Vec<serde_json::Value> = ctx
                .sync
                .as_ref()
                .map(|s| {
                    s.peer_agents()
                        .into_iter()
                        .map(|(addr, ver, agent)| {
                            json!({ "addr": addr, "protocol": ver, "agent": agent })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let connected: Vec<String> = ctx
                .gossip
                .as_ref()
                .map(|g| g.connected_peers().iter().map(|a| a.to_string()).collect())
                .unwrap_or_default();
            Ok(json!({
                "chainId": c.chain_id(),
                "version": env!("SOV_VERSION"),
                "genesisHash": genesis,
                "height": c.height(),
                "p2pEnabled": ctx.gossip.is_some(),
                "listenAddr": ctx.gossip.as_ref().map(|g| g.local_addr().to_string()),
                "tcpLinks": ctx.gossip.as_ref().map(|g| g.peer_count()).unwrap_or(0),
                "peers": peers,
                "connectedPeers": connected,
                "peerVersions": peer_versions,
                "protocolVersion": sov_network::PROTOCOL_VERSION,
                "bestPeerHeight": best,
                "behindBlocks": behind,
                "syncing": behind > 0,
            }))
        }
        // Nakamoto finality: confirmation depth in the heaviest-work chain.
        "sov_getConfirmations" => {
            let hash = param_hash(params)?;
            Ok(json!(node.chain().confirmations(&hash)))
        }
        "sov_isFinal" => {
            let hash = param_hash(params)?;
            Ok(json!(node.chain().is_final(&hash)))
        }
        "sov_getMiners" => {
            let miners: Vec<Value> = node
                .chain()
                .miner_registry()
                .iter()
                .map(|m| {
                    json!({
                        "account": m.account.as_str(),
                        "firstSeenHeight": m.first_seen_height,
                        "firstSeenTimestampMs": m.first_seen_timestamp_ms,
                        "blocksMined": m.blocks_mined,
                        "lastSeenHeight": m.last_seen_height,
                    })
                })
                .collect();
            Ok(Value::Array(paged(params, miners)))
        }
        // Miner-signaled governance (BIP-9/BIP-8): the live state of every deployment,
        // derived from committed header signals at the current height — the same
        // evaluation that gates real activation. Makes hashpower-voted upgrades
        // observable so an operator can watch a deployment move Defined→…→Active.
        "sov_getDeployments" => {
            let deployments: Vec<Value> = node
                .chain()
                .deployment_states()
                .iter()
                .map(|d| {
                    json!({
                        "name": d.name,
                        "bit": d.bit,
                        "state": format!("{:?}", d.state),
                        "startHeight": d.start_height,
                        "timeoutHeight": d.timeout_height,
                        "period": d.period,
                        "lockinontimeout": d.lockinontimeout,
                    })
                })
                .collect();
            Ok(json!({
                "height": node.chain().height(),
                "deployments": deployments,
            }))
        }
        "sov_getSigningDomain" => {
            // The network signing domain a client should bind a NEW transaction or
            // intent signature to, resolved at the next height (the earliest a
            // just-submitted tx could be mined). While the miner-signaled
            // `tx-domain` hard fork is dormant this is `active:false` / null, and
            // clients sign the legacy (un-bound) way — byte-identical to pre-fork.
            // Once the fork is active it returns this chain's {chainId, genesis},
            // and clients must `sign_in(domain)` or their transactions are rejected.
            let next_height = node.chain().height() + 1;
            match node.chain().resolved_tx_domain(next_height) {
                Some(domain) => Ok(json!({
                    "active": true,
                    "height": next_height,
                    "chainId": domain.chain_id(),
                    "genesis": domain.genesis().to_hex(),
                    "txTag": "sov:tx:v1",
                    "intentTag": "sov:intent:v1",
                })),
                None => Ok(json!({
                    "active": false,
                    "height": next_height,
                    "chainId": Value::Null,
                    "genesis": Value::Null,
                })),
            }
        }
        "sov_submitTransaction" => {
            let stx: SignedTransaction = serde_json::from_value(params.clone())
                .map_err(|e| RpcError::invalid_params(format!("invalid SignedTransaction: {e}")))?;
            let tx_id = stx.id();
            node.submit(stx.clone())
                .map_err(|e| RpcError::server(format!("rejected: {e}")))?;
            // GOSSIP the accepted tx to peers so it reaches EVERY node's mempool and any
            // miner can include it — not just the node it was submitted to. Release the
            // node lock first (mirror the block-gossip path: never do network I/O under
            // the lock). A node that receives it adds it to its mempool and re-floods.
            drop(node);
            if let Some(g) = &ctx.gossip {
                g.broadcast(&sov_network::NetMessage::NewTransaction(stx));
            }
            Ok(json!({"accepted": true, "txId": tx_id.to_hex()}))
        }
        // A PAGE of the token registry — never the whole set, so the response
        // stays bounded no matter how many assets exist. Params: `offset`
        // (default 0) and `limit` (default 100, hard-capped at MAX_TOKEN_PAGE).
        // Returns `{ tokens: [...], offset, limit, hasMore }`.
        "sov_listTokens" => {
            let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let limit = (params.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize)
                .clamp(1, MAX_TOKEN_PAGE);
            let ledger = node.chain().ledger();
            // Take one extra to learn whether another page exists, without scanning
            // (or serializing) the entire registry.
            let mut page: Vec<Value> = ledger
                .token_iter()
                .skip(offset)
                .take(limit + 1)
                .map(|(asset, info)| {
                    json!({
                        "asset": asset.to_hex(),
                        "issuer": info.issuer.as_str(),
                        "symbol": info.symbol,
                        "supply": info.supply().unwrap_or(Balance::ZERO).grains().to_string(),
                        "issued": info.issued.grains().to_string(),
                        "burned": info.burned.grains().to_string(),
                    })
                })
                .collect();
            let has_more = page.len() > limit;
            page.truncate(limit);
            Ok(json!({
                "tokens": page,
                "offset": offset,
                "limit": limit,
                "hasMore": has_more,
            }))
        }
        // A single asset by id — O(1), so it scales regardless of registry size.
        // `null` if no such asset.
        "sov_getTokenInfo" => {
            let asset = param_hash(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger.token(&asset).map_or(Value::Null, |info| {
                json!({
                    "asset": asset.to_hex(),
                    "issuer": info.issuer.as_str(),
                    "symbol": info.symbol,
                    "supply": info.supply().unwrap_or(Balance::ZERO).grains().to_string(),
                    "issued": info.issued.grains().to_string(),
                    "burned": info.burned.grains().to_string(),
                })
            }))
        }
        // The token balances an account holds (every asset with a nonzero balance).
        "sov_getTokenBalances" => {
            let id = param_account(params)?;
            let ledger = node.chain().ledger();
            let rows: Vec<Value> = ledger
                .token_balance_iter()
                .filter(|((_, holder), _)| holder == &id)
                .map(|((asset, _), bal)| {
                    let symbol = ledger
                        .token(asset)
                        .map(|t| t.symbol.clone())
                        .unwrap_or_default();
                    json!({
                        "asset": asset.to_hex(),
                        "symbol": symbol,
                        "balance": bal.grains().to_string(),
                    })
                })
                .collect();
            Ok(Value::Array(paged(params, rows)))
        }
        // A hash-time-locked escrow by id (the `HtlcLock` tx id). `null` if absent
        // (never opened, or already claimed/refunded).
        "sov_getHtlc" => {
            let id = param_hash(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger.htlc(&id).map_or(Value::Null, |h| {
                json!({
                    "locker": h.locker.as_str(),
                    "recipient": h.recipient.as_str(),
                    "amount": h.amount.grains().to_string(),
                    "hashlock": hex::encode(h.hashlock.as_bytes()),
                    "timeoutHeight": h.timeout_height,
                })
            }))
        }
        // Name registry (ENS/SNS): resolve a name to the account it points to.
        "sov_resolveName" => {
            let name = param_name(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger
                .resolve_name(&name)
                .map_or(Value::Null, |a| json!(a.as_str())))
        }
        // The full registry record for a name (owner + registration height).
        "sov_getName" => {
            let name = param_name(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger.name_record(&name).map_or(Value::Null, |r| {
                json!({
                    "name": name,
                    "owner": r.owner.as_str(),
                    "registeredHeight": r.registered_height,
                })
            }))
        }
        // Reverse lookup: names owned by (resolving to) an account (bounded/paged).
        "sov_namesOf" => {
            let id = param_account(params)?;
            let names: Vec<Value> = node
                .chain()
                .ledger()
                .names_owned_by(&id)
                .into_iter()
                .map(Value::String)
                .collect();
            Ok(Value::Array(paged(params, names)))
        }
        // A PAGE of the Sovereign Name Service registry, bounded like the token
        // listing. Params: `offset` (default 0), `limit` (default 100, capped at
        // MAX_TOKEN_PAGE). Returns `{ names: [...], offset, limit, hasMore }`.
        "sov_listNames" => {
            let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let limit = (params.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize)
                .clamp(1, MAX_TOKEN_PAGE);
            let ledger = node.chain().ledger();
            let mut page: Vec<Value> = ledger
                .names_iter()
                .skip(offset)
                .take(limit + 1)
                .map(|(name, rec)| {
                    json!({
                        "name": name,
                        "owner": rec.owner.as_str(),
                        "registeredHeight": rec.registered_height,
                    })
                })
                .collect();
            let has_more = page.len() > limit;
            page.truncate(limit);
            Ok(json!({
                "names": page,
                "offset": offset,
                "limit": limit,
                "hasMore": has_more,
                "total": ledger.name_count(),
            }))
        }
        // ── Non-fungible tokens (NFTs) ────────────────────────────────────────
        // An NFT collection by id (hex). `null` if it does not exist.
        "sov_getNftClass" => {
            let collection = param_collection(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger.nft_class(&collection).map_or(Value::Null, |c| {
                json!({
                    "collection": collection.to_hex(),
                    "issuer": c.issuer.as_str(),
                    "symbol": c.symbol,
                    "minted": c.minted,
                })
            }))
        }
        // A single NFT item by (collection hex, tokenId hex). `null` if absent.
        "sov_getNft" => {
            let collection = param_collection(params)?;
            let token_id = param_token_id(params)?;
            let ledger = node.chain().ledger();
            Ok(ledger.nft(&collection, &token_id).map_or(Value::Null, |t| {
                nft_json(
                    &collection,
                    &token_id,
                    t.owner.as_str(),
                    &t.metadata,
                    t.minted_height,
                )
            }))
        }
        // Reverse lookup: every NFT item owned by an account. Each item is tagged
        // `isSns` (it lives in the reserved SNS collection — i.e. it is a name) and
        // carries a readable `tokenText` when the token id is UTF-8 (e.g. a name).
        "sov_nftsOf" => {
            let id = param_account(params)?;
            let ledger = node.chain().ledger();
            let sns = ledger.sns_collection();
            let items: Vec<Value> = ledger
                .nfts_owned_by(&id)
                .into_iter()
                .map(|(collection, token_id)| {
                    json!({
                        "collection": collection.to_hex(),
                        "tokenId": hex::encode(&token_id),
                        "tokenText": std::str::from_utf8(&token_id).ok(),
                        "isSns": collection == sns,
                    })
                })
                .collect();
            Ok(Value::Array(paged(params, items)))
        }
        // A PAGE of all NFT items (bounded like the token/name listings).
        "sov_listNfts" => {
            let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let limit = (params.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize)
                .clamp(1, MAX_TOKEN_PAGE);
            let ledger = node.chain().ledger();
            let mut page: Vec<Value> = ledger
                .nfts_iter()
                .skip(offset)
                .take(limit + 1)
                .map(|((collection, token_id), t)| {
                    nft_json(
                        collection,
                        token_id,
                        t.owner.as_str(),
                        &t.metadata,
                        t.minted_height,
                    )
                })
                .collect();
            let has_more = page.len() > limit;
            page.truncate(limit);
            Ok(json!({ "nfts": page, "offset": offset, "limit": limit, "hasMore": has_more }))
        }
        // ── Mining work-distribution (getBlockTemplate / submitBlock) ─────────
        // ADDITIVE + genesis-safe: these expose the EXISTING template producer
        // (`build_candidate`) and validated import path (`import_block`) over RPC so an
        // out-of-process miner (a Stratum bridge) can grind a nonce and submit a block.
        // No new consensus rule — every submitted block is re-validated in full on import.
        "sov_getBlockTemplate" => {
            // Optional coinbase override: direct this block's reward to a chosen account
            // (a pool's), else the node's configured miner identity.
            let coinbase = match params.get("coinbaseAccount").and_then(Value::as_str) {
                Some(s) => Some(AccountId::new(s).map_err(|e| {
                    RpcError::invalid_params(format!("invalid coinbaseAccount: {e}"))
                })?),
                None => None,
            };
            // Clamp the timestamp exactly as the in-process mining loop does
            // (max(now, parent+1, mtp+1)), so a template we hand out is one import accepts.
            let (parent_ts, mtp) = {
                let c = node.chain();
                (c.head().header.timestamp_ms, c.median_time_past())
            };
            let ts = crate::daemon::clamp_block_timestamp(crate::daemon::now_ms(), parent_ts, mtp);
            // The consensus floor: strictly after the parent AND after MTP (BIP-113).
            let min_ts = parent_ts.saturating_add(1).max(mtp.saturating_add(1));
            let (candidate, _excluded) = match coinbase {
                Some(cb) => node.build_candidate_for(ts, cb),
                None => node.build_candidate(ts),
            }
            .map_err(|e| RpcError::server(format!("build template failed: {e}")))?;

            let header = candidate.block().header.clone();
            let template_id = header.hash();
            // The exact bytes a miner grinds: the Borsh header preimage. The `nonce` is
            // the trailing u64, so its byte offset within the blob is `len - 8` (a miner
            // can splice a candidate nonce in place without re-encoding the header).
            let preimage = header.pow_preimage();
            let nonce_offset = preimage.len().saturating_sub(8);
            let resp = json!({
                "templateId": template_id.to_hex(),
                "height": header.height.get(),
                "prevHash": header.prev_hash.to_hex(),
                "txRoot": header.tx_root.to_hex(),
                "stateRoot": header.state_root.to_hex(),
                "receiptsRoot": header.receipts_root.to_hex(),
                "timestampMs": header.timestamp_ms,
                "minTimestampMs": min_ts,
                "bits": header.bits,
                "target": candidate.target().as_hash().to_hex(),
                "powAlgo": format!("{:?}", candidate.pow_algo()),
                "powKey": candidate.pow_key().to_hex(),
                "proposer": header.proposer.as_str(),
                "versionBits": header.version_bits,
                "blob": hex::encode(&preimage),
                "nonceOffset": nonce_offset,
            });
            ctx.templates.insert(template_id, candidate);
            Ok(resp)
        }
        "sov_submitBlock" => {
            // Two accepted forms:
            //  (a) { templateId, nonce, timestampMs? } — the normal path.
            //  (b) { header: {…full header incl nonce…} } — a caller that already holds
            //      the whole header; its body is recovered from the cached candidate
            //      matched by `tx_root` (the full tx set never had to cross the wire).
            let sealed: Block = if let Some(hv) = params.get("header") {
                let header: BlockHeader = serde_json::from_value(hv.clone())
                    .map_err(|e| RpcError::invalid_params(format!("invalid header: {e}")))?;
                let cand = ctx
                    .templates
                    .get_by_tx_root(&header.tx_root)
                    .ok_or_else(|| {
                        RpcError::server(
                            "no cached template matches header.txRoot (unknown or expired) — \
                         call sov_getBlockTemplate again",
                        )
                    })?;
                cand.seal_from_header(header).ok_or_else(|| {
                    RpcError::server("submitted header does not meet the proof-of-work target")
                })?
            } else {
                let id_s = params
                    .get("templateId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("missing string param `templateId`"))?;
                let template_id = Hash::from_hex(id_s)
                    .map_err(|e| RpcError::invalid_params(format!("invalid templateId: {e}")))?;
                let nonce = param_u64_flexible(params, "nonce")?;
                let timestamp_ms = opt_u64_flexible(params, "timestampMs")?;
                let cand = ctx.templates.get(&template_id).ok_or_else(|| {
                    RpcError::server(
                        "unknown or expired templateId — call sov_getBlockTemplate again",
                    )
                })?;
                cand.seal_with_nonce(nonce, timestamp_ms).ok_or_else(|| {
                    RpcError::server("submitted nonce does not meet the proof-of-work target")
                })?
            };

            let hash = sealed.hash();
            let height = sealed.header.height.get();
            // Import through the UNTRUSTED-SOURCE path (`import_block`, not `commit_mined`):
            // a block arriving over the RPC came from an external miner, so it must clear
            // the SAME acceptance policy every peer applies on gossip — including the
            // 2-hour future-timestamp bound (MAX_FUTURE_DRIFT_MS). Committing it via the
            // self-mine path would skip that bound and let a crafted far-future submit be
            // accepted + gossiped locally yet rejected by every peer, self-forking this
            // node onto a branch no one extends. This path also returns a reorg's reverted
            // txs to the mempool. Full re-execution + heaviest-work fork choice as before.
            match node.import_block(sealed.clone()) {
                Ok(_) => {
                    // Durability (audit SOV-H001): append + fsync before advertising it.
                    // Fail closed — never gossip a block we could not persist.
                    if let Some(log) = &ctx.block_log {
                        if let Err(e) = log.append(&sealed) {
                            return Ok(json!({
                                "accepted": false,
                                "hash": hash.to_hex(),
                                "height": height,
                                "error": format!("committed to memory but log append/fsync failed: {e}"),
                            }));
                        }
                    }
                    // Release the node lock before network I/O (mirror the tx-gossip path),
                    // then flood the block so the whole network builds on it.
                    drop(node);
                    if let Some(g) = &ctx.gossip {
                        g.broadcast(&sov_network::NetMessage::NewBlock(sealed));
                    }
                    Ok(json!({ "accepted": true, "hash": hash.to_hex(), "height": height }))
                }
                Err(e) => Ok(json!({
                    "accepted": false,
                    "hash": hash.to_hex(),
                    "height": height,
                    "error": format!("import rejected: {e}"),
                })),
            }
        }
        other => Err(RpcError::method_not_found(other)),
    }
}
