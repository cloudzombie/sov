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
//! Reads: `sov_health`, `sov_chainId`, `sov_getHeight`, `sov_getSupply`,
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
//! Write: `sov_submitTransaction`.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};
use sov_node::Node;
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::SignedTransaction;

pub mod client;
pub use client::{RpcClient, RpcClientError};

pub mod daemon;
pub use daemon::{
    BlockLog, ChainSpec, CheckpointSpec, Daemon, DaemonError, DaemonHandle, Keystore,
    KeystoreEntry, NodeConfig, PolicyPreset, SpecAccount,
};

pub mod p2p;
pub use p2p::{P2p, P2pConfig, P2pHandle};

pub mod sync_status;
pub use sync_status::SyncShared;

/// Maximum accepted request body (4 MiB) — large enough for a contract-deploy
/// transaction, small enough that a public bind cannot be memory-DoSed.
const MAX_RPC_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Maximum JSON-RPC batch length, so one request cannot fan out without bound.
const MAX_RPC_BATCH: usize = 100;

/// Hard cap on `sov_listTokens` page size, so a registry of any size yields a
/// bounded response (the client pages through with `offset`).
const MAX_TOKEN_PAGE: usize = 200;

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
}

/// The live network state the RPC handlers need beyond the node itself: the gossip
/// transport (broadcast accepted txs AND list connected peers) and the sync
/// telemetry. Threaded to the dispatch chain so `sov_submitTransaction` can gossip
/// and `sov_getPeerInfo` can expose peering/sync in real time.
#[derive(Clone, Default)]
struct RpcCtx {
    gossip: Option<Arc<sov_network::TcpNode>>,
    sync: Option<Arc<crate::SyncShared>>,
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
        };
        let mut handles = Vec::new();
        for _ in 0..workers.max(1) {
            let listener = Arc::clone(&listener);
            let shutdown = Arc::clone(&shutdown);
            let node = Arc::clone(&self.node);
            let ctx = ctx.clone();
            handles.push(thread::spawn(move || {
                while !shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
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

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
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
            let connected: Vec<String> = ctx
                .gossip
                .as_ref()
                .map(|g| g.connected_peers().iter().map(|a| a.to_string()).collect())
                .unwrap_or_default();
            Ok(json!({
                "chainId": c.chain_id(),
                "genesisHash": genesis,
                "height": c.height(),
                "p2pEnabled": ctx.gossip.is_some(),
                "listenAddr": ctx.gossip.as_ref().map(|g| g.local_addr().to_string()),
                "tcpLinks": ctx.gossip.as_ref().map(|g| g.peer_count()).unwrap_or(0),
                "peers": peers,
                "connectedPeers": connected,
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
                    "hashlock": hex::encode(h.hashlock),
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
        other => Err(RpcError::method_not_found(other)),
    }
}
