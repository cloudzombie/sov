//! Minimal std-only JSON-RPC 2.0 / HTTP 1.1 client for a SOV node.
//!
//! Byte-compatible with the node's real wire protocol (the same framing
//! `sov_rpc::RpcClient` speaks: one `POST /` per call, `Connection: close`).
//! Deliberately dependency-free so the harness compiles in seconds and can
//! never drift consensus logic — it only ever *reads* what a real node serves.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

/// A JSON-RPC client bound to one node's `host:port`.
#[derive(Clone)]
pub struct Rpc {
    pub addr: String,
    timeout: Duration,
}

impl Rpc {
    pub fn new(addr: impl Into<String>) -> Self {
        Rpc {
            addr: addr.into(),
            timeout: Duration::from_secs(15),
        }
    }

    /// One JSON-RPC call; returns the `result` or a descriptive error
    /// (transport errors and JSON-RPC `error` objects both surface).
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let request = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
        let body = serde_json::to_vec(&request).map_err(|e| format!("encode: {e}"))?;

        let addr = self
            .addr
            .to_socket_addrs()
            .map_err(|e| format!("resolve {}: {e}", self.addr))?
            .next()
            .ok_or_else(|| format!("unresolvable address {}", self.addr))?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("connect {}: {e}", self.addr))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        let header = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .and_then(|_| stream.flush())
            .map_err(|e| format!("send to {}: {e}", self.addr))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| format!("read from {}: {e}", self.addr))?;
        let text = String::from_utf8_lossy(&raw);
        let split = text
            .find("\r\n\r\n")
            .ok_or_else(|| format!("{}: response had no HTTP body", self.addr))?;
        let envelope: Value = serde_json::from_str(text[split + 4..].trim())
            .map_err(|e| format!("{}: malformed JSON-RPC reply: {e}", self.addr))?;
        if let Some(err) = envelope.get("error") {
            return Err(format!(
                "{} rpc error on {method}: {}",
                self.addr,
                err.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn height(&self) -> Result<u64, String> {
        self.call("sov_getHeight", json!({}))?
            .as_u64()
            .ok_or_else(|| format!("{}: sov_getHeight returned a non-integer", self.addr))
    }

    pub fn chain_id(&self) -> Result<String, String> {
        self.call("sov_chainId", json!({}))?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("{}: sov_chainId returned a non-string", self.addr))
    }

    /// The block digest at `height`: `{hash, prevHash, stateRoot, coinbase, …}`,
    /// or `None` above the node's tip.
    pub fn digest(&self, height: u64) -> Result<Option<Value>, String> {
        let v = self.call("sov_getBlockDigest", json!({ "height": height }))?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    pub fn peer_info(&self) -> Result<Value, String> {
        self.call("sov_getPeerInfo", json!({}))
    }

    pub fn supply(&self) -> Result<Value, String> {
        self.call("sov_getSupply", json!({}))
    }

    pub fn shielded_info(&self) -> Result<Value, String> {
        self.call("sov_getShieldedInfo", json!({}))
    }

    pub fn deployments(&self) -> Result<Value, String> {
        self.call("sov_getDeployments", json!({}))
    }

    pub fn difficulty(&self) -> Result<Value, String> {
        self.call("sov_getDifficulty", json!({}))
    }

    /// An account's transparent balance in grains (the node serves a decimal
    /// grains string — exact, never floating point).
    pub fn balance_grains(&self, account: &str) -> Result<u128, String> {
        let v = self.call("sov_getBalance", json!({ "account": account }))?;
        grains_of(&v).ok_or_else(|| format!("{}: unparseable balance {v}", self.addr))
    }

    /// The shielded pool's total value in grains.
    pub fn pool_grains(&self) -> Result<u128, String> {
        let info = self.shielded_info()?;
        info.get("poolValue")
            .and_then(grains_of)
            .ok_or_else(|| format!("{}: unparseable poolValue in {info}", self.addr))
    }

    /// A transaction's receipt, or `None` while unmined.
    pub fn receipt(&self, tx_id: &str) -> Result<Option<Value>, String> {
        let v = self.call("sov_getReceipt", json!({ "txId": tx_id }))?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// Whether the node answers RPC at all (used only as a readiness probe).
    pub fn healthy(&self) -> bool {
        matches!(self.call("sov_health", json!({})), Ok(v) if v.get("ok").and_then(Value::as_bool) == Some(true))
    }
}

/// Parse a Balance JSON value (a decimal string of grains) to `u128`.
pub fn grains_of(v: &Value) -> Option<u128> {
    v.as_str().and_then(|s| s.parse::<u128>().ok())
}

/// Whether a receipt JSON records a SUCCESSFUL execution (fail-closed — the
/// same check the wallet and Station use).
pub fn receipt_succeeded(v: &Value) -> bool {
    v.get("status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        == Some("success")
}
