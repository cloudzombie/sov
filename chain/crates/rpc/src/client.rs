//! JSON-RPC client (Phase 8, p8-i3): how miners, wallets, and tools talk to a
//! running SOV node.
//!
//! [`RpcClient`] is a small, std-only HTTP/1.1 + JSON-RPC 2.0 client built on the
//! protocol types plus the leaf crates a client genuinely needs (crypto, mining,
//! proof-of-work, and the shielded-pool primitives) — never on `sov-node` or
//! `sov-chain`, so there is no dependency cycle with the server side.
//!
//! It does real work: [`RpcClient::transfer`] builds, signs, and submits a
//! transaction (transparent, shielded, or routed by address tier). Mining is
//! NOT an RPC operation under Nakamoto consensus — block production itself is
//! the mining, done by a running node (`sov-rpcd`), whose coinbase pays its
//! configured miner account.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sov_crypto::Keypair;
use sov_mining::Difficulty;
use sov_primitives::{AccountId, Balance, Hash};
use sov_shielded::{mint_to_shielded, AnyAddress, Receiver, ShieldedAddress, ShieldedParams};
use sov_state::Account;
use sov_types::{Action, Block, SignedTransaction, Transaction};

/// An error talking to a SOV node over JSON-RPC.
#[derive(Debug, thiserror::Error)]
pub enum RpcClientError {
    /// A transport (TCP / HTTP) failure.
    #[error("transport: {0}")]
    Io(#[from] std::io::Error),
    /// A (de)serialization failure on the request or response.
    #[error("encoding: {0}")]
    Json(#[from] serde_json::Error),
    /// The response was not a well-formed JSON-RPC reply.
    #[error("malformed response: {0}")]
    Malformed(String),
    /// The node returned a JSON-RPC error.
    #[error("rpc error {code}: {message}")]
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
        /// The error message.
        message: String,
    },
}

/// A client for a SOV node's JSON-RPC endpoint (e.g. `127.0.0.1:8645`).
#[derive(Debug, Clone)]
pub struct RpcClient {
    addr: String,
    timeout: Duration,
}

impl RpcClient {
    /// A client targeting `addr` (`host:port`), with a 30s default timeout.
    pub fn new(addr: impl Into<String>) -> Self {
        RpcClient {
            addr: addr.into(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Override the per-request socket timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Make a raw JSON-RPC call, returning the `result` value or mapping a
    /// JSON-RPC `error` into [`RpcClientError::Rpc`].
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcClientError> {
        let request = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
        let body = serde_json::to_vec(&request)?;

        // Bound the CONNECT too: `set_read_timeout`/`set_write_timeout` only govern
        // I/O after the handshake, so a saturated accept queue or black-holed SYN
        // would otherwise hang a caller for the OS default (a minute or more).
        let addr = self
            .addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| RpcClientError::Malformed(format!("unresolvable address {}", self.addr)))?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let header = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let text = String::from_utf8_lossy(&raw);
        let split = text
            .find("\r\n\r\n")
            .ok_or_else(|| RpcClientError::Malformed("response had no HTTP body".into()))?;
        let envelope: Value = serde_json::from_str(text[split + 4..].trim())?;

        if let Some(err) = envelope.get("error") {
            return Err(RpcClientError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string(),
            });
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    fn call_typed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, RpcClientError> {
        let result = self.call(method, params)?;
        serde_json::from_value(result).map_err(RpcClientError::from)
    }

    /// The node's chain id.
    pub fn chain_id(&self) -> Result<String, RpcClientError> {
        self.call_typed("sov_chainId", json!({}))
    }

    /// The current chain height.
    pub fn height(&self) -> Result<u64, RpcClientError> {
        self.call_typed("sov_getHeight", json!({}))
    }

    /// The next expected nonce for `account`.
    pub fn nonce(&self, account: &AccountId) -> Result<u64, RpcClientError> {
        self.call_typed("sov_getNonce", json!({ "account": account.as_str() }))
    }

    /// The liquid balance of `account`.
    pub fn balance(&self, account: &AccountId) -> Result<Balance, RpcClientError> {
        self.call_typed("sov_getBalance", json!({ "account": account.as_str() }))
    }

    /// The proof-of-work reward a mint currently earns (the emission schedule at
    /// the present mined supply). A shielded miner builds its coinbase bundle to
    /// exactly this value, since the runtime rejects any other amount.
    pub fn mint_reward(&self) -> Result<Balance, RpcClientError> {
        self.call_typed("sov_getMintReward", json!({}))
    }

    /// The full account record, or `None` if it has never been funded.
    pub fn account(&self, account: &AccountId) -> Result<Option<Account>, RpcClientError> {
        self.call_typed("sov_getAccount", json!({ "account": account.as_str() }))
    }

    /// The current head block.
    pub fn head(&self) -> Result<Block, RpcClientError> {
        self.call_typed("sov_getHead", json!({}))
    }

    /// Whether the block identified by `hash` is final under Nakamoto
    /// consensus: buried at least `FINALITY_DEPTH` confirmations deep in the
    /// heaviest-work chain.
    pub fn is_final(&self, hash: &Hash) -> Result<bool, RpcClientError> {
        self.call_typed("sov_isFinal", json!({ "hash": hash.to_hex() }))
    }

    /// The block at `height`, or `None` if the chain is shorter.
    pub fn block_by_height(&self, height: u64) -> Result<Option<Block>, RpcClientError> {
        self.call_typed("sov_getBlockByHeight", json!({ "height": height }))
    }

    /// The number of pending transactions in the node's mempool.
    pub fn mempool_size(&self) -> Result<usize, RpcClientError> {
        self.call_typed("sov_getMempoolSize", json!({}))
    }

    /// The current SHA-256d mining difficulty.
    pub fn sha256d_difficulty(&self) -> Result<Difficulty, RpcClientError> {
        let result = self.call("sov_getDifficulty", json!({}))?;
        let raw = result
            .get("sha256d")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcClientError::Malformed("missing sha256d difficulty".into()))?;
        let scalar: u128 = raw
            .parse()
            .map_err(|_| RpcClientError::Malformed(format!("bad difficulty value: {raw}")))?;
        Ok(Difficulty(scalar))
    }

    /// Submit an already-signed transaction; returns its id.
    pub fn submit_transaction(&self, stx: &SignedTransaction) -> Result<Hash, RpcClientError> {
        let result = self.call("sov_submitTransaction", serde_json::to_value(stx)?)?;
        let tx_id = result
            .get("txId")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcClientError::Malformed("missing txId in response".into()))?;
        Hash::from_hex(tx_id).map_err(|e| RpcClientError::Malformed(format!("bad txId: {e}")))
    }

    /// Build, sign, and submit a transfer from `from` to `to`. Looks up the
    /// signer's current nonce from the node. Returns the transaction id.
    pub fn transfer(
        &self,
        keypair: &Keypair,
        from: &AccountId,
        to: &AccountId,
        amount: Balance,
    ) -> Result<Hash, RpcClientError> {
        let nonce = self.nonce(from)?;
        let tx = Transaction {
            signer: from.clone(),
            public_key: keypair.public_key(),
            nonce,
            action: Action::Transfer {
                to: to.clone(),
                amount,
            },
        };
        let stx = SignedTransaction::sign(tx, keypair)
            .map_err(|e| RpcClientError::Malformed(format!("signing failed: {e}")))?;
        self.submit_transaction(&stx)
    }

    /// Pay a shielded (`xus1…`) receiver from `from`'s transparent balance: a
    /// REAL Halo2 shield bundle paying `recipient` exactly `amount`, submitted
    /// as an `Action::Shielded`. The sender is debited transparently; on-chain,
    /// the receiving note reveals nothing about the recipient or amount.
    /// `params` is the (expensive) proving key — build once, reuse.
    pub fn transfer_shielded(
        &self,
        keypair: &Keypair,
        from: &AccountId,
        recipient: &ShieldedAddress,
        amount: Balance,
        params: &ShieldedParams,
    ) -> Result<Hash, RpcClientError> {
        let units = u64::try_from(amount.grains())
            .map_err(|_| RpcClientError::Malformed("amount exceeds u64 grains".into()))?;
        let bundle = mint_to_shielded(params, recipient, units)
            .map_err(|e| RpcClientError::Malformed(format!("shield bundle build failed: {e}")))?;
        let nonce = self.nonce(from)?;
        let tx = Transaction {
            signer: from.clone(),
            public_key: keypair.public_key(),
            nonce,
            action: Action::Shielded {
                bundle: bundle.to_bytes(),
            },
        };
        let stx = SignedTransaction::sign(tx, keypair)
            .map_err(|e| RpcClientError::Malformed(format!("signing failed: {e}")))?;
        self.submit_transaction(&stx)
    }

    /// Pay ANY recipient string — a named account, a `xus1…` shielded address,
    /// or a `uxus1…` unified address — routing **privacy-first**: a unified
    /// address with a shielded receiver is paid into the shielded pool.
    /// `params` is required only when the route is shielded; passing `None`
    /// for a shielded route is an error, never a silent transparent fallback
    /// (a privacy downgrade must be the caller's explicit decision).
    pub fn pay(
        &self,
        keypair: &Keypair,
        from: &AccountId,
        to: &str,
        amount: Balance,
        params: Option<&ShieldedParams>,
    ) -> Result<Hash, RpcClientError> {
        let address = AnyAddress::parse(to)
            .map_err(|e| RpcClientError::Malformed(format!("invalid recipient: {e}")))?;
        match address.receiver() {
            Receiver::Transparent(account) => self.transfer(keypair, from, &account, amount),
            Receiver::Shielded(recipient) => {
                let params = params.ok_or_else(|| {
                    RpcClientError::Malformed(
                        "recipient routes to the shielded pool: a prover (ShieldedParams)                          is required — refusing to silently downgrade to a transparent send"
                            .into(),
                    )
                })?;
                self.transfer_shielded(keypair, from, &recipient, amount, params)
            }
        }
    }

    // NOTE: the `mine_block` / `mine_block_shielded` helpers (which submitted
    // `Mine` / `MineShielded` transactions) are RETIRED under Nakamoto
    // consensus: block production itself is the mining, and the coinbase pays
    // the producing node's miner account directly. To mine, run a mining node
    // (`sov-rpcd`) — there is no transaction that mints.
}
