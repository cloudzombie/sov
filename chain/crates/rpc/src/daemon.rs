//! The long-running node daemon (Phase 8, p8-i0 + p8-i4).
//!
//! A [`Daemon`] owns a shared [`Node`], serves the [JSON-RPC API](crate::RpcServer),
//! produces blocks on a schedule, and **persists state across restarts**. The
//! persisted source of truth is the *block log*: every produced block is appended
//! to `data_dir/blocks.log`, and on startup the chain is rebuilt by replaying that
//! log through the normal validated import path — the same deterministic replay
//! the verification suite proves reaches a byte-identical state root. State is
//! therefore never trusted from a snapshot; it is always re-derived from blocks.
//!
//! Chain-spec, node config, and keystore are plain JSON ([`ChainSpec`],
//! [`NodeConfig`], [`Keystore`]) so a node operator can launch a network without
//! recompiling.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sov_chain::{Blockchain, ChainError, GenesisAccount, GenesisConfig};
use sov_crypto::{Keypair, PublicKey};
use sov_mining::MiningPolicy;
use sov_network::{NetMessage, TcpNode};
use sov_node::{Node, NodeError, Produced};
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::Block;

use crate::{RpcHandle, RpcServer};

/// Why a daemon operation failed.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Filesystem / persistence error.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Genesis construction or block import rejected the chain.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    /// The node rejected a produced block.
    #[error("node: {0}")]
    Node(#[from] NodeError),
    /// A chain-spec, config, or keystore was malformed.
    #[error("config: {0}")]
    Config(String),
    /// The persisted data dir's schema is incompatible with this binary.
    #[error("data schema: {0}")]
    DataSchema(String),
}

impl DaemonError {
    fn config(msg: impl Into<String>) -> Self {
        DaemonError::Config(msg.into())
    }
}

/// A built-in consensus ruleset a chain-spec selects by name, so an operator does
/// not hand-write difficulty targets.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreset {
    /// Production-leaning parameters ([`MiningPolicy::mainnet_like`]).
    MainnetLike,
    /// Easy parameters for local/test networks ([`MiningPolicy::test`]).
    Test,
}

impl PolicyPreset {
    fn mining(self) -> MiningPolicy {
        match self {
            PolicyPreset::MainnetLike => MiningPolicy::mainnet_like(),
            PolicyPreset::Test => MiningPolicy::test(),
        }
    }
}

/// A genesis account in a chain-spec. Balances are decimal-grain strings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpecAccount {
    /// Account name (e.g. `val01.node.sov`).
    pub account: String,
    /// The controlling public key: bare 32-byte hex = Ed25519 (`V1`), or a
    /// `hybrid65:0x…`-prefixed (32+1952)-byte hex = hybrid post-quantum
    /// Ed25519+ML-DSA-65 (`V2`) — the default `sov-testnet gen` now emits.
    pub public_key: String,
    /// Liquid balance in grains (default `0`).
    #[serde(default)]
    pub balance: Balance,
}

/// A chain specification: the genesis a node starts from, as JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainSpec {
    /// Network identifier (e.g. `sov-testnet`).
    pub chain_id: String,
    /// Genesis timestamp, Unix milliseconds.
    pub timestamp_ms: u64,
    /// Which built-in consensus ruleset to use.
    pub policy: PolicyPreset,
    /// Override the policy's consensus block-time target, in milliseconds. `None`
    /// uses the policy's native value. Set by `sov-testnet gen --block-time-ms`
    /// so a testnet runs at a realistic cadence (e.g. 60s) instead of the
    /// unit-test preset's 1s. Kept consistent with the daemon's `block_time_ms`.
    #[serde(default)]
    pub block_time_ms: Option<u64>,
    /// Override the policy's proof-of-work seal: `"sha256d"` or `"randomx"`.
    /// `None` uses the policy's native algorithm. Lets a testnet run real
    /// **RandomX** (mainnet fidelity, a pre-launch dress rehearsal) or fast
    /// Sha256d (default, single-box friendly).
    #[serde(default)]
    pub pow: Option<String>,
    /// Funded accounts.
    pub accounts: Vec<SpecAccount>,
}

impl ChainSpec {
    /// Parse a chain-spec from JSON.
    pub fn from_json(json: &str) -> Result<Self, DaemonError> {
        serde_json::from_str(json).map_err(|e| DaemonError::config(format!("chain-spec: {e}")))
    }

    /// Build the [`GenesisConfig`] this spec describes.
    pub fn to_genesis_config(&self) -> Result<GenesisConfig, DaemonError> {
        let mut accounts = Vec::with_capacity(self.accounts.len());
        for a in &self.accounts {
            let key: PublicKey =
                serde_json::from_value(serde_json::Value::String(a.public_key.clone())).map_err(
                    |e| DaemonError::config(format!("account {}: bad public_key: {e}", a.account)),
                )?;
            let account = AccountId::new(&a.account)
                .map_err(|e| DaemonError::config(format!("invalid account {}: {e}", a.account)))?;
            accounts.push(GenesisAccount {
                account,
                key,
                balance: a.balance,
            });
        }
        // Start from the named preset, then apply the spec's optional overrides
        // (block time + PoW seal) so a testnet can run at a realistic cadence and
        // either Sha256d or real RandomX, all from the SAME node binary.
        let mut mining = self.policy.mining();
        if let Some(block_time_ms) = self.block_time_ms {
            mining.target_block_ms = block_time_ms;
        }
        if let Some(pow) = &self.pow {
            mining.pow_algo = match pow.to_ascii_lowercase().as_str() {
                "sha256d" => sov_mining::PowAlgo::Sha256d,
                "randomx" => sov_mining::PowAlgo::RandomX,
                other => {
                    return Err(DaemonError::config(format!(
                        "chain-spec: unknown pow `{other}` (expected `sha256d` or `randomx`)"
                    )))
                }
            };
        }
        Ok(GenesisConfig {
            chain_id: self.chain_id.clone(),
            timestamp_ms: self.timestamp_ms,
            accounts,
            mining,
            vesting: Vec::new(),
        })
    }
}

/// Operator configuration for a running node (JSON).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Address to bind the JSON-RPC server (e.g. `127.0.0.1:8645`).
    pub rpc_addr: String,
    /// RPC worker threads.
    #[serde(default = "default_rpc_workers")]
    pub rpc_workers: usize,
    /// Directory holding the persisted block log.
    pub data_dir: String,
    /// Block-production interval in milliseconds (the consensus heartbeat).
    #[serde(default = "default_block_time_ms")]
    pub block_time_ms: u64,
    /// Mempool capacity.
    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: usize,
    /// Maximum transactions per block.
    #[serde(default = "default_max_block_txs")]
    pub max_block_txs: usize,
    /// Address to bind the P2P gossip transport (e.g. `0.0.0.0:9645`). If unset,
    /// the node runs standalone — it produces blocks and serves RPC, but does not
    /// peer with anyone.
    #[serde(default)]
    pub p2p_addr: Option<String>,
    /// Bootstrap peers to dial on startup (`host:port`), typically the seed
    /// node's P2P address. Discovery then spreads the rest of the network
    /// gossip-style, so one good link is enough to join.
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Trusted weak-subjectivity checkpoints: blocks at these heights must hash to
    /// the pinned value, rejecting a forged long-range history. Empty by default.
    #[serde(default)]
    pub checkpoints: Vec<CheckpointSpec>,
}

/// A trusted weak-subjectivity checkpoint in a node config: a height pinned to a
/// known-good block hash (32-byte hex).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckpointSpec {
    /// Block height being pinned.
    pub height: u64,
    /// The block's hash at that height, 32-byte hex.
    pub hash: String,
}

impl CheckpointSpec {
    /// Parse into a `(height, Hash)` pair.
    pub fn parse(&self) -> Result<(u64, Hash), DaemonError> {
        let hash = Hash::from_hex(&self.hash).map_err(|e| {
            DaemonError::config(format!(
                "checkpoint at height {}: bad hash: {e}",
                self.height
            ))
        })?;
        Ok((self.height, hash))
    }
}

fn default_rpc_workers() -> usize {
    4
}
fn default_block_time_ms() -> u64 {
    1_000
}
fn default_mempool_capacity() -> usize {
    16_384
}
fn default_max_block_txs() -> usize {
    4_096
}

/// A keystore: miner signing keys, by seed. (Plaintext seeds suit a testnet;
/// encryption at rest / an HSM is a mainnet hardening step.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Keystore {
    /// The miner keys this node mines and signs with (the first is its coinbase
    /// identity). Consensus is pure proof-of-work; these are simply the keys the
    /// node controls.
    pub miners: Vec<KeystoreEntry>,
}

/// One signing key: its account, the 32-byte signing seed (hex), and the
/// key scheme the seed derives.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeystoreEntry {
    /// The key's account.
    pub account: String,
    /// The 32-byte signing seed, hex.
    pub seed_hex: String,
    /// Key scheme: `"hybrid65"` (post-quantum hybrid, the generated default)
    /// or `"ed25519"`. Absent = `"ed25519"` (pre-PQ keystores stay loadable).
    #[serde(default)]
    pub scheme: Option<String>,
    /// The BIP-39 recovery phrase the seed was derived from, when known. Lets a
    /// wallet app re-display ("export") the phrase after first generation —
    /// otherwise it is unrecoverable, since BIP-39 → seed is one-way. Optional
    /// and omitted when absent, so node keystores (seed-only) are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// For a WATCH-ONLY entry: the public key (`hybrid65:0x…`) being watched, with
    /// no seed (`seed_hex` empty). The wallet monitors the account but cannot sign.
    /// Optional and omitted when absent, so seeded entries are byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// An encrypted keystore envelope: the plaintext keystore JSON sealed with
/// ChaCha20-Poly1305 under a key derived from a passphrase via Argon2id. Stored as
/// JSON so it's a drop-in replacement for the plaintext file on disk.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct EncryptedKeystore {
    /// Always `true`; distinguishes this envelope from a plaintext keystore.
    encrypted: bool,
    /// Key-derivation function identifier (Argon2id).
    kdf: String,
    /// Argon2 salt, hex.
    salt: String,
    /// ChaCha20-Poly1305 nonce (12 bytes), hex.
    nonce: String,
    /// Ciphertext (includes the AEAD tag), hex.
    ciphertext: String,
}

/// Derive a 32-byte symmetric key from `passphrase` + `salt` using Argon2id (a
/// memory-hard KDF, so a stolen keystore file resists offline brute force).
fn derive_keystore_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], DaemonError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| DaemonError::config(format!("keystore key derivation failed: {e}")))?;
    Ok(key)
}

impl Keystore {
    /// Parse a keystore from plaintext JSON.
    pub fn from_json(json: &str) -> Result<Self, DaemonError> {
        serde_json::from_str(json).map_err(|e| DaemonError::config(format!("keystore: {e}")))
    }

    /// Load a keystore from text that may be plaintext OR an encrypted envelope.
    /// An encrypted keystore requires `passphrase`; a missing one errors with
    /// guidance rather than silently failing.
    pub fn from_encrypted_or_plain(
        text: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, DaemonError> {
        if let Ok(env) = serde_json::from_str::<EncryptedKeystore>(text) {
            if env.encrypted {
                let pass = passphrase.ok_or_else(|| {
                    DaemonError::config(
                        "keystore is encrypted; provide the passphrase \
                         (set SOV_KEYSTORE_PASSPHRASE)",
                    )
                })?;
                let salt = hex::decode(&env.salt)
                    .map_err(|e| DaemonError::config(format!("keystore: bad salt: {e}")))?;
                let nonce = hex::decode(&env.nonce)
                    .map_err(|e| DaemonError::config(format!("keystore: bad nonce: {e}")))?;
                if nonce.len() != 12 {
                    return Err(DaemonError::config("keystore: nonce must be 12 bytes"));
                }
                let ct = hex::decode(&env.ciphertext)
                    .map_err(|e| DaemonError::config(format!("keystore: bad ciphertext: {e}")))?;
                let key = derive_keystore_key(pass, &salt)?;
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                let plain = cipher
                    .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                    .map_err(|_| {
                        DaemonError::config("keystore decryption failed (wrong passphrase?)")
                    })?;
                let plain = String::from_utf8(plain).map_err(|e| {
                    DaemonError::config(format!("decrypted keystore is not UTF-8: {e}"))
                })?;
                return Keystore::from_json(&plain);
            }
        }
        Keystore::from_json(text)
    }

    /// Seal this keystore under `passphrase`, returning the encrypted envelope JSON.
    pub fn to_encrypted_json(&self, passphrase: &str) -> Result<String, DaemonError> {
        let plain = serde_json::to_string(self)
            .map_err(|e| DaemonError::config(format!("serialize keystore: {e}")))?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut salt)
            .map_err(|e| DaemonError::config(format!("entropy: {e}")))?;
        getrandom::getrandom(&mut nonce)
            .map_err(|e| DaemonError::config(format!("entropy: {e}")))?;
        let key = derive_keystore_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
            .map_err(|_| DaemonError::config("keystore encryption failed"))?;
        let env = EncryptedKeystore {
            encrypted: true,
            kdf: "argon2id".into(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        serde_json::to_string_pretty(&env)
            .map_err(|e| DaemonError::config(format!("serialize envelope: {e}")))
    }

    /// Resolve the keystore into `(account, keypair)` pairs.
    pub fn keys(&self) -> Result<Vec<(AccountId, Keypair)>, DaemonError> {
        let mut out = Vec::with_capacity(self.miners.len());
        for v in &self.miners {
            let raw = hex::decode(&v.seed_hex).map_err(|e| {
                DaemonError::config(format!("key {}: bad seed hex: {e}", v.account))
            })?;
            let seed: [u8; 32] = raw.try_into().map_err(|_| {
                DaemonError::config(format!("key {}: seed must be 32 bytes", v.account))
            })?;
            let account = AccountId::new(&v.account).map_err(|e| {
                DaemonError::config(format!("invalid key account {}: {e}", v.account))
            })?;
            let keypair = match v.scheme.as_deref() {
                None | Some("ed25519") => Keypair::from_seed(seed),
                Some("hybrid65") => Keypair::hybrid_from_seed(seed),
                Some(other) => {
                    return Err(DaemonError::config(format!(
                        "key {}: unknown key scheme `{other}`",
                        v.account
                    )))
                }
            };
            out.push((account, keypair));
        }
        Ok(out)
    }
}

fn blocks_path(dir: &Path) -> PathBuf {
    dir.join("blocks.log")
}

fn schema_version_path(dir: &Path) -> PathBuf {
    dir.join("schema_version")
}

/// On-disk data-dir schema version. Bump ONLY for a change that makes an existing
/// `blocks.log` unreplayable by the new binary (a Block/consensus encoding break).
/// Additive changes — new `Action` variants, new state slots, RPC additions — keep
/// this the same, because the chain resumes by *replaying* the block log through
/// the current code, so old blocks (which lack the new actions) re-execute
/// identically. A mismatch is reported, never silently mis-handled.
const DATA_SCHEMA_VERSION: u32 = 1;

/// Verify the data dir's schema version is one this binary can replay, stamping it
/// on first use. Errors (rather than risking a silent reset or mis-replay) if a
/// persisted chain was written by an incompatible schema.
fn check_schema_version(dir: &Path) -> Result<(), DaemonError> {
    let path = schema_version_path(dir);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let found: u32 = s.trim().parse().map_err(|_| {
                DaemonError::DataSchema(format!("unreadable schema_version file at {path:?}"))
            })?;
            if found != DATA_SCHEMA_VERSION {
                return Err(DaemonError::DataSchema(format!(
                    "data dir schema v{found} is incompatible with this binary (schema \
                     v{DATA_SCHEMA_VERSION}). Use a matching release, or start a fresh data dir."
                )));
            }
        }
        // Absent: first run, or a data dir created before versioning. Stamp the
        // current version — if its blocks.log is replayable it is, by definition,
        // this schema (the replay below is the real compatibility check).
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::write(&path, DATA_SCHEMA_VERSION.to_string())?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Upper bound on a single log record's payload (16 MiB), so a corrupt length
/// prefix can never trigger a huge allocation.
const MAX_RECORD: usize = 16 * 1024 * 1024;

/// On-disk record framing for the append-only logs:
/// `[len: u32 LE][checksum: 32-byte BLAKE3 of payload][payload: len bytes]`.
///
/// The checksum makes corruption (bit-rot, a partial/interleaved write) DETECTABLE,
/// not just truncation. [`append_record`] fsyncs, so a committed record survives
/// power loss; [`read_records`] recovers the longest intact prefix and stops at the
/// first damaged record rather than failing the whole log — the missing tail is
/// re-synced from peers, so corruption degrades gracefully instead of bricking a node.
fn append_record(f: &mut fs::File, payload: &[u8]) -> io::Result<()> {
    let checksum = Hash::digest(payload);
    f.write_all(&(payload.len() as u32).to_le_bytes())?;
    f.write_all(checksum.as_bytes())?;
    f.write_all(payload)?;
    f.flush()?;
    f.sync_all() // durability: the record is on stable storage before we return
}

/// Decode every intact record, stopping at the first truncated or checksum-failing
/// one and returning the valid prefix.
fn read_records(data: &[u8]) -> Vec<&[u8]> {
    const HEADER: usize = 4 + Hash::LEN;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + HEADER <= data.len() {
        let len = u32::from_le_bytes(data[i..i + 4].try_into().expect("4 bytes")) as usize;
        let payload_start = i + HEADER;
        if len == 0 || len > MAX_RECORD || payload_start + len > data.len() {
            break; // truncated (interrupted write)
        }
        let checksum = &data[i + 4..payload_start];
        let payload = &data[payload_start..payload_start + len];
        if Hash::digest(payload).as_bytes() != checksum {
            break; // corrupt record — recover the valid prefix, re-sync the rest
        }
        out.push(payload);
        i = payload_start + len;
    }
    out
}

/// An append-only, checksummed, fsync'd log of committed blocks — the persisted
/// source of truth a node replays on restart. A single shared `BlockLog` is written
/// by BOTH the block-production path and the P2P import path, and its mutex
/// serializes those writers so records never interleave on disk and the on-disk
/// order always matches chain-commit order. Persisting imported blocks (not just
/// produced ones) is what lets a *follower* restart and replay its own log instead
/// of re-syncing the whole chain from peers.
pub struct BlockLog {
    file: Mutex<fs::File>,
}

impl BlockLog {
    /// Open (creating if absent) the block log at `path` for appending.
    fn open(path: &Path) -> io::Result<BlockLog> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(BlockLog {
            file: Mutex::new(file),
        })
    }

    /// Append one block as a checksummed, fsync'd record.
    pub fn append(&self, block: &Block) -> io::Result<()> {
        let bytes = borsh::to_vec(block).expect("Borsh serialization of a Block is infallible");
        let mut f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("block log mutex poisoned"))?;
        append_record(&mut f, &bytes)
    }
}

/// Read every intact block from the log, stopping at a truncated or corrupt tail.
fn load_blocks(path: &Path) -> io::Result<Vec<Block>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path)?;
    let records = read_records(&data);
    let mut blocks = Vec::with_capacity(records.len());
    for (i, payload) in records.iter().enumerate() {
        match borsh::from_slice::<Block>(payload) {
            Ok(block) => blocks.push(block),
            // `read_records` already dropped any torn tail (checksum failure), so a
            // checksum-VALID record that won't decode is a fully-committed block the
            // running binary can't read — an incompatible upgrade. Fail loudly
            // rather than silently truncate a persisted chain (data loss).
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "block log record {i} of {} won't decode ({e}) — the data dir was \
                         written by an incompatible binary; refusing to silently drop committed \
                         blocks",
                        records.len()
                    ),
                ))
            }
        }
    }
    Ok(blocks)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A node daemon: a shared [`Node`] plus its persistence directory.
pub struct Daemon {
    node: Arc<Mutex<Node>>,
    resumed: usize,
    /// Append-only block log, replayed on boot to reconstruct the chain.
    block_log: Arc<BlockLog>,
    /// If set, blocks this daemon mines are gossiped to peers over this
    /// transport (attached via [`Daemon::with_gossip`]).
    gossip: Option<Arc<TcpNode>>,
}

/// A running daemon's RPC + block-production threads, with graceful shutdown.
pub struct DaemonHandle {
    rpc_addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    produce: JoinHandle<()>,
    rpc: RpcHandle,
}

impl DaemonHandle {
    /// The bound RPC address.
    pub fn rpc_addr(&self) -> std::net::SocketAddr {
        self.rpc_addr
    }

    /// Stop block production and the RPC server, then wait for both to finish.
    pub fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.produce.join();
        self.rpc.shutdown();
    }
}

impl Daemon {
    /// Build a daemon: construct the chain from `genesis`, **replay any persisted
    /// block log** under `data_dir` to resume state, then wrap it in a [`Node`]
    /// holding the given miner keys.
    pub fn new(
        genesis: &GenesisConfig,
        data_dir: impl AsRef<Path>,
        mempool_capacity: usize,
        max_block_txs: usize,
        miner_keys: Vec<(AccountId, Keypair)>,
    ) -> Result<Self, DaemonError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        // Refuse to boot against a data dir written by an incompatible schema,
        // rather than mis-replaying it (node-data stability across upgrades).
        check_schema_version(&data_dir)?;

        let mut chain = Blockchain::new(genesis)?;
        let persisted = load_blocks(&blocks_path(&data_dir))?;
        let resumed = persisted.len();
        // Deterministic replay through the validated import path: state, difficulty,
        // and roots are re-derived, never trusted from a snapshot.
        for block in persisted {
            chain.import_block(block)?;
        }
        let block_log = Arc::new(BlockLog::open(&blocks_path(&data_dir))?);

        let mut node = Node::new(chain, mempool_capacity, max_block_txs);
        // The first key is this node's miner identity: blocks it mines credit
        // their coinbase there (Nakamoto consensus — the header `proposer` names
        // whom the PoW pays). Consensus is pure proof-of-work; the keystore is
        // simply the keys this node can mine to and sign with.
        if let Some((account, _)) = miner_keys.first() {
            node.set_coinbase(account.clone());
        }

        Ok(Daemon {
            node: Arc::new(Mutex::new(node)),
            resumed,
            block_log,
            gossip: None,
        })
    }

    /// A clone of the shared node handle (for the RPC server, or direct access).
    pub fn node(&self) -> Arc<Mutex<Node>> {
        Arc::clone(&self.node)
    }

    /// How many blocks were replayed from the log at startup.
    pub fn resumed_blocks(&self) -> usize {
        self.resumed
    }

    /// Attach a P2P transport so blocks this daemon produces are gossiped to
    /// peers. Pair with a [`P2p`](crate::p2p::P2p) engine bound to the
    /// same [`node`](Self::node) handle for the receive/sync side.
    pub fn with_gossip(mut self, tcp: Arc<TcpNode>) -> Self {
        self.gossip = Some(tcp);
        self
    }

    /// Install trusted weak-subjectivity checkpoints on the node's chain, so a
    /// forged long-range history is rejected on import.
    pub fn with_checkpoints(self, checkpoints: impl IntoIterator<Item = (u64, Hash)>) -> Self {
        if let Ok(mut node) = self.node.lock() {
            node.set_checkpoints(checkpoints);
        }
        self
    }

    /// The block log this daemon persists committed blocks to. Share it with a
    /// [`P2p`](crate::p2p::P2p) engine via [`P2p::with_block_log`] so blocks received
    /// from peers are persisted too, and a follower can replay its own log on restart
    /// instead of re-syncing the whole chain.
    pub fn block_log(&self) -> Arc<BlockLog> {
        Arc::clone(&self.block_log)
    }

    /// The genesis block hash — the chain/fork identity peers bind to in the P2P
    /// handshake.
    pub fn genesis_hash(&self) -> Hash {
        self.node
            .lock()
            .expect("node lock poisoned")
            .chain()
            .block_by_height(0)
            .expect("genesis block always exists")
            .hash()
    }

    /// Gossip a mined block, if a transport is attached.
    fn gossip_produced(&self, produced: &Produced) {
        if let Some(tcp) = &self.gossip {
            tcp.broadcast(&NetMessage::NewBlock(produced.block.clone()));
        }
    }

    /// Current chain height.
    pub fn height(&self) -> u64 {
        self.node.lock().map(|n| n.chain().height()).unwrap_or(0)
    }

    /// Current liquid balance of `account`.
    pub fn balance(&self, account: &AccountId) -> Balance {
        self.node
            .lock()
            .map(|n| n.chain().ledger().account(account).balance)
            .unwrap_or(Balance::ZERO)
    }

    /// The committed state root.
    pub fn state_root_hex(&self) -> String {
        self.node
            .lock()
            .map(|n| n.chain().ledger().state_root().to_hex())
            .unwrap_or_default()
    }

    /// Start the JSON-RPC server over this daemon's node.
    pub fn serve_rpc(&self, addr: &str, workers: usize) -> io::Result<RpcHandle> {
        RpcServer::new(self.node()).start(addr, workers)
    }

    /// Produce a single block now (timestamped `timestamp_ms`) if the mempool has
    /// pending transactions, persisting it to the block log. Returns whether a
    /// block was produced. The deterministic building block of the production loop
    /// — also called directly by tests.
    pub fn produce_once(&self, timestamp_ms: u64) -> Result<bool, DaemonError> {
        let mut node = self
            .node
            .lock()
            .map_err(|_| DaemonError::config("node lock poisoned"))?;
        if node.mempool_len() == 0 {
            return Ok(false);
        }
        let produced = node.produce(timestamp_ms)?;
        // Persist while holding the node lock so the block log's order matches the
        // chain-commit order even when the P2P import path is committing concurrently.
        self.block_log.append(&produced.block)?;
        drop(node);
        self.gossip_produced(&produced);
        Ok(true)
    }

    /// Run the daemon: serve RPC and **mine continuously** — attempt a block
    /// every `block_time_ms`, empty or not (Nakamoto consensus: producing a
    /// block IS the mining; the PoW grind inside `produce` is the work that
    /// authorizes it, and the coinbase pays this node's miner account).
    /// Persisting each. Returns a handle; the daemon runs until
    /// [`DaemonHandle::shutdown`].
    pub fn run(
        self,
        addr: &str,
        workers: usize,
        block_time_ms: u64,
    ) -> Result<DaemonHandle, DaemonError> {
        let rpc = self.serve_rpc(addr, workers)?;
        let rpc_addr = rpc.local_addr();
        let shutdown = Arc::new(AtomicBool::new(false));

        let node = self.node();
        let gossip = self.gossip.clone();
        let block_log = Arc::clone(&self.block_log);
        let sd = Arc::clone(&shutdown);
        let interval = block_time_ms.max(1);

        let produce = thread::spawn(move || {
            while !sd.load(Ordering::SeqCst) {
                // Sleep up to `interval` in small steps so shutdown is prompt.
                let mut waited = 0u64;
                while waited < interval && !sd.load(Ordering::SeqCst) {
                    let step = interval.saturating_sub(waited).min(50);
                    thread::sleep(Duration::from_millis(step));
                    waited += step;
                }
                if sd.load(Ordering::SeqCst) {
                    break;
                }
                // Nakamoto cadence: EVERY mining node attempts a block each
                // interval, empty or not — there is no proposer schedule; proof
                // of work is the only authorization, and when two miners find
                // competing blocks the heaviest-work fork choice resolves the
                // race exactly as in Bitcoin.
                //
                // Build the candidate under a BRIEF lock, then grind the proof of
                // work OFF the lock so RPC and block import stay responsive while
                // this node mines — essential at mainnet/RandomX difficulty,
                // where the grind runs for ~the target block time. Commit the
                // sealed block under another brief lock.
                let candidate = {
                    let Ok(n) = node.lock() else { break };
                    n.build_candidate(now_ms())
                };
                let Ok(candidate) = candidate else { continue };
                let sealed = match candidate.into_sealed_block() {
                    Ok(block) => block,
                    Err(_) => continue,
                };
                if sd.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut n) = node.lock() else { break };
                match n.commit_mined(sealed) {
                    Ok(produced) => {
                        // Persist under the node lock (order == commit order).
                        let _ = block_log.append(&produced.block);
                        drop(n);
                        if let Some(tcp) = &gossip {
                            tcp.broadcast(&NetMessage::NewBlock(produced.block.clone()));
                        }
                    }
                    Err(_) => drop(n),
                }
            }
        });

        Ok(DaemonHandle {
            rpc_addr,
            shutdown,
            produce,
            rpc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed, FROZEN testnet-1 chain-spec, embedded at compile time. This
    /// is the single source of truth both the macOS seed and the Windows validator
    /// load; its genesis hash is the cross-machine identity.
    const TESTNET_1_SPEC: &str = include_str!("../../../specs/testnet-1.json");

    #[test]
    fn testnet_1_frozen_genesis_is_byte_for_byte_deterministic() {
        // CROSS-PLATFORM DETERMINISM GATE. Peers handshake only on matching
        // `chain_id` + `genesis_hash`, so the frozen testnet-1 spec MUST yield
        // this exact genesis block hash and state root on EVERY platform (macOS,
        // Windows, Linux). The whole consensus path is integer-only, clock-free,
        // RNG-free, BTreeMap-ordered, and Borsh (LE) — so a divergence here is a
        // real portability bug, caught before a node ever fails to join.
        let spec = ChainSpec::from_json(TESTNET_1_SPEC).expect("frozen spec parses");
        assert_eq!(spec.chain_id, "sov-testnet-1");
        assert_eq!(spec.pow.as_deref(), Some("sha256d"));
        assert_eq!(spec.block_time_ms, Some(60_000));
        let genesis = spec
            .to_genesis_config()
            .expect("spec -> genesis config")
            .build()
            .expect("genesis builds (zero pre-mine)");
        // No pre-mine: genesis supply is exactly zero.
        assert_eq!(
            genesis.ledger.total_supply().unwrap(),
            sov_primitives::Balance::ZERO
        );
        let genesis_hash = genesis.block.hash().to_hex();
        let state_root = genesis.ledger.state_root().to_hex();
        println!("TESTNET-1 GENESIS HASH = {genesis_hash}");
        println!("TESTNET-1 STATE ROOT  = {state_root}");
        assert_eq!(
            state_root,
            "53a16c310523757a381db76699a30c3f1529a3817f6b03c0787d58bd598f98f9"
        );
        assert_eq!(
            genesis_hash,
            "9d6e4b331b0e62af909bfb363bfeca17b3b6a5b84f374f01ddaaeba0ae636b84"
        );
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sov-rec-{tag}-{nanos}.log"))
    }

    #[test]
    fn records_round_trip() {
        let path = tmp_path("rt");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        append_record(&mut f, b"alpha").unwrap();
        append_record(&mut f, b"bravo").unwrap();
        append_record(&mut f, b"charlie").unwrap();
        drop(f);

        let data = fs::read(&path).unwrap();
        let recs = read_records(&data);
        assert_eq!(recs, vec![b"alpha".as_ref(), b"bravo", b"charlie"]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn corrupt_record_recovers_valid_prefix() {
        let path = tmp_path("corrupt");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        append_record(&mut f, b"first").unwrap();
        append_record(&mut f, b"second").unwrap();
        append_record(&mut f, b"third").unwrap();
        drop(f);

        // Flip one byte inside the SECOND record's payload. The first record must
        // still be recovered; the corrupt one and everything after it are dropped.
        let mut data = fs::read(&path).unwrap();
        let first_len = 4 + Hash::LEN + b"first".len();
        let second_payload = first_len + 4 + Hash::LEN; // start of "second"
        data[second_payload] ^= 0xff;

        let recs = read_records(&data);
        assert_eq!(
            recs,
            vec![b"first".as_ref()],
            "only the intact prefix survives"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn keystore_encrypt_decrypt_round_trip() {
        let ks = Keystore {
            miners: vec![KeystoreEntry {
                account: "val01.node.sov".into(),
                seed_hex: "1".repeat(64),
                scheme: None,
                mnemonic: None,
                public_key: None,
            }],
        };
        let enc = ks
            .to_encrypted_json("correct horse battery staple")
            .unwrap();
        assert!(enc.contains("\"encrypted\": true"));
        assert!(!enc.contains(&"1".repeat(64)), "seed is not in cleartext");

        // Correct passphrase recovers the seed.
        let back =
            Keystore::from_encrypted_or_plain(&enc, Some("correct horse battery staple")).unwrap();
        assert_eq!(back.miners[0].seed_hex, ks.miners[0].seed_hex);

        // Wrong / missing passphrase fail.
        assert!(Keystore::from_encrypted_or_plain(&enc, Some("wrong")).is_err());
        assert!(Keystore::from_encrypted_or_plain(&enc, None).is_err());

        // A plaintext keystore still loads (no passphrase needed).
        let plain = serde_json::to_string(&ks).unwrap();
        let p = Keystore::from_encrypted_or_plain(&plain, None).unwrap();
        assert_eq!(p.miners[0].seed_hex, ks.miners[0].seed_hex);
    }

    #[test]
    fn truncated_tail_is_dropped() {
        let path = tmp_path("trunc");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        append_record(&mut f, b"complete").unwrap();
        append_record(&mut f, b"partial").unwrap();
        drop(f);

        // Cut the file in the middle of the second record (simulating a crash
        // mid-write): the first record is still recovered.
        let mut data = fs::read(&path).unwrap();
        data.truncate(4 + Hash::LEN + b"complete".len() + 6);
        let recs = read_records(&data);
        assert_eq!(recs, vec![b"complete".as_ref()]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn schema_version_is_stamped_then_enforced() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sov-schema-{nanos}"));
        fs::create_dir_all(&dir).unwrap();

        // First boot stamps the current version and succeeds.
        check_schema_version(&dir).unwrap();
        assert_eq!(
            fs::read_to_string(schema_version_path(&dir))
                .unwrap()
                .trim(),
            DATA_SCHEMA_VERSION.to_string()
        );
        // A matching version still boots.
        check_schema_version(&dir).unwrap();
        // An incompatible (future) version is rejected, not silently mis-handled.
        fs::write(
            schema_version_path(&dir),
            (DATA_SCHEMA_VERSION + 1).to_string(),
        )
        .unwrap();
        assert!(matches!(
            check_schema_version(&dir),
            Err(DaemonError::DataSchema(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn committed_but_undecodable_record_aborts_load() {
        // A checksum-VALID record that is not a Block is a fully-committed block
        // the binary can't read — load must FAIL (never silently drop a persisted
        // chain's tail), distinct from the torn-tail case which is dropped.
        let path = tmp_path("undecodable");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        append_record(&mut f, b"this is not a borsh-encoded block").unwrap();
        drop(f);

        let err = load_blocks(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path);
    }
}
