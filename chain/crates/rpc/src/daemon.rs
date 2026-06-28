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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use sov_state::Ledger;
use sov_types::{Block, Receipt};

use crate::sync_status::SyncShared;
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
    /// Override the GENESIS proof-of-work difficulty, as the count of required
    /// leading zero bits ([`Target::from_leading_zero_bits`]). `None` uses the
    /// policy's native difficulty. A testnet sets this LOW (e.g. `8`) so a single
    /// machine mines trivially from the start; the per-block LWMA retarget then
    /// tracks the live hashrate from there. Only the genesis difficulty is set —
    /// difficulty is otherwise determined by consensus — so this never weakens a
    /// running chain. (Affects only the sha256d target the seal compares against.)
    #[serde(default)]
    pub difficulty_leading_zeros: Option<u32>,
    /// Override the de-shield drain-limiter's per-window cap, in whole SOV. `None`
    /// uses the policy's native limit. A testnet relaxes this (and/or
    /// [`deshield_window_blocks`](Self::deshield_window_blocks)) so de-shielding is
    /// freely testable, while mainnet keeps its native circuit breaker. The limiter
    /// is NOT a genesis-header field, so changing it never alters the genesis hash
    /// (no reset), and relaxing it is replay-compatible (past de-shields that fit the
    /// stricter cap still fit the looser one).
    #[serde(default)]
    pub deshield_limit_sov: Option<u128>,
    /// Override the de-shield drain-limiter's rolling window length, in blocks. `None`
    /// uses the policy's native window; `0` disables the limiter entirely. Same
    /// no-reset / replay-safe properties as [`deshield_limit_sov`](Self::deshield_limit_sov).
    #[serde(default)]
    pub deshield_window_blocks: Option<u64>,
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
        if let Some(lz) = self.difficulty_leading_zeros {
            mining.sha256d_target = sov_mining::Target::from_leading_zero_bits(lz);
        }
        // De-shield drain-limiter overrides (relaxed on testnet; not a header field, so
        // no reset). A `0` window disables the limiter outright.
        if let Some(sov) = self.deshield_limit_sov {
            mining.deshield_limit_grains = Balance::from_sov(sov)
                .map_err(|e| DaemonError::config(format!("deshield_limit_sov: {e}")))?
                .grains();
        }
        if let Some(blocks) = self.deshield_window_blocks {
            mining.deshield_window_blocks = blocks;
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

/// Path of the chainstate snapshot within a data dir.
fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("chainstate.snapshot")
}

/// How often (in committed blocks of active-head advance) a running daemon refreshes
/// its chainstate snapshot. Frequent enough that even an unclean exit leaves only a
/// small post-snapshot gap to trusted-replay; the snapshot write is cheap and done off
/// the node lock, so this costs little. A clean shutdown always writes a final one.
const SNAPSHOT_EVERY_BLOCKS: u64 = 50;

/// On-disk snapshot format version (independent of the block-log schema). A snapshot
/// with a different version, a bad checksum, or any decode error is simply IGNORED —
/// the node falls back to replaying the (authoritative) block log — so this never
/// blocks a boot or risks mis-loading state.
const SNAPSHOT_VERSION: u32 = 1;

/// Serialize a chainstate snapshot of `chain` to a checksummed byte blob:
/// `[checksum: 32-byte BLAKE3 of payload][payload]`, where the payload is Borsh
/// `(version, head_hash, head_height, head_state_root, ledger_bytes, active_receipts)`.
/// Cheap (no I/O) so it can be produced under a brief node lock; pair with
/// [`write_snapshot_bytes`], which does the (off-lock) durable write.
fn snapshot_bytes(chain: &Blockchain) -> Vec<u8> {
    let head = chain.head();
    let payload = borsh::to_vec(&(
        SNAPSHOT_VERSION,
        head.hash(),
        head.header.height.get(),
        head.header.state_root,
        chain.ledger().to_snapshot_bytes(),
        chain.active_receipts_snapshot(),
    ))
    .expect("snapshot serialization is infallible");
    let checksum = Hash::digest(&payload);
    let mut out = Vec::with_capacity(Hash::LEN + payload.len());
    out.extend_from_slice(checksum.as_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Atomically write snapshot `bytes` to `path` (temp file + fsync + rename), so a
/// crash mid-write can never corrupt a prior good snapshot. The snapshot is a
/// fast-start CACHE — the block log stays the source of truth and the snapshot is
/// re-verified against it on load.
fn write_snapshot_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Read + integrity-check a snapshot written by [`snapshot_bytes`], returning the
/// resume inputs `(ledger, active_receipts, head_hash, head_height)`. `None` on
/// absence, a short file, a bad checksum, a version mismatch, or any decode error —
/// the caller then replays the log.
#[allow(clippy::type_complexity)]
fn load_snapshot(path: &Path) -> Option<(Ledger, Vec<(u64, Vec<Receipt>)>, Hash, u64)> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() < Hash::LEN {
        return None;
    }
    let (checksum, payload) = bytes.split_at(Hash::LEN);
    if Hash::digest(payload).as_bytes() != checksum {
        return None; // corrupt / torn snapshot — ignore, replay the log
    }
    let (version, head_hash, head_height, _state_root, ledger_bytes, active_receipts): (
        u32,
        Hash,
        u64,
        Hash,
        Vec<u8>,
        Vec<(u64, Vec<Receipt>)>,
    ) = borsh::from_slice(payload).ok()?;
    if version != SNAPSHOT_VERSION {
        return None;
    }
    let ledger = Ledger::from_snapshot_bytes(&ledger_bytes).ok()?;
    Some((ledger, active_receipts, head_hash, head_height))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Nonces per inner micro-batch. Small, so the grind can stop near the end of a time
/// SLICE for ANY algorithm — microseconds-per-hash Sha256d or milliseconds-per-hash
/// RandomX alike — keeping the throttle and tip-following responsive.
const GRIND_MICRO_BATCH: u64 = 64;

/// How long the miner grinds before YIELDING the CPU. It then sleeps for a comparable
/// span, so mining runs at roughly a 50% duty cycle on one core. This is the fix for
/// "the node stopped connecting once it started mining": a tight, 100%-pegging grind
/// loop starves the P2P worker and the (CPU-heavy ML-KEM) handshake threads enough that
/// peers time out and drop. A desktop wallet must stay responsive and KEEP ITS PEERS
/// while it mines. The difficulty retarget adapts to the resulting effective hashrate,
/// so block time is unaffected; rewards still split by each miner's *relative* hashpower.
const GRIND_SLICE: Duration = Duration::from_millis(15);

/// How often the miner logs a "still searching" heartbeat while grinding a block, so the
/// Node log shows live activity between blocks (which are ~`target_block_ms` apart)
/// instead of going silent and looking hung.
const MINING_HEARTBEAT: Duration = Duration::from_secs(10);

/// On startup, how long to wait for peers to connect (and to sync to the tip) BEFORE
/// grinding any proof of work. Peer connection must happen before mining: it gives the
/// (CPU-heavy) handshake full processor time so links actually form, and it guarantees a
/// joining node downloads the existing chain instead of mining a fork ahead of the
/// network. If no peer has connected by the end of this window, a solo/seed node starts
/// mining anyway to bootstrap — it cannot wait forever for peers that may not exist.
const CONNECT_GRACE: Duration = Duration::from_secs(15);

/// What the block-production loop is doing right now — tracked so each transition is
/// logged once (not every iteration).
#[derive(PartialEq, Eq, Clone, Copy)]
enum MinePhase {
    /// Waiting for peers to connect before mining (startup grace).
    Connecting,
    /// Connected but behind a heavier peer chain — downloading, not mining.
    Syncing,
    /// At the tip (or solo past the grace) — actively mining.
    Mining,
}

/// A random 64-bit nonce start, so independent miners search different regions of the
/// space rather than racing the same nonces (Monero/Bitcoin practice).
fn random_nonce_start() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    u64::from_le_bytes(b)
}

/// Append a timestamped mining diagnostic to the optional Node-log sink (the desktop
/// app's log buffer), capped like the GUI's own logger. A no-op when there is no sink.
/// This makes the block-production loop OBSERVABLE — whether it mined, paused to sync,
/// or could not build a candidate — instead of a silent thread.
fn daemon_log(sink: &Option<Arc<Mutex<Vec<String>>>>, msg: impl AsRef<str>) {
    let Some(sink) = sink else { return };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    let line = format!(
        "{:02}:{:02}:{:02}  mine: {}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        msg.as_ref()
    );
    if let Ok(mut v) = sink.lock() {
        v.push(line);
        let n = v.len();
        if n > 5_000 {
            v.drain(0..n - 5_000);
        }
    }
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
    /// Where the chainstate fast-start snapshot is written/refreshed.
    snapshot_path: PathBuf,
    /// Whether this boot resumed from a chainstate snapshot (tier 1) rather than
    /// replaying the block log. Observability for operators/tests.
    resumed_fast: bool,
    /// Live sync telemetry, shared with the [`P2p`](crate::p2p::P2p) engine. When set,
    /// the production loop GATES mining on it — a node does not mine while it is still
    /// catching up to a heavier peer chain (so a freshly-joined node syncs the existing
    /// chain instead of extending its own competing fork).
    sync_status: Option<Arc<SyncShared>>,
    /// Optional Node-log sink so the block-production loop reports what it is doing
    /// (mined a block, paused to sync, or could not build a candidate) — observability
    /// for an operator instead of a silent mining thread.
    log: Option<Arc<Mutex<Vec<String>>>>,
}

/// A running daemon's RPC + block-production threads, with graceful shutdown.
pub struct DaemonHandle {
    rpc_addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    produce: JoinHandle<()>,
    rpc: RpcHandle,
    /// The shared in-process node — so a co-located UI (the desktop app) can read
    /// live state DIRECTLY instead of over a loopback RPC socket (which can time out
    /// and falsely read "offline" while the node is actually fine).
    node: Arc<Mutex<Node>>,
}

impl DaemonHandle {
    /// The bound RPC address.
    pub fn rpc_addr(&self) -> std::net::SocketAddr {
        self.rpc_addr
    }

    /// The shared in-process node, for direct (no-socket) status reads by a co-located
    /// UI. Use `try_lock` so a momentarily-busy node never blocks the caller.
    pub fn node(&self) -> Arc<Mutex<Node>> {
        Arc::clone(&self.node)
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
        Self::new_with_progress(
            genesis,
            data_dir,
            mempool_capacity,
            max_block_txs,
            miner_keys,
            &mut |_, _| {},
        )
    }

    /// Like [`new`](Self::new), but STREAMS replay progress to `on_progress(done,
    /// total)` as the block log is re-indexed on boot — so a UI can show a live
    /// "indexing N/total" counter instead of appearing to hang during a one-time
    /// replay of a long chain. Fired only on the replay tiers (a snapshot resume is
    /// effectively instant); throttled inside the chain so it's cheap.
    pub fn new_with_progress(
        genesis: &GenesisConfig,
        data_dir: impl AsRef<Path>,
        mempool_capacity: usize,
        max_block_txs: usize,
        miner_keys: Vec<(AccountId, Keypair)>,
        on_progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Self, DaemonError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        // Refuse to boot against a data dir written by an incompatible schema,
        // rather than mis-replaying it (node-data stability across upgrades).
        check_schema_version(&data_dir)?;

        let persisted = load_blocks(&blocks_path(&data_dir))?;
        let resumed = persisted.len();
        let snap_path = snapshot_path(&data_dir);
        // THREE-TIER fast start, each tier falling back to the next on ANY
        // inconsistency, so a node ALWAYS boots on a state verified against its own
        // (authoritative, integrity-checked) block log:
        //   1. Chainstate SNAPSHOT — load the tip state directly and rebuild the
        //      fork-choice index from block headers (no execution), then trusted-replay
        //      only the small post-snapshot gap. Bounded by state size, independent of
        //      chain length (the Bitcoin/Zcash chainstate model). Sub-second.
        //   2. Trusted REPLAY — re-execute the heaviest chain on the live ledger (no
        //      per-block clone / root recompute / PoW re-verify). Seconds.
        //   3. Full VERIFIED import — re-validate every block from genesis. Minutes;
        //      the last-resort source of truth if both caches are unusable.
        let mut chain = Blockchain::new(genesis)?;
        let resumed_fast = match load_snapshot(&snap_path) {
            Some((ledger, receipts, head, height)) => chain
                .resume_from_snapshot(ledger, receipts, head, height, &persisted)
                .unwrap_or(false),
            None => false,
        };
        if !resumed_fast {
            chain = Blockchain::new(genesis)?;
            if !chain
                .replay_log_trusted(&persisted, on_progress)
                .unwrap_or(false)
            {
                // Trusted replay's state root didn't verify — rebuild with FULL
                // validation, but along the heaviest chain IN ORDER (O(N)). Importing
                // the raw `persisted` log here instead would re-run every historical
                // reorg from genesis (O(reorgs×N)) — the multi-minute / "hung" boot.
                chain = Blockchain::new(genesis)?;
                chain.replay_log_verified(&persisted, on_progress)?;
            }
            // We replayed a non-empty chain rather than resuming a snapshot (none
            // existed, or it was stale). Write one NOW so the next start is an instant
            // tier-1 resume even if this process exits before the periodic/shutdown
            // snapshot runs (a force-quit or crash). Best-effort: a write failure just
            // means the next start replays again.
            if resumed > 0 {
                let _ = write_snapshot_bytes(&snap_path, &snapshot_bytes(&chain));
            }
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
            snapshot_path: snap_path,
            resumed_fast,
            sync_status: None,
            log: None,
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

    /// Whether this boot resumed instantly from a chainstate snapshot (tier 1) rather
    /// than replaying the block log (tier 2/3).
    pub fn resumed_from_snapshot(&self) -> bool {
        self.resumed_fast
    }

    /// Write a chainstate snapshot of the current head NOW, atomically. The running
    /// daemon also snapshots periodically and on clean shutdown; this lets an operator
    /// (or the desktop app on quit) force a checkpoint so the next start is an instant
    /// tier-1 resume. The (cheap) serialization happens under a brief node lock; the
    /// durable write does not.
    pub fn write_snapshot_now(&self) -> io::Result<()> {
        let bytes = {
            let n = self
                .node
                .lock()
                .map_err(|_| io::Error::other("node lock poisoned"))?;
            snapshot_bytes(n.chain())
        };
        write_snapshot_bytes(&self.snapshot_path, &bytes)
    }

    /// Attach a P2P transport so blocks this daemon produces are gossiped to
    /// peers. Pair with a [`P2p`](crate::p2p::P2p) engine bound to the
    /// same [`node`](Self::node) handle for the receive/sync side.
    pub fn with_gossip(mut self, tcp: Arc<TcpNode>) -> Self {
        self.gossip = Some(tcp);
        self
    }

    /// Gate block production on sync state: while the shared [`SyncShared`] reports we
    /// are behind a heavier peer chain, the production loop does NOT mine. Share the
    /// SAME handle with [`P2p::with_sync_status`](crate::p2p::P2p::with_sync_status) (the
    /// engine that writes it). Without this a freshly-joined node mines its own fork
    /// from its local height while it should be downloading the existing chain, and the
    /// network only reconverges after a deep reorg; with it, a node joins cleanly —
    /// sync first, mine once caught up. A solo node (no heavier peer) is never gated.
    pub fn with_sync_status(mut self, status: Arc<SyncShared>) -> Self {
        self.sync_status = Some(status);
        self
    }

    /// Surface block-production diagnostics (mined a block / paused to sync / could not
    /// build a candidate) into `sink` — typically the desktop app's Node-log buffer — so
    /// the mining loop is never a silent black box.
    pub fn with_log_sink(mut self, sink: Arc<Mutex<Vec<String>>>) -> Self {
        self.log = Some(sink);
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

    /// Start the JSON-RPC server over this daemon's node. The P2P transport (if any)
    /// is handed to it so a transaction accepted via `sov_submitTransaction` is
    /// gossiped to peers — reaching every node's mempool so any miner can include it,
    /// not just the node it was submitted to.
    pub fn serve_rpc(&self, addr: &str, workers: usize) -> io::Result<RpcHandle> {
        RpcServer::new(self.node())
            .with_gossip(self.gossip.clone())
            .with_sync_status(self.sync_status.clone())
            .start(addr, workers)
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
        let handle_node = self.node(); // for the DaemonHandle's direct-read accessor
        let gossip = self.gossip.clone();
        let block_log = Arc::clone(&self.block_log);
        let snap_path = self.snapshot_path.clone();
        let sync_status = self.sync_status.clone();
        let log = self.log.clone();
        let sd = Arc::clone(&shutdown);

        let produce = thread::spawn(move || {
            // Refresh the chainstate snapshot when the head advances by this many
            // blocks. Start at 0 so the just-loaded state is snapshotted soon after
            // boot — making the very NEXT restart a tier-1 instant resume even if THIS
            // boot had to replay (no snapshot existed yet, or it was stale).
            let _ = block_time_ms; // block cadence now comes from difficulty, not a sleep
                                   // NOTE: we deliberately do NOT lower this thread's OS priority. Doing so
                                   // (v0.1.25) risked a PRIORITY INVERSION — the low-priority miner briefly holds
                                   // the node lock (build/commit/snapshot) and a normal-priority networking thread
                                   // waiting on that lock would be blocked by a thread the scheduler won't run,
                                   // stalling peer connections. The duty-cycle THROTTLE below (a normal-priority
                                   // thread that sleeps OFF the lock) frees CPU for networking without that risk.
            let mut last_snap_height = 0u64;
            // Track the mining phase so each transition (connecting → syncing → mining) is
            // logged once. `start_at` bounds the connect-before-mining grace window.
            let mut last_phase: Option<MinePhase> = None;
            let start_at = Instant::now();
            // Hashrate meter: hashes attempted since the last publish, and when. Published
            // to the shared telemetry ~1×/s so the UI can show this node's H/s (and an
            // operator can confirm that multi-miner block shares track hashpower).
            let mut hashes_acc = 0u64;
            let mut rate_clock = Instant::now();
            // CONTINUOUS MINING (the Monero/Zcash/Bitcoin model, not "sleep then mine"):
            // the node grinds proof of work on a template built on the CURRENT tip,
            // batch after batch, abandoning the template the instant a better tip arrives.
            // Block discovery is therefore a memoryless lottery at the chain's live
            // difficulty — every miner has an equal per-hash chance each instant — so any
            // number of miners SHARE blocks fairly instead of whoever-got-ahead lapping
            // the rest (the fatal flaw of fixed-interval mining). The per-block difficulty
            // retarget keeps the whole network at `target_block_ms` no matter how many
            // miners join. Mining runs only when at the tip; a far-behind node downloads
            // first (the IBD gate).
            while !sd.load(Ordering::SeqCst) {
                // Periodic chainstate snapshot — keyed off the ACTIVE-head height, so it
                // captures blocks IMPORTED from peers as well as ones we mined. Serialize
                // under a brief lock; the fsync happens off the lock.
                let pending = {
                    let Ok(n) = node.lock() else { break };
                    let h = n.chain().height();
                    (h >= last_snap_height + SNAPSHOT_EVERY_BLOCKS)
                        .then(|| (h, snapshot_bytes(n.chain())))
                };
                if let Some((h, bytes)) = pending {
                    if write_snapshot_bytes(&snap_path, &bytes).is_ok() {
                        last_snap_height = h;
                    }
                }

                // CONNECT-then-SYNC-then-MINE. Decide the phase:
                //   • Connecting — startup grace, no peer yet: wait so handshakes get full
                //     CPU and we never mine ahead of the network. (Past the grace with no
                //     peers, a solo/seed node falls through to Mining to bootstrap.)
                //   • Syncing — connected but behind a heavier peer chain: download first
                //     (the IBD gate; only a real >1-block deficit, never a 1-block race, so
                //     two miners at the tip both keep mining and share rewards).
                //   • Mining — at the tip: grind.
                let peers = sync_status.as_ref().map(|s| s.authed_peers()).unwrap_or(0);
                let behind = sync_status
                    .as_ref()
                    .map(|s| s.should_gate_mining())
                    .unwrap_or(false);
                let phase =
                    if sync_status.is_some() && peers == 0 && start_at.elapsed() < CONNECT_GRACE {
                        // P2P is active but no peer has connected yet — wait (grace), so the
                        // handshake gets full CPU and we don't mine ahead of the network. With
                        // no P2P at all (standalone), there is nothing to wait for, so mine.
                        MinePhase::Connecting
                    } else if behind {
                        MinePhase::Syncing
                    } else {
                        MinePhase::Mining
                    };
                if last_phase != Some(phase) {
                    match phase {
                        MinePhase::Connecting => {
                            daemon_log(&log, "⏳ connecting to peers before mining…")
                        }
                        MinePhase::Syncing => {
                            let local = node.lock().map(|n| n.chain().height()).unwrap_or(0);
                            let best = sync_status
                                .as_ref()
                                .map(|s| s.best_peer_height())
                                .unwrap_or(0);
                            daemon_log(
                                &log,
                                format!(
                                    "⏸ mining PAUSED — downloading the existing chain (we're at {local}, peer at {best})"
                                ),
                            );
                        }
                        MinePhase::Mining => {
                            let h = node.lock().map(|n| n.chain().height()).unwrap_or(0);
                            let how = if peers > 0 {
                                "at the network tip"
                            } else {
                                "solo"
                            };
                            daemon_log(&log, format!("▶ mining {how} at height {h}"));
                        }
                    }
                    last_phase = Some(phase);
                }
                if phase != MinePhase::Mining {
                    // Not mining right now (connecting/downloading): report 0 H/s so the UI
                    // shows this node is paused, not silently stalled.
                    if let Some(ss) = sync_status.as_ref() {
                        ss.set_local_hashrate(0);
                    }
                    hashes_acc = 0;
                    rate_clock = Instant::now();
                    // Connecting or syncing: don't grind. Re-check shortly.
                    let mut waited = 0u64;
                    while waited < 200 && !sd.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(50));
                        waited += 50;
                    }
                    continue;
                }

                // Build a template on the CURRENT tip (brief lock); grind OFF the lock.
                let (mut candidate, tip_height) = {
                    let Ok(mut n) = node.lock() else { break };
                    let h = n.chain().height();
                    match n.build_candidate(now_ms()) {
                        Ok((c, excluded)) => {
                            // EVICT front-of-line unminable txs (their turn has come and
                            // they permanently fail — e.g. a sender who cannot afford
                            // amount + fee), so they stop clogging the mempool and
                            // producing empty blocks; log the reason so it is never
                            // silent. A tx merely blocked behind such a gap is left
                            // alone (select won't pick it until the gap is filled).
                            for (stx, reason) in excluded {
                                if n.account_nonce(&stx.transaction.signer) == stx.transaction.nonce
                                {
                                    let id = stx.id();
                                    n.drop_tx(&id);
                                    let hex = id.to_hex();
                                    daemon_log(
                                        &log,
                                        format!(
                                            "⚠ dropped unminable tx {}… (nonce {}): {reason}",
                                            &hex[..hex.len().min(12)],
                                            stx.transaction.nonce
                                        ),
                                    );
                                }
                            }
                            (c, h)
                        }
                        Err(e) => {
                            drop(n);
                            daemon_log(&log, format!("could not build a block candidate: {e}"));
                            thread::sleep(Duration::from_millis(200));
                            continue;
                        }
                    }
                };

                // Grind OFF the lock, in time slices that YIELD the CPU between them, so
                // the network/handshake/RPC/UI threads always get scheduled (a 100%-pegged
                // grind drops peers — see GRIND_SLICE). Between slices, abandon the
                // template if shutdown is requested or the tip moved (we adopted a peer's
                // block), so no work is wasted on a stale tip.
                let mining_height = candidate.block().header.height.get();
                let grind_started = Instant::now();
                let mut last_beat = grind_started;
                let mut nonce = random_nonce_start();
                let mut sealed = None;
                'grind: loop {
                    if sd.load(Ordering::SeqCst) {
                        break;
                    }
                    // Grind one slice (bounded by wall-clock, so it works for any PoW algo).
                    let slice_start = Instant::now();
                    while slice_start.elapsed() < GRIND_SLICE {
                        if let Some(block) = candidate.try_seal_batch(nonce, GRIND_MICRO_BATCH) {
                            sealed = Some(block);
                            break 'grind;
                        }
                        nonce = nonce.wrapping_add(GRIND_MICRO_BATCH);
                        hashes_acc = hashes_acc.saturating_add(GRIND_MICRO_BATCH);
                        if sd.load(Ordering::SeqCst) {
                            break 'grind;
                        }
                    }
                    // YIELD: sleep ~the slice's own grind time (≈50% duty), capped, so the
                    // miner never starves the rest of the node. THE peer-drop fix.
                    thread::sleep(slice_start.elapsed().min(Duration::from_millis(250)));
                    // Publish the measured hashrate ~1×/s (H/s = hashes / elapsed).
                    if rate_clock.elapsed() >= Duration::from_secs(1) {
                        let ms = rate_clock.elapsed().as_millis().max(1) as u64;
                        if let Some(ss) = sync_status.as_ref() {
                            ss.set_local_hashrate(hashes_acc.saturating_mul(1000) / ms);
                        }
                        hashes_acc = 0;
                        rate_clock = Instant::now();
                    }
                    // Liveness heartbeat so the operator sees active mining between blocks.
                    if last_beat.elapsed() >= MINING_HEARTBEAT {
                        daemon_log(
                            &log,
                            format!(
                                "⛏ mining block {mining_height} — searching for proof of work ({}s)",
                                grind_started.elapsed().as_secs()
                            ),
                        );
                        last_beat = Instant::now();
                    }
                    // A new tip? `try_lock` so a momentarily-busy node never stalls the grind.
                    if let Ok(n) = node.try_lock() {
                        if n.chain().height() != tip_height {
                            break; // rebuild on the new tip
                        }
                    }
                }
                let Some(sealed) = sealed else { continue }; // shutdown or new tip → rebuild
                if sd.load(Ordering::SeqCst) {
                    break;
                }

                // Commit + persist under a brief lock (order == commit order); gossip off it.
                {
                    let Ok(mut n) = node.lock() else { break };
                    match n.commit_mined(sealed) {
                        Ok(produced) => {
                            let height = produced.block.header.height.get();
                            let _ = block_log.append(&produced.block);
                            drop(n);
                            daemon_log(&log, format!("⛏ mined block {height}"));
                            if let Some(tcp) = &gossip {
                                tcp.broadcast(&NetMessage::NewBlock(produced.block.clone()));
                            }
                        }
                        // The tip moved between grind and commit (our block no longer
                        // extends the head): not an error — rebuild next iteration.
                        Err(_) => drop(n),
                    }
                }
            }
            // Final snapshot on clean shutdown, so the next start is a tier-1 instant
            // resume with NO post-snapshot gap to replay.
            if let Ok(n) = node.lock() {
                let bytes = snapshot_bytes(n.chain());
                drop(n);
                let _ = write_snapshot_bytes(&snap_path, &bytes);
            }
        });

        Ok(DaemonHandle {
            rpc_addr,
            shutdown,
            produce,
            rpc,
            node: handle_node,
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
        assert_eq!(spec.block_time_ms, Some(30_000));
        assert_eq!(spec.difficulty_leading_zeros, Some(8));
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
            "87edea95a5bdbc1b4d0d915cee7efafabba47d5ee131184f57e4fcce9df76c50"
        );
        assert_eq!(
            genesis_hash,
            "4b603052c7f38fe4f086a4d99eace27b2aafc6ce427e1579c316eaa371b20076"
        );
    }

    #[test]
    fn deshield_limiter_override_applies_without_changing_the_genesis_hash() {
        // Testnet relaxes the de-shield drain limiter. The override must reach the
        // mining policy...
        let spec = ChainSpec::from_json(TESTNET_1_SPEC).expect("frozen spec parses");
        assert_eq!(spec.deshield_limit_sov, Some(1_000_000));
        assert_eq!(spec.deshield_window_blocks, Some(12));
        let cfg = spec.to_genesis_config().expect("spec -> genesis config");
        assert_eq!(
            cfg.mining.deshield_limit_grains,
            sov_primitives::Balance::from_sov(1_000_000)
                .unwrap()
                .grains()
        );
        assert_eq!(cfg.mining.deshield_window_blocks, 12);
        // ...but the limiter is NOT a genesis-header field, so the genesis hash is
        // IDENTICAL with or without the override — proving relaxing it needs no reset
        // (and a node resumes its existing chain under the looser rule).
        let mut bare = spec.clone();
        bare.deshield_limit_sov = None;
        bare.deshield_window_blocks = None;
        let with = spec
            .to_genesis_config()
            .unwrap()
            .build()
            .unwrap()
            .block
            .hash();
        let without = bare
            .to_genesis_config()
            .unwrap()
            .build()
            .unwrap()
            .block
            .hash();
        assert_eq!(
            with, without,
            "de-shield limiter override must not change the genesis hash"
        );
        assert_eq!(
            with.to_hex(),
            "4b603052c7f38fe4f086a4d99eace27b2aafc6ce427e1579c316eaa371b20076"
        );
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Give each test file its OWN created subdirectory, rather than a bare file in
        // the shared temp root: the parent then provably exists at write time (no
        // dependence on a transient temp root) and tests can never collide on a path —
        // removing a parallel-run flake where an atomic snapshot write (temp + rename)
        // raced the temp directory.
        let dir = std::env::temp_dir().join(format!("sov-rec-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir.join("data.log")
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

    fn gate_test_genesis() -> GenesisConfig {
        GenesisConfig {
            chain_id: "sov-gate-test".into(),
            timestamp_ms: 1_000,
            accounts: vec![GenesisAccount {
                account: AccountId::new("val01.node.sov").unwrap(),
                key: Keypair::from_seed([7; 32]).public_key(),
                balance: Balance::ZERO,
            }],
            mining: MiningPolicy::test(),
            vesting: vec![],
        }
    }

    #[test]
    fn mining_is_gated_while_behind_then_resumes_when_caught_up() {
        // The bootstrap-correctness guarantee: a node that is BEHIND a heavier peer
        // chain does not mine (it would only fork), and it resumes mining the instant
        // it has caught up. This is what makes a freshly-joined node converge onto the
        // existing chain instead of extending its own competing one.
        let genesis = gate_test_genesis();
        let dir = std::env::temp_dir().join(format!(
            "sov-gate-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sync = Arc::new(SyncShared::new());
        // Start gated: pretend a peer is far ahead (100 blocks behind ⇒ initial download).
        sync.update(100, 100, 1);
        let daemon = Daemon::new(
            &genesis,
            &dir,
            1024,
            256,
            vec![(
                AccountId::new("val01.node.sov").unwrap(),
                Keypair::from_seed([7; 32]),
            )],
        )
        .unwrap()
        .with_sync_status(Arc::clone(&sync));
        // Fast cadence so the test is quick; the node mines empty blocks each interval.
        let handle = daemon.run("127.0.0.1:0", 1, 20).unwrap();

        // Across many intervals while "behind", the chain must NOT advance past genesis.
        thread::sleep(Duration::from_millis(300));
        let gated_height = handle.node().lock().unwrap().chain().height();
        assert_eq!(
            gated_height, 0,
            "a node behind a heavier peer must not mine its own fork"
        );

        // Catch up to the tip (0 behind): the gate clears and mining resumes.
        sync.update(0, 100, 1);
        let mut resumed = false;
        for _ in 0..200 {
            if handle.node().lock().unwrap().chain().height() > 0 {
                resumed = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(resumed, "mining resumes once caught up to the network tip");

        handle.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_sync_status_a_solo_node_mines_freely() {
        // No telemetry attached (or no heavier peer) ⇒ never gated, so a solo seed node
        // bootstraps the network by mining normally. Guards against the gate ever
        // wedging a lone node.
        let genesis = gate_test_genesis();
        let dir = std::env::temp_dir().join(format!(
            "sov-solo-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let daemon = Daemon::new(
            &genesis,
            &dir,
            1024,
            256,
            vec![(
                AccountId::new("val01.node.sov").unwrap(),
                Keypair::from_seed([7; 32]),
            )],
        )
        .unwrap();
        let handle = daemon.run("127.0.0.1:0", 1, 20).unwrap();
        let mut mined = false;
        for _ in 0..200 {
            if handle.node().lock().unwrap().chain().height() > 0 {
                mined = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(mined, "a solo node with no heavier peer mines normally");
        handle.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_bytes_round_trip_and_corruption_is_detected() {
        // A snapshot blob written by `snapshot_bytes` loads back to the same head and
        // receipts; a single flipped byte fails the checksum and is rejected (the node
        // then falls back to replaying the authoritative block log).
        let mut chain = {
            let config = GenesisConfig {
                chain_id: "sov-test".into(),
                timestamp_ms: 1_000,
                accounts: vec![GenesisAccount {
                    account: AccountId::new("val01.node.sov").unwrap(),
                    key: Keypair::from_seed([1; 32]).public_key(),
                    balance: Balance::from_sov(10).unwrap(),
                }],
                mining: MiningPolicy::test(),
                vesting: vec![],
            };
            Blockchain::new(&config).unwrap()
        };
        let block = chain.produce_block(vec![], 2_000).unwrap();
        chain.import_block(block).unwrap();

        let path = tmp_path("snap");
        write_snapshot_bytes(&path, &snapshot_bytes(&chain)).unwrap();
        let (_ledger, _receipts, head, height) = load_snapshot(&path).expect("snapshot loads");
        assert_eq!(head, chain.head().hash());
        assert_eq!(height, chain.height());

        // Flip a byte in the payload — the checksum must reject it.
        let mut raw = fs::read(&path).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0xff;
        fs::write(&path, &raw).unwrap();
        assert!(
            load_snapshot(&path).is_none(),
            "a corrupt snapshot is rejected, not loaded"
        );
        let _ = fs::remove_file(&path);
    }
}
