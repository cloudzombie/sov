//! Isolated testnet genesis + node bundle generation.
//!
//! Everything here is PINNED so a run is reproducible bit-for-bit: chain id,
//! genesis timestamp, policy, PoW seal, genesis difficulty, block cadence, and
//! every signing seed. The seeds are throwaway test constants — this chain can
//! never carry real value (its genesis differs from mainnet's, so no mainnet
//! peer will ever handshake with it), and the harness ASSERTS that difference
//! instead of assuming it.
//!
//! Keys are derived by the REAL `sov-wallet keygen` binary (hybrid post-quantum
//! Ed25519+ML-DSA-65, the same derivation the node uses) — the harness holds no
//! crypto of its own, so it can never drift from consensus.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::json;

use crate::backend::NodePlan;
use crate::util::{labeled_value, run_cmd_timeout};

/// The isolated network's chain id. Deliberately NOT containing "mainnet"
/// (which would attach the baked mainnet activation preset) and not a
/// canonical id (`sov-mainnet` / `sov-testnet-1`), so the binary applies no
/// hardcoded genesis pin — the spec fully defines this throwaway identity.
pub const CHAIN_ID: &str = "sov-e2e-v020-s8a";

/// Frozen MAINNET genesis hash — used ONLY to assert the e2e genesis differs.
pub const MAINNET_GENESIS_HASH: &str =
    "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d";
/// Frozen testnet-1 genesis hash — same negative assertion.
pub const TESTNET1_GENESIS_HASH: &str =
    "4d7d9123a489f4fd29486da3d66a6c20b04953cb886dee847662e11af293da15";

/// The genesis hash this pinned spec MUST reproduce, observed from a real node
/// on the first green run and pinned since (the KAT philosophy: consensus
/// bytes are frozen and any drift fails loudly). Also written into the spec's
/// `expected_genesis_hash`, so the NODE double-checks it at boot. Empty means
/// "not yet pinned" — the genesis step then FAILS with instructions, so an
/// unpinned harness can never quietly pass. (Bare hex, `Hash::to_hex` form.)
pub const EXPECTED_GENESIS_HASH: &str =
    "c53be5ab278b8349589de72ae0d105d5f6be757602a3971bd43862ae816a2e12";

/// Pinned genesis timestamp: 2026-01-01T00:00:00Z.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_767_225_600_000;

/// Block cadence for the run (daemon heartbeat AND consensus LWMA target —
/// written to both, as `sov-testnet gen` does). 2s: fast enough for a bounded
/// run, slow enough that loopback propagation (<1ms) makes tip races rare.
pub const BLOCK_TIME_MS: u64 = 2_000;

/// Genesis difficulty as leading zero bits — trivial, so one laptop mines from
/// block 1; LWMA then tracks the real hashrate.
pub const DIFFICULTY_LEADING_ZEROS: u32 = 8;

/// Gas price of the `mainnet_like` policy preset this spec selects, in grains
/// per gas (mirrors `MiningPolicy::mainnet_like().gas_price`). Fees are LIVE on
/// this net (mainnet fidelity); exact-delta assertions compute the fee from the
/// on-chain receipt's `gas_used` × this pinned price.
pub const GAS_PRICE_GRAINS: u128 = 10;

/// Grains per XUS (10^8 — `sov_primitives::GRAINS_PER_SOV`).
pub const GRAINS_PER_XUS: u128 = 100_000_000;

/// One pinned identity: account name + the throwaway seed that controls it.
pub struct Role {
    pub account: &'static str,
    pub seed_hex: String,
}

/// A derived key bundle, produced by the real `sov-wallet keygen`.
#[derive(Clone)]
pub struct KeyInfo {
    pub account: String,
    pub seed_hex: String,
    pub public_key: String,
    /// The seed's `xus1…` shielded (Orchard v1) address.
    pub shielded_addr: String,
}

/// The pinned cast: 3 miners, 2 observers (node identities), 2 wallet users.
/// Seeds are fixed byte patterns — reproducible, obviously non-secret, and
/// never valuable (this chain exists for minutes on loopback).
pub fn roles() -> Vec<Role> {
    fn seed(byte: u8) -> String {
        hex_repeat(byte)
    }
    vec![
        Role {
            account: "val01.e2e.sov",
            seed_hex: seed(0xe1),
        },
        Role {
            account: "val02.e2e.sov",
            seed_hex: seed(0xe2),
        },
        Role {
            account: "val03.e2e.sov",
            seed_hex: seed(0xe3),
        },
        Role {
            account: "obs04.e2e.sov",
            seed_hex: seed(0xe4),
        },
        Role {
            account: "obs05.e2e.sov",
            seed_hex: seed(0xe5),
        },
        Role {
            account: "user1.e2e.sov",
            seed_hex: seed(0xa1),
        },
        Role {
            account: "user2.e2e.sov",
            seed_hex: seed(0xa2),
        },
    ]
}

fn hex_repeat(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// Derive the key bundle for `role` with the REAL wallet binary (offline
/// command, no node needed) and parse its labeled output.
pub fn keygen(wallet_bin: &Path, role: &Role) -> Result<KeyInfo, String> {
    let out = run_cmd_timeout(
        wallet_bin,
        &["keygen", &role.seed_hex, role.account],
        None,
        Duration::from_secs(120),
    )?;
    if !out.status_ok {
        return Err(format!(
            "sov-wallet keygen failed for {}: {}",
            role.account, out.stderr
        ));
    }
    let public_key = labeled_value(&out.stdout, "public_key")
        .ok_or_else(|| format!("keygen output for {} lacks `public_key`", role.account))?;
    let shielded_addr = labeled_value(&out.stdout, "shielded")
        .ok_or_else(|| format!("keygen output for {} lacks `shielded`", role.account))?;
    if !public_key.starts_with("hybrid65:0x") {
        return Err(format!(
            "{}: expected a hybrid65 public key, got `{public_key}`",
            role.account
        ));
    }
    if !shielded_addr.starts_with("xus1") {
        return Err(format!(
            "{}: expected a xus1… shielded address, got `{shielded_addr}`",
            role.account
        ));
    }
    Ok(KeyInfo {
        account: role.account.to_string(),
        seed_hex: role.seed_hex.clone(),
        public_key,
        shielded_addr,
    })
}

/// The generated network: node plans plus the derived keys, ready to start.
/// (Each plan carries the shared chain-spec path.)
pub struct Net {
    pub plans: Vec<NodePlan>,
    /// Keys by account name, same order as [`roles`].
    pub keys: Vec<KeyInfo>,
}

impl Net {
    pub fn key(&self, account: &str) -> &KeyInfo {
        self.keys
            .iter()
            .find(|k| k.account == account)
            .expect("pinned role exists")
    }
    pub fn plan(&self, name: &str) -> &NodePlan {
        self.plans
            .iter()
            .find(|p| p.name == name)
            .expect("pinned node exists")
    }
}

/// Generate the whole isolated network under `run_dir`: one pinned chain-spec
/// plus five node bundles (3 miners, observer, late-join observer), all on
/// loopback. Every genesis account is balance ZERO — `mainnet_like` has no
/// pre-mine; spendable coins exist only once mined (real emission, real fees).
pub fn generate(
    run_dir: &Path,
    wallet_bin: &Path,
    base_rpc: u16,
    base_p2p: u16,
) -> Result<Net, String> {
    fs::create_dir_all(run_dir).map_err(|e| format!("create {}: {e}", run_dir.display()))?;

    let keys: Vec<KeyInfo> = roles()
        .iter()
        .map(|r| keygen(wallet_bin, r))
        .collect::<Result<_, _>>()?;

    // Genesis accounts: every pinned identity, zero balance (no pre-mine; the
    // named accounts exist so they are cryptographically key-bound at genesis).
    let accounts: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| json!({ "account": k.account, "public_key": k.public_key, "balance": "0" }))
        .collect();

    let spec = json!({
        "chain_id": CHAIN_ID,
        "timestamp_ms": GENESIS_TIMESTAMP_MS,
        "policy": "mainnet_like",           // real emission (12.5 XUS/block), real fees
        "block_time_ms": BLOCK_TIME_MS,      // consensus LWMA target
        "pow": "sha256d",                    // real PoW, single-box mineable
        "difficulty_leading_zeros": DIFFICULTY_LEADING_ZEROS,
        "seeds": [],                         // NO baked seeds — nothing to dial but us
        // The node itself re-verifies the pinned identity at boot and refuses on
        // drift (omitted only while the pin is being (re)established).
        "expected_genesis_hash": if EXPECTED_GENESIS_HASH.is_empty() {
            serde_json::Value::Null
        } else {
            json!(EXPECTED_GENESIS_HASH)
        },
        "accounts": accounts,
    });
    let spec_path = run_dir.join("chain-spec.json");
    write_pretty(&spec_path, &spec)?;

    // Five nodes: node-1..3 mine (val01..val03), node-4 observer (wallet ops +
    // restart-replay victim), node-5 late-join observer (started mid-matrix).
    let mut plans = Vec::new();
    for (i, (account, mine)) in [
        ("val01.e2e.sov", true),
        ("val02.e2e.sov", true),
        ("val03.e2e.sov", true),
        ("obs04.e2e.sov", false),
        ("obs05.e2e.sov", false),
    ]
    .iter()
    .enumerate()
    {
        let name = format!("node-{}", i + 1);
        let dir = run_dir.join(&name);
        fs::create_dir_all(dir.join("data"))
            .map_err(|e| format!("create {}: {e}", dir.display()))?;
        let rpc = format!("127.0.0.1:{}", base_rpc + i as u16);
        let p2p = format!("127.0.0.1:{}", base_p2p + i as u16);
        let key = keys
            .iter()
            .find(|k| k.account == *account)
            .expect("role generated above");

        // Loopback-only binds: this network is unreachable off-box by
        // construction, on top of the genesis-hash handshake isolation.
        let config = json!({
            "rpc_addr": rpc,
            "rpc_workers": 4,
            "data_dir": dir.join("data").to_string_lossy(),
            "block_time_ms": BLOCK_TIME_MS,
            "mempool_capacity": 16_384,
            "max_block_txs": 4_096,
            "mine": mine,
            "p2p_addr": p2p,
            // Star bootstrap onto node-1; gossip discovery meshes the rest.
            "bootstrap_peers": if i == 0 { json!([]) } else { json!([format!("127.0.0.1:{base_p2p}")]) },
            "checkpoints": [],
            "noban": [],
        });
        write_pretty(&dir.join("node-config.json"), &config)?;

        let keystore = json!({
            "miners": [{ "account": key.account, "seed_hex": key.seed_hex, "scheme": "hybrid65" }],
        });
        write_pretty(&dir.join("keystore.json"), &keystore)?;

        plans.push(NodePlan {
            name,
            dir,
            spec_path: spec_path.clone(),
            rpc,
            p2p,
            mine: *mine,
        });
    }

    Ok(Net { plans, keys })
}

fn write_pretty(path: &Path, v: &serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    fs::write(path, text + "\n").map_err(|e| format!("write {}: {e}", path.display()))
}
