//! `sov-testnet` — stand up and operate a real SOV network, end to end.
//!
//! One cross-platform binary (the same `cargo build` produces it on macOS,
//! Windows, and Linux) that mints **real** miner keys from the operating
//! system CSPRNG, writes a genesis chain-spec plus per-node configs and
//! keystores, launches and stops nodes, reports their live status, funds accounts
//! from the faucet, and resets state to genesis. It is a thin operator layer over
//! the real [`Daemon`](sov_rpc)/`sov-rpcd` and [`RpcClient`] — it fabricates
//! nothing: keys are real entropy, and every height/finality/balance it prints is
//! read live from a running node.
//!
//! The protocol underneath is Nakamoto proof-of-work and permissionless; this
//! tool is just how an operator drives one deployment of it. Every node mines
//! continuously (the block seal IS real work), heaviest-work fork choice
//! resolves races, and finality is confirmation depth — no miner votes.
//!
//! ```text
//! sov-testnet gen    [--miners N] [--out DIR] [--policy test|mainnet-like]
//!                    [--base-rpc 8645] [--base-p2p 9645] [--faucet-sov F]
//!                    [--block-time-ms 60000] [--pow sha256d|randomx]
//!     # DEFAULT policy is mainnet-like: NO pre-mine (genesis funds nothing, the
//!     # whole 21M cap is mined at 12.5 XUS/block and taxed 9%/1%). The faucet is
//!     # the first miner, dispensing coins it mines. `--policy test` instead
//!     # pre-funds a faucet (that preset has no emission) for plumbing tests.
//!     # `--pow randomx` runs the mainnet seal for a full-fidelity rehearsal.
//! sov-testnet join   --spec <chain-spec.json> [--out DIR] [--name acct]
//!                    [--seed-peer ip:port] [--rpc addr] [--p2p addr]
//!     # CROSS-MACHINE: wrap a local node around a FROZEN spec (e.g.
//!     # chain/specs/testnet-1.json), copied byte-for-byte. Seed node: no
//!     # --seed-peer; validators point --seed-peer at the seed's LAN ip:port.
//! sov-testnet up     [--out DIR] [--node node-K]   # launch all nodes, or just one
//! sov-testnet down   [--out DIR]                    # stop nodes started by `up`
//! sov-testnet status [--out DIR]                    # height / finality / mempool / balances
//! sov-testnet faucet <account> <sov> [--out DIR] [--node node-K]
//! sov-testnet reset  [--out DIR]                    # wipe block logs, keep keys
//! sov-testnet encrypt-keystore [--out DIR] [--node node-K]  # seal keystores (SOV_KEYSTORE_PASSPHRASE)
//! sov-testnet shielded  [--out DIR] [--sov 25]   # REAL Halo2 shielded round-trip on the
//!                    # RUNNING sim net: shield SOV into the pool, then de-shield it back,
//!                    # both with genuine zero-knowledge proofs; artifacts dumped.
//! sov-testnet heartbeat [--out DIR] [--interval-ms 3000]  # keep the RUNNING net visibly
//!                    # alive: a real micro-transfer (and periodic real PoW mint) every tick,
//!                    # so blocks keep committing and the explorer feed keeps moving. Ctrl-C stops.
//! sov-testnet sim    [--out DIR] [--miners N] [--rounds R]  # LIVE multi-node simulation:
//!                    # boots a real net, drives real signed traffic (transfers, tokens, HTLC,
//!                    # intent swaps, a real WASM contract, real PoW), streams live state, and
//!                    # dumps every raw artifact (keys, txs, blocks, bytecode) to disk.
//! ```

use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sov_primitives::{AccountId, Balance};
use sov_rpc::{
    ChainSpec, Keystore, KeystoreEntry, NodeConfig, PolicyPreset, RpcClient, SpecAccount,
};

use sov_crypto::Keypair;
use sov_intents::{Asset as IntentAsset, Intent, Settlement};
use sov_primitives::Hash;
use sov_state::token_asset_id;
use sov_types::{Action, SignedTransaction, Transaction};

/// The operator manifest written by `gen` and read by every other subcommand: it
/// records the node set and the faucet key so the tool can act without re-deriving
/// anything. Seeds here are plaintext — a testnet convenience, never a mainnet
/// practice (encryption at rest / an HSM is the production step).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    chain_id: String,
    /// Policy preset name, mirrored from the chain-spec for display.
    policy: String,
    /// The faucet account and the seed that controls it (so `faucet` can sign).
    faucet: String,
    faucet_seed_hex: String,
    nodes: Vec<NodeEntry>,
}

/// One simulation actor: a real funded genesis account with a hybrid key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActorEntry {
    /// The on-chain account (e.g. `alice.actor.sov`).
    account: String,
    /// The 32-byte master seed (hex) the hybrid keypair derives from. REAL and
    /// SECRET: whoever holds this controls the account.
    seed_hex: String,
    /// Key scheme (always `hybrid65` for generated actors).
    scheme: String,
    /// The full public key, chain-spec encoding (`hybrid65:0x…`).
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeEntry {
    /// Subdirectory name, e.g. `node-1`.
    dir: String,
    /// The miner account this node mines and signs with (its coinbase identity).
    miner: String,
    /// JSON-RPC address (`host:port`).
    rpc_addr: String,
    /// P2P gossip bind address (`host:port`).
    p2p_addr: String,
}

const MANIFEST_FILE: &str = "testnet.json";
/// Raw actor key file written by `gen --actors N` (and `sim`): the simulation's
/// user accounts, with their real seeds and hybrid public keys — the SOV analog
/// of an Ethereum keystore directory. Plaintext by design for the simulation.
const ACTORS_FILE: &str = "sim-actors.json";
const PIDS_FILE: &str = "testnet.pids";

/// The mainnet-like policy reserves the ENTIRE 21,000,000 SOV cap for
/// proof-of-work emission — there is NO pre-mine, so the genesis allocation
/// must be exactly zero. The node's own genesis check is the source of truth;
/// we mirror it here so `gen` fails fast with guidance instead of writing a
/// spec that won't boot.
const MAINNET_GENESIS_HEADROOM_SOV: u128 = 0;

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("sov-testnet: {e}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let (cmd, rest) = args
        .split_first()
        .ok_or("usage: sov-testnet <gen|join|up|down|status|faucet|reset> [options]")?;
    let flags = Flags::parse(rest);
    match cmd.as_str() {
        "gen" => cmd_gen(&flags),
        "join" => cmd_join(&flags),
        "up" => cmd_up(&flags),
        "down" => cmd_down(&flags),
        "status" => cmd_status(&flags),
        "faucet" => cmd_faucet(&flags),
        "reset" => cmd_reset(&flags),
        "encrypt-keystore" => cmd_encrypt_keystore(&flags),
        "sim" => cmd_sim(&flags),
        "shielded" => cmd_shielded(&flags),
        "heartbeat" => cmd_heartbeat(&flags),
        other => Err(format!(
            "unknown command `{other}` \
             (gen|join|up|down|status|faucet|reset|encrypt-keystore|sim|shielded|heartbeat)"
        )
        .into()),
    }
}

/// Minimal flag/positional parser: `--key value` flags plus bare positionals.
#[derive(Clone)]
struct Flags {
    opts: HashMap<String, String>,
    positionals: Vec<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Self {
        let mut opts = HashMap::new();
        let mut positionals = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(key) = a.strip_prefix("--") {
                let val = args.get(i + 1).cloned().unwrap_or_default();
                opts.insert(key.to_string(), val);
                i += 2;
            } else {
                positionals.push(a.clone());
                i += 1;
            }
        }
        Flags { opts, positionals }
    }

    fn out_dir(&self) -> PathBuf {
        PathBuf::from(
            self.opts
                .get("out")
                .cloned()
                .unwrap_or_else(|| "testnet".into()),
        )
    }

    fn set(&mut self, key: &str, value: &str) {
        self.opts.insert(key.to_string(), value.to_string());
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.opts.get(key).map(String::as_str)
    }

    fn parse_or<T: std::str::FromStr>(&self, key: &str, default: T) -> Result<T, Box<dyn Error>>
    where
        T::Err: std::fmt::Display,
    {
        match self.opts.get(key) {
            Some(v) => v.parse().map_err(|e| format!("--{key}: {e}").into()),
            None => Ok(default),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 32 bytes of real OS entropy, hex-encoded — a miner/faucet signing seed.
fn fresh_seed_hex() -> Result<String, Box<dyn Error>> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS entropy unavailable: {e}"))?;
    Ok(hex::encode(seed))
}

/// The chain-spec string for the HYBRID post-quantum key derived from `seed`
/// (`hybrid65:0x…`). Generated chains are PQ-native from genesis — no key
/// migration is ever needed for accounts minted here.
fn public_key_string(seed_hex: &str) -> Result<String, Box<dyn Error>> {
    let seed: [u8; 32] = hex::decode(seed_hex)?
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    let key = Keypair::hybrid_from_seed(seed).public_key();
    // The serde form is the canonical spec encoding (a prefixed hex string).
    Ok(serde_json::to_value(key)?
        .as_str()
        .expect("a PublicKey serializes as a string")
        .to_string())
}

// ---------------------------------------------------------------------------
// gen
// ---------------------------------------------------------------------------

fn cmd_gen(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let miners: usize = flags.parse_or("miners", 2usize)?;
    if miners == 0 {
        return Err("need at least one miner".into());
    }
    let base_rpc: u16 = flags.parse_or("base-rpc", 8645u16)?;
    let base_p2p: u16 = flags.parse_or("base-p2p", 9645u16)?;
    // DEFAULT is mainnet-faithful: the `mainnet_like` policy reserves the ENTIRE
    // 21M cap for mining, so genesis funds NOTHING — no pre-mine, supply starts
    // at exactly zero, every coin is mined (12.5 XUS/block) and taxed (9%/1%),
    // exactly like mainnet. `--policy test` is the plumbing-only shortcut whose
    // preset has no emission, so it pre-funds a faucet to have spendable coins.
    let policy = match flags.get("policy").unwrap_or("mainnet-like") {
        "test" => PolicyPreset::Test,
        "mainnet-like" | "mainnet_like" => PolicyPreset::MainnetLike,
        other => return Err(format!("--policy must be test|mainnet-like, got `{other}`").into()),
    };
    let policy_name = match policy {
        PolicyPreset::Test => "test",
        PolicyPreset::MainnetLike => "mainnet_like",
    };
    // Only the `test` net pre-funds a faucet account at genesis; the faithful net
    // funds nothing (no pre-mine) and dispenses MINED coins instead.
    let funded_faucet = matches!(policy, PolicyPreset::Test);
    let faucet_sov: u128 = flags.parse_or(
        "faucet-sov",
        if funded_faucet { 100_000u128 } else { 0u128 },
    )?;

    // Block cadence: a testnet runs at a realistic interval, NOT the unit-test
    // preset's 1s. Default 60s; pass `--block-time-ms 150000` to match mainnet
    // exactly for a full-fidelity rehearsal. Written to BOTH the daemon cadence
    // (node-config) and the consensus target (chain-spec) so they always agree.
    let block_time_ms: u64 = flags.parse_or("block-time-ms", 60_000u64)?;
    // PoW seal: default fast **Sha256d** (single-box friendly — overrides the
    // mainnet preset's RandomX so a testnet is mineable on one machine), or real
    // **RandomX** (`--pow randomx`, the mainnet-fidelity pre-launch rehearsal).
    let pow: Option<String> = match flags.get("pow") {
        None => Some("sha256d".to_string()),
        Some(p) if matches!(p.to_ascii_lowercase().as_str(), "sha256d" | "randomx") => {
            Some(p.to_ascii_lowercase())
        }
        Some(other) => return Err(format!("--pow must be sha256d|randomx, got `{other}`").into()),
    };
    // Genesis difficulty (leading zero bits). A testnet defaults LOW (8) so a single
    // machine mines trivially from block 1; per-block LWMA then tracks the live hashrate.
    // Pass `--difficulty-zeros 20` for a mainnet-difficulty rehearsal.
    let difficulty_zeros: u32 = flags.parse_or("difficulty-zeros", 8u32)?;

    let actors: usize = flags.parse_or("actors", 0usize)?;
    let actor_sov: u128 = flags.parse_or("actor-sov", 2_000u128)?;

    // Fail fast (before writing anything) if a mainnet-like genesis would exceed the
    // emission-reserved headroom — otherwise the node rejects the spec at boot.
    if matches!(policy, PolicyPreset::MainnetLike) {
        let total = faucet_sov.saturating_add((actors as u128).saturating_mul(actor_sov));
        if total > MAINNET_GENESIS_HEADROOM_SOV {
            return Err(format!(
                "mainnet-like genesis allows {MAINNET_GENESIS_HEADROOM_SOV} XUS of allocation — \
                 NO pre-mine: the entire 21,000,000 cap is mined via the coinbase; \
                 requested {total} SOV ({faucet_sov} faucet + actors). \
                 Use --faucet-sov 0 --actors 0, or --policy test for a funded test network."
            )
            .into());
        }
    }
    let chain_id = flags.get("chain-id").unwrap_or("sov-testnet").to_string();

    fs::create_dir_all(&out)?;

    // Mint miner keys and build the genesis account set. Miners are funded with
    // ZERO at genesis — under Nakamoto consensus every coin a miner holds is one
    // it mined (no pre-mine), exactly like mainnet.
    let mut accounts = Vec::with_capacity(miners + 1);
    let mut node_entries = Vec::with_capacity(miners);
    let mut node_seeds: Vec<(String, String, String)> = Vec::with_capacity(miners); // (dir, account, seed)

    for i in 1..=miners {
        let account = format!("val{i:02}.node.sov");
        let seed_hex = fresh_seed_hex()?;
        let pk_hex = public_key_string(&seed_hex)?;
        accounts.push(SpecAccount {
            account: account.clone(),
            public_key: pk_hex,
            balance: Balance::ZERO,
        });
        let dir = format!("node-{i}");
        node_entries.push(NodeEntry {
            dir: dir.clone(),
            miner: account.clone(),
            rpc_addr: format!("127.0.0.1:{}", base_rpc + (i as u16 - 1)),
            p2p_addr: format!("0.0.0.0:{}", base_p2p + (i as u16 - 1)),
        });
        node_seeds.push((dir, account, seed_hex));
    }

    // The faucet. On the funded `test` net it is a real pre-funded genesis
    // account — that preset has NO emission, so coins must exist at genesis to be
    // spendable at all. On the mainnet-faithful net there is NO pre-mine, so
    // genesis funds nothing: the "faucet" is simply the first miner, dispensing
    // the coins it actually MINES. Either way `cmd_faucet` signs transfers with
    // `faucet_seed_hex` from `faucet_account`.
    let (faucet_account, faucet_seed_hex) = if funded_faucet {
        let account = "faucet.reserve.sov".to_string();
        let seed_hex = fresh_seed_hex()?;
        accounts.push(SpecAccount {
            account: account.clone(),
            public_key: public_key_string(&seed_hex)?,
            balance: Balance::from_sov(faucet_sov)?,
        });
        (account, seed_hex)
    } else {
        // First miner's (account, seed): the faucet draws on its mined coinbase.
        let (_, account, seed_hex) = &node_seeds[0];
        (account.clone(), seed_hex.clone())
    };

    // Simulation actors: real funded genesis accounts with hybrid keys, their
    // raw key material written to sim-actors.json (the Ethereum-keystore
    // analog — open it and look).
    const ACTOR_NAMES: [&str; 5] = ["alice", "bob", "carol", "dave", "erin"];
    let mut actor_entries: Vec<ActorEntry> = Vec::with_capacity(actors);
    for i in 0..actors {
        let name = ACTOR_NAMES
            .get(i)
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("actor{i}"));
        let account = format!("{name}.actor.sov");
        let seed_hex = fresh_seed_hex()?;
        let public_key = public_key_string(&seed_hex)?;
        accounts.push(SpecAccount {
            account: account.clone(),
            public_key: public_key.clone(),
            balance: Balance::from_sov(actor_sov)?,
        });
        actor_entries.push(ActorEntry {
            account,
            seed_hex,
            scheme: "hybrid65".into(),
            public_key,
        });
    }
    if !actor_entries.is_empty() {
        write_json(&out.join(ACTORS_FILE), &actor_entries)?;
    }

    // Write the chain-spec (identical on every node; its hash gates the handshake).
    let spec = ChainSpec {
        chain_id: chain_id.clone(),
        timestamp_ms: now_ms(),
        policy,
        block_time_ms: Some(block_time_ms),
        pow: pow.clone(),
        difficulty_leading_zeros: Some(difficulty_zeros),
        // Use the selected policy's native de-shield limiter by default; the shipped
        // testnet-1.json relaxes it via these optional overrides.
        deshield_limit_sov: None,
        deshield_window_blocks: None,
        accounts,
    };
    write_json(&out.join("chain-spec.json"), &spec)?;

    // Write each node's config + keystore.
    let seed_p2p = format!("127.0.0.1:{base_p2p}"); // node-1's P2P addr, the bootstrap seed
    for (idx, (dir, account, seed_hex)) in node_seeds.iter().enumerate() {
        let node_dir = out.join(dir);
        fs::create_dir_all(&node_dir)?;
        let config = NodeConfig {
            rpc_addr: node_entries[idx].rpc_addr.clone(),
            rpc_workers: 4,
            data_dir: format!("{dir}/data"),
            block_time_ms,
            mempool_capacity: 16_384,
            max_block_txs: 4_096,
            p2p_addr: Some(node_entries[idx].p2p_addr.clone()),
            // Node 1 is the seed (no bootstrap); the rest dial it on loopback. On a
            // real LAN, edit the peer's bootstrap to the seed machine's IP:port.
            bootstrap_peers: if idx == 0 {
                Vec::new()
            } else {
                vec![seed_p2p.clone()]
            },
            checkpoints: Vec::new(),
        };
        write_json(&node_dir.join("node-config.json"), &config)?;
        let keystore = Keystore {
            miners: vec![KeystoreEntry {
                account: account.clone(),
                seed_hex: seed_hex.clone(),
                scheme: Some("hybrid65".into()),
                mnemonic: None,
                public_key: None,
            }],
        };
        write_json(&node_dir.join("keystore.json"), &keystore)?;
    }

    // Write the operator manifest.
    let manifest = Manifest {
        chain_id: chain_id.clone(),
        policy: policy_name.to_string(),
        faucet: faucet_account.clone(),
        faucet_seed_hex: faucet_seed_hex.clone(),
        nodes: node_entries.clone(),
    };
    write_json(&out.join(MANIFEST_FILE), &manifest)?;

    println!(
        "Generated a {miners}-miner SOV testnet in {}",
        out.display()
    );
    println!("  chain id : {chain_id}   policy: {policy_name}");
    println!("  mining nodes (each mines continuously; finality = 6-confirmation depth):");
    for (dir, account, seed_hex) in &node_seeds {
        let entry = node_entries.iter().find(|n| &n.dir == dir).unwrap();
        println!(
            "    {account:18} rpc {} p2p {}   seed {seed_hex}",
            entry.rpc_addr, entry.p2p_addr
        );
    }
    if funded_faucet {
        println!(
            "  faucet     : {faucet_account}  ({faucet_sov} XUS pre-funded)  seed {faucet_seed_hex}"
        );
    } else {
        println!(
            "  faucet     : {faucet_account}  (= first miner; no pre-mine — dispenses MINED coins)  seed {faucet_seed_hex}"
        );
    }
    println!();
    println!("SECRET: the seeds above (also stored in each node's keystore.json) control real");
    println!("signing keys. Treat them as secret; regenerate for anything you care about.");
    println!();
    println!(
        "Next: `sov-testnet up --out {}` then `sov-testnet status --out {}`.",
        out.display(),
        out.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// join — wrap a local node around an EXISTING frozen chain-spec (cross-machine)
// ---------------------------------------------------------------------------

/// Build a single local node bundle around a FROZEN chain-spec (e.g.
/// `chain/specs/testnet-1.json`) instead of generating a fresh chain. The spec is
/// copied **verbatim** — its exact bytes determine the genesis hash, and peers
/// handshake only on a matching `chain_id` + `genesis_hash`, so every machine
/// joining testnet-1 must use the identical spec. This machine gets its OWN fresh
/// miner key (its coinbase identity; NOT part of genesis). The seed node runs with
/// no `--seed-peer`; every other node points `--seed-peer` at the seed's LAN
/// `ip:port`. Afterwards `sov-testnet up --out <dir>` launches it.
fn cmd_join(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let spec_path = flags.get("spec").ok_or(
        "usage: sov-testnet join --spec <chain-spec.json> --out <dir> \
         [--name <miner-account>] [--seed-peer <ip:port>] [--rpc <addr>] [--p2p <addr>]",
    )?;
    let spec_json = fs::read_to_string(spec_path)
        .map_err(|e| format!("cannot read --spec {spec_path}: {e}"))?;
    // Validate it really is a chain-spec (fail fast before writing a bundle).
    let spec: ChainSpec = serde_json::from_str(&spec_json)
        .map_err(|e| format!("--spec {spec_path} is not a valid chain-spec: {e}"))?;

    let name = flags.get("name").unwrap_or("miner.node.sov").to_string();
    let rpc_addr = flags.get("rpc").unwrap_or("127.0.0.1:8645").to_string();
    let p2p_addr = flags.get("p2p").unwrap_or("0.0.0.0:9645").to_string();
    let bootstrap_peers: Vec<String> = match flags.get("seed-peer") {
        Some(p) => vec![p.to_string()],
        None => Vec::new(),
    };
    // The daemon cadence follows the frozen spec's consensus target, so the
    // operator never has to re-specify it.
    let block_time_ms = spec.block_time_ms.unwrap_or(60_000);

    fs::create_dir_all(&out)?;
    // Copy the frozen spec BYTE-FOR-BYTE — this is the shared chain identity.
    fs::write(out.join("chain-spec.json"), &spec_json)?;

    // This machine's own miner key — real OS entropy, hybrid post-quantum.
    let seed_hex = fresh_seed_hex()?;
    let dir = "node-1".to_string();
    let node_dir = out.join(&dir);
    fs::create_dir_all(node_dir.join("data"))?;
    let config = NodeConfig {
        rpc_addr: rpc_addr.clone(),
        rpc_workers: 4,
        data_dir: format!("{dir}/data"),
        block_time_ms,
        mempool_capacity: 16_384,
        max_block_txs: 4_096,
        p2p_addr: Some(p2p_addr.clone()),
        bootstrap_peers,
        checkpoints: Vec::new(),
    };
    write_json(&node_dir.join("node-config.json"), &config)?;
    let keystore = Keystore {
        miners: vec![KeystoreEntry {
            account: name.clone(),
            seed_hex: seed_hex.clone(),
            scheme: Some("hybrid65".into()),
            mnemonic: None,
            public_key: None,
        }],
    };
    write_json(&node_dir.join("keystore.json"), &keystore)?;

    let policy_name = match spec.policy {
        PolicyPreset::Test => "test",
        PolicyPreset::MainnetLike => "mainnet_like",
    };
    let manifest = Manifest {
        chain_id: spec.chain_id.clone(),
        policy: policy_name.to_string(),
        // No pre-mine: the "faucet" is this miner, dispensing the coins it mines.
        faucet: name.clone(),
        faucet_seed_hex: seed_hex.clone(),
        nodes: vec![NodeEntry {
            dir: dir.clone(),
            miner: name.clone(),
            rpc_addr: rpc_addr.clone(),
            p2p_addr: p2p_addr.clone(),
        }],
    };
    write_json(&out.join(MANIFEST_FILE), &manifest)?;

    println!(
        "Joined `{}` (policy {policy_name}) in {}",
        spec.chain_id,
        out.display()
    );
    println!("  spec      : {spec_path}  (copied verbatim — its genesis hash gates the handshake)");
    println!("  miner     : {name:18} rpc {rpc_addr}  p2p {p2p_addr}");
    println!(
        "  seed       : {name} (= this node; dispenses MINED coins, no pre-mine)  seed {seed_hex}"
    );
    match flags.get("seed-peer") {
        Some(p) => println!("  role      : VALIDATOR — dials the seed at {p}"),
        None => {
            println!("  role      : SEED — no bootstrap peer; other machines dial this node's p2p")
        }
    }
    println!();
    println!(
        "SECRET: the seed above (also in {dir}/keystore.json) controls this node's mined coins."
    );
    println!();
    println!(
        "Next: `sov-testnet up --out {0}` then `sov-testnet status --out {0}`.",
        out.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// up / down
// ---------------------------------------------------------------------------

fn cmd_up(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let manifest = load_manifest(&out)?;
    let rpcd = rpcd_path();
    let only = flags.get("node");

    let mut pid_lines = Vec::new();
    for node in &manifest.nodes {
        if let Some(only) = only {
            if only != node.dir {
                continue;
            }
        }
        let node_dir = out.join(&node.dir);
        fs::create_dir_all(node_dir.join("data"))?;
        let log = File::create(node_dir.join("node.log"))?;
        let err = log.try_clone()?;
        // sov-rpcd resolves the relative data_dir against its CWD, so launch from
        // the testnet root (where node-K/ and chain-spec.json live).
        let child = Command::new(&rpcd)
            .current_dir(&out)
            .arg(format!("{}/node-config.json", node.dir))
            .arg("chain-spec.json")
            .arg(format!("{}/keystore.json", node.dir))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|e| format!("failed to launch {} ({}): {e}", node.dir, rpcd.display()))?;
        println!(
            "started {} (pid {}) — rpc {}  p2p {}  log {}/node.log",
            node.dir,
            child.id(),
            node.rpc_addr,
            node.p2p_addr,
            node.dir
        );
        pid_lines.push(format!("{} {}", node.dir, child.id()));
        // The first node in the manifest is the seed; give its listener a moment to
        // bind before the peers dial it, so the first connection is immediate. (If
        // it isn't ready, the peers' bootstrap retry forms the link shortly anyway.)
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    if pid_lines.is_empty() {
        return Err(match only {
            Some(n) => format!("no node named `{n}` in the manifest"),
            None => "no nodes in the manifest".into(),
        }
        .into());
    }

    // Record PIDs (append when launching a single node so `down` stops them all).
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join(PIDS_FILE))?;
    for line in &pid_lines {
        writeln!(f, "{line}")?;
    }
    println!(
        "\n`sov-testnet status --out {}` to watch them; `down` to stop.",
        out.display()
    );
    Ok(())
}

fn cmd_down(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let pids_path = out.join(PIDS_FILE);
    if !pids_path.exists() {
        println!("no running nodes recorded ({} absent)", pids_path.display());
        return Ok(());
    }
    let file = File::open(&pids_path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let (Some(dir), Some(pid)) = (parts.next(), parts.next()) else {
            continue;
        };
        match pid.parse::<u32>() {
            Ok(pid) => {
                terminate(pid);
                println!("stopped {dir} (pid {pid})");
            }
            Err(_) => eprintln!("skipping malformed pid record: {line}"),
        }
    }
    fs::remove_file(&pids_path)?;
    Ok(())
}

/// Terminate a process by PID, cross-platform.
fn terminate(pid: u32) {
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F", "/T"])
        .status();
    #[cfg(not(windows))]
    let status = Command::new("kill").arg(pid.to_string()).status();
    if let Err(e) = status {
        eprintln!("could not signal pid {pid}: {e}");
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let manifest = load_manifest(&out)?;

    println!(
        "chain `{}`  (policy {})",
        manifest.chain_id, manifest.policy
    );
    println!(
        "{:<8} {:<20} {:>7} {:>9} {:>7}  head",
        "node", "rpc", "height", "mempool", "final"
    );
    for node in &manifest.nodes {
        let client = RpcClient::new(node.rpc_addr.clone());
        match node_line(&client) {
            Ok((height, mempool, final_str, head_hex)) => println!(
                "{:<8} {:<20} {:>7} {:>9} {:>7}  {}",
                node.dir, node.rpc_addr, height, mempool, final_str, head_hex
            ),
            Err(_) => println!(
                "{:<8} {:<20} {:>7} {:>9} {:>7}  —",
                node.dir, node.rpc_addr, "offline", "-", "-"
            ),
        }
    }

    // Balances of the faucet and each miner, read from the first reachable node.
    if let Some(client) = manifest
        .nodes
        .iter()
        .map(|n| RpcClient::new(n.rpc_addr.clone()))
        .find(|c| c.height().is_ok())
    {
        println!("\nbalances:");
        let mut accounts = vec![manifest.faucet.clone()];
        accounts.extend(manifest.nodes.iter().map(|n| n.miner.clone()));
        for name in accounts {
            if let Ok(account) = AccountId::new(&name) {
                if let Ok(bal) = client.balance(&account) {
                    println!("  {name:18} {bal}");
                }
            }
        }
    } else {
        println!("\n(no node reachable for balances — `sov-testnet up` first)");
    }
    Ok(())
}

/// One status row: (height, mempool size, finality of head, short head hash).
fn node_line(client: &RpcClient) -> Result<(u64, usize, String, String), Box<dyn Error>> {
    let height = client.height()?;
    let mempool = client.mempool_size()?;
    let head = client.head()?;
    let head_hash = head.hash();
    let final_str = if client.is_final(&head_hash)? {
        "final".to_string()
    } else {
        "pending".to_string()
    };
    let hex = head_hash.to_hex();
    let short = format!("{}…", &hex[..hex.len().min(12)]);
    Ok((height, mempool, final_str, short))
}

// ---------------------------------------------------------------------------
// faucet
// ---------------------------------------------------------------------------

fn cmd_faucet(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let manifest = load_manifest(&out)?;
    let to_name = flags
        .positionals
        .first()
        .ok_or("usage: sov-testnet faucet <account> <sov>")?;
    let amount_sov: u128 = flags
        .positionals
        .get(1)
        .ok_or("usage: sov-testnet faucet <account> <sov>")?
        .parse()
        .map_err(|e| format!("amount must be an integer number of XUS: {e}"))?;

    // Target node: --node by dir, else the first.
    let node = match flags.get("node") {
        Some(dir) => manifest
            .nodes
            .iter()
            .find(|n| n.dir == dir)
            .ok_or_else(|| format!("no node named `{dir}`"))?,
        None => manifest.nodes.first().ok_or("manifest has no nodes")?,
    };

    let seed: [u8; 32] = hex::decode(&manifest.faucet_seed_hex)?
        .try_into()
        .map_err(|_| "faucet seed must be 32 bytes")?;
    // Generated chains are PQ-native: the faucet key is hybrid.
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(&manifest.faucet)?;
    let to = AccountId::new(to_name)?;
    let amount = Balance::from_sov(amount_sov)?;

    let client = RpcClient::new(node.rpc_addr.clone());
    let tx_id = client.transfer(&kp, &from, &to, amount)?;
    println!(
        "faucet → {to_name}: {amount_sov} XUS submitted to {} (tx {})",
        node.rpc_addr,
        tx_id.to_hex()
    );
    println!("`sov-testnet status` once it is included (and finalized when miners agree).");
    Ok(())
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

fn cmd_reset(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let manifest = load_manifest(&out)?;
    if out.join(PIDS_FILE).exists() {
        return Err("nodes appear to be running — `sov-testnet down` before reset".into());
    }
    for node in &manifest.nodes {
        let data = out.join(&node.dir).join("data");
        if data.exists() {
            fs::remove_dir_all(&data)?;
            println!("wiped {}", data.display());
        }
    }
    println!("state reset to genesis; keys and chain-spec kept. `sov-testnet up` to start fresh.");
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt-keystore
// ---------------------------------------------------------------------------

fn cmd_encrypt_keystore(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let manifest = load_manifest(&out)?;
    let passphrase = std::env::var("SOV_KEYSTORE_PASSPHRASE").map_err(|_| {
        "set SOV_KEYSTORE_PASSPHRASE to the passphrase used to encrypt the keystores"
    })?;
    if passphrase.is_empty() {
        return Err("SOV_KEYSTORE_PASSPHRASE must not be empty".into());
    }
    let only = flags.get("node");

    let mut count = 0;
    for node in &manifest.nodes {
        if let Some(only) = only {
            if only != node.dir {
                continue;
            }
        }
        let path = out.join(&node.dir).join("keystore.json");
        let text = fs::read_to_string(&path)?;
        // Idempotent: load whether plaintext or already-encrypted, then (re)seal.
        let ks = Keystore::from_encrypted_or_plain(&text, Some(&passphrase))?;
        fs::write(&path, ks.to_encrypted_json(&passphrase)? + "\n")?;
        println!("encrypted {}/keystore.json", node.dir);
        count += 1;
    }
    if count == 0 {
        return Err(match only {
            Some(n) => format!("no node named `{n}`"),
            None => "no nodes in the manifest".into(),
        }
        .into());
    }
    println!("Done. sov-rpcd reads SOV_KEYSTORE_PASSPHRASE to decrypt at boot.");
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// shielded — a REAL zk shielded round-trip on the running net
// ---------------------------------------------------------------------------

/// A loaded sim actor: its account, hybrid keypair, and raw 32-byte seed.
type Actor = (AccountId, Keypair, [u8; 32]);

/// Load the sim actors and return (account, hybrid keypair, raw seed) tuples.
fn load_actors(out: &Path) -> Result<Vec<Actor>, Box<dyn Error>> {
    let entries: Vec<ActorEntry> =
        serde_json::from_str(&fs::read_to_string(out.join(ACTORS_FILE))?)?;
    let mut actors = Vec::new();
    for e in &entries {
        let seed: [u8; 32] = hex::decode(&e.seed_hex)?
            .try_into()
            .map_err(|_| "actor seed must be 32 bytes")?;
        actors.push((
            AccountId::new(&e.account)?,
            Keypair::hybrid_from_seed(seed),
            seed,
        ));
    }
    Ok(actors)
}

/// Wait until `id` appears in a committed block (or time out).
fn wait_included(client: &RpcClient, id: &Hash, secs: u64) -> Result<u64, Box<dyn Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let tip = client.height()?;
        for h in (1..=tip).rev().take(20) {
            if let Some(block) = client.block_by_height(h)? {
                if block.transactions.iter().any(|t| &t.id() == id) {
                    return Ok(h);
                }
            }
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("tx {} not included within {secs}s", id.to_hex()).into());
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

fn cmd_shielded(flags: &Flags) -> Result<(), Box<dyn Error>> {
    use sov_shielded::{
        mint_to_shielded, recover_outputs, unshield, witness_latest, ShieldedKey, ShieldedParams,
    };

    let out = flags.out_dir();
    let sov: u128 = flags.parse_or("sov", 25u128)?;
    let manifest = load_manifest(&out)?;
    let lead = RpcClient::new(manifest.nodes[0].rpc_addr.clone());
    let mut actors = load_actors(&out)?;
    let (alice_acct, _, alice_seed) = actors.remove(0);
    let alice_kp = Keypair::hybrid_from_seed(alice_seed);

    let tx_dir = out.join("artifacts/txs");
    fs::create_dir_all(&tx_dir)?;

    println!("=== REAL SHIELDED ROUND-TRIP ({sov} XUS) ===");
    println!("building the Halo2 proving parameters (one-time, ~seconds)...");
    let params = ShieldedParams::build();
    let zkey = ShieldedKey::from_seed(alice_seed).ok_or("shielded key derivation failed")?;

    let before = lead.balance(&alice_acct)?;
    println!("alice transparent balance before: {before}");

    // 1. SHIELD: a real zero-knowledge bundle moving value INTO the pool.
    println!("proving the SHIELD bundle (real Halo2)...");
    let amount = u64::try_from(Balance::from_sov(sov)?.grains())?;
    let bundle = mint_to_shielded(&params, &zkey.address(), amount)
        .map_err(|e| format!("shield bundle: {e}"))?;
    let nonce = lead.nonce(&alice_acct)?;
    let tx = Transaction {
        signer: alice_acct.clone(),
        public_key: alice_kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign(tx, &alice_kp)?;
    let shield_id = stx.id();
    fs::write(
        tx_dir.join(format!("shield-{}.json", &shield_id.to_hex()[..12])),
        serde_json::to_string_pretty(&stx)?,
    )?;
    lead.submit_transaction(&stx)?;
    let h = wait_included(&lead, &shield_id, 30)?;
    println!(
        "SHIELD committed in block {h}  tx {}\n  alice balance now: {}  (value is inside the pool — sender/recipient/amount hidden on-chain)",
        shield_id.to_hex(),
        lead.balance(&alice_acct)?
    );

    // 2. DE-SHIELD: spend the note back out with a second real proof. The
    //    witness is built over the shield bundle's own commitments (the pool
    //    was empty before it, so the anchor matches consensus state).
    println!("proving the DE-SHIELD bundle (real Halo2 spend)...");
    let note = recover_outputs(&zkey, &bundle)
        .into_iter()
        .next()
        .ok_or("could not recover the shielded note")?;
    let (path, anchor) =
        witness_latest(&bundle.note_commitment_bytes()).ok_or("could not witness the note")?;
    let out_bundle =
        unshield(&params, &zkey, &note, path, anchor).map_err(|e| format!("unshield: {e}"))?;
    let nonce = lead.nonce(&alice_acct)?;
    let tx = Transaction {
        signer: alice_acct.clone(),
        public_key: alice_kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: out_bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign(tx, &alice_kp)?;
    let deshield_id = stx.id();
    fs::write(
        tx_dir.join(format!("deshield-{}.json", &deshield_id.to_hex()[..12])),
        serde_json::to_string_pretty(&stx)?,
    )?;
    lead.submit_transaction(&stx)?;
    let h = wait_included(&lead, &deshield_id, 30)?;
    println!(
        "DE-SHIELD committed in block {h}  tx {}\n  alice balance now: {}  (round-trip complete; fees: test policy = 0)",
        deshield_id.to_hex(),
        lead.balance(&alice_acct)?
    );
    println!("raw artifacts: artifacts/txs/shield-*.json and deshield-*.json (the bundle bytes ARE the zk proofs)");
    Ok(())
}

// ---------------------------------------------------------------------------
// heartbeat — keep the running net visibly alive
// ---------------------------------------------------------------------------

fn cmd_heartbeat(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let interval: u64 = flags.parse_or("interval-ms", 3_000u64)?;
    let manifest = load_manifest(&out)?;
    let lead = RpcClient::new(manifest.nodes[0].rpc_addr.clone());
    let actors = load_actors(&out)?;
    if actors.len() < 2 {
        return Err("heartbeat needs at least 2 actors (gen --actors)".into());
    }
    let (alice_acct, alice_kp, _) = &actors[0];
    let (bob_acct, _, _) = &actors[1];

    println!(
        "heartbeat: a real 0.01-SOV transfer every {interval}ms; every block is MINED (Nakamoto \
         PoW — the daemon grinds each header and its coinbase pays its miner account); Ctrl-C to stop"
    );
    let mut tick: u64 = 0;
    loop {
        tick += 1;
        // A real micro-transfer keeps a block committing every tick. The block
        // itself is sealed by genuine proof of work in the daemon — mining is
        // no longer a transaction, it IS block production.
        let nonce = lead.nonce(alice_acct)?;
        let tx = Transaction {
            signer: alice_acct.clone(),
            public_key: alice_kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: bob_acct.clone(),
                amount: Balance::from_grains(1_000_000), // 0.01 SOV
            },
        };
        let stx = SignedTransaction::sign(tx, alice_kp)?;
        let id = stx.id();
        lead.submit_transaction(&stx)?;

        std::thread::sleep(std::time::Duration::from_millis(interval));
        let h = lead.height()?;
        let fin = lead
            .head()
            .ok()
            .map(|b| lead.is_final(&b.hash()).unwrap_or(false))
            .unwrap_or(false);
        println!(
            "tick {tick:>4}  height {h:>5}  final {fin}  tx {}  alice {}  bob {}",
            &id.to_hex()[..12],
            lead.balance(alice_acct)?,
            lead.balance(bob_acct)?,
        );
    }
}

// ---------------------------------------------------------------------------
// sim — the LIVE multi-node simulation
// ---------------------------------------------------------------------------

/// The simulation's on-chain WASM contract, compiled from this WAT at runtime
/// (the raw bytecode is dumped to disk). It echoes its calldata: stores it
/// under the key `"last"`, emits it as an event, and returns it.
const SIM_CONTRACT_WAT: &str = r#"(module
  (import "env" "calldata" (func $cd (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
  (import "env" "emit" (func $em (param i32 i32 i32 i32)))
  (import "env" "set_return" (func $sr (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "last")
  (func (export "call") (result i32)
    (local $n i32)
    (local.set $n (call $cd (i32.const 16) (i32.const 256)))
    (call $sw (i32.const 0) (i32.const 4) (i32.const 16) (local.get $n))
    (call $em (i32.const 0) (i32.const 4) (i32.const 16) (local.get $n))
    (call $sr (i32.const 16) (local.get $n))
    (local.get $n)))"#;

/// A simulation actor with its live keypair and locally-tracked nonce.
struct SimActor {
    account: AccountId,
    keypair: Keypair,
    nonce: u64,
}

/// Sign `action` from `actor`, dump the raw wire-format JSON artifact, submit
/// it to `client`, advance the local nonce, and return the transaction id.
#[allow(clippy::too_many_arguments)]
fn sim_submit(
    client: &RpcClient,
    actor: &mut SimActor,
    action: Action,
    label: &str,
    seq: &mut u32,
    tx_dir: &Path,
    log: &mut Vec<(String, Hash)>,
) -> Result<Hash, Box<dyn Error>> {
    let tx = Transaction {
        signer: actor.account.clone(),
        public_key: actor.keypair.public_key(),
        nonce: actor.nonce,
        action,
    };
    let stx = SignedTransaction::sign(tx, &actor.keypair)?;
    let id = stx.id();
    // The RAW signed transaction, exactly as it travels the wire (JSON form).
    let path = tx_dir.join(format!("{seq:03}-{label}-{}.json", &id.to_hex()[..12]));
    fs::write(&path, serde_json::to_string_pretty(&stx)?)?;
    *seq += 1;
    client.submit_transaction(&stx)?;
    actor.nonce += 1;
    log.push((label.to_string(), id));
    Ok(id)
}

/// SHA-256 (the HTLC hashlock primitive — same as Bitcoin's OP_SHA256).
fn sim_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn cmd_sim(flags: &Flags) -> Result<(), Box<dyn Error>> {
    let out = flags.out_dir();
    let rounds: u32 = flags.parse_or("rounds", 5u32)?;
    let miners: usize = flags.parse_or("miners", 3usize)?;

    println!("=== SOV LIVE SIMULATION ===");
    println!(
        "dir: {}   miners: {miners}   rounds: {rounds}",
        out.display()
    );
    println!();

    // 1. Fresh net: real keys, real genesis, three funded actors.
    let _ = cmd_down(flags);
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    {
        let mut gen_flags = flags.clone();
        gen_flags.set("miners", &miners.to_string());
        gen_flags.set("actors", "3");
        cmd_gen(&gen_flags)?;
    }
    println!();

    // 2. Boot every node (real sov-rpcd processes, Noise+ML-KEM P2P).
    cmd_up(flags)?;
    println!();

    let manifest = load_manifest(&out)?;
    let clients: Vec<(String, RpcClient)> = manifest
        .nodes
        .iter()
        .map(|n| (n.dir.clone(), RpcClient::new(n.rpc_addr.clone())))
        .collect();
    let lead = &clients[0].1;

    // Wait for every RPC to come alive.
    print!("waiting for nodes");
    for (_, c) in &clients {
        for attempt in 0.. {
            match c.height() {
                Ok(_) => break,
                Err(e) if attempt > 60 => return Err(format!("node not up: {e}").into()),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
            }
        }
        print!(".");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
    }
    println!(" all {} nodes live", clients.len());

    // 3. Actors from the raw key file (open sim-actors.json to see them).
    let actors_json = fs::read_to_string(out.join(ACTORS_FILE))?;
    let entries: Vec<ActorEntry> = serde_json::from_str(&actors_json)?;
    let mut actors: Vec<SimActor> = Vec::new();
    for e in &entries {
        let seed: [u8; 32] = hex::decode(&e.seed_hex)?
            .try_into()
            .map_err(|_| "actor seed must be 32 bytes")?;
        let account = AccountId::new(&e.account)?;
        let nonce = lead.nonce(&account)?;
        actors.push(SimActor {
            account,
            keypair: Keypair::hybrid_from_seed(seed),
            nonce,
        });
    }
    // The lead node's miner identity: under Nakamoto consensus every block's
    // coinbase pays the producing daemon's first keystore account — watch its
    // balance grow as it mines (no Mine transaction; the daemon does the work).
    let miner_id = AccountId::new(&manifest.nodes[0].miner)?;

    // 4. Artifact directories.
    let art = out.join("artifacts");
    let tx_dir = art.join("txs");
    let block_dir = art.join("blocks");
    fs::create_dir_all(&tx_dir)?;
    fs::create_dir_all(&block_dir)?;

    // 5. The contract: compile the WAT to REAL WASM bytecode and dump it raw.
    let wasm = wat::parse_str(SIM_CONTRACT_WAT)?;
    fs::write(art.join("contract.wat"), SIM_CONTRACT_WAT)?;
    fs::write(art.join("contract.wasm"), &wasm)?;
    fs::write(art.join("contract.hex"), hex::encode(&wasm))?;
    println!(
        "contract bytecode: {} bytes -> artifacts/contract.wasm (+ .hex, .wat)",
        wasm.len()
    );

    let usd1 = token_asset_id(&actors[0].account, "USD1");
    let mut seq: u32 = 0;
    let mut submitted: Vec<(String, Hash)> = Vec::new();
    let (alice_acct, bob_acct, carol_acct) = (
        actors[0].account.clone(),
        actors[1].account.clone(),
        actors[2].account.clone(),
    );

    // 6. Drive the rounds: REAL signed traffic of every kind the chain supports.
    for round in 1..=rounds {
        println!("\n--- round {round}/{rounds} ---");

        // Native transfer: alice -> bob, 5 SOV.
        sim_submit(
            lead,
            &mut actors[0],
            Action::Transfer {
                to: bob_acct.clone(),
                amount: Balance::from_sov(5)?,
            },
            "transfer",
            &mut seq,
            &tx_dir,
            &mut submitted,
        )?;

        // Token lane: round 1 issues USD1; later rounds move it.
        if round == 1 {
            sim_submit(
                lead,
                &mut actors[0],
                Action::TokenIssue {
                    symbol: "USD1".into(),
                    amount: Balance::from_sov(1_000)?,
                    to: alice_acct.clone(),
                },
                "token-issue",
                &mut seq,
                &tx_dir,
                &mut submitted,
            )?;
        } else {
            sim_submit(
                lead,
                &mut actors[0],
                Action::TokenTransfer {
                    asset: usd1,
                    to: bob_acct.clone(),
                    amount: Balance::from_sov(10)?,
                },
                "token-transfer",
                &mut seq,
                &tx_dir,
                &mut submitted,
            )?;
        }

        // HTLC atomic-swap lane: alice locks 1 SOV for bob behind a SHA-256
        // hashlock; bob claims it by revealing the preimage on-chain.
        let preimage = format!("sim-preimage-round-{round}");
        let lock_id = sim_submit(
            lead,
            &mut actors[0],
            Action::HtlcLock {
                recipient: bob_acct.clone(),
                amount: Balance::from_sov(1)?,
                hashlock: sim_sha256(preimage.as_bytes()),
                timeout_height: 1_000_000,
            },
            "htlc-lock",
            &mut seq,
            &tx_dir,
            &mut submitted,
        )?;
        sim_submit(
            lead,
            &mut actors[1],
            Action::HtlcClaim {
                htlc_id: lock_id,
                preimage: preimage.into_bytes(),
            },
            "htlc-claim",
            &mut seq,
            &tx_dir,
            &mut submitted,
        )?;

        // Intent lane (rounds >= 2, once alice holds USD1): alice SIGNS a real
        // declarative offer off-chain; bob fills it on-chain atomically.
        if round >= 2 {
            let intent = Intent {
                owner: alice_acct.clone(),
                public_key: actors[0].keypair.public_key(),
                nonce: u64::from(round),
                give_asset: IntentAsset::Token(usd1),
                give_amount: Balance::from_sov(10)?.grains(),
                want_asset: IntentAsset::Sov,
                min_receive: Balance::from_sov(1)?.grains(),
                expiry_height: 1_000_000,
            }
            .sign(&actors[0].keypair)?;
            fs::write(
                tx_dir.join(format!("{seq:03}-intent-offer.json")),
                serde_json::to_string_pretty(&intent)?,
            )?;
            sim_submit(
                lead,
                &mut actors[1],
                Action::IntentSettle {
                    settlement: Settlement {
                        intent,
                        solver: bob_acct.clone(),
                        deliver_amount: Balance::from_sov(2)?.grains(),
                    },
                },
                "intent-settle",
                &mut seq,
                &tx_dir,
                &mut submitted,
            )?;
        }

        // Contract lane: round 1 deploys the real bytecode from carol; later
        // rounds call it with fresh calldata.
        if round == 1 {
            sim_submit(
                lead,
                &mut actors[2],
                Action::Deploy { code: wasm.clone() },
                "deploy",
                &mut seq,
                &tx_dir,
                &mut submitted,
            )?;
        } else {
            sim_submit(
                lead,
                &mut actors[2],
                Action::Call {
                    contract: carol_acct.clone(),
                    gas_limit: 1_000_000,
                    calldata: format!("round-{round}").into_bytes(),
                },
                "call",
                &mut seq,
                &tx_dir,
                &mut submitted,
            )?;
        }

        // PoW: every block in this sim is REAL SHA-256d mining — the daemons
        // grind each header's double-SHA-256 to the live target before it
        // commits, and each block's coinbase pays the producing node's miner
        // account (Nakamoto consensus; there is no Mine transaction).

        // Let the nodes mine + finalize, then show the LIVE state.
        std::thread::sleep(std::time::Duration::from_millis(2_500));
        println!("  node            height  final  mempool");
        for (name, c) in &clients {
            let h = c.height().unwrap_or(0);
            let head = c.head().ok();
            let fin = head
                .as_ref()
                .map(|b| c.is_final(&b.hash()).unwrap_or(false))
                .unwrap_or(false);
            let mp = c.mempool_size().unwrap_or(0);
            println!("  {name:<14}  {h:>6}  {fin:<5}  {mp}");
        }
        println!(
            "  balances (SOV): alice {}  bob {}  miner {}",
            lead.balance(&alice_acct)?,
            lead.balance(&bob_acct)?,
            lead.balance(&miner_id).unwrap_or(Balance::ZERO),
        );

        // Dump the head block (header + full transactions) as a raw artifact.
        if let Ok(Some(block)) = lead.block_by_height(lead.height()?) {
            fs::write(
                block_dir.join(format!("block-{:05}.json", block.header.height.get())),
                serde_json::to_string_pretty(&block)?,
            )?;
        }
    }

    // 7. Verification: scan EVERY committed block and check each submitted
    //    transaction was actually included — no claim without inclusion proof.
    std::thread::sleep(std::time::Duration::from_millis(2_000));
    let tip = lead.height()?;
    let mut included = std::collections::HashSet::new();
    for h in 1..=tip {
        if let Ok(Some(block)) = lead.block_by_height(h) {
            fs::write(
                block_dir.join(format!("block-{h:05}.json")),
                serde_json::to_string_pretty(&block)?,
            )?;
            for tx in &block.transactions {
                included.insert(tx.id());
            }
        }
    }
    println!("\n=== INCLUSION REPORT (vs committed blocks 1..={tip}) ===");
    let mut ok = 0usize;
    for (label, id) in &submitted {
        let hit = included.contains(id);
        if hit {
            ok += 1;
        }
        println!(
            "  {}  {label:<16} {}",
            if hit { "OK " } else { "MISS" },
            id.to_hex()
        );
    }
    println!(
        "  {ok}/{} submitted transactions committed",
        submitted.len()
    );

    // 8. Raw artifact inventory.
    println!("\n=== RAW ARTIFACTS (open these) ===");
    let show = |p: PathBuf| {
        if let Ok(md) = fs::metadata(&p) {
            println!("  {:>9} bytes  {}", md.len(), p.display());
        }
    };
    show(out.join("chain-spec.json"));
    show(out.join(ACTORS_FILE));
    for n in &manifest.nodes {
        show(out.join(&n.dir).join("keystore.json"));
        show(out.join(&n.dir).join("data/blocks.log"));
    }
    show(art.join("contract.wat"));
    show(art.join("contract.wasm"));
    show(art.join("contract.hex"));
    println!(
        "  + {} signed-transaction JSONs in {}",
        seq,
        tx_dir.display()
    );
    println!("  + block JSONs in {}", block_dir.display());
    println!("\nNodes are still RUNNING (live RPC on each):");
    for n in &manifest.nodes {
        println!("  {}  http://{}", n.dir, n.rpc_addr);
    }
    println!(
        "Live web explorer: see explorer/README.md (point it at {});",
        manifest.nodes[0].rpc_addr
    );
    println!(
        "stop the net with: sov-testnet down --out {}",
        out.display()
    );

    if ok < submitted.len() {
        return Err(format!("{} transactions were not committed", submitted.len() - ok).into());
    }
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json + "\n")?;
    Ok(())
}

fn load_manifest(out: &Path) -> Result<Manifest, Box<dyn Error>> {
    let path = out.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "could not read {} ({e}) — run `sov-testnet gen --out {}` first",
            path.display(),
            out.display()
        )
    })?;
    Ok(serde_json::from_str(&text)?)
}

/// Locate the `sov-rpcd` binary: prefer the one beside this executable (the build
/// puts sibling bins together), else fall back to the name on `PATH`.
fn rpcd_path() -> PathBuf {
    let name = if cfg!(windows) {
        "sov-rpcd.exe"
    } else {
        "sov-rpcd"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}
