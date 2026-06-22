//! `sov-rpcd` — the long-running SOV node daemon (headless; built for a VPS).
//!
//! Boots a node from a chain-spec, replays any persisted block log to resume
//! state, peers over P2P, serves the JSON-RPC API, and mines on the network tip.
//! It is the SAME node the desktop app (`sov-station`) embeds — same continuous
//! mining loop, same sync-gating, same difficulty — with no GUI, so a seed node
//! on a public host behaves identically to a wallet node on a laptop.
//!
//! ```text
//! sov-rpcd <node-config.json> <chain-spec.json> <keystore.json>
//! ```
//!
//! Operational notes for running on a VPS:
//!   * Bind `rpc_addr`/`p2p_addr` to `0.0.0.0:<port>` so peers and clients can reach it.
//!   * Every block is fsync'd to `data_dir/blocks.log` before it is acknowledged, so an
//!     abrupt restart (e.g. systemd `SIGTERM`) loses nothing committed — the chain resumes
//!     from the log on the next boot. `Restart=always` is therefore safe.
//!   * All mining / peer / sync activity is streamed to stdout (captured by journald),
//!     so `journalctl -u sov-rpcd -f` shows the same live log the desktop app displays.

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fs, process, thread};

use sov_rpc::{ChainSpec, Daemon, Keystore, NodeConfig, P2p, P2pConfig, SyncShared};

/// Shared in-memory log buffer the node writes to; a background thread drains it to stdout.
type Logs = Arc<Mutex<Vec<String>>>;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <node-config.json> <chain-spec.json> <keystore.json>",
            args.first().map(String::as_str).unwrap_or("sov-rpcd")
        );
        process::exit(2);
    }
    if let Err(e) = run(&args[1], &args[2], &args[3]) {
        eprintln!("sov-rpcd: {e}");
        process::exit(1);
    }
}

/// Append an operational line to the shared log (drained to stdout by the background thread),
/// so the daemon's own milestones interleave in order with the node's mining/peer logs.
fn log(logs: &Logs, msg: impl Into<String>) {
    if let Ok(mut v) = logs.lock() {
        v.push(msg.into());
    }
}

/// Spawn the stdout drainer: every 200 ms it flushes newly-buffered log lines to stdout in
/// order. The node's `log_sink` (mining, peers, sync) and this binary's own milestones share
/// the one buffer, giving a single ordered stream that journald captures verbatim.
fn spawn_log_drain(logs: Logs) {
    thread::spawn(move || {
        use std::io::Write;
        loop {
            thread::sleep(Duration::from_millis(200));
            let batch: Vec<String> = match logs.lock() {
                Ok(mut v) => std::mem::take(&mut *v),
                Err(_) => continue,
            };
            if batch.is_empty() {
                continue;
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for line in batch {
                let _ = writeln!(out, "{line}");
            }
            let _ = out.flush();
        }
    });
}

fn run(config_path: &str, spec_path: &str, keystore_path: &str) -> Result<(), Box<dyn Error>> {
    let config: NodeConfig = serde_json::from_str(&fs::read_to_string(config_path)?)?;
    let spec = ChainSpec::from_json(&fs::read_to_string(spec_path)?)?;
    // The keystore may be plaintext or encrypted at rest; an encrypted one needs
    // SOV_KEYSTORE_PASSPHRASE.
    let passphrase = env::var("SOV_KEYSTORE_PASSPHRASE").ok();
    let keystore = Keystore::from_encrypted_or_plain(
        &fs::read_to_string(keystore_path)?,
        passphrase.as_deref(),
    )?;

    let genesis = spec.to_genesis_config()?;
    let miner_keys = keystore.keys()?;

    // One shared log buffer for the whole node; start streaming it to stdout immediately so
    // nothing is lost between here and the first block.
    let logs: Logs = Arc::new(Mutex::new(Vec::new()));
    spawn_log_drain(Arc::clone(&logs));

    let mut daemon = Daemon::new(
        &genesis,
        &config.data_dir,
        config.mempool_capacity,
        config.max_block_txs,
        miner_keys,
    )?;
    log(
        &logs,
        format!(
            "chain '{}' — resumed {} block(s) from {}",
            genesis.chain_id,
            daemon.resumed_blocks(),
            config.data_dir,
        ),
    );

    // Install any trusted weak-subjectivity checkpoints from the config, so a
    // forged long-range history is rejected on import.
    let checkpoints = config
        .checkpoints
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<_>, _>>()?;
    if !checkpoints.is_empty() {
        log(
            &logs,
            format!("{} weak-subjectivity checkpoint(s) loaded", checkpoints.len()),
        );
        daemon = daemon.with_checkpoints(checkpoints);
    }

    // Sync telemetry shared between the P2P engine (which WRITES our distance behind the
    // heaviest peer) and the mining loop (which READS it to gate production). Without this
    // a freshly-joined node would mine its own fork while still downloading the real chain;
    // with it, the node downloads first and only mines once it is AT the network tip. A solo
    // seed node is never "behind", so it still bootstraps the network by mining normally.
    let sync = Arc::new(SyncShared::new());

    // Optional peer-to-peer. Bind the gossip + sync engine to the SAME shared node the daemon
    // produces on, so transactions and blocks flow both ways with peers; attach the same
    // transport back to the daemon for OUTBOUND gossip of everything this node produces. Held
    // to the end of `run` (the engine's threads outlive this binding, but keeping it parks
    // shutdown to process exit).
    let _p2p = match config.p2p_addr.as_deref() {
        Some(p2p_addr) => {
            let (account, keypair) = keystore.keys()?.into_iter().next().ok_or_else(|| {
                "p2p_addr is set but the keystore has no miner key to identify this node"
                    .to_string()
            })?;
            let p2p = P2p::bind(
                daemon.node(),
                P2pConfig {
                    chain_id: genesis.chain_id.clone(),
                    genesis_hash: daemon.genesis_hash(),
                    account,
                    keypair,
                },
                p2p_addr,
            )?
            .with_block_log(daemon.block_log())
            .with_bootstrap(config.bootstrap_peers.clone())
            .with_sync_status(Arc::clone(&sync))
            .with_log_sink(Arc::clone(&logs));
            log(&logs, format!("P2P gossip listening on {}", p2p.local_addr()));
            for peer in &config.bootstrap_peers {
                // Best-effort first dial; if the seed isn't up yet, the engine keeps
                // retrying in the background, so the link forms once it is.
                match p2p.connect(peer) {
                    Ok(()) => log(&logs, format!("dialed bootstrap peer {peer}")),
                    Err(e) => log(
                        &logs,
                        format!("bootstrap peer {peer} not reachable yet ({e}); will keep retrying"),
                    ),
                }
            }
            // mDNS-style LAN auto-discovery: harmless on a public host (no multicast peers),
            // and it lets co-located nodes find each other with zero configuration.
            p2p.tcp().enable_lan_discovery(&genesis.chain_id);
            daemon = daemon.with_gossip(p2p.tcp());
            Some(p2p.start())
        }
        None => {
            log(&logs, "P2P disabled (no p2p_addr) — running standalone");
            None
        }
    };

    let handle = daemon
        .with_sync_status(Arc::clone(&sync))
        .with_log_sink(Arc::clone(&logs))
        .run(&config.rpc_addr, config.rpc_workers, config.block_time_ms)?;
    log(&logs, format!("JSON-RPC listening on http://{}", handle.rpc_addr()));
    log(
        &logs,
        format!(
            "producing blocks every {} ms; press Ctrl-C (or SIGTERM) to stop.",
            config.block_time_ms
        ),
    );

    // The daemon's RPC + production threads keep the chain running; park the main
    // thread to keep the process alive. SIGINT/SIGTERM terminates the process; the
    // last fsync'd block in blocks.log is the durable head, so restart is clean.
    loop {
        thread::park();
    }
}
