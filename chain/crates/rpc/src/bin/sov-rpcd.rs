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
/// Flush any buffered log lines to stdout NOW, synchronously.
///
/// The drainer runs on a 200 ms tick, which is invisible during normal
/// operation and exactly wrong at shutdown: `main` returns in microseconds, so
/// the last lines — the ones saying what the shutdown actually did — are lost
/// with the process. An operator then sees a node vanish silently and cannot
/// tell a clean stop from a crash.
fn drain_logs_now(logs: &Logs) {
    use std::io::Write;
    let batch: Vec<String> = match logs.lock() {
        Ok(mut v) => std::mem::take(&mut *v),
        Err(_) => return,
    };
    if batch.is_empty() {
        return;
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in batch {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
}

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

    // Verify the built genesis matches the spec's pinned hash (if any) before starting,
    // so a drifted/corrupt spec fails loudly instead of forking off the real network.
    let genesis = spec.to_genesis_config_verified()?;
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

    // Apply the operator's retention bounds for the NODE-LOCAL transaction-timing
    // index (`sov_getTxTiming`). Non-consensus observability: nothing in the index
    // reaches a block, a receipt, or a state root, so these may differ freely
    // across the network. Applied here rather than at construction so the
    // configured window also governs the rows already on disk.
    daemon = daemon.with_tx_timing_limits(
        config.tx_timing_retention_blocks,
        config.tx_timing_max_entries,
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
            format!(
                "{} weak-subjectivity checkpoint(s) loaded",
                checkpoints.len()
            ),
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
    // Held so a graceful shutdown can REMOVE the router mapping rather than
    // leaving it to lapse.
    let mut port_mapper: Option<(Arc<sov_network::PortMapper>, u16)> = None;
    let _p2p = match config.p2p_addr.as_deref() {
        Some(p2p_addr) => {
            let (account, keypair) = keystore.keys()?.into_iter().next().ok_or_else(|| {
                "p2p_addr is set but the keystore has no miner key to identify this node"
                    .to_string()
            })?;
            // A fresh node dials BOTH the operator's configured bootstrap peers AND the
            // stable seeds baked into the chain spec, so it can find the network off its
            // LAN. Dedup, config peers first (operator intent wins ordering).
            let mut bootstrap = config.bootstrap_peers.clone();
            for s in &spec.seeds {
                if !bootstrap.contains(s) {
                    bootstrap.push(s.clone());
                }
            }
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
            .with_bootstrap(bootstrap.clone())
            .with_noban(config.noban.clone())
            .with_sync_status(Arc::clone(&sync))
            .with_log_sink(Arc::clone(&logs));
            // Surface transport-level dial/handshake diagnostics (dialing → tcp connected
            // → link up, or the exact failure) on stdout/journald too, so a VPS operator
            // can see peering happen instead of guessing.
            p2p.tcp().set_log_sink(Arc::clone(&logs));
            log(
                &logs,
                format!("P2P gossip listening on {}", p2p.local_addr()),
            );
            // UPnP: ask the router to let peers IN.
            //
            // A node behind NAT dials out fine — it syncs, relays and mines, and
            // its blocks reach the network. What it cannot do is ACCEPT inbound
            // connections, so it is a leaf rather than a participant, and a
            // network of only leaves has nowhere to connect to.
            //
            // A `PortMapper` rather than a one-shot call, because a UPnP mapping
            // is a LEASE. Mapping once and forgetting means going quietly
            // unreachable an hour later with nothing in the log to explain it —
            // worse than never mapping, because the operator was told they were
            // reachable. The mapper renews at half the lease, rediscovers the
            // router if a renewal fails, backs off when refused, and removes the
            // mapping on shutdown so a restarting node does not fill the
            // router's mapping table.
            //
            // Opt-out honoured: some operators are required not to use UPnP, and
            // a node on a VPS with a public address has no use for it.
            if config.upnp.unwrap_or(true) {
                let local = p2p.local_addr();
                let logs_for_map = Arc::clone(&logs);
                let mapper = sov_network::PortMapper::start(local, "SOV node", move |msg| {
                    log(&logs_for_map, msg)
                });
                // Publish reachability so `sov_getPeerInfo` can answer "can
                // anyone reach me?" without the operator reading logs.
                let mapper = Arc::new(mapper);
                let sync_for_map = Arc::clone(&sync);
                let poll_mapper = Arc::clone(&mapper);
                // Exits with the mapper rather than outliving it: a detached
                // loop that never stops is a thread nobody owns.
                std::thread::spawn(move || {
                    while !poll_mapper.is_stopped() {
                        sync_for_map.set_reachability(poll_mapper.reachability().as_str());
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                    // Final state after shutdown, so the last thing published is
                    // accurate rather than a stale "mapped".
                    sync_for_map.set_reachability("stopped");
                });
                port_mapper = Some((mapper, local.port()));
            } else {
                log(&logs, "UPnP disabled by config (upnp = false)");
                sync.set_reachability("disabled");
            }

            // Persistent peer discovery: remember reachable peers across restarts so the
            // hard-coded seeds are only ever needed for the FIRST contact. Loads
            // <data_dir>/peers.dat, redials a sample, and re-flushes it periodically.
            p2p.tcp()
                .enable_persistence(std::path::Path::new(&config.data_dir).join("peers.dat"));
            for peer in &bootstrap {
                // Best-effort first dial; if the seed isn't up yet, the engine keeps
                // retrying in the background, so the link forms once it is.
                match p2p.connect(peer) {
                    Ok(()) => log(&logs, format!("dialed bootstrap peer {peer}")),
                    Err(e) => log(
                        &logs,
                        format!(
                            "bootstrap peer {peer} not reachable yet ({e}); will keep retrying"
                        ),
                    ),
                }
            }
            // mDNS-style LAN auto-discovery: harmless on a public host (no multicast
            // peers), and co-located nodes find one another with zero configuration.
            // Log the real bind/join result instead of claiming discovery is active
            // after a silent OS/network failure.
            match p2p.tcp().enable_lan_discovery(&genesis.chain_id) {
                Ok(()) => log(
                    &logs,
                    "LAN discovery active on 239.255.90.45:9646 (same-chain peers only)",
                ),
                Err(e) => log(
                    &logs,
                    format!(
                        "LAN discovery unavailable ({e}); bootstrap/gossip peering remains active"
                    ),
                ),
            }
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
        .run(
            &config.rpc_addr,
            config.rpc_workers,
            config.block_time_ms,
            config.mine,
            config.resolved_mining_duty(),
        )?;
    log(
        &logs,
        format!("JSON-RPC listening on http://{}", handle.rpc_addr()),
    );
    log(
        &logs,
        format!(
            "producing blocks every {} ms; press Ctrl-C (or SIGTERM) to stop.",
            config.block_time_ms
        ),
    );

    // GRACEFUL SHUTDOWN.
    //
    // The durable head is the last fsync'd block in blocks.log, so an abrupt
    // kill was already safe for the CHAIN. What it was not safe for is
    // everything around it: the pending mempool was lost rather than written,
    // and the router kept forwarding a port to a process that no longer exists
    // until the UPnP lease happened to expire.
    //
    // So the main thread now waits for SIGINT/SIGTERM instead of parking
    // forever, and unwinds in dependency order.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    if let Err(e) = ctrlc::set_handler(move || {
        // Signal-handler context: do nothing but wake the main thread. All the
        // real work happens below, on a normal thread with normal rules.
        let _ = tx.send(());
    }) {
        // Without a handler we cannot shut down cleanly, and pretending
        // otherwise would be worse than saying so.
        log(
            &logs,
            format!(
                "could not install a signal handler ({e}); \
             shutdown will not be graceful"
            ),
        );
    }
    let _ = rx.recv();
    log(&logs, "shutdown requested — stopping cleanly".to_string());
    // Flush after EACH step rather than at the end: if one of them hangs, the
    // operator can see which, instead of watching a silent process.
    drain_logs_now(&logs);

    // 1. Release the router mapping FIRST. It is the only piece of state that
    //    lives outside this machine, and the only one another device is
    //    actively relying on. The lease would expire eventually; leaving it is
    //    litter in a table with finite room.
    if let Some((mapper, port)) = port_mapper.take() {
        mapper.shutdown(port);
        log(&logs, "released the UPnP port mapping".to_string());
        drain_logs_now(&logs);
    }

    // 2. Stop block production and the RPC server, and WAIT for both. The
    //    handle's shutdown joins the production thread before returning, so the
    //    final mempool snapshot cannot race a block being assembled from it.
    handle.shutdown();
    log(
        &logs,
        "stopped block production and RPC; mempool + snapshot persisted".to_string(),
    );

    log(&logs, "shutdown complete".to_string());
    drain_logs_now(&logs);
    Ok(())
}
