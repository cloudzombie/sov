//! `sov-rpcd` — the long-running SOV node daemon (Phase 8, p8-i0).
//!
//! Boots a node from a chain-spec, replays any persisted block log to resume
//! state, serves the JSON-RPC API, and produces blocks on a schedule.
//!
//! ```text
//! sov-rpcd <node-config.json> <chain-spec.json> <keystore.json>
//! ```

use std::error::Error;
use std::{env, fs, process, thread};

use sov_rpc::{ChainSpec, Daemon, Keystore, NodeConfig, P2p, P2pConfig};

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

    let mut daemon = Daemon::new(
        &genesis,
        &config.data_dir,
        config.mempool_capacity,
        config.max_block_txs,
        miner_keys,
    )?;
    println!(
        "sov-rpcd: chain '{}' — resumed {} block(s) from {}",
        genesis.chain_id,
        daemon.resumed_blocks(),
        config.data_dir,
    );

    // Install any trusted weak-subjectivity checkpoints from the config, so a
    // forged long-range history is rejected on import.
    let checkpoints = config
        .checkpoints
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<_>, _>>()?;
    if !checkpoints.is_empty() {
        println!(
            "sov-rpcd: {} weak-subjectivity checkpoint(s) loaded",
            checkpoints.len()
        );
        daemon = daemon.with_checkpoints(checkpoints);
    }

    // Optional peer-to-peer. Bind the gossip + sync engine to the SAME shared node
    // the daemon produces on, so transactions and blocks flow both ways with peers;
    // attach the same transport back to the daemon for OUTBOUND gossip of everything
    // this node produces. Held to the end of `run` (the engine's threads outlive this
    // binding, but keeping it parks shutdown to process exit).
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
            .with_bootstrap(config.bootstrap_peers.clone());
            println!("sov-rpcd: P2P gossip listening on {}", p2p.local_addr());
            for peer in &config.bootstrap_peers {
                // Best-effort first dial; if the seed isn't up yet, the engine keeps
                // retrying in the background, so the link forms once it is.
                match p2p.connect(peer) {
                    Ok(()) => println!("sov-rpcd: dialed bootstrap peer {peer}"),
                    Err(e) => {
                        eprintln!("sov-rpcd: bootstrap peer {peer} not reachable yet ({e}); will keep retrying")
                    }
                }
            }
            daemon = daemon.with_gossip(p2p.tcp());
            Some(p2p.start())
        }
        None => {
            println!("sov-rpcd: P2P disabled (no p2p_addr) — running standalone");
            None
        }
    };

    let handle = daemon.run(&config.rpc_addr, config.rpc_workers, config.block_time_ms)?;
    println!(
        "sov-rpcd: JSON-RPC listening on http://{}",
        handle.rpc_addr()
    );
    println!(
        "sov-rpcd: producing blocks every {} ms; press Ctrl-C to stop.",
        config.block_time_ms
    );

    // The daemon's RPC + production threads keep the chain running; park the main
    // thread to keep the process alive. A SIGINT (Ctrl-C) terminates the process.
    loop {
        thread::park();
    }
}
