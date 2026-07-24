//! `sov-e2e` — S8a Live end-to-end harness (v0.2.0 program, W8).
//!
//! One command: builds/locates the release `sov-rpcd` + `sov-wallet` binaries,
//! generates a fresh ISOLATED testnet genesis (never mainnet's — asserted),
//! stands up a real 5-node network (3 miners + observer + late-join observer)
//! on the selected backend, runs the S8b lifecycle matrix, tears everything
//! down deterministically (even on failure), and emits a machine-readable JSON
//! report plus a human summary. Exit 0 ONLY if no step failed.
//!
//! ```text
//! sov-e2e run [--backend local|ssh|container] [--ssh-config hosts.json]
//!             [--bins DIR] [--run-dir DIR] [--report FILE]
//!             [--base-rpc 18645] [--base-p2p 19645] [--keep]
//! ```

mod backend;
mod net;
mod report;
mod rpc;
mod steps;
mod util;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use backend::{container_backend_stub, preflight_ports, Backend, LocalBackend, SshBackend};
use report::{print_summary, report_json, Status, StepResult};
use rpc::Rpc;
use util::{now_ms, poll, run_cmd_timeout};

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("sov-e2e: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Minimal `--key value` / `--flag` parser (the repo's tool convention).
struct Flags {
    opts: HashMap<String, String>,
    switches: Vec<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        const SWITCHES: [&str; 1] = ["keep"];
        let mut opts = HashMap::new();
        let mut switches = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            let key = a
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument `{a}` (flags only)"))?;
            if SWITCHES.contains(&key) {
                switches.push(key.to_string());
                i += 1;
            } else {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("--{key} needs a value"))?;
                opts.insert(key.to_string(), val.clone());
                i += 2;
            }
        }
        Ok(Flags { opts, switches })
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.opts.get(key).map(String::as_str)
    }
    fn has(&self, key: &str) -> bool {
        self.switches.iter().any(|s| s == key)
    }
    fn port(&self, key: &str, default: u16) -> Result<u16, String> {
        match self.get(key) {
            Some(v) => v.parse().map_err(|e| format!("--{key}: {e}")),
            None => Ok(default),
        }
    }
}

/// Repo root, from this crate's pinned location (`<repo>/tools/e2e-vm`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tools/e2e-vm sits two levels under the repo root")
        .to_path_buf()
}

/// Locate — or build — the release `sov-rpcd` and `sov-wallet` binaries. These
/// are the SAME bits an operator deploys (a built release artifact, never
/// `cargo run`).
fn locate_bins(flags: &Flags) -> Result<(PathBuf, PathBuf), String> {
    let dir = match flags.get("bins") {
        Some(d) => PathBuf::from(d),
        None => repo_root().join("chain/target/release"),
    };
    let rpcd = dir.join("sov-rpcd");
    let wallet = dir.join("sov-wallet");
    if rpcd.is_file() && wallet.is_file() {
        return Ok((rpcd, wallet));
    }
    if flags.get("bins").is_some() {
        return Err(format!(
            "--bins {}: sov-rpcd / sov-wallet not found there",
            dir.display()
        ));
    }
    println!("release binaries not found — building (cargo build --release -p sov-rpc)…");
    let manifest = repo_root().join("chain/Cargo.toml");
    let out = run_cmd_timeout(
        Path::new("cargo"),
        &[
            "build",
            "--release",
            "--manifest-path",
            &manifest.to_string_lossy(),
            "-p",
            "sov-rpc",
            "--bin",
            "sov-rpcd",
            "--bin",
            "sov-wallet",
        ],
        None,
        Duration::from_secs(3600),
    )?;
    if !out.status_ok {
        return Err(format!("release build failed:\n{}", out.stderr));
    }
    if rpcd.is_file() && wallet.is_file() {
        Ok((rpcd, wallet))
    } else {
        Err("build reported success but the binaries are missing".into())
    }
}

fn run(args: Vec<String>) -> Result<usize, String> {
    let (cmd, rest) = args
        .split_first()
        .map(|(c, r)| (c.as_str(), r))
        .unwrap_or(("run", &[]));
    if cmd != "run" {
        return Err(format!("unknown command `{cmd}` (only: run)"));
    }
    let flags = Flags::parse(rest)?;
    let started_at_ms = now_ms();

    let (rpcd, wallet) = locate_bins(&flags)?;
    println!("binaries : {} / {}", rpcd.display(), wallet.display());

    let backend_name = flags.get("backend").unwrap_or("local").to_string();
    let mut backend: Box<dyn Backend> = match backend_name.as_str() {
        "local" => Box::new(LocalBackend::new()),
        "ssh" => {
            let cfg = flags
                .get("ssh-config")
                .ok_or("--backend ssh needs --ssh-config <hosts.json>")?;
            Box::new(SshBackend::from_config(Path::new(cfg))?)
        }
        "container" => container_backend_stub()?,
        other => return Err(format!("unknown backend `{other}` (local|ssh|container)")),
    };

    let run_dir = match flags.get("run-dir") {
        Some(d) => PathBuf::from(d),
        None => std::env::temp_dir().join(format!("sov-e2e-{}", std::process::id())),
    };
    if run_dir.exists() {
        return Err(format!(
            "run dir {} already exists — refusing to reuse state (pass a fresh --run-dir)",
            run_dir.display()
        ));
    }
    let base_rpc = flags.port("base-rpc", 18_645)?;
    let base_p2p = flags.port("base-p2p", 19_645)?;

    println!("run dir  : {}", run_dir.display());
    println!(
        "chain id : {} (isolated; genesis asserted ≠ mainnet)",
        net::CHAIN_ID
    );

    // Generate the pinned network (keys via the REAL wallet binary).
    let network = net::generate(&run_dir, &wallet, base_rpc, base_p2p)?;
    if backend_name == "local" {
        preflight_ports(&network.plans)?;
    }

    // ---- run everything inside a teardown-always envelope -----------------
    let outcome = drive(&mut *backend, &network, &rpcd, &wallet);

    // Deterministic teardown: stop every node, verify all endpoints refuse,
    // then remove the run dir (unless --keep). Runs on success AND failure.
    let stopped = backend.stop_all();
    let down = backend.verify_down(&network.plans);
    println!(
        "teardown : stopped {:?}; endpoints closed: {}",
        stopped,
        match &down {
            Ok(()) => "verified".to_string(),
            Err(e) => format!("NOT VERIFIED — {e}"),
        }
    );
    let mut teardown_note = None;
    if let Err(e) = down {
        teardown_note = Some(format!("teardown verification failed: {e}"));
    }
    if flags.has("keep") {
        println!("teardown : --keep set, leaving {}", run_dir.display());
    } else {
        std::fs::remove_dir_all(&run_dir)
            .map_err(|e| format!("failed to remove run dir {}: {e}", run_dir.display()))?;
        println!("teardown : removed {}", run_dir.display());
    }

    // ---- report ------------------------------------------------------------
    let (genesis_hash, mut step_results) = outcome?;
    if let Some(note) = teardown_note {
        step_results.push(StepResult::fail(
            "teardown-verified",
            note,
            serde_json::json!({}),
        ));
    } else {
        step_results.push(StepResult::pass(
            "teardown-verified",
            "all nodes stopped, every RPC endpoint refuses, run dir handled",
            serde_json::json!({ "kept_run_dir": flags.has("keep") }),
        ));
    }

    let nodes: Vec<(String, String, bool)> = network
        .plans
        .iter()
        .map(|p| (p.name.clone(), p.rpc.clone(), p.mine))
        .collect();
    let json = report_json(
        &backend_name,
        net::CHAIN_ID,
        &genesis_hash,
        &nodes,
        &step_results,
        started_at_ms,
        now_ms(),
    );
    let pretty = serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?;
    println!("\n===== MACHINE-READABLE REPORT (JSON) =====\n{pretty}");
    if let Some(path) = flags.get("report") {
        std::fs::write(path, pretty.as_bytes())
            .map_err(|e| format!("write --report {path}: {e}"))?;
        println!("report written to {path}");
    }
    let failed = step_results
        .iter()
        .filter(|s| s.status == Status::Fail)
        .count();
    print_summary(&step_results, failed);
    Ok(failed)
}

/// Boot the initial nodes and run the matrix. Errors here still flow through
/// the caller's teardown path.
fn drive(
    backend: &mut dyn Backend,
    network: &net::Net,
    rpcd: &Path,
    wallet: &Path,
) -> Result<(String, Vec<StepResult>), String> {
    // Start nodes 1-4 (node-5 joins late inside the mesh step).
    let initial = ["node-1", "node-2", "node-3", "node-4"];
    for name in initial {
        backend.start(network.plan(name), rpcd)?;
    }
    // Readiness = the node ANSWERS RPC, never a sleep.
    for name in initial {
        let rpc = Rpc::new(network.plan(name).rpc.clone());
        poll(
            &format!("{name} RPC to come up"),
            Duration::from_secs(90),
            Duration::from_millis(300),
            || Ok(rpc.healthy().then_some(())),
        )?;
        println!("started  : {name} ({})", rpc.addr);
    }
    let genesis_hash = Rpc::new(network.plan("node-1").rpc.clone())
        .digest(0)?
        .and_then(|d| {
            d.get("hash")
                .and_then(|h| h.as_str())
                .map(|h| h.trim_start_matches("0x").to_string())
        })
        .ok_or("node-1 served no genesis digest")?;

    let mut ctx = steps::Ctx {
        backend,
        net: network,
        rpcd: rpcd.to_path_buf(),
        wallet: wallet.to_path_buf(),
        running: initial.iter().map(|s| s.to_string()).collect(),
    };
    let results = steps::run_matrix(&mut ctx);
    Ok((genesis_hash, results))
}
