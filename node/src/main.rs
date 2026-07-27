#![forbid(unsafe_code)]
// egui's API is uniformly `f32`, so float literals passed to it (`1.0`, colors, sizes)
// intentionally take the f32 fallback. rustc 1.97 added `float_literal_f32_fallback`,
// which flags that as surprising — it isn't here. Allow it crate-wide; `unknown_lints`
// keeps the allow harmless on older toolchains that don't know the lint yet.
#![allow(unknown_lints)]
#![allow(float_literal_f32_fallback)]

use std::env;
use std::fmt::Display;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sov_primitives::AccountId;
use sov_rpc::{RpcClient, RpcClientError};

mod gui;
mod vault;

const DEFAULT_RPC: &str = "127.0.0.1:8645";
const DEFAULT_INTERVAL_MS: u64 = 3_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    /// Open the native desktop window (the default with no arguments).
    Gui {
        rpc: String,
    },
    Status {
        rpc: String,
    },
    Mining {
        rpc: String,
    },
    Wallet {
        rpc: String,
        accounts: Vec<String>,
    },
    Watch {
        rpc: String,
        accounts: Vec<String>,
        interval_ms: u64,
    },
    /// Print the app version and exit — the machine-checkable version surface the
    /// release workflow asserts against the tag (see `scripts/verify-artifact-version.sh`).
    Version,
    Help,
}

/// The single line `--version` prints: `sov-station <CARGO_PKG_VERSION>`.
///
/// `CARGO_PKG_VERSION` comes from `node/Cargo.toml` — the SAME value the GUI shows in
/// its status bar ("SOV Station v…"), and the value the release gate requires to equal
/// the tag. Every release build is executed with `--version` on its own build runner and
/// the output must equal the tag exactly, so a published artifact can never merely
/// *claim* a version: it proves it. Keep the format stable — the check parses it.
fn version_line() -> String {
    format!("sov-station {}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    install_panic_log();
    if let Err(e) = run(env::args().skip(1).collect()) {
        eprintln!("sov-station: {e}");
        std::process::exit(1);
    }
}

/// Record a panic to `<station_dir>/logs/panic-<unix_ms>.log` before dying.
///
/// A Rust panic exits WITHOUT producing a macOS `.ips` crash report, and
/// Station previously wrote no diagnostics of any kind — so an operator whose
/// wallet vanished mid-sync had literally nothing to look at, and neither did
/// anyone trying to fix it. That is what happened to the first 0.2.2 build:
/// it closed while syncing and left no evidence anywhere on the system.
///
/// The hook chains to the default handler, so stderr behaviour is unchanged;
/// it only ADDS a durable record. It is deliberately dependency-free and
/// best-effort: a logger that can itself fail loudly during a panic would turn
/// a diagnosable crash into a confusing one.
fn install_panic_log() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // Same override the rest of the app honours, so a sandboxed dev build
        // never writes into the operator's real directory.
        let dir = std::env::var("SOV_STATION_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(
                    std::env::var("HOME")
                        .or_else(|_| std::env::var("USERPROFILE"))
                        .unwrap_or_default(),
                )
                .join(".sov-station")
            })
            .join("logs");
        if std::fs::create_dir_all(&dir).is_ok() {
            let body = format!(
                "sov-station {} panicked\n\
                 when      : {stamp} (unix ms)\n\
                 location  : {}\n\
                 message   : {info}\n\
                 backtrace :\n{:?}\n",
                env!("CARGO_PKG_VERSION"),
                info.location()
                    .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                    .unwrap_or_else(|| "unknown".into()),
                std::backtrace::Backtrace::force_capture(),
            );
            let _ = std::fs::write(dir.join(format!("panic-{stamp}.log")), body);
        }
        previous(info);
    }));
}

fn run(args: Vec<String>) -> Result<(), String> {
    let command = parse_args(&args)?;
    match command {
        Command::Gui { rpc } => gui::run(rpc),
        Command::Status { rpc } => print_status(&rpc, &client(&rpc)),
        Command::Mining { rpc } => print_mining(&rpc, &client(&rpc)),
        Command::Wallet { rpc, accounts } => print_wallet(&rpc, &client(&rpc), &accounts),
        Command::Watch {
            rpc,
            accounts,
            interval_ms,
        } => watch(&rpc, &client(&rpc), &accounts, interval_ms),
        Command::Version => {
            println!("{}", version_line());
            Ok(())
        }
        Command::Help => {
            print_usage();
            Ok(())
        }
    }
}

fn client(rpc: &str) -> RpcClient {
    RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(3))
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        // No arguments → the flagship experience: the desktop window.
        return Ok(Command::Gui {
            rpc: DEFAULT_RPC.to_string(),
        });
    }
    let command = args[0].as_str();
    if matches!(command, "-h" | "--help" | "help") {
        return Ok(Command::Help);
    }
    if matches!(command, "-V" | "--version" | "version") {
        return Ok(Command::Version);
    }

    match command {
        "gui" => {
            let rpc = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC.to_string());
            Ok(Command::Gui { rpc })
        }
        "status" => {
            let rpc = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC.to_string());
            Ok(Command::Status { rpc })
        }
        "mining" => {
            let rpc = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC.to_string());
            Ok(Command::Mining { rpc })
        }
        "wallet" => {
            let (rpc, rest) = rpc_and_rest(&args[1..]);
            Ok(Command::Wallet {
                rpc,
                accounts: rest.to_vec(),
            })
        }
        "watch" => {
            let (rpc, rest) = rpc_and_rest(&args[1..]);
            let mut accounts = Vec::new();
            let mut interval_ms = DEFAULT_INTERVAL_MS;
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--interval-ms" {
                    let raw = rest.get(i + 1).ok_or("missing value after --interval-ms")?;
                    interval_ms = raw
                        .parse::<u64>()
                        .map_err(|_| "bad --interval-ms value")?
                        .max(500);
                    i += 2;
                } else {
                    accounts.push(rest[i].clone());
                    i += 1;
                }
            }
            Ok(Command::Watch {
                rpc,
                accounts,
                interval_ms,
            })
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn rpc_and_rest(args: &[String]) -> (String, &[String]) {
    if let Some(first) = args.first() {
        if first.contains(':') && !first.starts_with("--") {
            return (first.clone(), &args[1..]);
        }
    }
    (DEFAULT_RPC.to_string(), args)
}

fn print_usage() {
    println!("SOV Station");
    println!();
    println!("Usage:");
    println!("  sov-station                       open the desktop window (default)");
    println!("  sov-station gui [rpc_addr]        open the desktop window");
    println!("  sov-station status [rpc_addr]");
    println!("  sov-station mining [rpc_addr]");
    println!("  sov-station wallet [rpc_addr] <account>...");
    println!("  sov-station watch [rpc_addr] [account]... [--interval-ms 3000]");
    println!("  sov-station --version             print the app version and exit");
    println!();
    println!("Default RPC: {DEFAULT_RPC}");
}

#[derive(Debug)]
struct Probe<T> {
    value: Option<T>,
    error: Option<String>,
}

impl<T> Probe<T> {
    fn ok(value: T) -> Self {
        Probe {
            value: Some(value),
            error: None,
        }
    }

    fn err(error: impl Display) -> Self {
        Probe {
            value: None,
            error: Some(error.to_string()),
        }
    }

    fn as_ref(&self) -> Probe<&T> {
        Probe {
            value: self.value.as_ref(),
            error: self.error.clone(),
        }
    }
}

fn probe<T>(f: impl FnOnce() -> Result<T, RpcClientError>) -> Probe<T> {
    match f() {
        Ok(value) => Probe::ok(value),
        Err(e) => Probe::err(e),
    }
}

fn probe_json(client: &RpcClient, method: &str) -> Probe<Value> {
    probe(|| client.call(method, json!({})))
}

fn display_probe<T: Display>(probe: Probe<&T>) -> String {
    match (probe.value, probe.error) {
        (Some(v), _) => v.to_string(),
        (None, Some(e)) => format!("unavailable ({e})"),
        _ => "unavailable".to_string(),
    }
}

fn value_field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn format_json_field(value: &Value, key: &str) -> String {
    match value_field(value, key) {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "--".to_string(),
        other => other.to_string(),
    }
}

fn short_hash(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    if s.len() <= 22 {
        s.to_string()
    } else {
        format!("{}...{}", &s[..14], &s[s.len() - 6..])
    }
}

fn print_status(rpc: &str, client: &RpcClient) -> Result<(), String> {
    let chain_id = probe(|| client.chain_id());
    let height = probe(|| client.height());
    let head = probe(|| client.head());
    let state_root = probe(|| client.call("sov_getStateRoot", json!({})));
    let supply = probe_json(client, "sov_getSupply");
    let difficulty = probe_json(client, "sov_getDifficulty");
    let mempool = probe(|| client.mempool_size());

    println!("SOV Station / Node");
    println!("RPC              {rpc}");
    println!(
        "Status           {}",
        if chain_id.value.is_some() {
            "online"
        } else {
            "offline"
        }
    );
    println!("Chain            {}", display_probe(chain_id.as_ref()));
    println!("Height           {}", display_probe(height.as_ref()));
    println!(
        "Head             {}",
        head.value
            .as_ref()
            .map(|b| short_hash(b.hash().to_hex()))
            .unwrap_or_else(|| head
                .error
                .clone()
                .unwrap_or_else(|| "unavailable".to_string()))
    );
    println!(
        "State Root       {}",
        state_root
            .value
            .as_ref()
            .and_then(Value::as_str)
            .map(short_hash)
            .unwrap_or_else(|| state_root
                .error
                .clone()
                .unwrap_or_else(|| "unavailable".to_string()))
    );
    if let Some(s) = &supply.value {
        println!("Supply Total     {}", format_json_field(s, "total"));
        println!("Supply Mined     {}", format_json_field(s, "mined"));
    } else {
        println!(
            "Supply           {}",
            supply.error.unwrap_or_else(|| "unavailable".to_string())
        );
    }
    if let Some(d) = &difficulty.value {
        println!("Difficulty       {}", format_json_field(d, "sha256d"));
    } else {
        println!(
            "Difficulty       {}",
            difficulty
                .error
                .unwrap_or_else(|| "unavailable".to_string())
        );
    }
    println!("Mempool          {}", display_probe(mempool.as_ref()));
    Ok(())
}

fn print_mining(rpc: &str, client: &RpcClient) -> Result<(), String> {
    let reward = probe(|| client.mint_reward());
    let difficulty = probe_json(client, "sov_getDifficulty");
    let mempool = probe(|| client.mempool_size());
    let miners = probe_json(client, "sov_getMiners");

    println!("SOV Station / Mining");
    println!("RPC              {rpc}");
    println!("Reward           {}", display_probe(reward.as_ref()));
    println!("Mempool          {}", display_probe(mempool.as_ref()));
    if let Some(d) = &difficulty.value {
        println!("Difficulty       {}", format_json_field(d, "sha256d"));
    } else {
        println!(
            "Difficulty       {}",
            difficulty
                .error
                .unwrap_or_else(|| "unavailable".to_string())
        );
    }
    println!();
    print_miners(miners.value.as_ref());
    Ok(())
}

fn print_miners(miners: Option<&Value>) {
    let rows = miners.and_then(Value::as_array);
    let Some(rows) = rows else {
        println!("Miner Registry   unavailable");
        return;
    };
    if rows.is_empty() {
        println!("Miner Registry   empty");
        return;
    }
    println!(
        "{:<34} {:>8} {:>10} {:>10}",
        "Account", "Blocks", "First", "Last"
    );
    for row in rows {
        let account = value_field(row, "account").as_str().unwrap_or("--");
        let blocks = value_field(row, "blocksMined").as_u64().unwrap_or_default();
        let first = value_field(row, "firstSeenHeight")
            .as_u64()
            .unwrap_or_default();
        let last = value_field(row, "lastSeenHeight")
            .as_u64()
            .unwrap_or_default();
        println!("{:<34} {:>8} {:>10} {:>10}", account, blocks, first, last);
    }
}

fn print_wallet(rpc: &str, client: &RpcClient, accounts: &[String]) -> Result<(), String> {
    println!("SOV Station / Wallet");
    println!("RPC              {rpc}");
    println!("Mode             watch-only");
    println!("Secrets          none loaded");
    if accounts.is_empty() {
        println!("Accounts         none");
        return Ok(());
    }
    println!();
    println!("{:<34} {:>22} {:>8}  Key", "Account", "Balance", "Nonce");
    for account in accounts {
        print_account(client, account);
    }
    Ok(())
}

fn print_account(client: &RpcClient, account: &str) {
    let id = match AccountId::new(account) {
        Ok(id) => id,
        Err(e) => {
            println!("{:<34} {:>22} {:>8}  invalid: {e}", account, "--", "--");
            return;
        }
    };
    let balance = probe(|| client.balance(&id));
    let nonce = probe(|| client.nonce(&id));
    let record = probe(|| client.account(&id));
    let key_state = match record.value {
        Some(Some(account)) if account.key.is_some() => "set",
        Some(Some(_)) => "keyless",
        Some(None) => "absent",
        None => "unknown",
    };
    println!(
        "{:<34} {:>22} {:>8}  {}",
        account,
        balance
            .value
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unavailable".to_string()),
        nonce
            .value
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "--".to_string()),
        key_state
    );
}

fn watch(
    rpc: &str,
    client: &RpcClient,
    accounts: &[String],
    interval_ms: u64,
) -> Result<(), String> {
    loop {
        print!("\x1b[2J\x1b[H");
        println!("SOV Station / Watch");
        println!("Updated          {}", unix_ms());
        println!();
        print_status(rpc, client)?;
        if !accounts.is_empty() {
            println!();
            print_wallet(rpc, client, accounts)?;
        }
        thread::sleep(Duration::from_millis(interval_ms));
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_command_is_gui() {
        // No arguments opens the desktop window (the flagship experience).
        assert_eq!(
            parse_args(&[]).unwrap(),
            Command::Gui {
                rpc: DEFAULT_RPC.to_string()
            }
        );
    }

    #[test]
    fn wallet_accepts_optional_rpc_then_accounts() {
        assert_eq!(
            parse_args(&args(&["wallet", "127.0.0.1:9000", "miner.sov"])).unwrap(),
            Command::Wallet {
                rpc: "127.0.0.1:9000".to_string(),
                accounts: vec!["miner.sov".to_string()]
            }
        );
    }

    #[test]
    fn watch_parses_interval() {
        assert_eq!(
            parse_args(&args(&["watch", "alice.sov", "--interval-ms", "750"])).unwrap(),
            Command::Watch {
                rpc: DEFAULT_RPC.to_string(),
                accounts: vec!["alice.sov".to_string()],
                interval_ms: 750
            }
        );
    }

    #[test]
    fn version_flag_is_recognised_in_every_spelling() {
        for spelling in ["--version", "-V", "version"] {
            assert_eq!(
                parse_args(&args(&[spelling])).unwrap(),
                Command::Version,
                "`{spelling}` must select the version command"
            );
        }
    }

    #[test]
    fn version_line_is_exactly_what_the_release_check_expects() {
        // The release workflow runs the BUILT binary with `--version` and requires the
        // output to equal `sov-station <tag-without-v>` exactly. Pin both the format and
        // the source of the number (node/Cargo.toml) so neither can drift silently.
        let line = version_line();
        assert_eq!(line, format!("sov-station {}", env!("CARGO_PKG_VERSION")));
        assert!(!line.contains('\n'), "version output must be a single line");
        let number = line.strip_prefix("sov-station ").expect("fixed prefix");
        assert!(
            number.split('.').count() == 3
                && number
                    .split('.')
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "version must be a bare X.Y.Z (no `v`, no git-describe suffix), got {number:?}"
        );
    }

    #[test]
    fn hash_shortening_keeps_edges() {
        assert_eq!(
            short_hash("abcdef0123456789abcdef0123456789"),
            "abcdef01234567...456789"
        );
    }
}

#[cfg(test)]
mod panic_log_tests {
    /// The panic log must actually be written, into the OVERRIDDEN directory.
    ///
    /// An untested crash logger is worse than none: it creates the belief that
    /// the next crash will be diagnosable. This spawns a real child process,
    /// panics it, and reads the file back.
    #[test]
    fn a_panic_is_recorded_to_the_station_dir() {
        // Re-exec this same test binary with a marker set, so the child runs
        // the real `install_panic_log` path and then panics for real.
        let dir = std::env::temp_dir().join(format!("sov-panic-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("panic_log_tests::child_that_panics")
            .arg("--ignored")
            .env("SOV_STATION_DIR", &dir)
            .env("SOV_PANIC_LOG_CHILD", "1")
            .output()
            .expect("spawn child");
        assert!(!out.status.success(), "the child must have panicked");

        let logs = dir.join("logs");
        let entries: Vec<_> = std::fs::read_dir(&logs)
            .unwrap_or_else(|e| panic!("no logs directory at {logs:?}: {e}"))
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one panic log");

        let body = std::fs::read_to_string(entries[0].path()).expect("read log");
        assert!(body.contains("panicked"), "log names the event");
        assert!(
            body.contains(env!("CARGO_PKG_VERSION")),
            "log records the version that crashed"
        );
        assert!(
            body.contains("deliberate test panic"),
            "log carries the panic message"
        );
        assert!(body.contains("location"), "log records where");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "child process for a_panic_is_recorded_to_the_station_dir"]
    fn child_that_panics() {
        if std::env::var("SOV_PANIC_LOG_CHILD").is_err() {
            return;
        }
        super::install_panic_log();
        panic!("deliberate test panic");
    }
}
