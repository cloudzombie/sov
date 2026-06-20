#![forbid(unsafe_code)]

use std::env;
use std::fmt::Display;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sov_primitives::AccountId;
use sov_rpc::{RpcClient, RpcClientError};

mod gui;

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
    Help,
}

fn main() {
    if let Err(e) = run(env::args().skip(1).collect()) {
        eprintln!("sov-station: {e}");
        std::process::exit(1);
    }
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
    fn hash_shortening_keeps_edges() {
        assert_eq!(
            short_hash("abcdef0123456789abcdef0123456789"),
            "abcdef01234567...456789"
        );
    }
}
