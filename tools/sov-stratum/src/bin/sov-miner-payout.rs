//! Sign sharechain payouts on the miner's machine and hand them to the pool.
//!
//! The pool never sees this seed. It checks the signatures and relays the
//! transactions to the node. Run it beside `xus-miner`, not on the pool host.
//!
//! ```text
//! sov-miner-payout --pool http://127.0.0.1:8080 --seed-hex <64 hex chars>
//! sov-miner-payout --print-account --seed-hex <64 hex chars>
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance, Hash, SigningDomain};
use sov_wallet::Wallet;

fn main() {
    let mut pool = String::from("http://127.0.0.1:8080");
    let mut seed_hex: Option<String> = None;
    let mut account: Option<String> = None;
    let mut print_account = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = |flag: &str| -> String {
            args.next().unwrap_or_else(|| {
                eprintln!("error: {flag} requires a value");
                std::process::exit(2);
            })
        };
        match flag.as_str() {
            "--pool" => pool = value("--pool"),
            "--seed-hex" => seed_hex = Some(value("--seed-hex")),
            "--account" => account = Some(value("--account")),
            "--print-account" => print_account = true,
            "--help" | "-h" => {
                eprintln!(
                    "sov-miner-payout — sign your own pool payouts\n\n\
                     --pool <url>         pool stats URL [http://127.0.0.1:8080]\n\
                     --seed-hex <hex>     32-byte ed25519 seed, hex\n\
                     --account <id>       payout account (default: implicit id of the seed)\n\
                     --print-account      print the implicit account id and exit"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown flag `{other}`");
                std::process::exit(2);
            }
        }
    }
    let seed_hex = seed_hex.unwrap_or_else(|| {
        eprintln!("error: --seed-hex is required");
        std::process::exit(2);
    });
    let seed = parse_seed(&seed_hex).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });
    let keypair = Keypair::from_seed(seed);
    let implicit = keypair.public_key().implicit_account_id();
    if print_account {
        println!("{}", implicit.as_str());
        return;
    }
    let account = match account {
        Some(raw) => AccountId::new(raw.trim()).unwrap_or_else(|e| {
            eprintln!("error: --account: {e}");
            std::process::exit(2);
        }),
        None => implicit.clone(),
    };
    if account.is_implicit() && account != implicit {
        eprintln!(
            "error: --account {} is an implicit id that does not match this seed",
            account.as_str()
        );
        std::process::exit(2);
    }

    let url = format!(
        "{}/api/payouts/{}",
        pool.trim_end_matches('/'),
        account.as_str()
    );
    let schedule = http_json("GET", &url, None).unwrap_or_else(|e| {
        eprintln!("error: payout schedule: {e}");
        std::process::exit(1);
    });
    if schedule
        .get("satisfied")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        println!("payouts already satisfied for {}", account.as_str());
        return;
    }
    let transfers = schedule
        .get("transfers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if transfers.is_empty() {
        eprintln!("nothing to sign yet ({schedule})");
        std::process::exit(1);
    }
    let mut nonce = schedule
        .get("nextNonce")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            eprintln!("error: schedule has no nextNonce");
            std::process::exit(1);
        });
    let domain = match schedule.get("signingDomain") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(parse_domain(v).unwrap_or_else(|e| {
            eprintln!("error: signing domain: {e}");
            std::process::exit(1);
        })),
    };

    let mut wallet = Wallet::new();
    wallet.import(account.clone(), keypair);
    let mut signed = Vec::with_capacity(transfers.len());
    for leg in &transfers {
        let to = leg
            .get("to")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                eprintln!("error: transfer missing `to`");
                std::process::exit(1);
            });
        let amount = leg
            .get("amount")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                eprintln!("error: transfer missing `amount`");
                std::process::exit(1);
            });
        let grains: u128 = amount.parse().unwrap_or_else(|_| {
            eprintln!("error: amount `{amount}` is not a grain count");
            std::process::exit(1);
        });
        let to_id = AccountId::new(to).unwrap_or_else(|e| {
            eprintln!("error: recipient `{to}`: {e}");
            std::process::exit(1);
        });
        let stx = wallet
            .transfer_in(
                &account,
                to_id,
                Balance::from_grains(grains),
                nonce,
                domain.as_ref(),
            )
            .unwrap_or_else(|e| {
                eprintln!("error: sign: {e}");
                std::process::exit(1);
            });
        nonce += 1;
        signed.push(stx);
    }
    let body = serde_json::json!({
        "account": account.as_str(),
        "txs": signed,
    })
    .to_string();
    let post_url = format!("{}/api/payout-txs", pool.trim_end_matches('/'));
    let reply = http_json("POST", &post_url, Some(&body)).unwrap_or_else(|e| {
        eprintln!("error: submit payouts: {e}");
        std::process::exit(1);
    });
    if reply
        .get("error")
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        eprintln!("pool refused payouts: {reply}");
        std::process::exit(1);
    }
    println!("{}", reply);
}

fn parse_seed(hex_seed: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_seed.trim()).map_err(|e| format!("seed is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("seed is {} bytes, want 32", v.len()))
}

fn parse_domain(v: &serde_json::Value) -> Result<SigningDomain, String> {
    let chain_id = v
        .get("chainId")
        .and_then(serde_json::Value::as_str)
        .ok_or("signingDomain.chainId missing")?;
    let genesis = v
        .get("genesis")
        .and_then(serde_json::Value::as_str)
        .ok_or("signingDomain.genesis missing")?;
    let hash = Hash::from_hex(genesis).map_err(|e| format!("genesis: {e}"))?;
    Ok(SigningDomain::new(chain_id, hash))
}

fn http_json(method: &str, url: &str, body: Option<&str>) -> Result<serde_json::Value, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// URLs are supported, got `{url}`"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        return Err("URL is missing a host".into());
    }
    let mut stream =
        TcpStream::connect(hostport).map_err(|e| format!("connect {hostport}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(20))).ok();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    let Some((_, payload)) = text.split_once("\r\n\r\n") else {
        return Err(format!("not an HTTP response: {text}"));
    };
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let value: serde_json::Value = serde_json::from_str(payload.trim())
        .map_err(|e| format!("HTTP {status}: {payload} ({e})"))?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {value}"));
    }
    Ok(value)
}
