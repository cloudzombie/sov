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

mod auction;
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
    /// Produce a public, read-only JSON diagnostic snapshot without loading any
    /// wallet/configuration files or changing node/miner state.
    Diagnostics {
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
    /// Exercise the packaged executable's native RandomX/JIT path without
    /// connecting to a node, loading a wallet, or starting mining.
    SelfTestPlatform,
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
    let args: Vec<String> = env::args().skip(1).collect();
    // Diagnostics promises no filesystem writes, including error paths. Other
    // commands retain the existing persistent panic diagnostics.
    if args.first().map(String::as_str) != Some("diagnostics") {
        install_panic_log();
    }
    if let Err(e) = run(args) {
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
        Command::Diagnostics { rpc } => {
            let report = diagnostics_report(&client(&rpc));
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
            Ok(())
        }
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
        Command::SelfTestPlatform => self_test_platform(),
        Command::Help => {
            print_usage();
            Ok(())
        }
    }
}

/// Run upstream RandomX known-answer vectors through the production node path.
///
/// Release packaging invokes this on the executable inside the signed .app,
/// because `--version` cannot detect a missing macOS JIT entitlement. No wallet,
/// RPC, networking or full mining dataset is involved (light cache: ~256 MiB).
fn self_test_platform() -> Result<(), String> {
    let vectors: &[(&[u8], [u8; 32])] = &[
        (
            b"This is a test",
            [
                0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a, 0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09,
                0xca, 0xd9, 0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72, 0x62, 0xa0, 0xac, 0x1c,
                0x2f, 0x0b, 0x4e, 0x3f,
            ],
        ),
        (
            b"Lorem ipsum dolor sit amet",
            [
                0x30, 0x0a, 0x0a, 0xdb, 0x47, 0x60, 0x3d, 0xed, 0xb4, 0x22, 0x28, 0xcc, 0xb2, 0xb2,
                0x11, 0x10, 0x4f, 0x4d, 0xa4, 0x5a, 0xf7, 0x09, 0xcd, 0x75, 0x47, 0xcd, 0x04, 0x9e,
                0x94, 0x89, 0xc9, 0x69,
            ],
        ),
    ];
    for (index, (input, expected)) in vectors.iter().enumerate() {
        for _ in 0..2 {
            let actual = sov_pow::pow_seal(sov_pow::PowAlgo::RandomX, b"test key 000", input);
            if actual != *expected {
                return Err(format!("RandomX platform self-test vector {index} failed"));
            }
        }
    }
    let jit = sov_pow::randomx_verifier_uses_jit().ok_or("RandomX verifier was not initialized")?;
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) && !jit {
        return Err("Apple Silicon platform self-test must exercise RandomX JIT".to_string());
    }
    println!(
        "{} platform self-test: RandomX known answers passed (backend: {})",
        version_line(),
        if jit { "JIT" } else { "interpreter" }
    );
    Ok(())
}

fn client(rpc: &str) -> RpcClient {
    RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(3))
}

const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(3);

/// Bound the whole probe, including DNS and a slowly streamed response. The
/// client's socket timeout alone is only a timeout on each individual read.
fn diagnostic_deadline<T: Send + 'static>(
    timeout: Duration,
    work: impl FnOnce() -> Result<T, RpcClientError> + Send + 'static,
) -> Result<T, RpcClientError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sov-diagnostics-rpc".into())
        .spawn(move || {
            let _ = sender.send(work());
        })?;
    receiver.recv_timeout(timeout).map_err(|error| {
        RpcClientError::Io(std::io::Error::new(
            match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => std::io::ErrorKind::TimedOut,
                std::sync::mpsc::RecvTimeoutError::Disconnected => std::io::ErrorKind::Other,
            },
            "diagnostic probe did not complete",
        ))
    })?
}

fn diagnostic_error(error: RpcClientError) -> Value {
    // Never echo an untrusted server message, endpoint or response body: any of
    // them could contain an authentication token or an unexpected private field.
    let data = match error {
        RpcClientError::Io(error) => json!({
            "kind": "transport", "ioKind": format!("{:?}", error.kind()),
        }),
        RpcClientError::Json(_) => json!({"kind": "invalid_json"}),
        RpcClientError::Malformed(message)
            if message.starts_with("canonical chain name has a different genesis") =>
        {
            json!({"kind": "canonical_genesis_mismatch"})
        }
        RpcClientError::Malformed(_) => json!({"kind": "malformed_response"}),
        RpcClientError::Rpc { code, .. } => json!({
            "kind": if code == -32601 { "method_unavailable" } else { "rpc_error" },
            "code": code,
        }),
    };
    json!({"ok": false, "error": data})
}

fn diagnostic_result(result: Result<Value, RpcClientError>) -> Value {
    match result {
        Ok(data) => json!({"ok": true, "data": data}),
        Err(error) => diagnostic_error(error),
    }
}

#[derive(Clone, Copy)]
enum DiagnosticType {
    Bool,
    UInt,
    Number,
    Decimal,
    Hash,
    Text,
    Versions,
}

fn diagnostic_shape_error() -> RpcClientError {
    RpcClientError::Malformed("unexpected public diagnostic field shape".into())
}

/// Explicitly project public fields. Unknown fields (including keys, tokens,
/// seed phrases, addresses and entire block transaction bodies) never leave
/// this function. Missing optional fields remain absent, rather than zero.
fn diagnostic_fields(
    value: &Value,
    schema: &[(&str, DiagnosticType)],
    required: &[&str],
) -> Result<Value, RpcClientError> {
    let object = value.as_object().ok_or_else(diagnostic_shape_error)?;
    let mut out = serde_json::Map::new();
    for (name, kind) in schema {
        let Some(field) = object.get(*name) else {
            continue;
        };
        if field.is_null() && !required.contains(name) {
            out.insert((*name).into(), Value::Null);
            continue;
        }
        let parsed = match kind {
            DiagnosticType::Bool if field.is_boolean() => field.clone(),
            DiagnosticType::UInt if field.as_u64().is_some() => field.clone(),
            DiagnosticType::Number if field.is_number() => field.clone(),
            DiagnosticType::Decimal => {
                let amount = field
                    .as_str()
                    .and_then(|raw| raw.parse::<u128>().ok())
                    .ok_or_else(diagnostic_shape_error)?;
                json!(amount.to_string())
            }
            DiagnosticType::Hash => {
                let hash = field
                    .as_str()
                    .and_then(|raw| sov_primitives::Hash::from_hex(raw).ok())
                    .ok_or_else(diagnostic_shape_error)?;
                json!(hash.to_hex())
            }
            DiagnosticType::Text => {
                let text = field.as_str().ok_or_else(diagnostic_shape_error)?;
                if text.len() > 256 || text.chars().any(char::is_control) {
                    return Err(diagnostic_shape_error());
                }
                json!(text)
            }
            DiagnosticType::Versions => {
                let versions = field.as_array().ok_or_else(diagnostic_shape_error)?;
                if versions.len() > 8 || versions.iter().any(|v| v.as_u64().is_none_or(|n| n > 255))
                {
                    return Err(diagnostic_shape_error());
                }
                field.clone()
            }
            _ => return Err(diagnostic_shape_error()),
        };
        out.insert((*name).into(), parsed);
    }
    if required.iter().any(|name| !out.contains_key(*name)) {
        return Err(diagnostic_shape_error());
    }
    Ok(Value::Object(out))
}

fn diagnostic_probe(
    client: &RpcClient,
    method: &'static str,
    project: impl FnOnce(Value) -> Result<Value, RpcClientError> + Send + 'static,
) -> Value {
    let client = client.clone();
    diagnostic_result(diagnostic_deadline(DIAGNOSTIC_TIMEOUT, move || {
        project(client.call(method, json!({}))?)
    }))
}

fn diagnostic_domain(client: &RpcClient) -> Value {
    let client = client.clone();
    diagnostic_result(diagnostic_deadline(DIAGNOSTIC_TIMEOUT, move || {
        let domain = client.chain_domain()?;
        let canonical = matches!(domain.chain_id(), "sov-mainnet" | "sov-testnet-1");
        diagnostic_fields(
            &json!({
                "chainId": domain.chain_id(), "genesis": domain.genesis().to_hex(),
                "canonicalName": canonical, "canonicalGenesisPinned": canonical,
            }),
            &[
                ("chainId", DiagnosticType::Text),
                ("genesis", DiagnosticType::Hash),
                ("canonicalName", DiagnosticType::Bool),
                ("canonicalGenesisPinned", DiagnosticType::Bool),
            ],
            &[
                "chainId",
                "genesis",
                "canonicalName",
                "canonicalGenesisPinned",
            ],
        )
    }))
}

fn diagnostic_head(client: &RpcClient) -> Value {
    diagnostic_probe(client, "sov_getHead", |raw| {
        // Parse only the typed header, then recompute its hash. Transaction
        // bodies are neither deserialized into wallet objects nor reported.
        let header: sov_types::BlockHeader = serde_json::from_value(
            raw.get("header")
                .cloned()
                .ok_or_else(diagnostic_shape_error)?,
        )?;
        Ok(json!({
            "height": header.height.get(), "hash": header.hash().to_hex(),
            "stateRoot": header.state_root.to_hex(), "timestampMs": header.timestamp_ms,
            "bits": header.bits, "versionBits": header.version_bits,
        }))
    })
}

fn diagnostic_peer_info(raw: Value) -> Result<Value, RpcClientError> {
    use DiagnosticType::{Bool, Hash, Text, UInt};
    let mut out = diagnostic_fields(
        &raw,
        &[
            ("chainId", Text),
            ("version", Text),
            ("genesisHash", Hash),
            ("height", UInt),
            ("p2pEnabled", Bool),
            ("tcpLinks", UInt),
            ("peers", UInt),
            ("protocolVersion", UInt),
            ("reachability", Text),
            ("bestPeerHeight", UInt),
            ("behindBlocks", UInt),
            ("behindKnown", Bool),
            ("syncing", Bool),
        ],
        &["chainId", "genesisHash", "height", "peers"],
    )?;
    if let Some(versions) = raw.get("peerVersions") {
        let versions = versions.as_array().ok_or_else(diagnostic_shape_error)?;
        let mut projected = Vec::new();
        let mut unrecognized = 0u64;
        for peer in versions.iter().take(64) {
            let agent = peer
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if agent.starts_with("sov/v")
                && agent.len() <= 128
                && agent
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/.-".contains(&byte))
            {
                projected.push(diagnostic_fields(
                    peer,
                    &[("protocol", UInt), ("agent", Text)],
                    &["protocol", "agent"],
                )?);
            } else {
                unrecognized += 1;
            }
        }
        out["peerVersions"] = json!(projected);
        out["unrecognizedAgentCount"] = json!(unrecognized);
        out["peerVersionsTruncated"] = json!(versions.len() > 64);
    }
    Ok(out)
}

fn diagnostic_quantum(raw: Value) -> Result<Value, RpcClientError> {
    use DiagnosticType::{Bool, Decimal, Number, Text, UInt, Versions};
    let mut out = diagnostic_fields(
        &raw,
        &[
            ("height", UInt),
            ("evaluatedHeight", UInt),
            ("legacyTransactionsAllowed", Bool),
            ("legacyMigrationAllowed", Bool),
            ("legacyTransactionPolicy", Text),
            ("newLegacyAccountsAllowed", Bool),
            ("poolV1Stage", Text),
            ("poolV1DepositsAllowed", Bool),
            ("poolV1SpendsAllowed", Bool),
            ("poolV1CarrierBindingRequired", Bool),
            ("poolV1RecoveryAllowed", Bool),
            ("v2Active", Bool),
            ("v2ProofSecurityEstablished", Bool),
            ("v2PrivacyEstablished", Bool),
            ("poolV2CreationAllowed", Bool),
            ("poolV2SpendsAllowed", Bool),
            ("poolV2RecoveryAllowed", Bool),
            ("poolV2HistoricalReplaySupported", Bool),
            ("poolV2HistoricalProofVersions", Versions),
            ("poolV2AcceptedNewProofVersions", Versions),
            ("poolV2Suite2ParameterId", UInt),
            ("poolV2WriteBlockReason", Text),
            ("fullyPostQuantum", Bool),
            ("signatureScheme", Text),
        ],
        &["height", "fullyPostQuantum"],
    )?;
    if let Some(hash) = raw.get("hash") {
        out["hash"] = diagnostic_fields(
            hash,
            &[
                ("algorithm", Text),
                ("outputBits", UInt),
                ("genericQuantumPreimageBits", UInt),
                ("genericQuantumCollisionBitsApprox", Number),
                ("securityEstimateModel", Text),
            ],
            &[],
        )?;
    }
    if let Some(sunset) = raw.get("pqSunset") {
        out["pqSunset"] = diagnostic_fields(
            sunset,
            &[
                ("armed", Bool),
                ("state", Text),
                ("stage", Text),
                ("bit", UInt),
                ("startHeight", UInt),
                ("timeoutHeight", UInt),
                ("period", UInt),
                ("minActivationHeight", UInt),
                ("lockinontimeout", Bool),
                ("sunsetDelayBlocks", UInt),
                ("thresholdGrains", Decimal),
                ("rotationOnlyHeight", UInt),
                ("sunsetHeight", UInt),
            ],
            &[],
        )?;
    }
    Ok(out)
}

fn diagnostic_data<'a>(report: &'a Value, field: &str) -> Option<&'a Value> {
    report.get(field)?.get("data")
}

fn diagnostic_equal(left: Option<&Value>, right: Option<&Value>) -> Option<bool> {
    Some(left? == right?)
}

fn diagnostic_amount(report: &Value, method: &str, field: &str) -> Option<u128> {
    diagnostic_data(report, method)?
        .get(field)?
        .as_str()?
        .parse()
        .ok()
}

fn diagnostics_report(client: &RpcClient) -> Value {
    use DiagnosticType::{Bool, Decimal, Hash, Number, Text, UInt, Versions};
    let mut report = json!({
        "schemaVersion": 1, "collectedAtUnixMs": unix_ms(),
        "app": {"version": env!("CARGO_PKG_VERSION"), "targetOs": env::consts::OS, "targetArch": env::consts::ARCH},
        "source": {"transport": "tcp-json-rpc", "rpcCryptographicallyAuthenticated": false,
            "consensusRevalidated": false, "perProbeDeadlineMs": 3000,
            "walletDataIncluded": false, "peerAddressesIncluded": false},
    });
    report["chainDomainStart"] = diagnostic_domain(client);
    report["headStart"] = diagnostic_head(client);
    report["nodeVersion"] = diagnostic_probe(client, "sov_version", |v| {
        diagnostic_fields(&v, &[("version", Text)], &["version"])
    });
    report["stateRoot"] = diagnostic_probe(client, "sov_getStateRoot", |value| {
        diagnostic_fields(&json!({"root": value}), &[("root", Hash)], &["root"])
    });
    report["supply"] = diagnostic_probe(client, "sov_getSupply", |v| {
        diagnostic_fields(
            &v,
            &[
                ("total", Decimal),
                ("circulating", Decimal),
                ("mined", Decimal),
                ("shielded", Decimal),
                ("shieldedV2", Decimal),
                ("shieldedTotal", Decimal),
                ("transparent", Decimal),
                ("shieldedPercent", Number),
            ],
            &["total", "mined"],
        )
    });
    report["peers"] = diagnostic_probe(client, "sov_getPeerInfo", diagnostic_peer_info);
    report["mining"] = diagnostic_probe(client, "sov_getDifficulty", |v| {
        let mut out = diagnostic_fields(
            &v,
            &[
                ("sha256d", Decimal),
                ("algo", Text),
                ("targetBlockMs", UInt),
                ("hashrate", Number),
            ],
            &["sha256d", "algo"],
        )?;
        // These RPCs describe consensus/network mining. They do not report
        // whether this specific desktop instance is mining or its local rate.
        out["localMiningEnabled"] = Value::Null;
        out["localHashrate"] = Value::Null;
        Ok(out)
    });
    report["mempool"] = diagnostic_probe(client, "sov_getMempoolInfo", |v| {
        diagnostic_fields(
            &v,
            &[
                ("txCount", UInt),
                ("queuedCount", UInt),
                ("capacity", UInt),
                ("maxPerSender", UInt),
                ("queuedCapacity", UInt),
                ("maxQueuedPerSender", UInt),
                ("maxBlockTxs", UInt),
                ("maxBlockBytes", UInt),
                ("nextBlockFloorGrains", Decimal),
                ("poolFloorGrains", Decimal),
                ("oldestPendingAgeMs", UInt),
                ("oldestQueuedAgeMs", UInt),
            ],
            &["txCount"],
        )
    });
    report["quantum"] = diagnostic_probe(client, "sov_getQuantumStatus", diagnostic_quantum);
    report["poolV2"] = diagnostic_probe(client, "sov_getShieldedV2Info", |v| {
        diagnostic_fields(
            &v,
            &[
                ("active", Bool),
                ("proofSecurityEstablished", Bool),
                ("privacyEstablished", Bool),
                ("creationAllowed", Bool),
                ("spendsAllowed", Bool),
                ("recoveryAllowed", Bool),
                ("scanSupported", Bool),
                ("historicalReplaySupported", Bool),
                ("historicalProofVersions", Versions),
                ("acceptedNewProofVersions", Versions),
                ("suite2Compiled", Bool),
                ("suite2Active", Bool),
                ("suite2ParameterId", UInt),
                ("experimentalSuite2", Bool),
                ("legacyKeyExposureRecoveryEstablished", Bool),
                ("writeBlockReason", Text),
                ("poolValue", Decimal),
                ("noteCount", UInt),
                ("nullifierCount", UInt),
                ("anchor", Hash),
                ("deshieldLimitGrains", Decimal),
                ("deshieldWindowBlocks", UInt),
                ("windowStartHeight", UInt),
                ("windowSpentGrains", Decimal),
                ("deshieldableNowGrains", Decimal),
                ("windowResetsAtHeight", UInt),
                ("height", UInt),
            ],
            &["active", "poolValue", "anchor", "height"],
        )
    });
    report["headEnd"] = diagnostic_head(client);
    report["chainDomainEnd"] = diagnostic_domain(client);
    let start = diagnostic_data(&report, "headStart");
    let end = diagnostic_data(&report, "headEnd");
    let domain = diagnostic_data(&report, "chainDomainStart");
    let peer = diagnostic_data(&report, "peers");
    let stable_head = diagnostic_equal(start, end);
    let stable_identity = diagnostic_equal(domain, diagnostic_data(&report, "chainDomainEnd"));
    let root_matches = diagnostic_equal(
        start.and_then(|v| v.get("stateRoot")),
        diagnostic_data(&report, "stateRoot").and_then(|v| v.get("root")),
    );
    let peer_identity = match (domain, peer) {
        (Some(domain), Some(peer)) => {
            Some(domain["chainId"] == peer["chainId"] && domain["genesis"] == peer["genesisHash"])
        }
        _ => None,
    };
    let height = start.and_then(|v| v.get("height"));
    let heights_match: Option<bool> =
        ["peers", "quantum", "poolV2"]
            .iter()
            .try_fold(true, |matches, field| {
                Some(
                    matches
                        && diagnostic_equal(
                            height,
                            diagnostic_data(&report, field)?.get("height"),
                        )?,
                )
            });
    let supply_conserved = (|| {
        let total = diagnostic_amount(&report, "supply", "total")?;
        let transparent = diagnostic_amount(&report, "supply", "transparent")?;
        let v1 = diagnostic_amount(&report, "supply", "shielded")?;
        let v2 = diagnostic_amount(&report, "supply", "shieldedV2")?;
        let shielded = diagnostic_amount(&report, "supply", "shieldedTotal")?;
        Some(
            v1.checked_add(v2) == Some(shielded)
                && transparent.checked_add(shielded) == Some(total),
        )
    })();
    let pool_matches_supply = (|| {
        Some(
            diagnostic_amount(&report, "poolV2", "poolValue")?
                == diagnostic_amount(&report, "supply", "shieldedV2")?,
        )
    })();
    let checks = [
        stable_head,
        stable_identity,
        root_matches,
        peer_identity,
        heights_match,
        supply_conserved,
        pool_matches_supply,
    ];
    let consistent = if checks.contains(&Some(false)) {
        Some(false)
    } else if checks.iter().all(|v| *v == Some(true)) {
        Some(true)
    } else {
        None
    };
    let failed = report
        .as_object()
        .map(|o| {
            o.values()
                .filter(|v| v.get("ok") == Some(&Value::Bool(false)))
                .count()
        })
        .unwrap_or(0);
    report["snapshot"] = json!({
        "stableHead": stable_head, "stableChainIdentity": stable_identity,
        "stateRootMatchesHead": root_matches, "peerIdentityMatchesChain": peer_identity,
        "reportedHeightsMatch": heights_match, "consistent": consistent,
        "supplyConserved": supply_conserved, "poolV2MatchesSupply": pool_matches_supply,
        "failedProbes": failed, "partial": failed != 0,
    });
    report
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
    if command == "--self-test-platform" {
        if args.len() != 1 {
            return Err("--self-test-platform takes no arguments".to_string());
        }
        return Ok(Command::SelfTestPlatform);
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
        "diagnostics" => {
            if args.len() > 2 {
                return Err("diagnostics accepts only an optional RPC host:port".into());
            }
            Ok(Command::Diagnostics {
                rpc: args
                    .get(1)
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_RPC.to_string()),
            })
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
    println!("  sov-station diagnostics [rpc_addr] public read-only JSON report");
    println!("  sov-station wallet [rpc_addr] <account>...");
    println!("  sov-station watch [rpc_addr] [account]... [--interval-ms 3000]");
    println!("  sov-station --version             print the app version and exit");
    println!("  sov-station --self-test-platform  check native RandomX without a wallet/node");
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

#[cfg(test)]
mod native_diagnostics_tests {
    use super::*;
    use std::io::{BufRead, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    const PRIVATE_FIXTURE: &str = "PRIVATE-WALLET-FIXTURE-NEVER-COPY";

    #[derive(Clone, Copy)]
    enum Mode {
        Stable,
        Partial,
        ChangedHead,
        FakeCanonical,
    }

    /// A real HTTP/JSON-RPC fixture makes the production client perform its
    /// canonical-domain validation, while recording every requested method.
    struct Fixture {
        addr: String,
        stop: Arc<AtomicBool>,
        methods: Arc<Mutex<Vec<String>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Fixture {
        fn start(mode: Mode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
            let addr = listener.local_addr().unwrap().to_string();
            let stop = Arc::new(AtomicBool::new(false));
            let methods = Arc::new(Mutex::new(Vec::new()));
            let worker_stop = stop.clone();
            let worker_methods = methods.clone();
            let thread = thread::spawn(move || {
                let mut heads = 0u64;
                for connection in listener.incoming() {
                    if worker_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut stream = connection.expect("fixture connection");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                    assert!(
                        length < 16_384,
                        "diagnostics sends only small empty-parameter requests"
                    );
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    let method = request["method"].as_str().unwrap();
                    assert_eq!(request["params"], json!({}));
                    worker_methods.lock().unwrap().push(method.to_string());
                    let envelope =
                        if matches!(mode, Mode::Partial) && method == "sov_getQuantumStatus" {
                            json!({"jsonrpc": "2.0", "id": 1,
                            "error": {"code": -32601, "message": PRIVATE_FIXTURE}})
                        } else {
                            json!({"jsonrpc": "2.0", "id": 1,
                            "result": Self::response(method, mode, &mut heads)})
                        };
                    let response = serde_json::to_vec(&envelope).unwrap();
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .unwrap();
                    stream.write_all(&response).unwrap();
                }
            });
            Self {
                addr,
                stop,
                methods,
                thread: Some(thread),
            }
        }

        fn response(method: &str, mode: Mode, heads: &mut u64) -> Value {
            let root = sov_primitives::Hash::digest(b"diagnostics-fixture-state");
            let genesis = if matches!(mode, Mode::FakeCanonical) {
                sov_primitives::Hash::ZERO.to_hex()
            } else {
                sov_rpc::ChainSpec::MAINNET_GENESIS_HASH.to_string()
            };
            match method {
                "sov_getChainDomain" => json!({"chainId": "sov-mainnet", "genesis": genesis,
                    "seed": PRIVATE_FIXTURE}),
                "sov_getHead" => {
                    let nonce = if matches!(mode, Mode::ChangedHead) {
                        *heads
                    } else {
                        0
                    };
                    *heads += 1;
                    let header = sov_types::BlockHeader {
                        height: sov_primitives::BlockHeight::new(20),
                        prev_hash: sov_primitives::Hash::ZERO,
                        tx_root: sov_primitives::Hash::ZERO,
                        receipts_root: sov_primitives::Hash::ZERO,
                        state_root: root,
                        timestamp_ms: 123_000,
                        proposer: AccountId::new("diagnostics.node.sov").unwrap(),
                        version_bits: 0,
                        bits: 0x207f_ffff,
                        nonce,
                    };
                    // The report parses only the typed header, not this private
                    // fixture body or arbitrary additional server fields.
                    json!({"header": header, "transactions": [{"seed": PRIVATE_FIXTURE}],
                        "walletFile": PRIVATE_FIXTURE})
                }
                "sov_version" => json!({"version": "v0.2.16", "token": PRIVATE_FIXTURE}),
                "sov_getStateRoot" => json!(root.to_hex()),
                "sov_getSupply" => json!({"total": "1000", "circulating": "1000",
                    "mined": "1000", "shielded": "50", "shieldedV2": "150",
                    "shieldedTotal": "200", "transparent": "800", "shieldedPercent": 20,
                    "seed": PRIVATE_FIXTURE}),
                "sov_getPeerInfo" => json!({"chainId": "sov-mainnet", "genesisHash": genesis,
                    "version": "v0.2.16", "height": 20, "peers": 1, "tcpLinks": 2,
                    "p2pEnabled": true, "protocolVersion": 3, "reachability": "unmapped",
                    "bestPeerHeight": 20, "behindBlocks": 0, "behindKnown": true,
                    "syncing": false, "connectedPeers": [PRIVATE_FIXTURE],
                    "peerVersions": [{"addr": PRIVATE_FIXTURE, "protocol": 3,
                        "agent": "sov/v0.2.16", "privateKey": PRIVATE_FIXTURE}]}),
                "sov_getDifficulty" => json!({"sha256d": "1", "algo": "RandomX",
                    "targetBlockMs": 150_000, "hashrate": 42.5, "password": PRIVATE_FIXTURE}),
                "sov_getMempoolInfo" => json!({"txCount": 2, "queuedCount": 1,
                    "capacity": 1000, "nextBlockFloorGrains": "0", "seed": PRIVATE_FIXTURE}),
                "sov_getQuantumStatus" => json!({"height": 20, "evaluatedHeight": 21,
                    "fullyPostQuantum": false, "signatureScheme": "Ed25519 + ML-DSA-65 (hybrid)",
                    "poolV2CreationAllowed": false, "poolV2AcceptedNewProofVersions": [],
                    "pqSunset": {"armed": false, "state": null, "stage": "unarmed",
                        "secret": PRIVATE_FIXTURE},
                    "hash": {"algorithm": "BLAKE3-256", "outputBits": 256,
                        "genericQuantumPreimageBits": 128, "genericQuantumCollisionBitsApprox": 85.3,
                        "securityEstimateModel": "ideal generic quantum query model",
                        "secret": PRIVATE_FIXTURE}, "seed": PRIVATE_FIXTURE}),
                "sov_getShieldedV2Info" => json!({"active": true,
                    "poolValue": if matches!(mode, Mode::Partial) { PRIVATE_FIXTURE } else { "150" },
                    "anchor": sov_primitives::Hash::digest(b"pool-v2-root").to_hex(),
                    "height": 20, "noteCount": 2, "nullifierCount": 1,
                    "scanSupported": true, "historicalReplaySupported": true,
                    "historicalProofVersions": [1, 2], "acceptedNewProofVersions": [],
                    "creationAllowed": false, "spendsAllowed": false, "recoveryAllowed": false,
                    "writeBlockReason": "replacement_proof_not_activated", "secret": PRIVATE_FIXTURE}),
                other => panic!("unexpected diagnostic method: {other}"),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(&self.addr);
            if let Some(worker) = self.thread.take() {
                worker.join().expect("fixture worker");
            }
        }
    }

    #[test]
    fn diagnostics_stable_report_is_read_only_and_does_not_copy_private_fields() {
        let fixture = Fixture::start(Mode::Stable);
        let report = diagnostics_report(&client(&fixture.addr));
        assert_eq!(report["schemaVersion"], 1);
        assert_eq!(report["app"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            report["chainDomainStart"]["data"]["canonicalGenesisPinned"],
            true
        );
        assert_eq!(report["snapshot"]["consistent"], true);
        assert_eq!(report["snapshot"]["partial"], false);
        assert_eq!(report["snapshot"]["failedProbes"], 0);
        assert_eq!(report["poolV2"]["data"]["poolValue"], "150");
        assert_eq!(report["poolV2"]["data"]["creationAllowed"], false);
        assert_eq!(report["source"]["rpcCryptographicallyAuthenticated"], false);
        assert!(report["mining"]["data"]["localMiningEnabled"].is_null());
        assert_eq!(
            report["peers"]["data"]["peerVersions"],
            json!([{"agent": "sov/v0.2.16", "protocol": 3}])
        );
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(PRIVATE_FIXTURE));
        assert!(!serialized.contains("transactions"));
        assert!(!serialized.contains("connectedPeers"));
        let methods = fixture.methods.lock().unwrap();
        assert_eq!(methods.len(), 12);
        assert!(methods.iter().all(|method| matches!(
            method.as_str(),
            "sov_getChainDomain"
                | "sov_getHead"
                | "sov_version"
                | "sov_getStateRoot"
                | "sov_getSupply"
                | "sov_getPeerInfo"
                | "sov_getDifficulty"
                | "sov_getMempoolInfo"
                | "sov_getQuantumStatus"
                | "sov_getShieldedV2Info"
        )));
    }

    #[test]
    fn diagnostics_partial_errors_are_independent_and_redacted() {
        let fixture = Fixture::start(Mode::Partial);
        let report = diagnostics_report(&client(&fixture.addr));
        assert_eq!(
            report["quantum"]["error"],
            json!({"kind": "method_unavailable", "code": -32601})
        );
        assert_eq!(
            report["poolV2"]["error"],
            json!({"kind": "malformed_response"})
        );
        assert_eq!(report["supply"]["ok"], true);
        assert_eq!(report["snapshot"]["failedProbes"], 2);
        assert_eq!(report["snapshot"]["partial"], true);
        assert!(report["snapshot"]["consistent"].is_null());
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains(PRIVATE_FIXTURE));
    }

    #[test]
    fn diagnostics_detects_a_same_height_reorg_during_collection() {
        let fixture = Fixture::start(Mode::ChangedHead);
        let report = diagnostics_report(&client(&fixture.addr));
        assert_eq!(
            report["headStart"]["data"]["height"],
            report["headEnd"]["data"]["height"]
        );
        assert_ne!(
            report["headStart"]["data"]["hash"],
            report["headEnd"]["data"]["hash"]
        );
        assert_eq!(report["snapshot"]["stableHead"], false);
        assert_eq!(report["snapshot"]["consistent"], false);
    }

    #[test]
    fn diagnostics_refuses_fake_canonical_genesis_via_real_client_validation() {
        let fixture = Fixture::start(Mode::FakeCanonical);
        let report = diagnostics_report(&client(&fixture.addr));
        assert_eq!(
            report["chainDomainStart"]["error"],
            json!({"kind": "canonical_genesis_mismatch"})
        );
        assert_eq!(report["chainDomainEnd"]["ok"], false);
        assert!(report["snapshot"]["stableChainIdentity"].is_null());
        assert_eq!(report["snapshot"]["partial"], true);
    }

    #[test]
    fn diagnostics_deadline_bounds_slow_workers_and_redacts_transport_details() {
        let started = std::time::Instant::now();
        let result = diagnostic_deadline(Duration::from_millis(20), || {
            thread::sleep(Duration::from_millis(80));
            Ok::<_, RpcClientError>(())
        });
        assert!(
            matches!(result, Err(RpcClientError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        let error = diagnostic_error(RpcClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            PRIVATE_FIXTURE,
        )));
        assert_eq!(
            error,
            json!({"ok": false, "error": {"kind": "transport", "ioKind": "ConnectionRefused"}})
        );
    }

    #[test]
    fn diagnostics_cli_arguments_are_specific_and_do_not_select_wallet_commands() {
        assert_eq!(
            parse_args(&["diagnostics".into()]).unwrap(),
            Command::Diagnostics {
                rpc: DEFAULT_RPC.into()
            }
        );
        assert_eq!(
            parse_args(&["diagnostics".into(), "127.0.0.1:9000".into()]).unwrap(),
            Command::Diagnostics {
                rpc: "127.0.0.1:9000".into()
            }
        );
        assert!(parse_args(&[
            "diagnostics".into(),
            "127.0.0.1:9000".into(),
            "wallet.sov".into()
        ])
        .is_err());
    }
}
