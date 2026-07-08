//! sov-selfcheck — a self-consistency auditor for SOV.
//!
//! Two independent checks, each of which the chain runs against ITSELF:
//!
//!   keys   Generate many fresh wallets down the real pipeline
//!          (OS entropy → BIP-39 mnemonic → seed → hybrid Ed25519+ML-DSA-65 key →
//!          implicit account id) and prove there is NO collision at any stage, the
//!          derivation is deterministic, and the account-id space is unbiased.
//!
//!   chain  Walk every block of a live node and re-derive its structure from the
//!          raw data, checking it against the chain's own committed hashes: each
//!          block hashes to its committed id, its tx-root matches its body, the
//!          prev-hash chain is unbroken, heights and timestamps advance, the
//!          coinbase equals the emission schedule (within the 21M budget), and the
//!          node's reported mined supply equals the sum of coinbases. Genesis must
//!          hash to the frozen network identity.
//!
//! Usage:
//!   sov-selfcheck keys  [--count N] [--words 12|15|18|21|24]
//!   sov-selfcheck chain [--rpc HOST:PORT] [--from H] [--to H]
//!
//! Exit code is nonzero if any check fails — so it drops into CI or a cron cleanly.

use std::collections::HashSet;
use std::process::exit;

use serde_json::{json, Value};
use sov_mining::MiningPolicy;
use sov_primitives::{Balance, Hash, MAX_SUPPLY_GRAINS};
use sov_rpc::RpcClient;
use sov_types::Block;
use sov_wallet::{generate_mnemonic, HdWallet};

// The frozen network identities — genesis must hash to exactly these.
const MAINNET_GENESIS: &str = "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d";
const TESTNET_GENESIS: &str = "4d7d9123a489f4fd29486da3d66a6c20b04953cb886dee847662e11af293da15";

// A pinned derivation fingerprint: the BIP-39 all-zero-entropy 24-word test
// mnemonic must derive to exactly this implicit account. Ties the mnemonic→account
// pipeline to a fixed value across runs, machines, and (eventually) the TS SDK.
const KAT_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const KAT_ACCOUNT: &str = "65e32c441625675d4c644e4be8c5001e0e53f5d66633515b451eae19ddccd148";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str);
    let ok = match mode {
        Some("keys") => keys_check(&args[2..]),
        Some("chain") => chain_check(&args[2..]),
        _ => {
            eprintln!("usage: sov-selfcheck <keys|chain> [options]");
            eprintln!("  keys  [--count N] [--words 12|15|18|21|24]");
            eprintln!("  chain [--rpc HOST:PORT] [--from H] [--to H]");
            exit(2);
        }
    };
    if ok {
        println!("\n\x1b[32m\x1b[1m✓ SELF-CHECK PASSED\x1b[0m");
        exit(0);
    } else {
        println!("\n\x1b[31m\x1b[1m✗ SELF-CHECK FAILED\x1b[0m");
        exit(1);
    }
}

fn arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

// ── keys: mnemonic / seed / account collision + entropy sweep ─────────────────
fn keys_check(args: &[String]) -> bool {
    let count: usize = arg(args, "--count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let words: usize = arg(args, "--words")
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    println!("\x1b[1mKEY PIPELINE COLLISION + ENTROPY SWEEP\x1b[0m");
    println!("  generating {count} wallets · {words}-word mnemonics");
    println!("  path: OS entropy → BIP-39 → seed → hybrid Ed25519+ML-DSA-65 → implicit account\n");

    let mut mnemonics: HashSet<String> = HashSet::with_capacity(count);
    let mut seeds: HashSet<[u8; 32]> = HashSet::with_capacity(count);
    let mut accounts: HashSet<String> = HashSet::with_capacity(count);
    // The RAW ENTROPY that actually seeds each wallet, recovered from its mnemonic
    // (BIP-39 is reversible). This — NOT any downstream hash — is where randomness
    // must be proven: BLAKE3/PBKDF2 would whitewash a broken source into uniform
    // output, so we test the source bytes directly with a statistical battery.
    let mut entropy_buf: Vec<u8> = Vec::with_capacity(count * 32);
    // Downstream account-id bit balance — a SANITY line only (post-BLAKE3, uniform
    // by construction regardless of source), kept to catch a stuck derivation.
    let mut bit_ones = [0u64; 256];
    let mut collisions = 0usize;

    for i in 0..count {
        let phrase = match generate_mnemonic(words) {
            Ok(p) => p,
            Err(e) => {
                println!("  \x1b[31mFAIL\x1b[0m: generate_mnemonic: {e}");
                return false;
            }
        };
        // Recover the exact entropy this wallet was seeded with (before it is moved
        // into the dedup set) and accumulate it for the battery.
        match bip39::Mnemonic::parse(&phrase) {
            Ok(m) => entropy_buf.extend_from_slice(&m.to_entropy()),
            Err(e) => {
                println!("  \x1b[31mFAIL\x1b[0m: mnemonic did not round-trip to entropy: {e}");
                return false;
            }
        }
        let wallet = HdWallet::from_mnemonic(&phrase, "").expect("fresh mnemonic parses");
        let seed = wallet.derive_seed(0, 0);
        let account = wallet
            .derive_keypair(0, 0)
            .public_key()
            .implicit_account_id()
            .to_string();

        if !mnemonics.insert(phrase) {
            println!("  \x1b[31mCOLLISION\x1b[0m: duplicate mnemonic at #{i}");
            collisions += 1;
        }
        if !seeds.insert(seed) {
            println!("  \x1b[31mCOLLISION\x1b[0m: duplicate derived seed at #{i}");
            collisions += 1;
        }
        if !accounts.insert(account.clone()) {
            println!("  \x1b[31mCOLLISION\x1b[0m: duplicate account id at #{i}: {account}");
            collisions += 1;
        }
        if let Some(bytes) = hex32(&account) {
            for (b, byte) in bytes.iter().enumerate() {
                for bit in 0..8 {
                    if byte >> bit & 1 == 1 {
                        bit_ones[b * 8 + bit] += 1;
                    }
                }
            }
        }
        if count >= 10_000 && i > 0 && i % (count / 10) == 0 {
            println!("  … {}%", i * 100 / count);
        }
    }

    let mut ok = true;
    println!();
    ok &= report_unique("distinct mnemonics", mnemonics.len(), count);
    ok &= report_unique("distinct derived seeds", seeds.len(), count);
    ok &= report_unique("distinct account ids", accounts.len(), count);
    if collisions == 0 {
        println!("  \x1b[32m✓\x1b[0m zero collisions across {count} wallets at every stage");
    } else {
        println!("  \x1b[31m✗\x1b[0m {collisions} collision(s) — CRYPTO PIPELINE IS BROKEN");
        ok = false;
    }

    // THE REAL RANDOMNESS TEST: a statistical battery on the raw entropy that
    // actually seeded these wallets (recovered from the mnemonics). This is where a
    // broken/biased/stuck RNG shows up — downstream hashes cannot hide it here.
    println!(
        "\n  \x1b[1mentropy battery\x1b[0m — {} bytes of real wallet seed entropy:",
        entropy_buf.len()
    );
    ok &= randomness_battery(&entropy_buf);

    // Independently, exercise the OS CSPRNG source itself (what generate_mnemonic
    // draws from) with a fresh 1 MiB pull through the same battery.
    let mut raw = vec![0u8; 1 << 20];
    if getrandom::getrandom(&mut raw).is_err() {
        println!("  \x1b[31m✗\x1b[0m getrandom (OS entropy) is unavailable");
        ok = false;
    } else {
        println!(
            "  \x1b[1mgetrandom source\x1b[0m — fresh {} bytes from the OS CSPRNG:",
            raw.len()
        );
        ok &= randomness_battery(&raw);
    }

    // Downstream sanity only: post-BLAKE3 account-id bits stay ~50/50 (uniform by
    // construction; this just catches a stuck/constant derivation, not source bias).
    let expected = count as f64 / 2.0;
    let worst = bit_ones
        .iter()
        .map(|&ones| ((ones as f64 - expected) / expected).abs())
        .fold(0.0f64, f64::max);
    println!(
        "  \x1b[2m·\x1b[0m downstream account-id bits {:.2}% off 50/50 (sanity; whitewashed by BLAKE3)",
        worst * 100.0
    );

    // Determinism: the same mnemonic must always derive the same account.
    let sample = generate_mnemonic(words).unwrap();
    let a = HdWallet::from_mnemonic(&sample, "")
        .unwrap()
        .derive_keypair(0, 0)
        .public_key()
        .implicit_account_id()
        .to_string();
    let b = HdWallet::from_mnemonic(&sample, "")
        .unwrap()
        .derive_keypair(0, 0)
        .public_key()
        .implicit_account_id()
        .to_string();
    if a == b {
        println!("  \x1b[32m✓\x1b[0m derivation is deterministic (re-derive is identical)");
    } else {
        println!("  \x1b[31m✗\x1b[0m derivation is NON-deterministic: {a} != {b}");
        ok = false;
    }

    // KAT: the fixed test mnemonic pins the whole pipeline to a known account.
    let kat = HdWallet::from_mnemonic(KAT_MNEMONIC, "")
        .unwrap()
        .derive_keypair(0, 0)
        .public_key()
        .implicit_account_id()
        .to_string();
    if KAT_ACCOUNT == "@KAT@" {
        println!("  \x1b[33m•\x1b[0m KAT fingerprint (pin this into KAT_ACCOUNT): {kat}");
    } else if kat == KAT_ACCOUNT {
        println!("  \x1b[32m✓\x1b[0m KAT: test mnemonic derives to the pinned account");
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m KAT MISMATCH: {kat} != pinned {KAT_ACCOUNT} — derivation drifted"
        );
        ok = false;
    }
    ok
}

fn report_unique(label: &str, got: usize, want: usize) -> bool {
    if got == want {
        println!("  \x1b[32m✓\x1b[0m {label}: {got}/{want}");
        true
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m {label}: {got}/{want} — {} duplicate(s)",
            want - got
        );
        false
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A statistical randomness battery over RAW entropy `data`. Prints each test and
/// returns whether ALL passed. Thresholds are ~6σ, so a healthy CSPRNG never
/// false-fails while a biased/stuck/patterned source is caught. Four independent
/// views: bit balance, byte-value uniformity, information content, and structure.
fn randomness_battery(data: &[u8]) -> bool {
    let n = data.len();
    if n < 4096 {
        println!("    \x1b[33m•\x1b[0m battery skipped: need ≥4096 bytes, got {n}");
        return true;
    }
    let mut ok = true;

    // 1. Monobit — the fraction of 1-bits must be ~0.5 (Frequency test).
    let ones: u64 = data.iter().map(|b| b.count_ones() as u64).sum();
    let nbits = n as f64 * 8.0;
    let z = (ones as f64 - nbits / 2.0) / (nbits.sqrt() / 2.0);
    let mono = z.abs() <= 6.0;
    line(
        mono,
        &format!(
            "monobit: {:.4}% ones (z={z:+.2}, |z|≤6)",
            ones as f64 / nbits * 100.0
        ),
    );
    ok &= mono;

    // 2. Byte uniformity — χ² over 256 values (255 dof; mean 255, sd ≈22.6). Every
    //    value must appear (a missing symbol means a constrained/broken source).
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let exp = n as f64 / 256.0;
    let chi: f64 = counts.iter().map(|&c| (c as f64 - exp).powi(2) / exp).sum();
    let missing = counts.iter().filter(|&&c| c == 0).count();
    let chi_ok = (120.0..=390.0).contains(&chi) && missing == 0;
    line(
        chi_ok,
        &format!("byte χ²: {chi:.1} (expect ~255±23; {missing} of 256 values unseen)"),
    );
    ok &= chi_ok;

    // 3. Shannon entropy per byte — must be ~8.0 bits (near-maximal information).
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum();
    let h_ok = h >= 7.90;
    line(
        h_ok,
        &format!("Shannon entropy: {h:.4} bits/byte (ideal 8.0, ≥7.90)"),
    );
    ok &= h_ok;

    // 4. Serial (lag-1) correlation — consecutive bytes must be uncorrelated, so a
    //    counter/LFSR/structured stream (which passes 1–3) is still caught here.
    let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n as f64;
    let (mut num, mut den) = (0.0f64, 0.0f64);
    for i in 0..n {
        let d = data[i] as f64 - mean;
        den += d * d;
        if i + 1 < n {
            num += d * (data[i + 1] as f64 - mean);
        }
    }
    let r = if den > 0.0 { num / den } else { 1.0 };
    let corr_ok = r.abs() <= 0.05;
    line(
        corr_ok,
        &format!("lag-1 correlation: {r:+.4} (ideal 0, |r|≤0.05)"),
    );
    ok &= corr_ok;

    ok
}

fn line(pass: bool, msg: &str) {
    if pass {
        println!("    \x1b[32m✓\x1b[0m {msg}");
    } else {
        println!("    \x1b[31m✗\x1b[0m {msg}");
    }
}

// ── chain: structural self-consistency against a live node ────────────────────
fn chain_check(args: &[String]) -> bool {
    let addr = arg(args, "--rpc").unwrap_or("127.0.0.1:8645").to_string();
    let client = RpcClient::new(addr.clone());
    println!("\x1b[1mCHAIN SELF-CONSISTENCY AUDIT\x1b[0m");
    println!("  node: {addr}\n");

    let chain_id = match client.call("sov_chainId", json!({})) {
        Ok(v) => v.as_str().unwrap_or("").to_string(),
        Err(e) => {
            println!("  \x1b[31mFAIL\x1b[0m: cannot reach node: {e}");
            return false;
        }
    };
    let tip = client
        .call("sov_getHeight", json!({}))
        .ok()
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    // Snapshot mined supply NOW, together with the tip — so the later reconciliation
    // is against a consistent height. The chain is live and advances during a long
    // walk; reading supply at the end would race ahead of where we stopped.
    let mined_snapshot = client.call("sov_getSupply", json!({})).ok().and_then(|v| {
        v.get("mined")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
    });
    let pinned = match chain_id.as_str() {
        "sov-mainnet" => Some(MAINNET_GENESIS),
        "sov-testnet-1" => Some(TESTNET_GENESIS),
        _ => None,
    };
    println!("  chain {chain_id} · tip {tip}");
    let from: u64 = arg(args, "--from")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let to: u64 = arg(args, "--to")
        .and_then(|s| s.parse().ok())
        .unwrap_or(tip);

    let policy = MiningPolicy::mainnet_like();
    let mut prev_hash: Option<Hash> = None;
    let mut prev_ts = 0u64;
    let mut mined: u128 = 0;
    let (mut hash_ok, mut root_ok, mut link_ok, mut emit_ok, mut n) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut ok = true;

    for h in from..=to {
        let block: Block = match client.call("sov_getBlockByHeight", json!({ "height": h })) {
            Ok(v) if !v.is_null() => match serde_json::from_value(v) {
                Ok(b) => b,
                Err(e) => {
                    println!("  \x1b[31m✗\x1b[0m block {h}: undecodable: {e}");
                    return false;
                }
            },
            _ => {
                println!("  \x1b[31m✗\x1b[0m block {h}: node returned no block");
                return false;
            }
        };
        let digest = client
            .call("sov_getBlockDigest", json!({ "height": h }))
            .unwrap_or(Value::Null);
        n += 1;

        // 1. Hash integrity: the block's content hashes to its committed id.
        let recomputed = block.hash();
        let committed = digest
            .get("hash")
            .and_then(Value::as_str)
            .map(|s| s.trim_start_matches("0x").to_string());
        if committed.as_deref() == Some(recomputed.to_hex().as_str()) {
            hash_ok += 1;
        } else {
            println!(
                "  \x1b[31m✗\x1b[0m block {h}: hash mismatch — content does not match committed id"
            );
            ok = false;
        }
        // Genesis must be the frozen identity.
        if h == 0 {
            if let Some(pin) = pinned {
                if recomputed.to_hex() == pin {
                    println!(
                        "  \x1b[32m✓\x1b[0m genesis is the frozen {chain_id} identity ({pin})"
                    );
                } else {
                    println!(
                        "  \x1b[31m✗\x1b[0m genesis {} != frozen {pin}",
                        recomputed.to_hex()
                    );
                    ok = false;
                }
            }
        }
        // 2. Tx-root recomputes from the body.
        if block.tx_root_matches() {
            root_ok += 1;
        } else {
            println!("  \x1b[31m✗\x1b[0m block {h}: tx-root does not match its transactions");
            ok = false;
        }
        // 3. Linkage: height succession, prev-hash chain, timestamp monotonicity.
        let mut linked = block.header.height.get() == h;
        if h > 0 {
            linked &= Some(block.header.prev_hash) == prev_hash;
            linked &= block.header.timestamp_ms >= prev_ts;
        }
        if linked {
            link_ok += 1;
        } else {
            println!("  \x1b[31m✗\x1b[0m block {h}: broken linkage (height/prev-hash/timestamp)");
            ok = false;
        }
        // 4. Emission: coinbase equals the schedule, within the 21M budget.
        let reward = digest
            .get("coinbase")
            .and_then(|c| c.get("reward"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let expected = policy.reward_at(h, Balance::from_grains(mined)).grains();
        if reward == expected && mined + reward <= MAX_SUPPLY_GRAINS {
            emit_ok += 1;
        } else {
            println!("  \x1b[31m✗\x1b[0m block {h}: coinbase {reward} != scheduled {expected} (or over budget)");
            ok = false;
        }
        mined += reward;

        prev_hash = Some(recomputed);
        prev_ts = block.header.timestamp_ms;
        if to >= 1000 && h > from && h % ((to - from) / 10).max(1) == 0 {
            println!("  … {}/{}", h, to);
        }
    }

    println!();
    println!("  \x1b[32m✓\x1b[0m {hash_ok}/{n} blocks hash to their committed id");
    println!("  \x1b[32m✓\x1b[0m {root_ok}/{n} tx-roots match their bodies");
    println!("  \x1b[32m✓\x1b[0m {link_ok}/{n} blocks link cleanly (height · prev-hash · time)");
    println!("  \x1b[32m✓\x1b[0m {emit_ok}/{n} coinbases equal the emission schedule");

    // 5. Supply: on a FULL audit (genesis→tip), the node's mined-supply counter —
    // snapshotted at the START, consistent with the tip we walked — must equal the
    // sum of coinbases we independently re-derived. (Reading supply at the end would
    // race ahead: a live chain mines new blocks during a long walk.) A partial range
    // can't reconcile against whole-chain supply, so we only assert on a full walk.
    let full_audit = from == 0 && to == tip;
    if !full_audit {
        println!("  \x1b[33m•\x1b[0m supply reconciliation skipped (partial range {from}..={to}, not genesis→tip)");
    } else if mined_snapshot == Some(mined) {
        println!("  \x1b[32m✓\x1b[0m mined supply reconciles: node {mined} == Σ coinbases");
    } else {
        println!("  \x1b[31m✗\x1b[0m supply mismatch: node snapshot {mined_snapshot:?}, Σ coinbases = {mined}");
        ok = false;
    }
    ok
}
