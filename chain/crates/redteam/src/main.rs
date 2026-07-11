//! `sov-redteam` CLI — runs the adversarial battery (implemented in the `sov_redteam`
//! library, so the standalone GUI can run the exact same attacks) and prints a terminal
//! report. Exits non-zero if any attack is VULNERABLE, so CI or a release gate can
//! consume it.
//!
//! Two modes:
//!   sov-redteam                          in-process: attack a private replica of consensus
//!   sov-redteam --target <host[:port]>   live-fire: probe a REAL running node's RPC front door
//!
//! The live-fire probe is side-effect-free — every tx it sends is rejected at admission,
//! so nothing lands in the target's mempool.

use sov_redteam::{
    backdoor_any_vulnerable, funded_any_vulnerable, keypair_from_secret, live_any_vulnerable,
    probe_backdoor, probe_frontdoor, probe_funded, run_all, Verdict,
};

fn main() {
    // `--target <addr>` switches to a live probe; add `--p2p` for the back-door probe, or
    // `--funded` for the funded-adversary probe (key from the SOV_REDTEAM_KEY env var, so
    // the secret is never on the command line).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = parse_target(&args);
    let p2p = args.iter().any(|a| a == "--p2p" || a == "--backdoor");
    let funded = args.iter().any(|a| a == "--funded");

    match target {
        Some(addr) if funded => funded_mode(&addr),
        Some(addr) if p2p => backdoor_mode(&addr),
        Some(addr) => live_mode(&addr),
        None => in_process_mode(),
    }
}

fn funded_mode(addr: &str) {
    println!("\n  sov-redteam — FUNDED-ADVERSARY probe");
    let secret = match std::env::var("SOV_REDTEAM_KEY") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            println!("  \x1b[31mset SOV_REDTEAM_KEY to the funded account's mnemonic or 32-byte hex seed\x1b[0m\n");
            std::process::exit(2);
        }
    };
    let kp = match keypair_from_secret(&secret) {
        Ok(kp) => kp,
        Err(e) => {
            println!("  \x1b[31m{e}\x1b[0m\n");
            std::process::exit(2);
        }
    };
    println!("  attacking AS a real funded account — probing it like a thief (double-spend, replay, rewind, drain)…\n");
    let report = probe_funded(addr, &kp, 100_000);
    if let Some(err) = &report.error {
        println!("  \x1b[31m{err}\x1b[0m\n");
        std::process::exit(2);
    }
    let banner = if report.is_mainnet { "\x1b[33mLIVE MAINNET\x1b[0m" } else { report.chain_id.as_deref().unwrap_or("unknown") };
    println!("  account {}  ·  balance {}  ·  nonce {}  ·  {}", short(&report.account), report.balance, report.nonce, banner);
    println!();

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    for o in &report.outcomes {
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<44} {}", o.name, o.detail);
    }
    println!(
        "\n  {} steps · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if funded_any_vulnerable(&report) {
        println!("  \x1b[31mA DOUBLE-SPEND OR REPLAY WAS ADMITTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the chain refused to spend the same coin twice.\n");
    }
}

fn short(s: &str) -> String {
    s.chars().take(16).collect()
}

/// Pull the value of `--target <addr>` / `--target=<addr>` out of the args, if present.
fn parse_target(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--target=") {
            return Some(v.to_string());
        }
        if a == "--target" {
            return it.next().cloned();
        }
    }
    None
}

fn in_process_mode() {
    println!("\n  sov-redteam — adversarial harness for the SOV chain");
    println!("  building a real in-process chain and attacking consensus…\n");

    let outcomes = run_all();

    let mut last_cat = "";
    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    for o in &outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<42} {}", o.name, o.detail);
    }

    println!(
        "\n  {} attacks · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        outcomes.len()
    );
    if vulnerable == 0 {
        println!("  every defense held.\n");
    } else {
        println!("  \x1b[31mVULNERABILITIES FOUND — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    }
}

fn live_mode(addr: &str) {
    println!("\n  sov-redteam — LIVE front-door probe");
    println!("  submitting adversarial transactions to a real node (rejected at admission — nothing lands)…\n");

    let report = probe_frontdoor(addr);

    if !report.reachable {
        println!("  \x1b[31mcould not reach {} — is the node running and RPC exposed?\x1b[0m\n", report.target);
        std::process::exit(2);
    }

    let chain = report.chain_id.as_deref().unwrap_or("unknown");
    let height = report.height.map(|h| h.to_string()).unwrap_or_else(|| "?".into());
    let banner = if report.is_mainnet { "\x1b[33mLIVE MAINNET\x1b[0m" } else { chain };
    println!("  target {}  ·  chain {}  ·  height {}\n", report.target, banner, height);

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    let mut last_cat = "";
    for o in &report.outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<48} {}", o.name, o.detail);
    }

    // No-residue proof: the mempool must be unchanged if every attack was rejected
    // before admission.
    if let (Some(b), Some(a)) = (report.mempool_before, report.mempool_after) {
        let verdict = if report.no_residue() {
            "\x1b[32mno residue — nothing landed\x1b[0m"
        } else {
            "\x1b[31mRESIDUE — a tx was admitted!\x1b[0m"
        };
        println!("\n  mempool {b} → {a}  ·  {verdict}");
    }

    println!(
        "  {} probes · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if live_any_vulnerable(&report) {
        println!("  \x1b[31mAN ADVERSARIAL TX WAS ADMITTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the front door held — every adversarial tx was rejected before admission.\n");
    }
}

fn backdoor_mode(addr: &str) {
    println!("\n  sov-redteam — LIVE BACK-DOOR probe (P2P peer)");
    println!("  joining the network as a hostile peer and gossiping forged blocks/txs over the wire…\n");

    let report = probe_backdoor(addr);

    if let Some(err) = &report.error {
        println!("  \x1b[31mcould not run: {err}\x1b[0m\n");
        std::process::exit(2);
    }

    let chain = report.chain_id.as_deref().unwrap_or("unknown");
    let banner = if report.is_mainnet { "\x1b[33mLIVE MAINNET\x1b[0m" } else { chain };
    let auth = if report.authenticated { "\x1b[32mauthenticated\x1b[0m" } else { "\x1b[31mNOT authenticated\x1b[0m" };
    println!("  p2p {}  ·  chain {}  ·  hostile peer {}", report.p2p_target, banner, auth);
    if let Some((h, hash)) = &report.head_before {
        println!("  head before: height {h}  {}", &hash[..16.min(hash.len())]);
    }
    println!();

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    let mut last_cat = "";
    for o in &report.outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<44} {}", o.name, o.detail);
    }

    // Tip-held proof + ejection.
    if let (Some((hb, _)), Some((ha, _))) = (&report.head_before, &report.head_after) {
        let moved = ha != hb;
        println!(
            "\n  head after: height {ha}  ·  {}",
            if moved { "advanced by the node's OWN honest mining (no forged hash adopted)" } else { "unmoved" }
        );
    }
    if report.ejected {
        println!("  \x1b[32mthe node BANNED our peer — the attacker was ejected\x1b[0m");
    }
    println!(
        "  {} probes · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if backdoor_any_vulnerable(&report) {
        println!("  \x1b[31mA FORGED BLOCK/TX WAS ACCEPTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the back door held — no forged block was adopted, no forged tx admitted.\n");
    }
}

fn mark_of(
    v: Verdict,
    defended: &mut u32,
    vulnerable: &mut u32,
    info: &mut u32,
) -> (&'static str, &'static str) {
    match v {
        Verdict::Defended => {
            *defended += 1;
            ("DEFENDED", "\x1b[32m✓\x1b[0m")
        }
        Verdict::Vulnerable => {
            *vulnerable += 1;
            ("VULNERABLE", "\x1b[31m✗\x1b[0m")
        }
        Verdict::Info => {
            *info += 1;
            ("INFO", "\x1b[33m•\x1b[0m")
        }
    }
}
