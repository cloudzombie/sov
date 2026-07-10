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

use sov_redteam::{live_any_vulnerable, probe_frontdoor, run_all, Verdict};

fn main() {
    // `--target <addr>` (or `--target=<addr>`) switches to the live front-door probe.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = parse_target(&args);

    match target {
        Some(addr) => live_mode(&addr),
        None => in_process_mode(),
    }
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
