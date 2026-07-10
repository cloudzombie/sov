//! `sov-redteam` CLI — runs the adversarial battery (implemented in the `sov_redteam`
//! library, so SOV Station's Red Team tab can run the exact same attacks in-process)
//! and prints a terminal report. Exits non-zero if any attack is VULNERABLE, so CI or
//! a release gate can consume it.

use sov_redteam::{run_all, Verdict};

fn main() {
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
        let (tag, mark) = match o.verdict {
            Verdict::Defended => {
                defended += 1;
                ("DEFENDED", "\x1b[32m✓\x1b[0m")
            }
            Verdict::Vulnerable => {
                vulnerable += 1;
                ("VULNERABLE", "\x1b[31m✗\x1b[0m")
            }
            Verdict::Info => {
                info += 1;
                ("INFO", "\x1b[33m•\x1b[0m")
            }
        };
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
