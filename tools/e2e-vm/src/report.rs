//! The machine-readable report + human summary.
//!
//! Exit contract (owner directive): exit 0 ONLY if no step failed; SKIPs are
//! allowed but every one carries the exact reason and the program slice it
//! waits on — a skip is a stated debt, never a quiet pass.

use serde_json::{json, Value};

/// A step's verdict.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skip => "skip",
        }
    }
}

/// One matrix step's outcome: verdict, a one-line detail, and the raw
/// heights/hashes/deltas it asserted (evidence — auditable after the fact).
pub struct StepResult {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub evidence: Value,
}

impl StepResult {
    pub fn pass(name: &'static str, detail: impl Into<String>, evidence: Value) -> Self {
        StepResult {
            name,
            status: Status::Pass,
            detail: detail.into(),
            evidence,
        }
    }
    pub fn fail(name: &'static str, detail: impl Into<String>, evidence: Value) -> Self {
        StepResult {
            name,
            status: Status::Fail,
            detail: detail.into(),
            evidence,
        }
    }
    pub fn skip(name: &'static str, detail: impl Into<String>, evidence: Value) -> Self {
        StepResult {
            name,
            status: Status::Skip,
            detail: detail.into(),
            evidence,
        }
    }
}

/// Assemble the full report JSON.
pub fn report_json(
    backend: &str,
    chain_id: &str,
    genesis_hash: &str,
    nodes: &[(String, String, bool)], // (name, rpc, mine)
    steps: &[StepResult],
    started_at_ms: u64,
    finished_at_ms: u64,
) -> Value {
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    for s in steps {
        match s.status {
            Status::Pass => passed += 1,
            Status::Fail => failed += 1,
            Status::Skip => skipped += 1,
        }
    }
    json!({
        "harness": "sov-e2e-vm",
        "slice": "S8a + S8b (achievable-now subset)",
        "backend": backend,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "nodes": nodes.iter().map(|(name, rpc, mine)| json!({
            "name": name, "rpc": rpc, "role": if *mine { "miner" } else { "observer" },
        })).collect::<Vec<_>>(),
        "steps": steps.iter().map(|s| json!({
            "name": s.name,
            "status": s.status.as_str(),
            "detail": s.detail,
            "evidence": s.evidence,
        })).collect::<Vec<_>>(),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "started_at_ms": started_at_ms,
        "finished_at_ms": finished_at_ms,
    })
}

/// Print the human summary to stdout.
pub fn print_summary(steps: &[StepResult], failed: usize) {
    println!();
    println!("================ SOV E2E MATRIX SUMMARY ================");
    for s in steps {
        let mark = match s.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        };
        println!("  [{mark}] {:<34} {}", s.name, s.detail);
    }
    println!("========================================================");
    if failed == 0 {
        println!("RESULT: GREEN — no step failed (skips are listed debts).");
    } else {
        println!("RESULT: RED — {failed} step(s) FAILED.");
    }
}
