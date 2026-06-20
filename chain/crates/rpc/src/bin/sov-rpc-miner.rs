//! `sov-rpc-miner` — RETIRED under Nakamoto consensus (Phase 21).
//!
//! This tool used to submit `Mine` / `MineShielded` transactions over JSON-RPC.
//! Those transactions no longer exist as an issuance path: **block production
//! itself is the mining** — a node grinds the block header's double-SHA-256
//! proof of work, and the block's coinbase pays the node's configured miner
//! account directly (Bitcoin's model). There is no transaction that mints.
//!
//! To mine SOV, run a mining node:
//!
//! ```text
//! sov-rpcd <chain-spec.json> <node-config.json> <keystore.json>
//! ```
//!
//! The first keystore account is the node's miner identity (its coinbase
//! recipient). A standalone getwork-style external miner protocol — letting a
//! separate machine grind the header while a node assembles blocks — is the
//! planned replacement for this tool.

use std::process;

fn main() {
    eprintln!(
        "sov-rpc-miner is RETIRED: SOV uses Nakamoto consensus — block production itself is \
         the mining, and there is no Mine transaction.\n\
         To mine, run a mining node: sov-rpcd <chain-spec> <node-config> <keystore>\n\
         (the first keystore account receives the coinbase)."
    );
    process::exit(2);
}
