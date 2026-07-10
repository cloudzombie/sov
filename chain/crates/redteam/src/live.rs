//! **Live-fire front-door probe** — attack a REAL running node over JSON-RPC.
//!
//! Where the in-process harness feeds adversarial blocks straight to `import_block`,
//! this module reaches a live node the only way an outside attacker can: through
//! `sov_submitTransaction`. It submits transactions that are *designed to be rejected
//! at admission* and confirms each one is turned away before it reaches the mempool.
//!
//! SAFETY — this is deliberately side-effect-free. Every probe here is rejected by
//! `node.submit` / `mempool.insert` (bad signature, wrong key, or undecodable), so
//! NOTHING is admitted to the live mempool: no transaction lands, no fee is spent, no
//! state changes, genesis is untouched. Each probe uses a throwaway IMPLICIT account
//! (id = hash of a random key), so it never even names a real account.
//!
//! What is intentionally NOT fired live: overspend / overflow (the mempool admits them
//! by design and reverts them at execution — firing them would litter the real
//! mempool) and the tx flood (a DoS on a production network). Those live in the
//! in-process harness, which exercises the execution/consensus layer the front door
//! defers to.

use std::time::Duration;

use serde_json::json;
use sov_crypto::Keypair;
use sov_primitives::Balance;
use sov_rpc::{RpcClient, RpcClientError};
use sov_types::{Action, SignedTransaction, Transaction};

use crate::{tamper_signature, Half, Outcome, Verdict};

/// The result of pointing the probe at a node: whether it answered, what chain it is,
/// and the outcome of each front-door attack.
pub struct LiveReport {
    /// The `host:port` the probe targeted.
    pub target: String,
    /// True if the node answered a `sov_getHeight` within the timeout.
    pub reachable: bool,
    /// The node's current height, if reachable.
    pub height: Option<u64>,
    /// The node's chain id (e.g. `sov-mainnet`), if it reported one.
    pub chain_id: Option<String>,
    /// True if the chain id names mainnet — i.e. we are probing the LIVE chain.
    pub is_mainnet: bool,
    /// One outcome per front-door attack (empty if the node was unreachable).
    pub outcomes: Vec<Outcome>,
}

const CATEGORY: &str = "live front-door";

/// Normalize a user-typed target into the `host:port` the client expects: strip a
/// `http://` / `https://` scheme and any trailing path, and default the port to 8645
/// (the SOV JSON-RPC port) when none is given.
fn normalize(target: &str) -> String {
    let t = target.trim();
    let t = t.strip_prefix("http://").or_else(|| t.strip_prefix("https://")).unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    if t.contains(':') {
        t.to_string()
    } else {
        format!("{t}:8645")
    }
}

/// Submit `stx` to the live node and judge the result: an RPC/transport rejection is a
/// DEFENSE (the door held); acceptance means the adversarial tx was ADMITTED to the
/// live mempool — a real finding.
fn expect_rejected(client: &RpcClient, name: &'static str, stx: SignedTransaction) -> Outcome {
    match client.submit_transaction(&stx) {
        Err(RpcClientError::Rpc { message, .. }) => {
            Outcome::defended(CATEGORY, name, format!("REJECTED at the RPC boundary — {}", trim(&message)))
        }
        Err(RpcClientError::Io(e)) => {
            // Not a defense — we could not reach the node to even ask.
            Outcome::info(CATEGORY, name, format!("could not reach node: {e}"))
        }
        Err(e) => Outcome::defended(CATEGORY, name, format!("REJECTED — {}", trim(&e.to_string()))),
        Ok(id) => Outcome::vulnerable(
            CATEGORY,
            name,
            format!("ADMITTED to the live mempool as {} — the front door did not reject it", id.to_hex()),
        ),
    }
}

/// Trim an error message to a single tidy line.
fn trim(s: &str) -> String {
    let s = s.trim();
    let first = s.lines().next().unwrap_or(s);
    if first.len() > 140 {
        format!("{}…", &first[..139])
    } else {
        first.to_string()
    }
}

/// A 1-SOV transfer whose declared account is the implicit id of `account_seed`, signed
/// by `key_seed`'s keypair (its `public_key` field also being `key_seed`, so the
/// signature itself is valid). When the two seeds match, this is a well-formed
/// self-certifying tx (a base to then corrupt); when they differ, the account is being
/// spent by a key that is NOT its own — an impersonation the node must reject.
fn implicit_transfer(account_seed: u8, key_seed: u8) -> SignedTransaction {
    let account_kp = Keypair::hybrid_from_seed([account_seed; 32]);
    let key_kp = Keypair::hybrid_from_seed([key_seed; 32]);
    let to = Keypair::hybrid_from_seed([200; 32]).public_key().implicit_account_id();
    let tx = Transaction {
        signer: account_kp.public_key().implicit_account_id(),
        public_key: key_kp.public_key(),
        nonce: 0,
        action: Action::Transfer { to, amount: Balance::from_sov(1).unwrap() },
    };
    // `public_key` == the signing key, so `sign` succeeds even when the *account* differs.
    SignedTransaction::sign(tx, &key_kp).unwrap()
}

/// Point the front-door probe at `target` (`host[:port]`, or a full `http://…` URL) and
/// run every side-effect-free attack against the live node.
pub fn probe_frontdoor(target: &str) -> LiveReport {
    let addr = normalize(target);
    let client = RpcClient::new(addr.clone()).with_timeout(Duration::from_secs(10));

    // Connectivity + identity: prove we are actually talking to a live node, and say
    // WHICH chain, so a mainnet run is unmistakable.
    let height = client.height().ok();
    let chain_id = client.chain_id().ok();
    let reachable = height.is_some();
    let is_mainnet = chain_id.as_deref().map(|c| c.contains("mainnet")).unwrap_or(false);

    let mut outcomes = Vec::new();
    if reachable {
        // 1. Forged signature: a well-formed hybrid tx whose Ed25519 signature half has
        //    one flipped byte. `mempool.insert` runs `verify_signature()` → must reject.
        let mut forged = implicit_transfer(9, 9);
        forged.signature = tamper_signature(forged.signature, Half::Ed25519);
        outcomes.push(expect_rejected(&client, "forged signature (flip Ed25519 byte)", forged));

        // 2. Malleability: sign, THEN bump the amount. The signature no longer binds the
        //    body, so verification must fail closed.
        let mut malleable = implicit_transfer(2, 2);
        let to = Keypair::hybrid_from_seed([200; 32]).public_key().implicit_account_id();
        malleable.transaction.action =
            Action::Transfer { to, amount: Balance::from_sov(500).unwrap() };
        outcomes.push(expect_rejected(&client, "edit amount after signing (malleability)", malleable));

        // 3. Impersonation: declare account A but sign with key B. `node.submit`'s
        //    authorization (implicit id must equal the signing key's hash) must reject.
        let impersonated = implicit_transfer(3, 4);
        outcomes.push(expect_rejected(&client, "impersonate (sign with the wrong key)", impersonated));

        // 4. Malformed payload: params that are not a SignedTransaction at all. This
        //    never becomes a transaction — the handler must reject at decode.
        let malformed = match client.call("sov_submitTransaction", json!("not-a-transaction")) {
            Err(RpcClientError::Rpc { message, .. }) => {
                Outcome::defended(CATEGORY, "malformed payload (undecodable)", format!("REJECTED at decode — {}", trim(&message)))
            }
            Err(RpcClientError::Io(e)) => {
                Outcome::info(CATEGORY, "malformed payload (undecodable)", format!("could not reach node: {e}"))
            }
            Err(e) => Outcome::defended(CATEGORY, "malformed payload (undecodable)", format!("REJECTED — {}", trim(&e.to_string()))),
            Ok(_) => Outcome::vulnerable(CATEGORY, "malformed payload (undecodable)", "the node ACCEPTED a non-transaction payload"),
        };
        outcomes.push(malformed);
    }

    LiveReport { target: addr, reachable, height, chain_id, is_mainnet, outcomes }
}

/// Convenience for the CLI: does the report contain any VULNERABLE outcome?
pub fn any_vulnerable(report: &LiveReport) -> bool {
    report.outcomes.iter().any(|o| o.verdict == Verdict::Vulnerable)
}
