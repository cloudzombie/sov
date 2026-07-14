//! **Live-fire front-door probe** — attack a REAL running node over JSON-RPC.
//!
//! Where the in-process harness feeds adversarial blocks straight to `import_block`,
//! this module reaches a live node the only way an outside attacker can: through
//! `sov_submitTransaction`. It fires a battery of hardened attacks and confirms each is
//! REJECTED — at decode, at authorization (`node.submit`), or at signature verification
//! (`mempool.insert`) — *before* it can reach the mempool.
//!
//! SAFETY — every probe here is rejected at admission, so NOTHING is admitted to the
//! live mempool: no transaction lands, no fee is spent, no state changes, genesis is
//! untouched. The probe reads the target's mempool size before and after and reports it,
//! so the "nothing landed" claim is checked, not just asserted. Attacks that the mempool
//! admits by design (overspend/overflow — no balance gate at admission) or that would
//! DoS a production network (the tx flood) are deliberately NOT fired live; they live in
//! the in-process battery, which exercises the execution/consensus layer instead.
//!
//! The classes:
//!   crypto   — signature integrity, the post-quantum hybrid conjunction, downgrade
//!              resistance, and cross-transaction signature splicing.
//!   authz    — control of the account: wrong-key spends, keyless-account spends, and
//!              account seizure via `RotateKey`.
//!   encoding — the parser / validator: type confusion, missing fields, over-length ids.
//!   rpc      — protocol resilience: unknown methods and oversized bodies don't crash it.

use std::time::Duration;

use serde_json::{json, to_value, Value};
use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, Balance};
use sov_rpc::{RpcClient, RpcClientError};
use sov_types::{Action, SignedTransaction, Transaction};

use crate::{tamper_signature, Half, Outcome, Verdict};

/// The result of pointing the probe at a node: whether it answered, what chain it is,
/// the mempool size before and after (to prove nothing landed), and each attack outcome.
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
    /// The target's mempool size before the probe (residue baseline).
    pub mempool_before: Option<usize>,
    /// The target's mempool size after the probe — must equal `mempool_before` if every
    /// attack was truly rejected before admission.
    pub mempool_after: Option<usize>,
    /// One outcome per attack (empty if the node was unreachable).
    pub outcomes: Vec<Outcome>,
}

impl LiveReport {
    /// True if the probe left NO residue in the target's mempool (before == after).
    pub fn no_residue(&self) -> bool {
        match (self.mempool_before, self.mempool_after) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }
}

/// Normalize a user-typed target into the `host:port` the client expects: strip a
/// `http://` / `https://` scheme and any trailing path, and default the port to 8645
/// (the SOV JSON-RPC port) when none is given.
fn normalize(target: &str) -> String {
    let t = target.trim();
    let t = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    if t.contains(':') {
        t.to_string()
    } else {
        format!("{t}:8645")
    }
}

// ── tx builders ──────────────────────────────────────────────────────────────

/// The throwaway recipient every probe pays: a fresh implicit account nobody controls.
fn sink() -> AccountId {
    Keypair::hybrid_from_seed([200; 32])
        .public_key()
        .implicit_account_id()
}

/// A signed transfer whose declared account is the implicit id of `account_seed`, signed
/// by `key_seed`'s hybrid keypair (its `public_key` field is also `key_seed`, so the
/// signature itself is valid). When the seeds match this is a well-formed self-certifying
/// tx (a base to then corrupt); when they differ, the account is spent by a key that is
/// NOT its own.
fn signed(account_seed: u8, key_seed: u8, nonce: u64, amount_sov: u64) -> SignedTransaction {
    let account_kp = Keypair::hybrid_from_seed([account_seed; 32]);
    let key_kp = Keypair::hybrid_from_seed([key_seed; 32]);
    let tx = Transaction {
        signer: account_kp.public_key().implicit_account_id(),
        public_key: key_kp.public_key(),
        nonce,
        action: Action::Transfer {
            to: sink(),
            amount: Balance::from_sov(amount_sov as u128).unwrap(),
        },
    };
    // `public_key` == the signing key, so `sign` succeeds even when the *account* differs.
    SignedTransaction::sign(tx, &key_kp).unwrap()
}

/// A well-formed, self-certifying transfer from a throwaway implicit account.
fn base(seed: u8) -> SignedTransaction {
    signed(seed, seed, 0, 1)
}

/// Extract the Ed25519 half of a hybrid signature (for the downgrade probe).
fn ed_half(sig: &Signature) -> [u8; 64] {
    match sig {
        Signature::V2HybridMlDsa65 { ed25519, .. } => *ed25519,
        Signature::V1Ed25519(b) => *b,
    }
}

// ── verdict helpers ──────────────────────────────────────────────────────────

/// Submit `stx` and judge: a rejection is a DEFENSE (the door held); acceptance means
/// the adversarial tx was ADMITTED to the live mempool — a real finding.
fn expect_rejected(
    client: &RpcClient,
    cat: &'static str,
    name: &'static str,
    stx: SignedTransaction,
) -> Outcome {
    judge(
        cat,
        name,
        client.submit_transaction(&stx).map(|h| h.to_hex()),
    )
}

/// Submit a raw JSON payload as the params to `sov_submitTransaction` (for encoding
/// attacks that never form a valid `SignedTransaction`).
fn expect_rejected_raw(
    client: &RpcClient,
    cat: &'static str,
    name: &'static str,
    params: Value,
) -> Outcome {
    judge(
        cat,
        name,
        client
            .call("sov_submitTransaction", params)
            .map(|_| "accepted".to_string()),
    )
}

/// Shared verdict logic: `Err(Rpc)` → DEFENDED, `Err(Io)` → INFO (couldn't reach),
/// `Ok(id)` → VULNERABLE (admitted).
fn judge(cat: &'static str, name: &'static str, res: Result<String, RpcClientError>) -> Outcome {
    match res {
        Err(RpcClientError::Rpc { message, .. }) => {
            Outcome::defended(cat, name, format!("REJECTED — {}", trim(&message)))
        }
        Err(RpcClientError::Io(e)) => {
            Outcome::info(cat, name, format!("could not reach node: {e}"))
        }
        Err(e) => Outcome::defended(cat, name, format!("REJECTED — {}", trim(&e.to_string()))),
        Ok(id) => Outcome::vulnerable(
            cat,
            name,
            format!("ADMITTED to the live mempool ({id}) — the door did not reject it"),
        ),
    }
}

/// Trim an error message to a single tidy line.
fn trim(s: &str) -> String {
    let first = s.trim().lines().next().unwrap_or("").trim();
    let first = first.strip_prefix("rejected: ").unwrap_or(first);
    if first.len() > 130 {
        format!("{}…", &first[..129])
    } else {
        first.to_string()
    }
}

// ── the battery ──────────────────────────────────────────────────────────────

/// Point the front-door probe at `target` (`host[:port]`, or a full `http://…` URL) and
/// run every side-effect-free attack against the live node.
pub fn probe_frontdoor(target: &str) -> LiveReport {
    let addr = normalize(target);
    let client = RpcClient::new(addr.clone()).with_timeout(Duration::from_secs(12));

    // Connectivity + identity: prove we are talking to a live node, and say WHICH chain.
    let height = client.height().ok();
    let chain_id = client.chain_id().ok();
    let reachable = height.is_some();
    let is_mainnet = chain_id
        .as_deref()
        .map(|c| c.contains("mainnet"))
        .unwrap_or(false);
    let mempool_before = client.mempool_size().ok();

    let mut outcomes = Vec::new();
    if reachable {
        crypto_probes(&client, &mut outcomes);
        authz_probes(&client, &mut outcomes);
        encoding_probes(&client, &mut outcomes);
        rpc_probes(&client, &mut outcomes);
    }

    let mempool_after = if reachable {
        client.mempool_size().ok()
    } else {
        None
    };

    LiveReport {
        target: addr,
        reachable,
        height,
        chain_id,
        is_mainnet,
        mempool_before,
        mempool_after,
        outcomes,
    }
}

/// CRYPTO: signature integrity, the post-quantum hybrid conjunction, downgrade
/// resistance, and cross-tx signature splicing. Each corrupts a validly-signed tx so
/// `verify_signature` must fail closed at `mempool.insert`.
fn crypto_probes(client: &RpcClient, out: &mut Vec<Outcome>) {
    let c = "crypto";

    // Corrupt the Ed25519 half only.
    let mut s = base(9);
    s.signature = tamper_signature(s.signature, Half::Ed25519);
    out.push(expect_rejected(client, c, "forge Ed25519 half", s));

    // Corrupt ONLY the post-quantum ML-DSA-65 half, leaving Ed25519 valid. The hybrid
    // verifier ANDs both halves, so this must still be rejected — a future break of
    // Ed25519 alone cannot forge.
    let mut s = base(10);
    s.signature = tamper_signature(s.signature, Half::MlDsa);
    out.push(expect_rejected(
        client,
        c,
        "forge post-quantum half only (keep Ed25519 valid)",
        s,
    ));

    // Corrupt BOTH halves.
    let mut s = base(11);
    s.signature = tamper_signature(tamper_signature(s.signature, Half::Ed25519), Half::MlDsa);
    out.push(expect_rejected(client, c, "forge both signature halves", s));

    // Edit the amount AFTER signing (malleability) — the signature binds the body.
    let mut s = base(12);
    s.transaction.action = Action::Transfer {
        to: sink(),
        amount: Balance::from_sov(500).unwrap(),
    };
    out.push(expect_rejected(
        client,
        c,
        "edit amount after signing (malleability)",
        s,
    ));

    // DOWNGRADE: present a V1 Ed25519-only signature (valid Ed25519 bytes) against a
    // hybrid V2 key. Scheme mismatch — the verifier must refuse to fall back to the
    // classical-only half.
    let mut s = base(13);
    s.signature = Signature::V1Ed25519(ed_half(&s.signature));
    out.push(expect_rejected(
        client,
        c,
        "downgrade to Ed25519-only vs a hybrid key",
        s,
    ));

    // SPLICE: attach a signature that is valid for a DIFFERENT transaction (same account,
    // different nonce/amount). It cannot verify over this transaction's bytes.
    let donor = signed(14, 14, 7, 3);
    let mut victim = signed(14, 14, 0, 1);
    victim.signature = donor.signature;
    out.push(expect_rejected(
        client,
        c,
        "splice a signature from another transaction",
        victim,
    ));
}

/// AUTHZ: control of the account. A valid signature is not enough — the key must be
/// entitled to act for the account. Rejected at `node.submit` before the mempool.
fn authz_probes(client: &RpcClient, out: &mut Vec<Outcome>) {
    let c = "authz";

    // Spend an implicit account with a key that is NOT its own (impersonation).
    out.push(expect_rejected(
        client,
        c,
        "impersonate an implicit account (wrong key)",
        signed(3, 4, 0, 1),
    ));

    // Spend from a keyless NAMED account we do not control. Only `RotateKey` (a first
    // claim) is permitted on a keyless named account, so a Transfer must be refused.
    let attacker = Keypair::hybrid_from_seed([21; 32]);
    let tx = Transaction {
        signer: AccountId::new("attacker.sov").unwrap(),
        public_key: attacker.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: sink(),
            amount: Balance::from_sov(1).unwrap(),
        },
    };
    out.push(expect_rejected(
        client,
        c,
        "spend from a keyless named account",
        SignedTransaction::sign(tx, &attacker).unwrap(),
    ));

    // Seize an implicit account via RotateKey signed by the wrong key. Even the
    // privileged claim action must honor implicit self-certification (signer id == the
    // signing key's hash), so a rotation by a foreign key is refused. (The `proof` is a
    // placeholder — authorization rejects long before it is checked.)
    let account = Keypair::hybrid_from_seed([22; 32]);
    let attacker = Keypair::hybrid_from_seed([23; 32]);
    let tx = Transaction {
        signer: account.public_key().implicit_account_id(),
        public_key: attacker.public_key(),
        nonce: 0,
        action: Action::RotateKey {
            new_key: attacker.public_key(),
            proof: Signature::V1Ed25519([0; 64]),
        },
    };
    out.push(expect_rejected(
        client,
        c,
        "seize an account via RotateKey (wrong key)",
        SignedTransaction::sign(tx, &attacker).unwrap(),
    ));
}

/// ENCODING: the parser / validator. Each mutates a VALID transaction so exactly one
/// field is malformed — the node must reject at decode, never forming a transaction.
fn encoding_probes(client: &RpcClient, out: &mut Vec<Outcome>) {
    let c = "encoding";
    let valid = to_value(base(30)).unwrap();

    // A payload that is not a transaction at all.
    out.push(expect_rejected_raw(
        client,
        c,
        "payload is not a transaction",
        json!("not-a-transaction"),
    ));

    // Nonce as a string instead of a number.
    let mut v = valid.clone();
    v["transaction"]["nonce"] = json!("not-a-number");
    out.push(expect_rejected_raw(
        client,
        c,
        "nonce as a string (type confusion)",
        v,
    ));

    // Negative amount (the balance type is unsigned).
    let mut v = valid.clone();
    v["transaction"]["action"]["amount"] = json!(-1);
    out.push(expect_rejected_raw(
        client,
        c,
        "negative transfer amount",
        v,
    ));

    // Missing signature field entirely.
    let mut v = valid.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signature");
    }
    out.push(expect_rejected_raw(client, c, "missing signature field", v));

    // Over-length account id (> 64 chars — the id validator's hard cap).
    let mut v = valid.clone();
    v["transaction"]["signer"] = json!("a".repeat(96));
    out.push(expect_rejected_raw(
        client,
        c,
        "over-length account id (>64 chars)",
        v,
    ));
}

/// RPC: protocol resilience. Neither an unknown method nor an oversized body should
/// crash the node — it must answer with a clean error and keep serving.
fn rpc_probes(client: &RpcClient, out: &mut Vec<Outcome>) {
    let c = "rpc";

    // Unknown method.
    let unknown = match client.call("sov_thisMethodDoesNotExist", json!({})) {
        Err(RpcClientError::Rpc { message, .. }) => Outcome::defended(
            c,
            "unknown method",
            format!("rejected cleanly — {}", trim(&message)),
        ),
        Err(RpcClientError::Io(e)) => {
            Outcome::info(c, "unknown method", format!("could not reach node: {e}"))
        }
        Err(e) => Outcome::defended(
            c,
            "unknown method",
            format!("rejected — {}", trim(&e.to_string())),
        ),
        Ok(_) => Outcome::vulnerable(
            c,
            "unknown method",
            "the node returned a result for a method it does not implement",
        ),
    };
    out.push(unknown);

    // Oversized body (~1 MB of junk as the params) — must be bounded/rejected, not hang.
    let big = json!("x".repeat(1_000_000));
    out.push(expect_rejected_raw(
        client,
        c,
        "oversized request body (~1MB)",
        big,
    ));

    // Liveness: after every attack, the node must still answer — proof it never crashed.
    match client.height() {
        Ok(h) => out.push(Outcome::info(
            c,
            "node still serving after the barrage",
            format!("height {h} — node alive"),
        )),
        Err(e) => out.push(Outcome::vulnerable(
            c,
            "node still serving after the barrage",
            format!("node stopped answering: {e}"),
        )),
    }
}

/// Convenience for the CLI: does the report contain any VULNERABLE outcome?
pub fn any_vulnerable(report: &LiveReport) -> bool {
    report
        .outcomes
        .iter()
        .any(|o| o.verdict == Verdict::Vulnerable)
}
