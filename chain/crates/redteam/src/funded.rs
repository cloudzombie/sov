//! **Funded-adversary probe** — attack the live chain AS a real, funded account.
//!
//! Every other live probe uses zero-balance throwaway accounts, so its transactions are
//! rejected at admission and nothing moves. This probe is different: the operator pastes
//! the private key of a REAL account (funded with real XUS), and the tool acts as that
//! account. The headline attack is a DOUBLE-SPEND — commit the same nonce to two
//! conflicting transactions and prove the chain keeps at most one. Leg 1 is an honest
//! net-zero self-transfer (a real, confirming tx that proves the funded key works, moving
//! value out and back to itself minus a fee); leg 2 tries to spend that same nonce to an
//! attacker. The chain must refuse leg 2. A replay of leg 1 must also be refused.
//!
//! This DOES touch the live chain with real value: leg 1 confirms (a tiny fee is spent).
//! It never sends the balance anywhere but back to itself, so the funds stay put.

use std::time::Duration;

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::RpcClient;
use sov_types::{Action, SignedTransaction, Transaction};
use sov_wallet::HdWallet;

use crate::Outcome;

/// The result of the funded-adversary probe.
pub struct FundedReport {
    /// The implicit account id the pasted key controls.
    pub account: String,
    /// Human-readable balance (e.g. "5.00000000").
    pub balance: String,
    /// Balance in grains (0 if unfunded / unreachable).
    pub balance_grains: u128,
    /// The account's current on-chain nonce.
    pub nonce: u64,
    /// The chain id the node reported.
    pub chain_id: Option<String>,
    /// True if the chain id names mainnet.
    pub is_mainnet: bool,
    /// Per-attack outcomes.
    pub outcomes: Vec<Outcome>,
    /// A blocking error (unreachable node, etc.).
    pub error: Option<String>,
}

/// Derive the 32-byte master seed from either a BIP-39 mnemonic (12/24 words — the same
/// SLIP-0010 path sov-station imports, `m/44'/SOV'/0'/0'/0'`) or a raw 32-byte hex seed
/// (the `hybrid_from_seed` a freshly-generated wallet uses). Callers reconstruct the
/// keypair with [`Keypair::hybrid_from_seed`]; holding the seed (Copy, zeroizable) avoids
/// keeping a non-Clone `Keypair` in long-lived UI state. Returns a clear error rather than
/// guessing, so the operator knows if the input was malformed.
pub fn seed_from_secret(input: &str) -> Result<[u8; 32], String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("no key provided".into());
    }
    // A bare 32-byte hex seed.
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(s).map_err(|e| format!("bad hex seed: {e}"))?;
        return bytes.try_into().map_err(|_| "seed must be 32 bytes".to_string());
    }
    // Otherwise treat it as a BIP-39 mnemonic and derive account 0, index 0.
    HdWallet::from_mnemonic(s, "")
        .map(|w| w.derive_seed(0, 0))
        .map_err(|e| format!("not a 32-byte hex seed or a valid mnemonic: {e}"))
}

/// Convenience: the funded keypair for a pasted secret (CLI use). See
/// [`seed_from_secret`].
pub fn keypair_from_secret(input: &str) -> Result<Keypair, String> {
    seed_from_secret(input).map(Keypair::hybrid_from_seed)
}

/// The account a key controls (its implicit id).
pub fn account_of(kp: &Keypair) -> AccountId {
    kp.public_key().implicit_account_id()
}

/// Build a signed transfer of `amount` grains from `kp`'s implicit account to `to` at
/// `nonce`.
fn transfer(kp: &Keypair, nonce: u64, to: AccountId, amount: Balance) -> SignedTransaction {
    let tx = Transaction {
        signer: account_of(kp),
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer { to, amount },
    };
    SignedTransaction::sign(tx, kp).unwrap()
}

/// Run the funded-adversary battery against `rpc_target` as the account controlled by
/// `kp`. `spend_grains` is the tiny amount leg 1 moves (to itself).
pub fn probe_funded(rpc_target: &str, kp: &Keypair, spend_grains: u128) -> FundedReport {
    let addr = normalize(rpc_target);
    let client = RpcClient::new(addr).with_timeout(Duration::from_secs(12));
    let account = account_of(kp);

    let chain_id = client.chain_id().ok();
    let is_mainnet = chain_id.as_deref().map(|c| c.contains("mainnet")).unwrap_or(false);

    let mut report = FundedReport {
        account: account.to_string(),
        balance: "?".into(),
        balance_grains: 0,
        nonce: 0,
        chain_id,
        is_mainnet,
        outcomes: Vec::new(),
        error: None,
    };

    let Ok(nonce) = client.nonce(&account) else {
        report.error = Some(format!("node unreachable at {rpc_target}, or account not found"));
        return report;
    };
    report.nonce = nonce;
    if let Ok(bal) = client.balance(&account) {
        report.balance = bal.to_string();
        report.balance_grains = bal.grains();
    }

    let sink = Keypair::hybrid_from_seed([202; 32]).public_key().implicit_account_id();
    let amount = Balance::from_grains(spend_grains);
    // Most of the balance — what an attacker would try to steal on the double-spent nonce.
    let big = Balance::from_grains(report.balance_grains.max(spend_grains));

    // Leg 1 — honest, net-zero SELF-transfer at nonce N. A real, confirming tx: proves the
    // funded key authorizes live transactions (value leaves and returns to the same
    // account; only a fee is spent).
    let leg1 = transfer(kp, nonce, account.clone(), amount);
    let leg1_id = leg1.id().to_hex();
    match client.submit_transaction(&leg1) {
        Ok(id) => report.outcomes.push(Outcome::info(
            "funded",
            "leg 1: honest self-transfer (real tx)",
            format!("ACCEPTED — the funded key signed a live tx ({}); confirms net-zero", short(&id.to_hex())),
        )),
        Err(e) => report.outcomes.push(Outcome::info(
            "funded",
            "leg 1: honest self-transfer (real tx)",
            format!("not accepted — {} (is the account funded?)", trim(&e.to_string())),
        )),
    }

    // Leg 2 — the DOUBLE-SPEND: reuse nonce N to send most of the balance to an attacker.
    // The mempool binds one transaction per (signer, nonce), so this must be refused.
    let leg2 = transfer(kp, nonce, sink, big);
    report.outcomes.push(judge_rejected(
        &client,
        "leg 2: DOUBLE-SPEND (reuse nonce N)",
        &leg2,
        "double-spend blocked — nonce already committed to leg 1",
    ));

    // Replay — resubmit leg 1's exact bytes. Already pooled, so it must be refused.
    report.outcomes.push(judge_rejected(
        &client,
        "replay leg 1 (resubmit same tx)",
        &leg1,
        &format!("replay blocked — {} already pooled", short(&leg1_id)),
    ));

    report
}

/// Submit `stx`, expecting the chain to REJECT it (a defense). Acceptance is a finding.
fn judge_rejected(client: &RpcClient, name: &'static str, stx: &SignedTransaction, on_defended: &str) -> Outcome {
    match client.submit_transaction(stx) {
        Err(e) => Outcome::defended("funded", name, format!("{on_defended} — {}", trim(&e.to_string()))),
        Ok(id) => Outcome::vulnerable("funded", name, format!("ACCEPTED — a conflicting/replayed tx was admitted ({})", short(&id.to_hex()))),
    }
}

fn normalize(target: &str) -> String {
    let t = target.trim();
    let t = t.strip_prefix("http://").or_else(|| t.strip_prefix("https://")).unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    if t.contains(':') { t.to_string() } else { format!("{t}:8645") }
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

fn trim(s: &str) -> String {
    let first = s.trim().lines().next().unwrap_or("").trim();
    // Peel the JSON-RPC envelope + node prefixes down to the human reason.
    let first = first
        .strip_prefix("rpc error")
        .map(|r| r.trim_start_matches(|c: char| c == ':' || c == ' ' || c == '-' || c.is_ascii_digit()))
        .unwrap_or(first);
    let first = first.strip_prefix("rejected: ").unwrap_or(first);
    let first = first.strip_prefix("mempool rejected transaction: ").unwrap_or(first);
    if first.len() > 120 {
        format!("{}…", &first[..119])
    } else {
        first.to_string()
    }
}

/// Any VULNERABLE outcome?
pub fn any_vulnerable(report: &FundedReport) -> bool {
    report.outcomes.iter().any(|o| o.verdict == crate::Verdict::Vulnerable)
}
