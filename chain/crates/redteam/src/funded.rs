//! **Funded-adversary probe** — attack the live chain AS a real, funded account, probing
//! it the way a thief would: try to spend the same coins twice, replay a payment, rewind
//! the nonce, front-run yourself, and drain an account you don't own.
//!
//! Every other live probe uses zero-balance throwaways. This one holds a REAL key the
//! operator pastes and controls real XUS. It first proves control with an honest net-zero
//! self-transfer (the ONE tx that lands — value leaves and returns to the same account,
//! only a gas fee spent), then runs a THEFT campaign whose every attempt the chain must
//! refuse:
//!   - double-spend the whole balance to a thief (nonce reuse) → refused (one tx / nonce),
//!   - front-run / replace-by-fee (swap recipient on the same nonce) → refused (no RBF),
//!   - replay the payment to drain twice → refused (already pooled),
//!   - rewind the nonce to re-spend a past state → refused (stale nonce),
//!   - drain an account we don't own (wrong signer) → refused (unauthorized).
//!
//! It also tries to CREATE value from nothing — a mint-from-thin-air and an integer
//! overflow — fired live but signed by THROWAWAY empty accounts, so a node with the
//! mempool affordability gate rejects them at admission (no value, no wedge) and a node
//! that predates the gate only strands the throwaway, never the funded account.
//!
//! SAFETY: the theft attempts are all rejected at admission (or, for the mint attempts,
//! signed by throwaways), so none consume the funded account's nonce or move its coins;
//! only the honest self-transfer lands (a small gas fee).

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

/// Build a signed transfer of `amount` from `kp`'s implicit account to `to` at `nonce`.
fn transfer(kp: &Keypair, nonce: u64, to: AccountId, amount: Balance) -> SignedTransaction {
    transfer_as(account_of(kp), kp, nonce, to, amount)
}

/// Build a transfer that DECLARES `signer` as the source account but is signed by `kp`.
/// When `signer` is not `kp`'s own account, this is an attempt to spend an account the
/// key does not control.
fn transfer_as(signer: AccountId, kp: &Keypair, nonce: u64, to: AccountId, amount: Balance) -> SignedTransaction {
    let tx = Transaction {
        signer,
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer { to, amount },
    };
    SignedTransaction::sign(tx, kp).unwrap()
}

/// A distinct throwaway "thief" account (an implicit id nobody controls).
fn thief(seed: u8) -> AccountId {
    Keypair::hybrid_from_seed([seed; 32]).public_key().implicit_account_id()
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

    let whole = Balance::from_grains(report.balance_grains.max(spend_grains)); // the whole stash
    let dust = Balance::from_grains(spend_grains);

    // ── CONTROL: prove the key really owns spendable funds ──
    // An honest, net-zero SELF-transfer at nonce N. The ONE tx that lands (value leaves
    // and returns to the same account; only a gas fee is spent). Everything after it is a
    // theft attempt that must fail.
    let baseline = transfer(kp, nonce, account.clone(), dust);
    let baseline_id = baseline.id().to_hex();
    match client.submit_transaction(&baseline) {
        Ok(id) => report.outcomes.push(Outcome::info(
            "control",
            "prove control — net-zero self-transfer",
            format!("ACCEPTED — the funded key signed a live tx ({}); confirms net-zero", short(&id.to_hex())),
        )),
        Err(e) => report.outcomes.push(Outcome::info(
            "control",
            "prove control — net-zero self-transfer",
            format!("not accepted — {} (is the account funded?)", trim(&e.to_string())),
        )),
    }

    // ── THEFT: spend the same coins more than once ──
    report.outcomes.push(judge_rejected(
        &client,
        "double-spend the whole balance to a thief",
        &transfer(kp, nonce, thief(211), whole),
        "refused — nonce N already committed; the coins can't be spent twice",
    ));
    report.outcomes.push(judge_rejected(
        &client,
        "front-run / replace-by-fee (swap recipient, same nonce)",
        &transfer(kp, nonce, thief(212), whole),
        "refused — no replace-by-fee; the nonce is already bound",
    ));
    report.outcomes.push(judge_rejected(
        &client,
        "replay to drain twice (resubmit the same tx)",
        &baseline,
        &format!("refused — {} already pooled", short(&baseline_id)),
    ));
    if nonce > 0 {
        report.outcomes.push(judge_rejected(
            &client,
            "rewind the nonce to re-spend (stale nonce N-1)",
            &transfer(kp, nonce - 1, thief(213), whole),
            "refused — stale nonce; you can't rewind to re-spend",
        ));
    } else {
        report.outcomes.push(Outcome::info(
            "theft",
            "rewind the nonce to re-spend (stale nonce N-1)",
            "n/a — account has no history yet (nonce 0)".to_string(),
        ));
    }

    // ── THEFT: spend an account we don't own ──
    let victim = thief(216);
    report.outcomes.push(judge_rejected(
        &client,
        "drain an account we don't own (wrong signer)",
        &transfer_as(victim, kp, 0, account.clone(), whole),
        "refused — our key can't authorize an account it doesn't control",
    ));

    // ── THEFT: create value from nothing ──
    // Fired LIVE, but signed by THROWAWAY empty accounts — so a node with the affordability
    // gate rejects them at admission (no value, no wedge), and a node that predates the gate
    // would only strand the throwaway's own nonce, never the funded account. Either way the
    // beneficiary is never credited, which is the property that actually matters.
    report.outcomes.push(judge_mint(
        &client,
        "mint from thin air (spend from an EMPTY account)",
        &mint_attempt(230, thief(231), Balance::from_sov(1_000_000).unwrap()),
        &thief(231),
    ));
    report.outcomes.push(judge_mint(
        &client,
        "integer-overflow a credit (~u128::MAX)",
        &mint_attempt(232, thief(233), Balance::from_grains(u128::MAX)),
        &thief(233),
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

/// A transfer of `amount` FROM a throwaway empty implicit account (self-certifying, so it
/// authenticates) — an attempt to move value the account does not have. Signed by the
/// throwaway's own key, so any admission strands only the throwaway, never a real account.
fn mint_attempt(from_seed: u8, to: AccountId, amount: Balance) -> SignedTransaction {
    let kp = Keypair::hybrid_from_seed([from_seed; 32]);
    let tx = Transaction {
        signer: kp.public_key().implicit_account_id(),
        public_key: kp.public_key(),
        nonce: 0,
        action: Action::Transfer { to, amount },
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

/// Judge a mint/overflow attempt by the only thing that matters — did value appear? The
/// `beneficiary`'s balance must stay zero. A gated node also REJECTS it at admission (best);
/// a pre-gate node admits it but execution reverts (no credit) — reported as INFO with a
/// nudge to deploy the affordability gate.
fn judge_mint(client: &RpcClient, name: &'static str, stx: &SignedTransaction, beneficiary: &AccountId) -> Outcome {
    let admitted = client.submit_transaction(stx).is_ok();
    let credited = client.balance(beneficiary).map(|b| b.grains() > 0).unwrap_or(false);
    if credited {
        Outcome::vulnerable("theft", name, "VALUE CREATED — the beneficiary was credited from thin air".to_string())
    } else if !admitted {
        Outcome::defended("theft", name, "refused at admission — an unaffordable transfer can't be pooled (affordability gate); no value created".to_string())
    } else {
        Outcome::info("theft", name, "admitted but reverts — no value created (this node predates the affordability gate; rebuild to reject it at the door)".to_string())
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
