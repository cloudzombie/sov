//! **The Gauntlet probe** — attack the live steal-the-pot account every way an OUTSIDER
//! can, and prove the 500 XUS never moves.
//!
//! This is the public challenge made concrete: a real account on live mainnet holds a real
//! balance, and its private key is in cold storage (never published). An attacker who wants
//! the pot has NO key — the account is a keyless *implicit* id (`id == blake3(pubkey)`), so
//! the only signature the chain accepts is the one whose key hashes to that id. This module
//! is the adversary who doesn't have it: it throws every key-less theft it can at the pot
//! over the real RPC and confirms each is refused AND that the pot balance is unchanged
//! afterward. Success for the attacker = the pot balance dropped; every DEFENDED line is the
//! chain saying "not without the key."
//!
//! Side-effect-free: none of these forgeries can be admitted (bad signature or wrong key),
//! so nothing enters the mempool and nothing but a rejection is ever produced.

use std::time::Duration;

use serde_json::{json, to_value};
use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, Balance};
use sov_rpc::{RpcClient, RpcClientError};
use sov_types::{Action, SignedTransaction, Transaction};

use crate::{tamper_signature, Half, Outcome, Verdict};

/// The live Gauntlet pot account (published on sovxus.com/challenge).
pub const POT: &str = "8d670310fc5618e1cf1f8fe6548d2c76bdf9c22b1da594d7eb49f8ecbfa1953a";

const CAT: &str = "gauntlet";

/// The result of attacking the pot.
pub struct GauntletReport {
    /// The pot account id.
    pub pot: String,
    /// Chain id the node reported.
    pub chain_id: Option<String>,
    /// True if the node names mainnet — i.e. this is the REAL pot.
    pub is_mainnet: bool,
    /// Pot balance in grains before the barrage.
    pub balance_before: Option<u128>,
    /// Pot balance in grains after — must equal `balance_before`.
    pub balance_after: Option<u128>,
    /// One outcome per attack.
    pub outcomes: Vec<Outcome>,
    /// A blocking error (unreachable, etc.).
    pub error: Option<String>,
}

impl GauntletReport {
    /// The pot is intact iff not a grain moved.
    pub fn pot_intact(&self) -> bool {
        match (self.balance_before, self.balance_after) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }
    /// Grains a human-readable XUS balance, best-effort.
    pub fn xus(g: Option<u128>) -> String {
        g.map(|v| format!("{:.8}", v as f64 / 1e8))
            .unwrap_or_else(|| "?".into())
    }
}

fn pot_id() -> AccountId {
    AccountId::new(POT).unwrap()
}

/// A throwaway "thief" account the attacker controls (a fresh implicit id).
fn thief(seed: u8) -> AccountId {
    Keypair::hybrid_from_seed([seed; 32])
        .public_key()
        .implicit_account_id()
}

/// A transfer OUT OF the pot to `to`, declared by the pot but signed by attacker `kp` — the
/// forgery at the heart of every steal attempt. `sign` binds `public_key` to the signer key,
/// so the tx carries the ATTACKER's key; the chain's authorization then rejects it because
/// that key's hash is not the pot's id.
fn drain(kp: &Keypair, nonce: u64, to: AccountId, amount: Balance) -> SignedTransaction {
    let tx = Transaction {
        signer: pot_id(),
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer { to, amount },
    };
    SignedTransaction::sign(tx, kp).unwrap()
}

/// Submit `stx` expecting REJECTION. An Ok means a pot-draining tx was ADMITTED — a real
/// finding — so we surface it loudly.
fn expect_rejected(client: &RpcClient, name: &'static str, stx: &SignedTransaction) -> Outcome {
    match client.submit_transaction(stx) {
        Err(RpcClientError::Rpc { message, .. }) => {
            Outcome::defended(CAT, name, format!("REFUSED — {}", trim(&message)))
        }
        Err(RpcClientError::Io(e)) => {
            Outcome::info(CAT, name, format!("could not reach node: {e}"))
        }
        Err(e) => Outcome::defended(CAT, name, format!("REFUSED — {}", trim(&e.to_string()))),
        Ok(id) => Outcome::vulnerable(
            CAT,
            name,
            format!(
                "ADMITTED — a pot-draining tx entered the mempool ({})",
                short(&id.to_hex())
            ),
        ),
    }
}

fn trim(s: &str) -> String {
    let first = s.trim().lines().next().unwrap_or("").trim();
    let first = first.strip_prefix("rejected: ").unwrap_or(first);
    let first = first
        .strip_prefix("mempool rejected transaction: ")
        .unwrap_or(first);
    if first.len() > 120 {
        format!("{}…", &first[..119])
    } else {
        first.to_string()
    }
}

fn short(h: &str) -> String {
    h.chars().take(12).collect()
}

/// Attack the pot at `rpc_target` (`host[:port]`) every key-less way, and verify it's intact.
pub fn probe_gauntlet(rpc_target: &str) -> GauntletReport {
    let addr = normalize(rpc_target);
    let client = RpcClient::new(addr).with_timeout(Duration::from_secs(12));
    let pot = pot_id();

    let chain_id = client.chain_id().ok();
    let mut report = GauntletReport {
        pot: POT.to_string(),
        is_mainnet: chain_id
            .as_deref()
            .map(|c| c.contains("mainnet"))
            .unwrap_or(false),
        chain_id,
        balance_before: None,
        balance_after: None,
        outcomes: Vec::new(),
        error: None,
    };

    let Ok(before) = client.balance(&pot) else {
        report.error = Some(format!(
            "node unreachable at {rpc_target}, or pot not found"
        ));
        return report;
    };
    report.balance_before = Some(before.grains());
    let whole = Balance::from_grains(before.grains().max(1)); // drain the lot
    let sink = thief(240);

    // 1. Forge a spend with a random key (impersonate the pot's owner).
    report.outcomes.push(expect_rejected(
        &client,
        "forge a spend with the wrong key",
        &drain(
            &Keypair::hybrid_from_seed([201; 32]),
            0,
            sink.clone(),
            whole,
        ),
    ));

    // 2. A structurally-valid drain, then corrupt the signature (both halves).
    let mut forged = drain(
        &Keypair::hybrid_from_seed([202; 32]),
        0,
        sink.clone(),
        whole,
    );
    forged.signature = tamper_signature(
        tamper_signature(forged.signature, Half::Ed25519),
        Half::MlDsa,
    );
    report
        .outcomes
        .push(expect_rejected(&client, "forge the signature", &forged));

    // 3. Corrupt ONLY the post-quantum half (keep Ed25519 valid) — the PQ conjunction.
    let mut pq = drain(
        &Keypair::hybrid_from_seed([203; 32]),
        0,
        sink.clone(),
        whole,
    );
    pq.signature = tamper_signature(pq.signature, Half::MlDsa);
    report.outcomes.push(expect_rejected(
        &client,
        "forge only the post-quantum half",
        &pq,
    ));

    // 4. Sign a 1-XUS drain, then bump it to the whole pot AFTER signing (malleability).
    let mut mal = drain(
        &Keypair::hybrid_from_seed([204; 32]),
        0,
        sink.clone(),
        Balance::from_sov(1).unwrap(),
    );
    mal.transaction.action = Action::Transfer {
        to: sink.clone(),
        amount: whole,
    };
    report.outcomes.push(expect_rejected(
        &client,
        "edit the amount after signing",
        &mal,
    ));

    // 5. A zeroed / empty signature.
    let mut zero = drain(
        &Keypair::hybrid_from_seed([205; 32]),
        0,
        sink.clone(),
        whole,
    );
    zero.signature = Signature::V1Ed25519([0; 64]);
    report
        .outcomes
        .push(expect_rejected(&client, "empty (zeroed) signature", &zero));

    // 6. Brute-force futility: many distinct random keys, none is the pot's.
    let mut brute_rejected = 0u32;
    for seed in 20u8..28 {
        let tx = drain(
            &Keypair::hybrid_from_seed([seed; 32]),
            0,
            sink.clone(),
            whole,
        );
        if client.submit_transaction(&tx).is_err() {
            brute_rejected += 1;
        }
    }
    report.outcomes.push(if brute_rejected == 8 {
        Outcome::defended(
            CAT,
            "brute-force 8 random keys",
            "all 8 refused — only the key whose hash IS the account can spend it",
        )
    } else {
        Outcome::vulnerable(
            CAT,
            "brute-force 8 random keys",
            format!("{}/8 forged spends were admitted", 8 - brute_rejected),
        )
    });

    // 7. Seize the pot: rotate its key to the attacker's, signed by the attacker.
    let attacker = Keypair::hybrid_from_seed([206; 32]);
    let seize = SignedTransaction::sign(
        Transaction {
            signer: pot.clone(),
            public_key: attacker.public_key(),
            nonce: 0,
            action: Action::RotateKey {
                new_key: attacker.public_key(),
                proof: Signature::V1Ed25519([0; 64]),
            },
        },
        &attacker,
    )
    .unwrap();
    report.outcomes.push(expect_rejected(
        &client,
        "seize via RotateKey (wrong key)",
        &seize,
    ));

    // 8. Overspend/overflow drain (~u128::MAX) — probe the arithmetic path too.
    report.outcomes.push(expect_rejected(
        &client,
        "overflow drain (~u128::MAX)",
        &drain(
            &Keypair::hybrid_from_seed([207; 32]),
            0,
            sink.clone(),
            Balance::from_grains(u128::MAX),
        ),
    ));

    // 9. Malformed pot-drain: a hand-mangled payload naming the pot as signer.
    let mut raw = to_value(drain(
        &Keypair::hybrid_from_seed([208; 32]),
        0,
        sink.clone(),
        whole,
    ))
    .unwrap();
    raw["signature"] = json!("not-a-signature");
    report
        .outcomes
        .push(match client.call("sov_submitTransaction", raw) {
            Err(RpcClientError::Rpc { message, .. }) => Outcome::defended(
                CAT,
                "malformed pot-drain payload",
                format!("REFUSED at decode — {}", trim(&message)),
            ),
            Err(RpcClientError::Io(e)) => Outcome::info(
                CAT,
                "malformed pot-drain payload",
                format!("could not reach node: {e}"),
            ),
            Err(e) => Outcome::defended(
                CAT,
                "malformed pot-drain payload",
                format!("REFUSED — {}", trim(&e.to_string())),
            ),
            Ok(_) => Outcome::vulnerable(
                CAT,
                "malformed pot-drain payload",
                "the node accepted a malformed pot-draining payload",
            ),
        });

    // 10. Replay a forged drain twice — no second bite either.
    let replay = drain(
        &Keypair::hybrid_from_seed([209; 32]),
        0,
        sink.clone(),
        whole,
    );
    let _ = client.submit_transaction(&replay);
    report
        .outcomes
        .push(expect_rejected(&client, "replay the forged drain", &replay));

    // ── conservation proof: not a grain moved, no thief was credited ──
    if let Ok(after) = client.balance(&pot) {
        report.balance_after = Some(after.grains());
    }
    let thief_credited = client
        .balance(&sink)
        .map(|b| b.grains() > 0)
        .unwrap_or(false);
    report
        .outcomes
        .push(if report.pot_intact() && !thief_credited {
            Outcome::defended(
                CAT,
                "pot conservation",
                format!(
                    "intact — {} XUS still in the pot, no thief credited",
                    GauntletReport::xus(report.balance_after)
                ),
            )
        } else {
            Outcome::vulnerable(
                CAT,
                "pot conservation",
                "THE POT MOVED — value left the account or a thief was credited",
            )
        });

    report
}

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

/// Any VULNERABLE outcome — i.e. the pot is in danger.
pub fn any_vulnerable(report: &GauntletReport) -> bool {
    report
        .outcomes
        .iter()
        .any(|o| o.verdict == Verdict::Vulnerable)
}
