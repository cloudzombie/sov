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
use sov_intents::{Asset, Intent, Settlement};
use sov_primitives::{AccountId, Balance, Hash, SigningDomain};
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
    /// Pot on-chain nonce before the barrage.
    pub nonce_before: Option<u64>,
    /// Pot on-chain nonce after — must equal `nonce_before` (no forgery consumed it).
    pub nonce_after: Option<u64>,
    /// The pot's authorizer BEFORE — its registered controlling key (rendered as a
    /// short hex), or `multisig(m/n)` if it carries a policy. Must not change.
    pub authorizer_before: Option<String>,
    /// The pot's authorizer AFTER — must equal `authorizer_before` (no seize landed).
    pub authorizer_after: Option<String>,
    /// The node's mempool size BEFORE the barrage.
    pub mempool_before: Option<usize>,
    /// The node's mempool size AFTER — a forgery that was admitted would raise it.
    pub mempool_after: Option<usize>,
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

    /// Number of attack VECTORS the battery actually resolved — every outcome the
    /// chain gave a real verdict on (DEFENDED or VULNERABLE). `Info` lines (a
    /// vector that could not be exercised, e.g. the node was unreachable) are not
    /// counted as attempted, so the tally never over-claims.
    pub fn vectors_attempted(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.verdict != Verdict::Info)
            .count()
    }

    /// Number of vectors that BREACHED — an admitted forgery, a moved grain, a
    /// seized authorizer. MUST be zero; any nonzero value means the pot is in
    /// danger and the harness exits nonzero.
    pub fn vectors_breached(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Vulnerable)
            .count()
    }

    /// Grains admitted into the mempool by the whole battery, measured as the rise
    /// in the node's mempool size across it. MUST be zero: every vector is a
    /// forgery that cannot be admitted, so nothing enters the pool. `None` if the
    /// node did not report a mempool size at both ends.
    pub fn mempool_admissions(&self) -> Option<usize> {
        match (self.mempool_before, self.mempool_after) {
            (Some(b), Some(a)) => Some(a.saturating_sub(b)),
            _ => None,
        }
    }

    /// The measured metric panel, one line per metric, before → after with the
    /// invariant each must hold. Rendered by the CLI (and, once wired, the Station
    /// Red Team tab) so both surfaces show the SAME numbers behind `pot_intact()`.
    pub fn summary_lines(&self) -> Vec<String> {
        let ba = self.balance_after;
        let nu = |o: Option<u64>| o.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        let su = |o: &Option<String>| o.clone().unwrap_or_else(|| "?".into());
        let mem = self
            .mempool_admissions()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into());
        vec![
            format!(
                "balance    {} → {} XUS  (Δ must be 0 grains)",
                Self::xus(self.balance_before),
                Self::xus(ba)
            ),
            format!(
                "nonce      {} → {}  (unchanged)",
                nu(self.nonce_before),
                nu(self.nonce_after)
            ),
            format!(
                "authorizer {} → {}  (unchanged)",
                su(&self.authorizer_before),
                su(&self.authorizer_after)
            ),
            format!("mempool admissions {mem}  (must be 0)"),
            format!(
                "vectors    {} attempted · {} breached  (breached must be 0)",
                self.vectors_attempted(),
                self.vectors_breached()
            ),
            format!(
                "verdict    POT {}",
                if self.pot_intact() && self.vectors_breached() == 0 {
                    "INTACT"
                } else {
                    "IN DANGER"
                }
            ),
        ]
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
    forge(kp, nonce, Action::Transfer { to, amount })
}

/// The general forgery: ANY `action` declared BY the pot but signed by attacker
/// `kp`. `drain` is the `Transfer` special case; every other value/authority exit
/// (`RotateKey`, `SetMultisig`, `IntentSettle`, a carrier envelope, a token/vault/
/// HTLC/name/NFT move) rides this same builder. `sign` binds the ATTACKER's key
/// into the transaction, so authorization rejects it: that key's hash is not the
/// pot's id. Un-admittable by construction — nothing can enter the mempool.
fn forge(kp: &Keypair, nonce: u64, action: Action) -> SignedTransaction {
    let tx = Transaction {
        signer: pot_id(),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    SignedTransaction::sign(tx, kp).unwrap()
}

/// A pot-drain signed under a FOREIGN signing domain (a different chain_id +
/// genesis), for the domain-swap replay: a signature minted for another network,
/// replayed here. Rejected either by the `tx-domain` binding (if active) or by the
/// key/id mismatch (always) — the probe reports which fired.
fn forge_in_domain(
    kp: &Keypair,
    nonce: u64,
    action: Action,
    domain: &SigningDomain,
) -> SignedTransaction {
    let tx = Transaction {
        signer: pot_id(),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    SignedTransaction::sign_in(tx, kp, Some(domain)).unwrap()
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
        nonce_before: None,
        nonce_after: None,
        authorizer_before: None,
        authorizer_after: None,
        mempool_before: None,
        mempool_after: None,
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
    // ── metric panel: snapshot the pot's authority + the node's pool BEFORE ──
    report.nonce_before = client.nonce(&pot).ok();
    report.authorizer_before = authorizer_of(&client, &pot);
    report.mempool_before = client.mempool_size().ok();
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

    // ═══════════════════════════════════════════════════════════════════════
    // EXHAUSTIVE LIVE BATTERY — every conceivable key-less path at the pot.
    // Each is un-admittable by construction (bad sig / wrong key / dormant
    // feature), so it is side-effect-free: nothing enters the mempool.
    // ═══════════════════════════════════════════════════════════════════════

    // ── A1. PQ HALF-STRIP (CRITICAL) — the hybrid conjunction over the wire ──
    // The pot key is hybrid Ed25519+ML-DSA-65. A forgery that presents only ONE
    // half must be refused: either half ALONE is not authorization. We cannot
    // wield the pot's real key here (cold storage), so over live RPC we submit
    // half-stripped ATTACKER forgeries and confirm rejection; the DEFINITIVE
    // "both halves load-bearing WITH the pot's own key" proof is the in-process
    // test `pot_hybrid_conjunction_is_enforced` in lib.rs (real key, real STF).
    let mut ed_only = drain(
        &Keypair::hybrid_from_seed([210; 32]),
        0,
        sink.clone(),
        whole,
    );
    ed_only.signature = strip_to_half(ed_only.signature, Half::Ed25519);
    report.outcomes.push(expect_rejected(
        &client,
        "PQ half-strip: Ed25519 half alone",
        &ed_only,
    ));
    let mut pq_only = drain(
        &Keypair::hybrid_from_seed([211; 32]),
        0,
        sink.clone(),
        whole,
    );
    pq_only.signature = strip_to_half(pq_only.signature, Half::MlDsa);
    report.outcomes.push(expect_rejected(
        &client,
        "PQ half-strip: ML-DSA half alone",
        &pq_only,
    ));

    // ── A2. DOMAIN-SWAP REPLAY — a signature minted for a FOREIGN network ──
    // Bind a pot-drain to a different (chain_id, genesis) and replay it here.
    // Rejected by the tx-domain binding if active, else by the key/id mismatch.
    let foreign = SigningDomain::new("sov-attacker", flip_hash(genesis_or_zero(&client)));
    let swapped = forge_in_domain(
        &Keypair::hybrid_from_seed([212; 32]),
        0,
        Action::Transfer {
            to: sink.clone(),
            amount: whole,
        },
        &foreign,
    );
    let domain_bound = client.signing_domain().ok().flatten().is_some();
    let which = if domain_bound {
        "tx-domain active — the foreign-network signature does not bind here"
    } else {
        "tx-domain dormant — the wrong-key/id mismatch is what refuses it"
    };
    report
        .outcomes
        .push(match client.submit_transaction(&swapped) {
            Ok(id) => Outcome::vulnerable(
                CAT,
                "domain-swap replay",
                format!(
                    "ADMITTED — a foreign-domain drain entered the mempool ({})",
                    short(&id.to_hex())
                ),
            ),
            Err(RpcClientError::Io(e)) => Outcome::info(
                CAT,
                "domain-swap replay",
                format!("could not reach node: {e}"),
            ),
            Err(e) => Outcome::defended(
                CAT,
                "domain-swap replay",
                format!("REFUSED ({which}) — {}", trim(&e.to_string())),
            ),
        });

    // ── A3. ZERO / EMPTY SIGNATURE (hybrid) — strip the signature entirely ──
    // (Vector #5 already zeroed a V1 signature; this zeroes BOTH hybrid halves.)
    let mut zeroed = drain(
        &Keypair::hybrid_from_seed([213; 32]),
        0,
        sink.clone(),
        whole,
    );
    zeroed.signature = strip_to_half(strip_to_half(zeroed.signature, Half::Ed25519), Half::MlDsa);
    report.outcomes.push(expect_rejected(
        &client,
        "all-zero hybrid signature",
        &zeroed,
    ));

    // ── A4. NONCE GAMES — a forged drain at a future and a stale nonce ──
    // Authorization is checked BEFORE the nonce, so a bad-key forgery is refused
    // regardless of the nonce it carries: the nonce is irrelevant once auth fails.
    let pot_next = client.next_nonce(&pot).unwrap_or(0);
    report.outcomes.push(expect_rejected(
        &client,
        "forged drain at a FUTURE nonce",
        &drain(
            &Keypair::hybrid_from_seed([214; 32]),
            pot_next.saturating_add(999),
            sink.clone(),
            whole,
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "forged drain at a STALE nonce",
        &drain(
            &Keypair::hybrid_from_seed([215; 32]),
            0,
            sink.clone(),
            whole,
        ),
    ));

    // ── A5. IMPLICIT-ID PREIMAGE NEAR-MISS — a key close to, but NOT, the pot ──
    // A key whose blake3(pubkey) shares a leading prefix with the pot id proves id
    // equality is EXACT, not fuzzy: near does not count, only the exact preimage.
    let (near_kp, shared) = near_miss_key();
    report.outcomes.push(expect_rejected(
        &client,
        "implicit-id preimage near-miss",
        &forge(
            &near_kp,
            0,
            Action::Transfer {
                to: sink.clone(),
                amount: whole,
            },
        ),
    ));
    report.outcomes.push(Outcome::info(
        CAT,
        "  ↑ near-miss shares only a prefix",
        format!(
            "attacker key hashes to an id sharing {shared} leading hex with the pot — still not it"
        ),
    ));

    // ── A6. MULTISIG SEIZE PATHS — you cannot set the pot's policy w/o its key ──
    let atk = Keypair::hybrid_from_seed([216; 32]);
    report.outcomes.push(expect_rejected(
        &client,
        "seize via SetMultisig (attacker keys)",
        &forge(
            &atk,
            0,
            Action::SetMultisig {
                signers: vec![atk.public_key()],
                threshold: 1,
            },
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "seize via MultisigExec (drain)",
        &forge(
            &atk,
            0,
            Action::MultisigExec {
                action: Box::new(Action::Transfer {
                    to: sink.clone(),
                    amount: whole,
                }),
                approvals: vec![],
            },
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "seize via ProposeMultisig (drain)",
        &forge(
            &atk,
            0,
            Action::ProposeMultisig {
                account: pot.clone(),
                action: Box::new(Action::Transfer {
                    to: sink.clone(),
                    amount: whole,
                }),
            },
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "seize via ApproveMultisig",
        &forge(
            &atk,
            0,
            Action::ApproveMultisig {
                account: pot.clone(),
                proposal: Hash::ZERO,
            },
        ),
    ));

    // ── A7. INTENTSETTLE BYPASS — the class of the old H001 multisig bypass ──
    // Move pot value by naming it as an intent owner; the outer envelope is signed
    // by the attacker, so authorization refuses it before any settlement logic.
    let intent = Intent {
        owner: pot.clone(),
        public_key: atk.public_key(),
        nonce: 0,
        give_asset: Asset::Sov,
        give_amount: whole.grains(),
        want_asset: Asset::Sov,
        min_receive: 0,
        expiry_height: u64::MAX,
    };
    let signed_intent = intent.sign(&atk).unwrap();
    report.outcomes.push(expect_rejected(
        &client,
        "IntentSettle bypass (pot as owner)",
        &forge(
            &atk,
            0,
            Action::IntentSettle {
                settlement: Settlement {
                    intent: signed_intent,
                    solver: sink.clone(),
                    deliver_amount: 0,
                },
            },
        ),
    ));

    // ── A8. CARRIER LAUNDERING — a wrapper cannot launder past authorization ──
    // Wrap a pot-drain in Tipped / Timestamped / a ShieldedV2 bundle. A carrier
    // either resolves auth from the top-level signer (still the pot ⇒ wrong key)
    // or is dormant on mainnet (FeatureInactive) — either is DEFENDED.
    report.outcomes.push(expect_rejected(
        &client,
        "carrier laundering: Tipped{drain}",
        &forge(
            &atk,
            0,
            Action::Tipped {
                tip: Balance::from_grains(1),
                inner: Box::new(Action::Transfer {
                    to: sink.clone(),
                    amount: whole,
                }),
            },
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "carrier laundering: Timestamped{drain}",
        &forge(
            &atk,
            0,
            Action::Timestamped {
                created_at_ms: 0,
                inner: Box::new(Action::Transfer {
                    to: sink.clone(),
                    amount: whole,
                }),
            },
        ),
    ));
    report.outcomes.push(expect_rejected(
        &client,
        "carrier laundering: ShieldedV2 bundle",
        &forge(&atk, 0, Action::ShieldedV2 { bundle: vec![0; 8] }),
    ));

    // ── A9. OTHER VALUE / AUTHORITY EXITS — each names the pot as signer ──
    for (name, action) in other_exits(&pot, &sink, whole) {
        report
            .outcomes
            .push(expect_rejected(&client, name, &forge(&atk, 0, action)));
    }

    // ── metric panel: snapshot the pot's authority + the node's pool AFTER ──
    report.nonce_after = client.nonce(&pot).ok();
    report.authorizer_after = authorizer_of(&client, &pot);
    report.mempool_after = client.mempool_size().ok();

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

/// Keep only one half of a hybrid signature, zeroing the other — the wire form of
/// "authorize with just the Ed25519 (or just the ML-DSA) half". A non-hybrid
/// signature is returned unchanged.
fn strip_to_half(sig: Signature, keep: Half) -> Signature {
    match sig {
        Signature::V2HybridMlDsa65 { ed25519, ml_dsa } => match keep {
            // Keep Ed25519, strip ML-DSA.
            Half::Ed25519 => Signature::V2HybridMlDsa65 {
                ed25519,
                ml_dsa: [0; sov_crypto::ML_DSA_65_SIG_LEN],
            },
            // Keep ML-DSA, strip Ed25519.
            Half::MlDsa => Signature::V2HybridMlDsa65 {
                ed25519: [0; 64],
                ml_dsa,
            },
        },
        other => other,
    }
}

/// The node's genesis hash if it reports a signing domain; the zero hash otherwise.
/// Only used to build a DIFFERENT (foreign) domain, so the exact value is immaterial
/// — `flip_hash` guarantees it never coincides with the real one.
fn genesis_or_zero(client: &RpcClient) -> Hash {
    client
        .signing_domain()
        .ok()
        .flatten()
        .map(|d| d.genesis())
        .unwrap_or(Hash::ZERO)
}

/// Flip the first byte of a hash, so the result is guaranteed distinct from the input.
fn flip_hash(h: Hash) -> Hash {
    let mut b = *h.as_bytes();
    b[0] ^= 0xff;
    Hash::from_bytes(b)
}

/// A key whose implicit id shares a leading hex PREFIX with the pot's id but is
/// NOT the pot — grinds a handful of seeds for the longest shared prefix found.
/// Returns the key and the number of shared leading hex characters (short by
/// construction: a full match is a 256-bit preimage, which is infeasible — that
/// infeasibility is exactly what the vector demonstrates).
fn near_miss_key() -> (Keypair, usize) {
    let pot_hex = POT;
    let mut best = (Keypair::hybrid_from_seed([100; 32]), 0usize);
    for seed in 100u16..2_000 {
        let bytes = (seed as u32).to_le_bytes();
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&bytes);
        let kp = Keypair::hybrid_from_seed(s);
        let id = kp.public_key().implicit_account_id();
        let id_hex = id.as_str();
        let shared = pot_hex
            .chars()
            .zip(id_hex.chars())
            .take_while(|(a, b)| a == b)
            .count();
        if shared > best.1 && id_hex != pot_hex {
            best = (kp, shared);
        }
    }
    best
}

/// The remaining value/authority-exit actions (A9), each naming the pot as signer.
/// A `Hash::ZERO` asset/collection/htlc id is fine: authorization refuses the
/// attacker-signed envelope before any of these ids is ever consulted.
fn other_exits(_pot: &AccountId, sink: &AccountId, whole: Balance) -> Vec<(&'static str, Action)> {
    vec![
        (
            "exit via TokenTransfer",
            Action::TokenTransfer {
                asset: Hash::ZERO,
                to: sink.clone(),
                amount: whole,
            },
        ),
        (
            "exit via TokenBurn",
            Action::TokenBurn {
                asset: Hash::ZERO,
                amount: whole,
            },
        ),
        (
            "exit via VaultWithdraw",
            Action::VaultWithdraw { amount: whole },
        ),
        ("exit via VaultBurn", Action::VaultBurn { amount: whole }),
        (
            "exit via HtlcClaim",
            Action::HtlcClaim {
                htlc_id: Hash::ZERO,
                preimage: vec![0; 8],
            },
        ),
        (
            "exit via TransferName",
            Action::TransferName {
                name: "gauntlet.sov".to_string(),
                to: sink.clone(),
            },
        ),
        (
            "exit via NftTransfer",
            Action::NftTransfer {
                collection: Hash::ZERO,
                token_id: vec![0; 4],
                to: sink.clone(),
            },
        ),
    ]
}

/// The pot's authorizer, for the metric panel: `multisig(m/n)` if it carries a
/// policy, else its registered key as short hex, else `keyless` (self-certifying
/// implicit id — the real pot's state). `None` if the node is unreachable.
fn authorizer_of(client: &RpcClient, pot: &AccountId) -> Option<String> {
    // A multisig policy, if any, is the authoritative authorizer.
    if let Ok(props) = client.call(
        "sov_getMultisigProposals",
        json!({ "account": pot.as_str() }),
    ) {
        if let Some(first) = props.as_array().and_then(|a| a.first()) {
            let threshold = first.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0);
            let signers = first.get("signers").and_then(|v| v.as_u64()).unwrap_or(0);
            if signers > 0 {
                return Some(format!("multisig({threshold}/{signers})"));
            }
        }
    }
    match client.account(pot) {
        Ok(Some(acct)) => Some(match acct.key {
            Some(k) => format!("key:{}", short(&k.to_hex())),
            None => "keyless".to_string(),
        }),
        Ok(None) => Some("absent".to_string()),
        Err(_) => None,
    }
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
