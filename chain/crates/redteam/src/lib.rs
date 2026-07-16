//! `sov-redteam` — a STANDALONE adversarial harness for the SOV chain.
//!
//! It builds a real in-process chain (the actual consensus code — `produce_block`
//! / `import_block`, the same path a node runs) and throws a battery of theoretical
//! attacks at it, then reports which DEFENSES HELD. This is not the unit-test suite;
//! it is a red team you run on demand to answer "is the chain safe even with almost
//! no honest hashpower, against timewarp / forgery / a future quantum break / a lone
//! reorging miner / value inflation?".
//!
//! Semantics: each attack is judged DEFENDED (the chain rejected it or resolved it
//! correctly) or VULNERABLE (the attack succeeded — a real finding). Exit code is
//! non-zero if any attack is VULNERABLE, so CI / a release gate can consume it.
//!
//! Honest scope: we cannot run Shor's or Grover's algorithm, and we cannot forge a
//! BLAKE3 collision — no one can. What we CAN prove, and do, is that the chain FAILS
//! CLOSED: every forgery a classical attacker can produce is rejected, the PoW seal
//! binds every header field, and the hybrid signature needs BOTH halves — so a future
//! break of Ed25519 ALONE still leaves ML-DSA-65 (FIPS-204) stopping the forgery.

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::{Keypair, Signature};
use sov_mining::{Difficulty, MiningPolicy, Target, Work};
use sov_primitives::{AccountId, Balance};
use sov_types::{Action, Block, SignedTransaction, Transaction};

/// Live-fire front-door probe: attack a REAL running node over JSON-RPC.
pub mod live;
pub use live::{any_vulnerable as live_any_vulnerable, probe_frontdoor, LiveReport};

/// Live-fire back-door probe: join the P2P network as a hostile peer and gossip forgeries.
pub mod backdoor;
pub use backdoor::{any_vulnerable as backdoor_any_vulnerable, probe_backdoor, P2pReport};

/// The Gauntlet probe: attack the live steal-the-pot account every key-less way.
pub mod gauntlet;
pub use gauntlet::{
    any_vulnerable as gauntlet_any_vulnerable, probe_gauntlet, GauntletReport, POT,
};

/// Funded-adversary probe: attack the live chain AS a real, funded account.
pub mod funded;
pub use funded::{
    account_of, any_vulnerable as funded_any_vulnerable, keypair_from_secret, probe_funded,
    seed_from_secret, FundedReport,
};

// ── attack framework ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Defended,
    Vulnerable,
    Info,
}

/// One attack's result: which class it belongs to, its name, the verdict, and a
/// human-readable detail of how the defense held (or failed).
pub struct Outcome {
    pub category: &'static str,
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

impl Outcome {
    fn defended(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            category,
            name,
            verdict: Verdict::Defended,
            detail: detail.into(),
        }
    }
    fn vulnerable(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            category,
            name,
            verdict: Verdict::Vulnerable,
            detail: detail.into(),
        }
    }
    fn info(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            category,
            name,
            verdict: Verdict::Info,
            detail: detail.into(),
        }
    }
}

// ── chain builders ─────────────────────────────────────────────────────────

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// A fresh test chain: one miner (`val01`, key seed `[1; 32]`) and a funded account
/// (`usa.reserve.sov`, seed `[2; 32]`, 1000 SOV). Test mining policy = SHA-256d at low
/// difficulty, so blocks mine in milliseconds.
fn fresh_chain() -> Blockchain {
    let config = GenesisConfig {
        chain_id: "sov-redteam".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::from_seed([2; 32]).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    };
    Blockchain::new(&config).unwrap()
}

/// Mine `n` honest blocks onto `chain`, timestamps stepping by 2s. Returns the
/// timestamp of the last block so callers can craft "future"/"past" relative to it.
fn advance(chain: &mut Blockchain, n: u64) -> u64 {
    let mut ts = 2_000;
    for _ in 0..n {
        let block = chain
            .produce_block(vec![], ts)
            .expect("honest block produces");
        chain.import_block(block).expect("honest block imports");
        ts += 2_000;
    }
    ts - 2_000
}

/// True if importing `block` into a fresh chain advanced to `n` honest blocks is
/// REJECTED (the defense held). Isolates each tamper attack on its own chain.
fn rejected_on_fresh(prep: u64, block: Block) -> bool {
    let mut chain = fresh_chain();
    advance(&mut chain, prep);
    chain.import_block(block).is_err()
}

// ── the attacks ──────────────────────────────────────────────────────────────

/// TIME: timewarp — a miner backdates the timestamp to sit at/under the
/// median-time-past (BIP-113), cheating the difficulty retarget into easing off.
fn atk_timewarp_backdate() -> Outcome {
    let c = "time";
    let mut chain = fresh_chain();
    advance(&mut chain, 12);
    let mtp = chain.median_time_past();
    // A block that does NOT strictly exceed the median-time-past.
    match chain.produce_block(vec![], mtp) {
        Err(_) => Outcome::defended(
            c,
            "timewarp: backdate to MTP",
            "production refused a non-advancing timestamp",
        ),
        Ok(block) => {
            if chain.import_block(block).is_err() {
                Outcome::defended(
                    c,
                    "timewarp: backdate to MTP",
                    "import rejected timestamp ≤ median-time-past",
                )
            } else {
                Outcome::vulnerable(
                    c,
                    "timewarp: backdate to MTP",
                    "a block at/under MTP was ACCEPTED — retarget can be gamed",
                )
            }
        }
    }
}

/// TIME: EDA farming — a miner stamps its block as far in the future as it
/// dares, claiming a stall that never happened so the emergency difficulty
/// adjustment eases its required target. The defense is the CAP: the easing a
/// single block can claim is bounded at 2^EDA_MAX_HALVINGS — exactly what the
/// node-acceptance 2-hour future-drift rule tolerates anyway — and an eased
/// block carries proportionally less chain work, so an honestly-difficult
/// competitor still outweighs it. Verifies both: the cap holds for an absurd
/// future stamp, and the eased block cannot out-work an honest one.
fn atk_eda_future_farm() -> Outcome {
    let c = "time";
    let name = "EDA farming: future-stamp for easier difficulty";
    let mut chain = fresh_chain();
    advance(&mut chain, 12);
    // Cross into the EDA era, then demand the easing an ABSURD (year-scale)
    // future stamp yields. The claimable reduction must cap at EDA_MAX_HALVINGS.
    // Compact-grid canonical form of a target, as consensus stores/compares it.
    let canonical =
        |t: Target| Target::from_compact(t.to_compact()).expect("canonical target decodes");
    let year_ms: u64 = 365 * 24 * 60 * 60 * 1000;
    let far_future = sov_chain::EDA_ACTIVATION_MS + year_ms;
    let Ok(block) = chain.produce_block(vec![], far_future) else {
        return Outcome::defended(c, name, "production refused the future stamp");
    };
    let honest = Difficulty::from_target(canonical(MiningPolicy::test().sha256d_target)).0;
    let claimed =
        Difficulty::from_target(Target::from_compact(block.header.bits).expect("bits decode")).0;
    let floor = (honest >> sov_mining::EDA_MAX_HALVINGS).max(1);
    if claimed < floor {
        return Outcome::vulnerable(
            c,
            name,
            "a future stamp eased difficulty PAST the EDA cap — unbounded farming",
        );
    }
    // The eased block must also carry LESS work than an honest-difficulty block,
    // so fork choice cannot be gamed by farming easings.
    let eased_work = Work::of_target(&Target::from_compact(block.header.bits).unwrap());
    let honest_work = Work::of_target(&canonical(MiningPolicy::test().sha256d_target));
    if eased_work >= honest_work {
        return Outcome::vulnerable(
            c,
            name,
            "an EDA-eased block claims >= the honest chain work — fork choice gameable",
        );
    }
    Outcome::defended(
        c,
        name,
        "easing capped at 2^EDA_MAX_HALVINGS and eased work weighs proportionally less",
    )
}

/// TIME: a timestamp far in the past (before genesis) must never be accepted.
fn atk_timewarp_far_past() -> Outcome {
    let c = "time";
    let mut chain = fresh_chain();
    advance(&mut chain, 8);
    match chain.produce_block(vec![], 1) {
        Err(_) => Outcome::defended(
            c,
            "timewarp: pre-genesis stamp",
            "production refused a pre-genesis timestamp",
        ),
        Ok(block) => {
            if chain.import_block(block).is_err() {
                Outcome::defended(
                    c,
                    "timewarp: pre-genesis stamp",
                    "import rejected a pre-genesis timestamp",
                )
            } else {
                Outcome::vulnerable(
                    c,
                    "timewarp: pre-genesis stamp",
                    "a block timestamped before genesis was ACCEPTED",
                )
            }
        }
    }
}

/// Tamper one header field AFTER the block is validly sealed, then import. The PoW
/// seal is computed over the whole header, so ANY change must invalidate the seal
/// (or trip an explicit rule) — proving the seal binds that field.
fn atk_tamper_header(name: &'static str, mutate: impl Fn(&mut Block)) -> Outcome {
    let c = "tamper";
    let mut chain = fresh_chain();
    advance(&mut chain, 5);
    let mut block = chain
        .produce_block(vec![], 20_000)
        .expect("seal a valid block");
    mutate(&mut block);
    if rejected_on_fresh(5, block) {
        Outcome::defended(c, name, "seal/rule rejected the tampered header")
    } else {
        Outcome::vulnerable(c, name, "a tampered header was ACCEPTED")
    }
}

/// SUPPLY / coinbase theft: redirect the block reward to an attacker by rewriting
/// `proposer` after sealing. Must be rejected (the seal covers the proposer).
fn atk_coinbase_redirect() -> Outcome {
    atk_tamper_header("coinbase: redirect reward", |b| {
        b.header.proposer = id("attacker.evil.sov");
    })
}

/// FORGERY: corrupt a valid transaction signature — verification must fail closed.
fn atk_forged_tx_signature() -> Outcome {
    let c = "forgery";
    // Mainnet keys are HYBRID (Ed25519 + ML-DSA-65) — build + sign accordingly.
    let kp = Keypair::hybrid_from_seed([9; 32]);
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: id("val01.node.sov"),
            amount: Balance::from_sov(1).unwrap(),
        },
    };
    let mut stx = SignedTransaction::sign(tx, &kp).unwrap();
    // Flip a byte in the Ed25519 half of the hybrid signature.
    stx.signature = tamper_signature(stx.signature, Half::Ed25519);
    if !stx.verify_signature() {
        Outcome::defended(
            c,
            "forged tx signature",
            "verification failed closed on a corrupted signature",
        )
    } else {
        Outcome::vulnerable(c, "forged tx signature", "a corrupted signature VERIFIED")
    }
}

/// POST-QUANTUM: the hybrid signature is a CONJUNCTION — Ed25519 AND ML-DSA-65 must
/// both verify. Simulate a future world where the attacker has broken Ed25519 (they
/// produce a valid Ed25519 half) but NOT ML-DSA-65: tamper ONLY the ML-DSA half and
/// prove verification still fails. The post-quantum half is load-bearing.
fn atk_hybrid_pq_conjunction() -> Outcome {
    let c = "post-quantum";
    let kp = Keypair::hybrid_from_seed([2; 32]);
    let msg = b"the treasury pays the bearer";
    let sig = kp.sign(msg);
    // Keep the (valid) Ed25519 half; corrupt only the ML-DSA-65 half.
    let tampered = tamper_signature(sig, Half::MlDsa);
    if !kp.public_key().verify(msg, &tampered) {
        Outcome::defended(
            c,
            "hybrid conjunction (Ed25519 break ⇒ ML-DSA holds)",
            "a valid Ed25519 half with a broken ML-DSA half was REJECTED",
        )
    } else {
        Outcome::vulnerable(
            c,
            "hybrid conjunction (Ed25519 break ⇒ ML-DSA holds)",
            "signature verified with a broken ML-DSA half — PQ half is NOT enforced",
        )
    }
}

/// REPLAY: importing the very same sealed block twice must not advance the chain
/// twice (no duplicate credit of the coinbase).
fn atk_duplicate_block() -> Outcome {
    let c = "replay";
    let mut chain = fresh_chain();
    advance(&mut chain, 4);
    let block = chain.produce_block(vec![], 12_000).expect("seal");
    chain
        .import_block(block.clone())
        .expect("first import commits");
    let h = chain.height();
    let second = chain.import_block(block);
    if second.is_err() || chain.height() == h {
        Outcome::defended(
            c,
            "duplicate block import",
            "re-importing the same block did not double-advance",
        )
    } else {
        Outcome::vulnerable(
            c,
            "duplicate block import",
            "the same block was imported twice",
        )
    }
}

/// LOW-HASHPOWER CONSENSUS: two competing blocks of EQUAL work at the same height
/// must resolve to the SAME tip on every node regardless of arrival order — a
/// deterministic tie-break (smaller block hash = more PoW). Otherwise equal-work
/// miners fork forever, which is fatal when honest hashpower is thin.
fn atk_equal_work_tiebreak() -> Outcome {
    let c = "consensus";
    // Two forks that share the same parent but differ (distinct timestamps ⇒
    // distinct block hashes, equal work at the same height/difficulty).
    let mut base = fresh_chain();
    advance(&mut base, 3);
    let block_a = base.produce_block(vec![], 10_000).expect("fork A");
    let block_b = base.produce_block(vec![], 10_500).expect("fork B");
    if block_a.header.tx_root == block_b.header.tx_root && block_a.hash() == block_b.hash() {
        return Outcome::info(
            c,
            "equal-work tie-break",
            "could not construct two distinct competitors",
        );
    }
    // Import A-then-B on one node, B-then-A on another; both must agree on the tip.
    let mut node1 = fresh_chain();
    advance(&mut node1, 3);
    let _ = node1.import_block(block_a.clone());
    let _ = node1.import_block(block_b.clone());
    let mut node2 = fresh_chain();
    advance(&mut node2, 3);
    let _ = node2.import_block(block_b);
    let _ = node2.import_block(block_a);
    if node1.head().hash() == node2.head().hash() {
        Outcome::defended(
            c,
            "equal-work tie-break",
            "both arrival orders converged on the same tip (deterministic)",
        )
    } else {
        Outcome::vulnerable(
            c,
            "equal-work tie-break",
            "arrival order changed the tip — equal-work miners can fork",
        )
    }
}

// ── signature tampering helper ───────────────────────────────────────────────

enum Half {
    Ed25519,
    MlDsa,
}

/// Flip a byte in one half of a hybrid signature, returning the corrupted sig.
fn tamper_signature(sig: Signature, half: Half) -> Signature {
    match sig {
        Signature::V2HybridMlDsa65 {
            mut ed25519,
            mut ml_dsa,
        } => {
            match half {
                Half::Ed25519 => ed25519[0] ^= 0xff,
                Half::MlDsa => ml_dsa[0] ^= 0xff,
            }
            Signature::V2HybridMlDsa65 { ed25519, ml_dsa }
        }
        other => other,
    }
}

// ── runner ───────────────────────────────────────────────────────────────────

// ── forged / malicious transactions ─────────────────────────────────────────

/// A signed transfer from `signer` (an account bound to key seed `seed`) at `nonce`,
/// moving `amount` to `to`, signed by the account's own key.
fn transfer(signer: &str, seed: u8, nonce: u64, to: &str, amount: Balance) -> SignedTransaction {
    let kp = Keypair::from_seed([seed; 32]);
    let tx = Transaction {
        signer: id(signer),
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer { to: id(to), amount },
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

/// True if the chain REFUSES to commit `tx` in a valid block — it is excluded during
/// block selection, or the block that includes it fails strict import. This is the bar
/// every fudged transaction must clear.
fn tx_refused(tx: SignedTransaction) -> bool {
    let mut chain = fresh_chain();
    advance(&mut chain, 3);
    let Ok(block) = chain.produce_block(vec![tx.clone()], 100_000) else {
        return true;
    };
    let landed = block.transactions.iter().any(|t| t.id() == tx.id());
    !landed || chain.import_block(block).is_err()
}

/// True if, after mining + importing a block containing `tx`, `recipient`'s balance is
/// UNCHANGED — i.e. the transfer created no value. A failed transfer (overspend,
/// overflow) is mined but reverts (Ethereum-style: nonce consumed, state untouched), so
/// the correct defense to check is that no funds actually moved, not that the tx was
/// kept out of the block.
fn value_did_not_move(tx: SignedTransaction, recipient: &AccountId) -> bool {
    let mut chain = fresh_chain();
    advance(&mut chain, 3);
    let before = chain.ledger().account(recipient).balance.grains();
    let Ok(block) = chain.produce_block(vec![tx], 100_000) else {
        return true;
    };
    if chain.import_block(block).is_err() {
        return true;
    }
    chain.ledger().account(recipient).balance.grains() == before
}

/// A tx from `usa.reserve.sov` (1000 SOV) transferring `amount` to a fresh sink account
/// (balance 0, never the coinbase), for value-movement checks.
fn overspend_tx(amount: Balance) -> (SignedTransaction, AccountId) {
    let sink = Keypair::from_seed([7; 32])
        .public_key()
        .implicit_account_id();
    let kp = Keypair::from_seed([2; 32]);
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: sink.clone(),
            amount,
        },
    };
    (SignedTransaction::sign(tx, &kp).unwrap(), sink)
}

/// FORGERY: spend more than the account holds. A failed transfer is still mined but
/// reverts — the defense is that no funds move.
fn atk_tx_overspend() -> Outcome {
    let c = "forgery";
    let (tx, sink) = overspend_tx(Balance::from_sov(10_000).unwrap()); // holds 1000
    if value_did_not_move(tx, &sink) {
        Outcome::defended(
            c,
            "overspend (send > balance)",
            "transfer FAILED — no funds moved (nonce consumed, reverted)",
        )
    } else {
        Outcome::vulnerable(
            c,
            "overspend (send > balance)",
            "over-balance funds were actually credited",
        )
    }
}

/// FORGERY: an astronomically large amount (~u128::MAX) to probe integer overflow in
/// the balance/fee arithmetic.
fn atk_tx_overflow() -> Outcome {
    let c = "forgery";
    let (tx, sink) = overspend_tx(Balance::from_grains(u128::MAX));
    if value_did_not_move(tx, &sink) {
        Outcome::defended(
            c,
            "amount overflow (~u128::MAX)",
            "checked arithmetic — transfer failed, no funds moved",
        )
    } else {
        Outcome::vulnerable(
            c,
            "amount overflow (~u128::MAX)",
            "an overflowing transfer credited the recipient",
        )
    }
}

/// FORGERY: impersonate an account by signing with a key that is not its own.
fn atk_tx_wrong_key() -> Outcome {
    let c = "forgery";
    let attacker = Keypair::from_seed([9; 32]); // NOT usa.reserve.sov's key (seed 2)
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: attacker.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to: id("val01.node.sov"),
            amount: Balance::from_sov(1).unwrap(),
        },
    };
    let stx = SignedTransaction::sign(tx, &attacker).unwrap();
    if tx_refused(stx) {
        Outcome::defended(
            c,
            "impersonation (wrong signing key)",
            "excluded — key is not the account's",
        )
    } else {
        Outcome::vulnerable(
            c,
            "impersonation (wrong signing key)",
            "a spend by the wrong key was committed",
        )
    }
}

/// FORGERY: edit the amount AFTER signing (signature malleability).
fn atk_tx_malleability() -> Outcome {
    let c = "forgery";
    let mut stx = transfer(
        "usa.reserve.sov",
        2,
        0,
        "val01.node.sov",
        Balance::from_sov(1).unwrap(),
    );
    stx.transaction.action = Action::Transfer {
        to: id("val01.node.sov"),
        amount: Balance::from_sov(500).unwrap(), // bumped 1 -> 500 after signing
    };
    if !stx.verify_signature() {
        Outcome::defended(
            c,
            "malleability (edit amount after sign)",
            "failed closed — the signature binds the amount",
        )
    } else {
        Outcome::vulnerable(
            c,
            "malleability (edit amount after sign)",
            "a post-signing edit still verified",
        )
    }
}

/// REPLAY: re-submit an already-mined transaction (its nonce is spent).
fn atk_tx_replay() -> Outcome {
    let c = "replay";
    let mut chain = fresh_chain();
    advance(&mut chain, 3);
    let tx = transfer(
        "usa.reserve.sov",
        2,
        0,
        "val01.node.sov",
        Balance::from_sov(1).unwrap(),
    );
    if let Ok(b) = chain.produce_block(vec![tx.clone()], 100_000) {
        let _ = chain.import_block(b); // nonce 0 now spent
    }
    let Ok(b2) = chain.produce_block(vec![tx.clone()], 200_000) else {
        return Outcome::defended(
            c,
            "transaction replay (reuse spent nonce)",
            "producer refused to rebuild with it",
        );
    };
    let landed = b2.transactions.iter().any(|t| t.id() == tx.id());
    if !landed {
        Outcome::defended(
            c,
            "transaction replay (reuse spent nonce)",
            "excluded — nonce is enforced",
        )
    } else {
        Outcome::vulnerable(
            c,
            "transaction replay (reuse spent nonce)",
            "a spent transaction was mined twice",
        )
    }
}

/// FLOOD: submit a huge batch of valid transactions; the elastic block-size cap must
/// bound the block regardless of demand (a flood can't create an unbounded block).
fn atk_tx_flood() -> Outcome {
    let c = "flood";
    let mut chain = fresh_chain();
    advance(&mut chain, 3);
    let flood: Vec<SignedTransaction> = (0..20_000u64)
        .map(|n| {
            transfer(
                "usa.reserve.sov",
                2,
                n,
                "val01.node.sov",
                Balance::from_grains(1),
            )
        })
        .collect();
    let submitted = flood.len();
    let Ok(block) = chain.produce_block(flood, 100_000) else {
        return Outcome::defended(
            c,
            "mempool tx flood (20k txs)",
            "producer refused to build under the flood",
        );
    };
    let included = block.transactions.len();
    let valid = chain.import_block(block).is_ok();
    if included < submitted && valid {
        Outcome::defended(
            c,
            "mempool tx flood (20k txs)",
            format!(
                "block capped at {included}/{submitted} txs — elastic size cap held; block valid"
            ),
        )
    } else if !valid {
        Outcome::defended(
            c,
            "mempool tx flood (20k txs)",
            "an over-full block was rejected on import",
        )
    } else {
        Outcome::vulnerable(
            c,
            "mempool tx flood (20k txs)",
            format!("all {submitted} txs entered one block — no cap"),
        )
    }
}

/// Run the full adversarial battery against a fresh in-process chain and return
/// every attack's [`Outcome`], grouped by class in a stable order. Pure + in-process:
/// a GUI (SOV Station's Red Team tab) or the CLI can both call this and render the
/// results however they like. No I/O, no process exit — the caller decides.
pub fn run_all() -> Vec<Outcome> {
    vec![
        atk_timewarp_backdate(),
        atk_timewarp_far_past(),
        atk_eda_future_farm(),
        atk_tamper_header("tamper: state_root", |b| {
            b.header.state_root = flip_hash(b.header.state_root)
        }),
        atk_tamper_header("tamper: tx_root", |b| {
            b.header.tx_root = flip_hash(b.header.tx_root)
        }),
        atk_tamper_header("tamper: timestamp (post-seal)", |b| {
            b.header.timestamp_ms ^= 0x5555
        }),
        atk_tamper_header("tamper: nonce (break PoW)", |b| {
            b.header.nonce ^= 0xdead_beef
        }),
        atk_tamper_header("tamper: bits (claim easier target)", |b| {
            b.header.bits = b.header.bits.wrapping_add(1)
        }),
        atk_tamper_header("tamper: prev_hash (wrong parent)", |b| {
            b.header.prev_hash = flip_hash(b.header.prev_hash)
        }),
        atk_coinbase_redirect(),
        // forgery — fudged transactions
        atk_forged_tx_signature(),
        atk_tx_malleability(),
        atk_tx_wrong_key(),
        atk_tx_overspend(),
        atk_tx_overflow(),
        // post-quantum
        atk_hybrid_pq_conjunction(),
        // replay
        atk_duplicate_block(),
        atk_tx_replay(),
        // consensus
        atk_equal_work_tiebreak(),
        // flood / DoS
        atk_tx_flood(),
    ]
}

/// Flip the first byte of a 32-byte hash to corrupt it deterministically.
fn flip_hash(h: sov_primitives::Hash) -> sov_primitives::Hash {
    let mut bytes = *h.as_bytes();
    bytes[0] ^= 0xff;
    sov_primitives::Hash::from_bytes(bytes)
}
