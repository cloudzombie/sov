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
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance};
use sov_types::{Action, Block, SignedTransaction, Transaction};

// ── attack framework ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Verdict {
    Defended,
    Vulnerable,
    Info,
}

struct Outcome {
    category: &'static str,
    name: &'static str,
    verdict: Verdict,
    detail: String,
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

/// A fresh test chain: one miner (`val01`, key seed [1]) and a funded account
/// (`usa.reserve.sov`, seed [2], 1000 SOV). Test mining policy = SHA-256d at low
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

fn main() {
    println!("\n  sov-redteam — adversarial harness for the SOV chain");
    println!("  building a real in-process chain and attacking consensus…\n");

    let outcomes: Vec<Outcome> = vec![
        atk_timewarp_backdate(),
        atk_timewarp_far_past(),
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
        atk_forged_tx_signature(),
        atk_hybrid_pq_conjunction(),
        atk_duplicate_block(),
        atk_equal_work_tiebreak(),
    ];

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

/// Flip the first byte of a 32-byte hash to corrupt it deterministically.
fn flip_hash(h: sov_primitives::Hash) -> sov_primitives::Hash {
    let mut bytes = *h.as_bytes();
    bytes[0] ^= 0xff;
    sov_primitives::Hash::from_bytes(bytes)
}
