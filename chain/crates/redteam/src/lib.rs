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

// The steal-the-pot sweep constructs the full Action surface, whose variants name
// these types; they are exercised only by the in-process tests, so gate the imports.
#[cfg(test)]
use sov_compliance::CompliancePolicy;
#[cfg(test)]
use sov_intents::{Asset, Intent, Settlement};
#[cfg(test)]
use sov_primitives::Hash;
#[cfg(test)]
use sov_types::MultisigApproval;

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

// ── foreign-chain injection ─────────────────────────────────────────────────
//
// The class: "build your own chain and try to spend it onto the honest chain."
// An attacker can always mint a private universe — its own genesis, its own
// balances, its own (fabricated) proof of work — for free. The only thing that
// matters is whether ANY artifact of that universe (a block, a transaction, a
// heavier-looking branch) can cross over onto a chain that never agreed to it.

/// The attacker's key. Its IMPLICIT account id (`hex(blake3(pubkey))`) is
/// cryptographically bound to the key on EVERY chain, so the attacker genuinely
/// controls the same account name on the honest chain too — the interesting case.
/// Nothing about the identity is forged; only the BALANCE is, and only on the
/// attacker's own chain.
const ATTACKER_SEED: [u8; 32] = [42; 32];

/// The attacker's account id: implicit, key-bound, identical on both chains.
fn attacker_account() -> AccountId {
    Keypair::from_seed(ATTACKER_SEED)
        .public_key()
        .implicit_account_id()
}

/// The attacker's OWN chain: a different `chain_id` (⇒ a different genesis hash),
/// same test mining policy (so its blocks carry REAL PoW under that policy), and
/// an attacker account minted 1,000,000 SOV out of thin air in ITS genesis. This
/// is exactly what an adversary can build on a laptop in one second, for free.
fn attacker_chain() -> Blockchain {
    let config = GenesisConfig {
        chain_id: "sov-attacker".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: attacker_account(),
                key: Keypair::from_seed(ATTACKER_SEED).public_key(),
                balance: Balance::from_sov(1_000_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    };
    Blockchain::new(&config).unwrap()
}

/// A fresh sink account (implicit, zero balance, never a coinbase recipient) that
/// receives the attacker's fabricated value, so "did value move?" is unambiguous.
fn sink_account(seed: u8) -> AccountId {
    Keypair::from_seed([seed; 32])
        .public_key()
        .implicit_account_id()
}

/// FOREIGN-CHAIN: import a block mined on a chain with a DIFFERENT GENESIS.
///
/// The attacker mines a real, fully-sealed block on its own chain (real PoW under
/// the test policy — nothing about the block is malformed) and offers it to an
/// honest node. Its `prev_hash` is the attacker's genesis, a hash the honest chain
/// has never seen, so the block cannot connect to any known parent. Acceptance
/// would mean an honest node adopting a stranger's history wholesale.
fn atk_foreign_genesis_block_import() -> Outcome {
    let c = "foreign-chain";
    let name = "import a block from a foreign genesis";
    let mut evil = attacker_chain();
    let Ok(evil_block) = evil.produce_block(vec![], 2_000) else {
        return Outcome::info(c, name, "could not seal a block on the attacker chain");
    };
    evil.import_block(evil_block.clone())
        .expect("the attacker's own chain accepts its own block");
    // Sanity: the two chains really do disagree about genesis.
    let mut honest = fresh_chain();
    if honest.head().hash() == evil_block.header.prev_hash {
        return Outcome::info(
            c,
            name,
            "the two genesis blocks collided — no foreign parent",
        );
    }
    let before = honest.head().hash();
    match honest.import_block(evil_block) {
        Err(err) => {
            if honest.head().hash() != before {
                return Outcome::vulnerable(
                    c,
                    name,
                    "the foreign block was rejected but still moved the tip",
                );
            }
            Outcome::defended(
                c,
                name,
                format!("rejected ({err:?}) — its parent is the ATTACKER's genesis, unknown here"),
            )
        }
        Ok(_) => Outcome::vulnerable(
            c,
            name,
            "a block from a foreign genesis was ACCEPTED — histories are interchangeable",
        ),
    }
}

/// FOREIGN-CHAIN: the literal "spend it onto mainnet" attack.
///
/// The attacker prints itself 1,000,000 SOV on its own chain, spends it there for
/// real (mined + imported, recipient credited — proof the transaction is VALID in
/// its universe), then lifts that SAME signed transaction onto the honest chain.
/// Two independent defenses can fire: the account holds ZERO here (the transfer
/// reverts, moving nothing), and — once the `tx-domain` fork is active — the
/// signature is bound to the attacker's (chain_id, genesis) and fails outright.
/// We report which one actually did the work.
fn atk_extract_tx_from_foreign_chain() -> Outcome {
    let c = "foreign-chain";
    let name = "spend a foreign-chain balance onto the honest chain";
    let kp = Keypair::from_seed(ATTACKER_SEED);
    let attacker = attacker_account();
    let victim = sink_account(11);
    let amount = Balance::from_sov(500_000).unwrap();
    let tx = SignedTransaction::sign(
        Transaction {
            signer: attacker.clone(),
            public_key: kp.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: victim.clone(),
                amount,
            },
        },
        &kp,
    )
    .unwrap();

    // 1. Prove the transaction is genuinely VALID on the attacker's chain.
    let mut evil = attacker_chain();
    advance(&mut evil, 3);
    let Ok(evil_block) = evil.produce_block(vec![tx.clone()], 100_000) else {
        return Outcome::info(
            c,
            name,
            "the attacker chain refused to build with its own tx",
        );
    };
    if evil.import_block(evil_block).is_err()
        || evil.ledger().account(&victim).balance.grains() != amount.grains()
    {
        return Outcome::info(
            c,
            name,
            "could not establish the transaction as valid on the attacker chain",
        );
    }

    // 2. Offer that identical transaction to the honest chain.
    let mut honest = fresh_chain();
    advance(&mut honest, 3);
    let held = honest.ledger().account(&attacker).balance.grains();
    let before = honest.ledger().account(&victim).balance.grains();
    let domain_bound = honest.resolved_tx_domain(honest.height() + 1).is_some();
    let Ok(block) = honest.produce_block(vec![tx.clone()], 100_000) else {
        return Outcome::defended(
            c,
            name,
            "the honest producer refused to build with the foreign transaction",
        );
    };
    let landed = block.transactions.iter().any(|t| t.id() == tx.id());
    let imported = honest.import_block(block).is_ok();
    let after = honest.ledger().account(&victim).balance.grains();
    if after != before {
        return Outcome::vulnerable(
            c,
            name,
            format!(
                "foreign-minted value CREDITED on the honest chain (+{} grains)",
                after - before
            ),
        );
    }
    let defense = if !landed {
        "excluded at block selection"
    } else if !imported {
        "the block carrying it failed strict import"
    } else {
        "mined but REVERTED"
    };
    let domain = if domain_bound {
        "tx-domain active: the signature is also bound to the attacker's (chain_id, genesis)"
    } else {
        "tx-domain dormant here, so BALANCE is the live defense: the attacker holds nothing"
    };
    Outcome::defended(
        c,
        name,
        format!("{defense} — attacker balance {held} grains on this chain; {domain}"),
    )
}

/// FOREIGN-CHAIN: a rival branch claiming work it never did.
///
/// This targets the assumevalid PoW-skip directly. A checkpoint is pinned ABOVE
/// the tip (exactly as mainnet bakes one), and the attacker offers a branch of
/// blocks that sit BELOW that checkpoint height but descend from nothing pinned —
/// their seals do not meet target at all. Under a HEIGHT-gated skip every one of
/// them would be waved through, and a free branch could out-weigh the honest
/// chain. Under the ANCESTRY gate (`is_linked_to_checkpoint`, blockchain.rs:2187)
/// an unlinked block gets its seal verified like any other, and fabricated PoW
/// fails.
fn atk_fabricated_heavier_branch() -> Outcome {
    let c = "foreign-chain";
    let name = "fabricated-PoW branch under a checkpoint";
    // A scratch chain (identical genesis) supplies well-formed, correctly-retargeted
    // blocks; we then break each seal, so the ONLY thing wrong is the proof of work.
    let mut scratch = fresh_chain();
    advance(&mut scratch, 5);
    let mut branch = Vec::new();
    let mut ts = 20_000;
    for _ in 0..3 {
        let Ok(b) = scratch.produce_block(vec![], ts) else {
            return Outcome::info(c, name, "could not build the branch blocks");
        };
        scratch.import_block(b.clone()).expect("scratch extends");
        let mut fake = b;
        fake.header.nonce ^= 0xdead_beef; // seal no longer meets target
        branch.push(fake);
        ts += 2_000;
    }

    let mut honest = fresh_chain();
    advance(&mut honest, 5);
    // Pin a checkpoint FAR above the tip — the height-gated skip's whole surface.
    honest.add_checkpoints([(100_000, flip_hash(honest.head().hash()))]);
    let tip = honest.head().hash();
    let first = branch[0].clone();
    if honest.is_linked_to_checkpoint(&first.hash()) {
        return Outcome::info(
            c,
            name,
            "the fabricated block was (impossibly) proven checkpoint-linked",
        );
    }
    let mut accepted = 0usize;
    let mut reason = String::new();
    for b in branch {
        match honest.import_block(b) {
            Ok(_) => accepted += 1,
            Err(err) => {
                if reason.is_empty() {
                    reason = format!("{err:?}");
                }
            }
        }
    }
    if accepted > 0 || honest.head().hash() != tip {
        return Outcome::vulnerable(
            c,
            name,
            format!("{accepted} fabricated-PoW block(s) below the checkpoint were ACCEPTED — the assumevalid skip is height-gated"),
        );
    }
    Outcome::defended(
        c,
        name,
        format!(
            "rejected ({reason}) — the PoW skip is ancestry-gated (is_linked_to_checkpoint), \
             not height-gated, so a fabricated branch gets full PoW verification and fails"
        ),
    )
}

/// FOREIGN-CHAIN: spend on the honest chain, then try to erase it privately.
///
/// The attacker pays a victim, lets it confirm, then reveals a branch it built in
/// private from BEFORE the payment, omitting it. Fork choice is heaviest-WORK, and
/// a LIGHTER branch cannot move the tip: the payment stands. Reversal is not a
/// protocol trick here, it is a hashpower purchase. (We do not fake extra
/// hashpower — that is the point.)
///
/// We then push the honest case one notch further and reveal an EQUAL-work branch,
/// because that is where SOV differs from first-seen Bitcoin: at exactly equal
/// cumulative work the tip is chosen by SMALLER TIP HASH (`import_block_tracked`,
/// the convergence rule that stops equal-work miners fork-warring forever). That
/// rule is deliberate, but it means an attacker who MATCHES the honest chain's
/// work over the reorg span — and who can grind extra seals and publish the one
/// with the smallest hash — reverses the payment deterministically rather than
/// with 50% luck. That is reported as INFO, not as a green: it is a real property
/// at the parity boundary, and it costs the attacker the full honest work.
fn atk_private_reorg_double_spend() -> Outcome {
    let c = "foreign-chain";
    let name = "private branch double-spend (reorg out a confirmed payment)";
    let victim = sink_account(12);
    let amount = Balance::from_sov(250).unwrap();
    let kp = Keypair::from_seed([2; 32]);
    let pay = SignedTransaction::sign(
        Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: victim.clone(),
                amount,
            },
        },
        &kp,
    )
    .unwrap();

    // Honest chain: 3 blocks (the shared prefix), then the payment, then 2
    // confirmations on top of it.
    let mut honest = fresh_chain();
    advance(&mut honest, 3);
    let fork_point = honest.head().hash();
    let Ok(pay_block) = honest.produce_block(vec![pay.clone()], 8_000) else {
        return Outcome::info(c, name, "could not mine the payment");
    };
    if honest.import_block(pay_block).is_err() {
        return Outcome::info(c, name, "the payment block did not import");
    }
    let paid = honest.ledger().account(&victim).balance.grains();
    if paid != amount.grains() {
        return Outcome::info(c, name, "the payment did not credit the victim");
    }
    for ts in [10_000u64, 12_000] {
        let b = honest.produce_block(vec![], ts).expect("confirmation");
        honest.import_block(b).expect("confirmation imports");
    }
    let honest_tip = honest.head().hash();
    let honest_work = honest.chain_work();

    // The PRIVATE branch: same genesis, same shared prefix (block production is
    // deterministic, so replaying the first 3 blocks reproduces them exactly),
    // then blocks that OMIT the payment. It is built with real work — just not
    // MORE of it than the honest chain has.
    let mut private = fresh_chain();
    advance(&mut private, 3);
    if private.head().hash() != fork_point {
        return Outcome::info(c, name, "could not reproduce the shared prefix");
    }
    let mut hidden = Vec::new();
    let mut ts = 8_500;
    for _ in 0..2 {
        let Ok(b) = private.produce_block(vec![], ts) else {
            return Outcome::info(c, name, "could not build the private branch");
        };
        private.import_block(b.clone()).expect("private extends");
        hidden.push(b);
        ts += 2_000;
    }
    if private.chain_work() >= honest_work {
        return Outcome::info(
            c,
            name,
            "the private branch was not lighter — the work premise did not hold",
        );
    }
    // Reveal it.
    for b in hidden {
        let _ = honest.import_block(b);
    }
    let still_paid = honest.ledger().account(&victim).balance.grains() == paid;
    if honest.head().hash() == honest_tip && still_paid {
        // The lighter branch failed. Now the parity case: one more private block,
        // making the hidden branch EQUAL in work to the honest chain.
        let equal_work_reversed = private_branch_at_parity();
        if equal_work_reversed {
            return Outcome::info(
                c,
                name,
                "a LIGHTER private branch cannot reorg out a confirmed payment (heaviest-work \
                 fork choice held); an EQUAL-work branch did reverse it via the deterministic \
                 smaller-tip-hash tie-break — reversal still costs the attacker work equal to \
                 the honest chain's over the span (~parity hashpower), but at parity it is \
                 deterministic, not a coin flip",
            );
        }
        Outcome::defended(
            c,
            name,
            "fork choice is heaviest-work: a private branch without MORE real work \
             cannot reorg out a confirmed payment (equal-work branch did not reverse it either)",
        )
    } else if !still_paid {
        Outcome::vulnerable(
            c,
            name,
            "a lighter private branch REVERSED a confirmed payment — double-spend for free",
        )
    } else {
        Outcome::vulnerable(
            c,
            name,
            "a lighter private branch replaced the tip — fork choice is not work-ordered",
        )
    }
}

/// The parity case of [`atk_private_reorg_double_spend`]: the same confirmed
/// payment, against a private branch of EQUAL cumulative work (same length, same
/// per-block difficulty). Returns true if the payment was actually reversed —
/// i.e. real fork choice adopted the hidden branch on the tie-break. Drives the
/// same real `produce_block` / `import_block` path; nothing is simulated.
fn private_branch_at_parity() -> bool {
    let victim = sink_account(13);
    let amount = Balance::from_sov(250).unwrap();
    let kp = Keypair::from_seed([2; 32]);
    let Ok(pay) = SignedTransaction::sign(
        Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: victim.clone(),
                amount,
            },
        },
        &kp,
    ) else {
        return false;
    };
    let mut honest = fresh_chain();
    advance(&mut honest, 3);
    let Ok(b) = honest.produce_block(vec![pay], 8_000) else {
        return false;
    };
    if honest.import_block(b).is_err() {
        return false;
    }
    let paid = honest.ledger().account(&victim).balance.grains();
    for ts in [10_000u64, 12_000] {
        let Ok(b) = honest.produce_block(vec![], ts) else {
            return false;
        };
        if honest.import_block(b).is_err() {
            return false;
        }
    }
    // Three hidden blocks against the honest chain's three post-fork blocks.
    let mut private = fresh_chain();
    advance(&mut private, 3);
    let mut hidden = Vec::new();
    let mut ts = 8_500;
    for _ in 0..3 {
        let Ok(b) = private.produce_block(vec![], ts) else {
            return false;
        };
        if private.import_block(b.clone()).is_err() {
            return false;
        }
        hidden.push(b);
        ts += 2_000;
    }
    if private.chain_work() != honest.chain_work() {
        return false; // not the parity case; nothing to report
    }
    for b in hidden {
        let _ = honest.import_block(b);
    }
    honest.ledger().account(&victim).balance.grains() != paid
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

// ── steal-the-pot: EXHAUSTIVE in-process sweep ───────────────────────────────
//
// The live Gauntlet (`gauntlet.rs`) attacks the real pot over RPC. This is its
// CI-runnable twin: a local chain where a pot-like keyless implicit account holds
// a balance, so the same theft attempts run through REAL consensus
// (`produce_block`/`import_block`, real signature + authorization verification)
// with no live node. The completeness guarantee lives here: EVERY `Action` variant
// is constructed as a pot-theft signed by an ATTACKER key and must be REJECTED with
// the pot's balance unchanged — no action type has a weak authorization path.

/// The pot's key seed. Hybrid (Ed25519 + ML-DSA-65), exactly like the mainnet pot,
/// so the post-quantum conjunction can be exercised with the pot's OWN key.
#[cfg(test)]
const POT_SEED: [u8; 32] = [77; 32];

/// The attacker's key seed for the sweep — anything that is NOT the pot's key.
#[cfg(test)]
const POT_ATTACKER_SEED: [u8; 32] = [88; 32];

/// The number of `Action` variants the sweep must cover. Bump this when a variant
/// is added — the coverage test (`every_action_variant_has_a_steal_attempt`) fails
/// until the new variant appears in [`every_pot_theft`], and [`action_kind`]'s
/// wildcard-free match fails to compile until it is named there too.
#[cfg(test)]
const ACTION_VARIANT_COUNT: usize = 33;

/// The pot account: a keyless IMPLICIT id (`id == blake3(pubkey)`), bound to the
/// pot key — the on-chain shape of the real steal-the-pot account.
#[cfg(test)]
fn pot_account() -> AccountId {
    Keypair::hybrid_from_seed(POT_SEED)
        .public_key()
        .implicit_account_id()
}

/// A chain like [`fresh_chain`] with a funded pot: the pot's implicit id holds 500
/// SOV under the pot's hybrid key. Same test mining policy, so blocks mine fast.
#[cfg(test)]
fn pot_chain() -> Blockchain {
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
                account: pot_account(),
                key: Keypair::hybrid_from_seed(POT_SEED).public_key(),
                balance: Balance::from_sov(500).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    };
    Blockchain::new(&config).unwrap()
}

/// Forge `action` DECLARED by the pot but signed by the attacker key — the
/// in-process twin of `gauntlet::forge`. The tx carries the attacker's key, so
/// authorization rejects it (that key's hash is not the pot's id).
#[cfg(test)]
fn pot_forgery(action: Action) -> SignedTransaction {
    let attacker = Keypair::hybrid_from_seed(POT_ATTACKER_SEED);
    let tx = Transaction {
        signer: pot_account(),
        public_key: attacker.public_key(),
        nonce: 0,
        action,
    };
    SignedTransaction::sign(tx, &attacker).unwrap()
}

/// The bar every pot-theft must clear on the real chain: mining + importing a block
/// carrying the forgery leaves the POT BALANCE UNCHANGED, and the forgery is
/// REJECTED (excluded at selection, or the block that includes it fails import). A
/// theft that is merely "mined but reverted" would still be a fail here IF it moved
/// a grain — so we assert on the balance, the thing that actually matters.
#[cfg(test)]
fn pot_theft_refused(action: Action) -> bool {
    let tx = pot_forgery(action);
    let mut chain = pot_chain();
    advance(&mut chain, 3);
    let pot = pot_account();
    let before = chain.ledger().account(&pot).balance.grains();
    let Ok(block) = chain.produce_block(vec![tx.clone()], 100_000) else {
        // The producer refused to build with it — no block, nothing moved.
        return true;
    };
    let landed = block.transactions.iter().any(|t| t.id() == tx.id());
    let imported = chain.import_block(block).is_ok();
    let after = chain.ledger().account(&pot).balance.grains();
    // Refused = the forgery never took effect (excluded, or its block bounced),
    // AND the pot balance did not move by a single grain.
    (!landed || !imported) && after == before
}

/// The kind of an [`Action`], as a compile-time EXHAUSTIVENESS GATE. The match has
/// no wildcard arm, so adding a new `Action` variant makes this fail to compile
/// until the variant is named here — the signal to also add its steal-attempt to
/// [`every_pot_theft`] and bump [`ACTION_VARIANT_COUNT`]. This is the mechanism
/// that stops a new action type from silently shipping without a theft test.
#[cfg(test)]
fn action_kind(a: &Action) -> &'static str {
    match a {
        Action::Transfer { .. } => "Transfer",
        Action::ClaimVesting => "ClaimVesting",
        Action::Deploy { .. } => "Deploy",
        Action::Call { .. } => "Call",
        Action::Shielded { .. } => "Shielded",
        Action::HtlcLock { .. } => "HtlcLock",
        Action::HtlcClaim { .. } => "HtlcClaim",
        Action::HtlcRefund { .. } => "HtlcRefund",
        Action::TokenIssue { .. } => "TokenIssue",
        Action::TokenTransfer { .. } => "TokenTransfer",
        Action::TokenBurn { .. } => "TokenBurn",
        Action::TokenSetPolicy { .. } => "TokenSetPolicy",
        Action::IntentSettle { .. } => "IntentSettle",
        Action::IntentCancel { .. } => "IntentCancel",
        Action::RotateKey { .. } => "RotateKey",
        Action::RegisterName { .. } => "RegisterName",
        Action::TransferName { .. } => "TransferName",
        Action::NftMint { .. } => "NftMint",
        Action::NftTransfer { .. } => "NftTransfer",
        Action::NftSetMeta { .. } => "NftSetMeta",
        Action::SetMultisig { .. } => "SetMultisig",
        Action::MultisigExec { .. } => "MultisigExec",
        Action::ProposeMultisig { .. } => "ProposeMultisig",
        Action::ApproveMultisig { .. } => "ApproveMultisig",
        Action::CancelMultisig { .. } => "CancelMultisig",
        Action::VaultDeposit { .. } => "VaultDeposit",
        Action::VaultMint { .. } => "VaultMint",
        Action::VaultBurn { .. } => "VaultBurn",
        Action::VaultWithdraw { .. } => "VaultWithdraw",
        Action::OracleUpdate { .. } => "OracleUpdate",
        Action::Tipped { .. } => "Tipped",
        Action::ShieldedV2 { .. } => "ShieldedV2",
        Action::Timestamped { .. } => "Timestamped",
    }
}

/// One pot-theft per `Action` variant — the complete steal surface. Every entry
/// names the pot as signer (built via [`pot_forgery`], attacker-signed) and tries
/// to move value or seize authority. Ids (`Hash::ZERO` assets/HTLCs/collections,
/// unregistered names) are placeholders: authorization refuses the attacker's
/// envelope long before any of them is consulted.
#[cfg(test)]
fn every_pot_theft() -> Vec<Action> {
    let attacker = Keypair::hybrid_from_seed(POT_ATTACKER_SEED);
    let sink = sink_account(200);
    let whole = Balance::from_sov(500).unwrap();
    let drain = Action::Transfer {
        to: sink.clone(),
        amount: whole,
    };
    // An attacker-signed intent naming the pot as owner (the H001 bypass class).
    let intent = Intent {
        owner: pot_account(),
        public_key: attacker.public_key(),
        nonce: 0,
        give_asset: Asset::Sov,
        give_amount: whole.grains(),
        want_asset: Asset::Sov,
        min_receive: 0,
        expiry_height: u64::MAX,
    };
    let signed_intent = intent.clone().sign(&attacker).unwrap();
    vec![
        drain.clone(),
        Action::ClaimVesting,
        Action::Deploy { code: vec![0; 8] },
        Action::Call {
            contract: pot_account(),
            gas_limit: 1,
            calldata: vec![],
        },
        Action::Shielded { bundle: vec![0; 8] },
        Action::HtlcLock {
            recipient: sink.clone(),
            amount: whole,
            hashlock: Hash::ZERO,
            timeout_height: u64::MAX,
        },
        Action::HtlcClaim {
            htlc_id: Hash::ZERO,
            preimage: vec![0; 8],
        },
        Action::HtlcRefund {
            htlc_id: Hash::ZERO,
        },
        Action::TokenIssue {
            symbol: "STEAL".to_string(),
            amount: whole,
            to: sink.clone(),
        },
        Action::TokenTransfer {
            asset: Hash::ZERO,
            to: sink.clone(),
            amount: whole,
        },
        Action::TokenBurn {
            asset: Hash::ZERO,
            amount: whole,
        },
        Action::TokenSetPolicy {
            asset: Hash::ZERO,
            policy: CompliancePolicy::unrestricted(),
        },
        Action::IntentSettle {
            settlement: Settlement {
                intent: signed_intent,
                solver: sink.clone(),
                deliver_amount: 0,
            },
        },
        Action::IntentCancel { intent },
        Action::RotateKey {
            new_key: attacker.public_key(),
            proof: Signature::V1Ed25519([0; 64]),
        },
        Action::RegisterName {
            name: "steal.sov".to_string(),
        },
        Action::TransferName {
            name: "gauntlet.sov".to_string(),
            to: sink.clone(),
        },
        Action::NftMint {
            symbol: "STEAL".to_string(),
            token_id: vec![1],
            to: sink.clone(),
            metadata: vec![],
        },
        Action::NftTransfer {
            collection: Hash::ZERO,
            token_id: vec![1],
            to: sink.clone(),
        },
        Action::NftSetMeta {
            collection: Hash::ZERO,
            token_id: vec![1],
            metadata: vec![0; 4],
        },
        Action::SetMultisig {
            signers: vec![attacker.public_key()],
            threshold: 1,
        },
        Action::MultisigExec {
            action: Box::new(drain.clone()),
            approvals: Vec::<MultisigApproval>::new(),
        },
        Action::ProposeMultisig {
            account: pot_account(),
            action: Box::new(drain.clone()),
        },
        Action::ApproveMultisig {
            account: pot_account(),
            proposal: Hash::ZERO,
        },
        Action::CancelMultisig {
            account: pot_account(),
            proposal: Hash::ZERO,
        },
        Action::VaultDeposit { amount: whole },
        Action::VaultMint { amount: whole },
        Action::VaultBurn { amount: whole },
        Action::VaultWithdraw { amount: whole },
        Action::OracleUpdate { price: 1 },
        Action::Tipped {
            tip: Balance::from_grains(1),
            inner: Box::new(drain.clone()),
        },
        Action::ShieldedV2 { bundle: vec![0; 8] },
        Action::Timestamped {
            created_at_ms: 0,
            inner: Box::new(drain),
        },
    ]
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
        // foreign-chain injection
        atk_foreign_genesis_block_import(),
        atk_extract_tx_from_foreign_chain(),
        atk_fabricated_heavier_branch(),
        atk_private_reorg_double_spend(),
    ]
}

/// Flip the first byte of a 32-byte hash to corrupt it deterministically.
fn flip_hash(h: sov_primitives::Hash) -> sov_primitives::Hash {
    let mut bytes = *h.as_bytes();
    bytes[0] ^= 0xff;
    sov_primitives::Hash::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verdict of every foreign-chain vector, asserted against what REAL
    /// consensus did — not against a fixture. A regression that lets any of these
    /// through turns the assertion (and the harness's exit code) red.
    fn assert_defended(o: Outcome) {
        assert!(
            o.verdict == Verdict::Defended,
            "{}: {} — {}",
            o.category,
            o.name,
            o.detail
        );
    }

    #[test]
    fn foreign_genesis_block_is_rejected() {
        assert_defended(atk_foreign_genesis_block_import());
    }

    #[test]
    fn foreign_chain_transaction_cannot_move_value_here() {
        assert_defended(atk_extract_tx_from_foreign_chain());
    }

    #[test]
    fn fabricated_pow_branch_under_a_checkpoint_is_rejected() {
        assert_defended(atk_fabricated_heavier_branch());
    }

    /// A LIGHTER private branch must never reverse a confirmed payment. The
    /// attack's verdict is DEFENDED, or INFO when the parity probe fires (an
    /// EQUAL-work branch wins the documented smaller-tip-hash tie-break) — never
    /// VULNERABLE, which is what a free reversal would be.
    #[test]
    fn lighter_private_branch_cannot_reverse_a_payment() {
        let o = atk_private_reorg_double_spend();
        assert!(
            o.verdict != Verdict::Vulnerable,
            "{}: {} — {}",
            o.category,
            o.name,
            o.detail
        );
    }

    /// The parity boundary, pinned as an observed fact rather than an assumption:
    /// at EQUAL cumulative work the tie-break can adopt the hidden branch, so a
    /// reversal at parity is possible and is disclosed by the harness.
    #[test]
    fn equal_work_parity_reversal_is_observed_not_assumed() {
        let reversed = private_branch_at_parity();
        let o = atk_private_reorg_double_spend();
        assert_eq!(
            reversed,
            o.verdict == Verdict::Info,
            "the parity probe and the reported verdict must agree: {}",
            o.detail
        );
    }

    // ── steal-the-pot: exhaustive in-process sweep ──────────────────────────

    /// EVERY `Action` variant, fired as an attacker-signed pot-theft through real
    /// consensus, is REJECTED with the pot's balance unchanged. This is the
    /// completeness guarantee: no action type has a weak authorization path.
    #[test]
    fn every_action_variant_is_refused_as_a_pot_theft() {
        for action in every_pot_theft() {
            let kind = action_kind(&action);
            assert!(
                pot_theft_refused(action.clone()),
                "STEAL SUCCEEDED via {kind}: an attacker-signed {kind} moved the pot or was admitted",
            );
        }
    }

    /// The sweep is EXHAUSTIVE: it constructs exactly one theft per `Action`
    /// variant, covering all [`ACTION_VARIANT_COUNT`] of them with no duplicates.
    /// A newly added variant fails to compile in [`action_kind`] (no wildcard) and
    /// then fails this test until it is added to [`every_pot_theft`].
    #[test]
    fn every_action_variant_has_a_steal_attempt() {
        let thefts = every_pot_theft();
        let mut kinds: Vec<&str> = thefts.iter().map(action_kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            kinds.len(),
            ACTION_VARIANT_COUNT,
            "the pot-theft sweep must cover all {ACTION_VARIANT_COUNT} Action variants exactly once; \
             covered {} distinct kinds",
            kinds.len(),
        );
        assert_eq!(
            thefts.len(),
            ACTION_VARIANT_COUNT,
            "one theft per variant — no duplicates, no gaps",
        );
    }

    /// The post-quantum conjunction, proven with the POT'S OWN key (what the live
    /// Gauntlet cannot wield): the pot signs a real self-drain, then ONE hybrid
    /// half is corrupted. Consensus must refuse it — either half alone is not
    /// authorization, so a future break of Ed25519 alone still leaves ML-DSA-65
    /// guarding the pot. This is the definitive backing for the live A1 vector.
    #[test]
    fn pot_hybrid_conjunction_is_enforced() {
        let pot_kp = Keypair::hybrid_from_seed(POT_SEED);
        let sink = sink_account(201);
        let base = Transaction {
            signer: pot_account(),
            public_key: pot_kp.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: sink.clone(),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        // A genuine, fully-valid pot signature is the control: it MUST verify.
        let honest = SignedTransaction::sign(base.clone(), &pot_kp).unwrap();
        assert!(
            honest.verify_signature(),
            "sanity: the pot's own real signature must verify",
        );
        // Now break each half in turn; the conjunction must fail closed both ways.
        for half in [Half::Ed25519, Half::MlDsa] {
            let mut tampered = honest.clone();
            tampered.signature = tamper_signature(tampered.signature, half);
            assert!(
                !tampered.verify_signature(),
                "the pot signature verified with ONE hybrid half broken — conjunction not enforced",
            );
        }
    }

    /// The whole battery still runs clean, and the new class is registered.
    #[test]
    fn run_all_registers_the_foreign_chain_class_and_reports_no_vulnerability() {
        let all = run_all();
        assert_eq!(
            all.iter().filter(|o| o.category == "foreign-chain").count(),
            4
        );
        let bad: Vec<_> = all
            .iter()
            .filter(|o| o.verdict == Verdict::Vulnerable)
            .map(|o| format!("{}: {} — {}", o.category, o.name, o.detail))
            .collect();
        assert!(bad.is_empty(), "VULNERABLE: {bad:#?}");
    }
}
