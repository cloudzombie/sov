//! Continuous chaos simulation & fault injection (Phase 7, p7-i8 — buildable part).
//!
//! A long, seeded, randomized run over **two replica nodes** built from one
//! genesis. Each round the scheduler either (a) produces a valid block and gossips
//! it to both replicas — checking they stay byte-identical and invariant-clean —
//! (b) injects a fault (forged roots, broken parent link, tampered signature) and
//! asserts it is rejected with the chain unmoved, or (c) checks Nakamoto
//! finality: confirmation depth of a tracked block only ever grows as the chain
//! extends, and both replicas agree on it. Deterministic (fixed seed), so a
//! failure reproduces exactly.
//!
//! Honest boundary: this is a simulated network of in-process replicas. *Live*,
//! multi-machine continuous testnet chaos is operational and needs the Phase 8
//! node daemon; this is the deterministic harness that runs on every CI.

use std::collections::BTreeMap;

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig, FINALITY_DEPTH};
use sov_crypto::{Keypair, Signature};
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::{Action, SignedTransaction, Transaction};
use sov_verify::check_ledger;

/// Tiny deterministic PRNG (SplitMix64) — std-only, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const ACTORS: [(&str, u8); 3] = [("a.sov", 11), ("b.sov", 12), ("c.sov", 13)];

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn config() -> GenesisConfig {
    let mut accounts = vec![GenesisAccount {
        account: id("val01.node.sov"),
        key: Keypair::from_seed([1; 32]).public_key(),
        balance: Balance::ZERO,
    }];
    for (name, seed) in ACTORS {
        accounts.push(GenesisAccount {
            account: id(name),
            key: Keypair::from_seed([seed; 32]).public_key(),
            balance: Balance::from_sov(1_000).unwrap(),
        });
    }
    GenesisConfig {
        chain_id: "sov-chaos".into(),
        timestamp_ms: 1_000,
        accounts,
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    }
}

fn actor_tx(idx: usize, nonce: u64, rng: &mut Rng) -> SignedTransaction {
    let (name, seed) = ACTORS[idx];
    let kp = Keypair::from_seed([seed; 32]);
    let action = if rng.below(4) == 0 {
        Action::HtlcLock {
            recipient: id(ACTORS[(idx + 1) % ACTORS.len()].0),
            amount: Balance::from_sov(u128::from(rng.below(50))).unwrap(),
            hashlock: Hash::from_bytes([0x42; 32]),
            timeout_height: 1_000_000,
        }
    } else {
        let to = ACTORS[(idx + 1 + rng.below(2) as usize) % ACTORS.len()].0;
        Action::Transfer {
            to: id(to),
            amount: Balance::from_sov(u128::from(rng.below(50))).unwrap(),
        }
    };
    let tx = Transaction {
        signer: id(name),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

#[test]
fn continuous_chaos_preserves_safety_and_agreement() {
    let cfg = config();
    let mining = cfg.mining.clone();
    let mut node1 = Blockchain::new(&cfg).unwrap();
    let mut node2 = Blockchain::new(&cfg).unwrap();

    let mut rng = Rng(0x5EED_C0DE_1234_5678);
    let mut nonces = [0u64; 3];
    let mut ts = 2_000u64;
    let mut finalized: BTreeMap<u64, Hash> = BTreeMap::new();
    let (mut honest, mut faults, mut finals) = (0u64, 0u64, 0u64);

    for _ in 0..1_200 {
        match rng.below(10) {
            // ---- honest block, gossiped to both replicas ----
            0..=5 => {
                let idx = rng.below(3) as usize;
                let tx = actor_tx(idx, nonces[idx], &mut rng);
                nonces[idx] += 1; // admitted ⇒ nonce consumed (even if the action fails)
                ts += 1_000;
                let block = node1.produce_block(vec![tx], ts).unwrap();
                node1.import_block(block.clone()).unwrap();
                node2.import_block(block).unwrap();
                // Cross-node agreement: identical blocks ⇒ identical authenticated state.
                assert_eq!(
                    node1.ledger().state_root(),
                    node2.ledger().state_root(),
                    "replicas diverged at height {}",
                    node1.height()
                );
                check_ledger(node1.ledger(), &mining).unwrap();
                check_ledger(node2.ledger(), &mining).unwrap();
                honest += 1;
            }
            // ---- injected fault: must be rejected, chain unmoved ----
            6..=8 => {
                let h_before = node1.height();
                let root_before = node1.ledger().state_root();
                match rng.below(4) {
                    0 => {
                        let mut b = node1.produce_block(vec![], ts + 1).unwrap();
                        b.header.state_root = Hash::digest(b"forged");
                        assert!(node1.import_block(b).is_err());
                    }
                    1 => {
                        let mut b = node1.produce_block(vec![], ts + 1).unwrap();
                        b.header.tx_root = Hash::digest(b"forged");
                        assert!(node1.import_block(b).is_err());
                    }
                    2 => {
                        let mut b = node1.produce_block(vec![], ts + 1).unwrap();
                        b.header.prev_hash = Hash::digest(b"wrong-parent");
                        assert!(node1.import_block(b).is_err());
                    }
                    _ => {
                        // Tamper a transaction's signature (nonce not consumed: the
                        // whole block is rejected, so we do not advance `nonces`).
                        let idx = rng.below(3) as usize;
                        let tx = actor_tx(idx, nonces[idx], &mut rng);
                        let mut b = node1.produce_block(vec![tx], ts + 1).unwrap();
                        b.transactions[0].signature = Signature::from_bytes([0u8; 64]);
                        assert!(node1.import_block(b).is_err());
                    }
                }
                // The rejected block left no trace.
                assert_eq!(
                    node1.height(),
                    h_before,
                    "a rejected block advanced the chain"
                );
                assert_eq!(node1.ledger().state_root(), root_before);
                check_ledger(node1.ledger(), &mining).unwrap();
                faults += 1;
            }
            // ---- Nakamoto finality: confirmations only ever grow, replicas agree ----
            _ => {
                let h = node1.height();
                if h == 0 {
                    continue;
                }
                let hh = node1.head().hash();
                finalized.insert(h, hh);
                // Every tracked block's confirmation count equals the chain
                // growth past it, identically on both replicas; once a block is
                // FINALITY_DEPTH deep, it reports final on both.
                for (bh, bhash) in &finalized {
                    let expect = node1.height() - bh + 1;
                    assert_eq!(node1.confirmations(bhash), Some(expect));
                    assert_eq!(node2.confirmations(bhash), Some(expect));
                    if expect >= FINALITY_DEPTH {
                        assert!(node1.is_final(bhash) && node2.is_final(bhash));
                    }
                }
                // The other replica holds the identical head.
                assert_eq!(node2.head().hash(), hh, "replicas disagree at height {h}");
                finals += 1;
            }
        }
    }

    // The run actually exercised all three paths and both nodes agree at the end.
    assert!(
        honest > 0 && faults > 0 && finals > 0,
        "chaos run lacked coverage"
    );
    assert_eq!(node1.height(), node2.height());
    assert_eq!(node1.ledger().state_root(), node2.ledger().state_root());
}
