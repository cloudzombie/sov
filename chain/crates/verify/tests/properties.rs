//! Property-based testing (Phase 7, p7-i3).
//!
//! These assert the protocol's *laws* hold for arbitrary inputs, not just the
//! hand-picked cases in unit tests. The headline property drives a real
//! [`Blockchain`] through randomized transaction sequences and checks the Phase 7
//! invariants after every block; the rest pin down serialization round-tripping,
//! decode robustness, exact balance arithmetic, and the emission-curve laws.
//!
//! Coverage-guided fuzzing of the same decode/execution surface lives in
//! `chain/fuzz/` (libFuzzer targets, run with `cargo +nightly fuzz run …`).

use proptest::prelude::*;

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance, Hash};
use sov_types::{Action, Block, SignedTransaction, Transaction};
use sov_verify::{check_ledger, check_transition};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

// Three funded actors (seeds 11/12/13), each starting with 1,000 SOV, plus a
// founding operator. Genesis supply is fixed and known, so absolute
// conservation is checkable: total_supply == genesis_supply + mined at all
// times.
const ACTORS: [(&str, u8); 3] = [("a.sov", 11), ("b.sov", 12), ("c.sov", 13)];
const ACTOR_START_SOV: u128 = 1_000;

fn genesis() -> GenesisConfig {
    let mut accounts = vec![GenesisAccount {
        account: id("val01.node.sov"),
        key: Keypair::from_seed([1; 32]).public_key(),
        balance: Balance::ZERO,
    }];
    for (name, seed) in ACTORS {
        accounts.push(GenesisAccount {
            account: id(name),
            key: Keypair::from_seed([seed; 32]).public_key(),
            balance: Balance::from_sov(ACTOR_START_SOV).unwrap(),
        });
    }
    GenesisConfig {
        chain_id: "sov-prop".into(),
        timestamp_ms: 1_000,
        accounts,
        mining: MiningPolicy::test(),
        vesting: vec![],
    }
}

fn genesis_supply_grains() -> u128 {
    (ACTORS.len() as u128 * ACTOR_START_SOV) * 100_000_000
}

/// One randomized operation: actor `from` does something with `amount` SOV.
/// `kind` selects transfer vs. HTLC lock; values may exceed balances on
/// purpose, so failed-but-conserving paths are exercised too.
#[derive(Debug, Clone)]
struct Op {
    kind: bool,
    from: usize,
    to: usize,
    amount: u64,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    (any::<bool>(), 0usize..3, 0usize..3, 0u64..2_000).prop_map(|(kind, from, to, amount)| Op {
        kind,
        from,
        to,
        amount,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// The core property: for ANY sequence of well-formed (correctly-signed,
    /// correctly-nonced) transactions — whether their actions succeed or fail —
    /// the per-block transition invariant and the per-state invariants hold, and
    /// absolute supply stays exactly accounted for.
    #[test]
    fn invariants_hold_under_random_tx_sequences(ops in proptest::collection::vec(op_strategy(), 0..8)) {
        let config = genesis();
        let mining = config.mining.clone();
        let mut chain = Blockchain::new(&config).unwrap();
        let mut nonces = [0u64; 3];

        for (i, op) in ops.iter().enumerate() {
            let (name, seed) = ACTORS[op.from];
            let amount = Balance::from_sov(op.amount as u128).unwrap();
            let action = if op.kind {
                Action::Transfer { to: id(ACTORS[op.to].0), amount }
            } else {
                // An HTLC escrow exercises the lock/conserve path (supply is
                // unchanged: value moves into the chain-held escrow).
                Action::HtlcLock {
                    recipient: id(ACTORS[op.to].0),
                    amount,
                    hashlock: Hash::from_bytes([0x42; 32]),
                    timeout_height: 1_000_000,
                }
            };
            let kp = Keypair::from_seed([seed; 32]);
            let tx = Transaction { signer: id(name), public_key: kp.public_key(), nonce: nonces[op.from], action };
            let signed = SignedTransaction::sign(tx, &kp).unwrap();
            // The tx is admitted (valid sig + nonce), so its nonce is consumed even
            // if the action fails — mirror that here.
            nonces[op.from] += 1;

            let before = chain.ledger().clone();
            let block = chain.produce_block(vec![signed], 2_000 + i as u64 * 1_000).unwrap();
            chain.import_block(block).unwrap();
            let after = chain.ledger();

            prop_assert!(check_transition(&before, after).is_ok(),
                "transition invariant: {:?}", check_transition(&before, after));
            prop_assert!(check_ledger(after, &mining).is_ok(),
                "ledger invariant: {:?}", check_ledger(after, &mining));
        }

        // Absolute conservation: the test preset's coinbase is zero, so the
        // whole supply is exactly the genesis allocation — nothing minted,
        // nothing lost (HTLC escrows hold value inside the chain).
        let l = chain.ledger();
        prop_assert_eq!(l.mined_emitted(), Balance::ZERO);
        prop_assert_eq!(l.total_supply().unwrap().grains(), genesis_supply_grains());
    }

    /// Borsh (the consensus encoding) round-trips a transaction exactly.
    #[test]
    fn borsh_roundtrips_transaction(nonce in any::<u64>(), amount in any::<u128>(), seed in any::<u8>()) {
        let kp = Keypair::from_seed([seed; 32]);
        let tx = Transaction {
            signer: id("a.sov"),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer { to: id("b.sov"), amount: Balance::from_grains(amount) },
        };
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        let bytes = borsh::to_vec(&signed).unwrap();
        let back: SignedTransaction = borsh::from_slice(&bytes).unwrap();
        prop_assert_eq!(signed, back);
    }

    /// Decoding arbitrary bytes must never panic — only return a clean error. This
    /// is the stable-Rust counterpart to the libFuzzer decode targets.
    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = borsh::from_slice::<Transaction>(&bytes);
        let _ = borsh::from_slice::<SignedTransaction>(&bytes);
        let _ = borsh::from_slice::<Block>(&bytes);
        // Reaching here without panicking is the property.
    }

    /// `Balance` is exact integer math: `from_sov` scales by 10^8, and checked
    /// add/sub agree with raw `u128` checked arithmetic (never silently wrap).
    #[test]
    fn balance_arithmetic_is_exact(a in any::<u128>(), b in any::<u128>()) {
        let (x, y) = (Balance::from_grains(a), Balance::from_grains(b));
        match x.checked_add(y) {
            Some(s) => prop_assert_eq!(s.grains(), a.checked_add(b).unwrap()),
            None => prop_assert!(a.checked_add(b).is_none()),
        }
        match x.checked_sub(y) {
            Some(d) => prop_assert_eq!(d.grains(), a - b),
            None => prop_assert!(a < b),
        }
    }

    /// The block subsidy is non-increasing in height (Bitcoin's height-keyed
    /// halving) and never exceeds the budget backstop.
    #[test]
    fn block_subsidy_is_monotonic_in_height_and_budget_bounded(h1 in 1u64..10_000_000, h2 in 1u64..10_000_000) {
        let p = MiningPolicy::mainnet_like();
        let (lo, hi) = if h1 <= h2 { (h1, h2) } else { (h2, h1) };
        let r_lo = p.reward_at(lo, Balance::ZERO);
        let r_hi = p.reward_at(hi, Balance::ZERO);
        prop_assert!(r_lo >= r_hi);
        prop_assert!(r_hi.grains() <= p.mining_budget_grains);
        // Genesis never mints (no pre-mine).
        prop_assert_eq!(p.reward_at(0, Balance::ZERO), Balance::ZERO);
    }
}
