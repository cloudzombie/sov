//! Known-answer-test (KAT) vector generator.
//!
//! Emits, as JSON to stdout, canonical vectors derived from the REAL SOV types:
//! for each sample transaction it prints the deterministic Borsh signing bytes,
//! the transaction id (Blake3 of those bytes), the Ed25519 signature, and the
//! full Borsh encoding of the signed transaction. The JS/TS SDK reproduces these
//! byte-for-byte in its test suite, proving its transaction encoding and signing
//! are wire-compatible with the node — not "probably correct".
//!
//! Run: `cargo run -p sov-rpc --bin sov-katgen > sdk/vectors/transactions.json`

use serde_json::{json, Value};
use sov_crypto::Keypair;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance, BlockHeight, Hash};
use sov_runtime::{apply_coinbase, apply_transactions, BlockContext};
use sov_state::{Account, Ledger};
use sov_types::{Action, Block, SignedTransaction, Transaction};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// The structured on-chain fields of an account (no Merkle slot/value), shared by
/// the state and STF vectors. Balances are decimal grain strings.
fn account_fields(account_id: &AccountId, account: &Account) -> Value {
    json!({
        "id": account_id.as_str(),
        "nonce": account.nonce,
        "balance": account.balance.grains().to_string(),
        "locked": account.locked.grains().to_string(),
        "unlock_height": account.unlock_height,
        "public_key_hex": account.key.map(|k| format!("0x{}", k.to_hex())),
        "code_hex": account.code.as_ref().map(hex::encode),
    })
}

/// Build one vector entry from a seed, signer, nonce, action, and a JSON
/// description of the action that mirrors the SDK's `Action` shape.
fn vector(
    name: &str,
    seed: [u8; 32],
    signer: &str,
    nonce: u64,
    action: Action,
    action_json: Value,
) -> Value {
    let kp = Keypair::from_seed(seed);
    let tx = Transaction {
        signer: id(signer),
        public_key: kp.public_key(),
        nonce,
        action,
    };
    let signing_bytes = tx.signing_bytes();
    let tx_id = tx.id();
    let signed = SignedTransaction::sign(tx, &kp).unwrap();
    let signed_borsh = borsh::to_vec(&signed).unwrap();
    let signature_borsh = borsh::to_vec(&signed.signature).unwrap();

    json!({
        "name": name,
        "seed_hex": hex::encode(seed),
        "signer": signer,
        "public_key_hex": kp.public_key().to_hex(),
        "public_key_json": format!("0x{}", kp.public_key().to_hex()),
        "nonce": nonce,
        "action": action_json,
        "signing_bytes_hex": hex::encode(&signing_bytes),
        "tx_id_hex": hex::encode(tx_id.as_bytes()),
        "signature_hex": hex::encode(&signature_borsh),
        "signed_tx_borsh_hex": hex::encode(&signed_borsh),
    })
}

/// A block known-answer vector: a real assembled block (header + transactions)
/// with its node-computed block id, transaction Merkle root (in the header), and
/// per-transaction ids. The TS SDK's independent verifier reproduces all of these
/// byte-for-byte, proving cross-implementation agreement on consensus hashing.
fn block_vector() -> Value {
    let mk = |nonce: u64, to: &str, sov: u128| -> (SignedTransaction, Value) {
        let kp = Keypair::from_seed([1; 32]);
        let amount = Balance::from_sov(sov).unwrap();
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer { to: id(to), amount },
        };
        let entry = json!({
            "signer": "usa.reserve.sov",
            "public_key_hex": kp.public_key().to_hex(),
            "nonce": nonce,
            "action": { "type": "transfer", "to": to, "amount": amount.grains().to_string() },
        });
        (SignedTransaction::sign(tx, &kp).unwrap(), entry)
    };

    let (t0, j0) = mk(0, "ecb.reserve.sov", 5);
    let (t1, j1) = mk(1, "boj.reserve.sov", 7);
    let txs = vec![t0, t1];
    let mut block = Block::assemble(
        BlockHeight::new(1),
        Hash::ZERO,
        Hash::digest(b"sample-state-root"),
        Hash::digest(b"sample-receipts-root"),
        1_000,
        id("val01.node.sov"),
        txs.clone(),
    );
    // Commit a real difficulty in Bitcoin's compact nBits form, so the vector
    // exercises the header's `bits` field (hash-committed) in the SDK decoder.
    block.header.bits = MiningPolicy::mainnet_like().sha256d_target.to_compact();

    json!({
        "header": serde_json::to_value(&block.header).unwrap(),
        "block_hash": serde_json::to_value(block.hash()).unwrap(),
        "tx_ids": txs.iter().map(|t| serde_json::to_value(t.id()).unwrap()).collect::<Vec<_>>(),
        "transactions": [j0, j1],
    })
}

/// A state known-answer vector: a real [`Ledger`] populated with accounts that
/// exercise every `Account` field (nonce, balance, vesting lockup with an
/// unlock height, an authorizing public key, and deployed contract code). It emits each account's structured fields, the slot
/// it occupies in the Sparse Merkle Tree, and the exact Borsh value committed at
/// that slot, plus the authenticated `state_root` and one inclusion and one
/// exclusion Merkle proof.
///
/// The TS SDK's independent state verifier reproduces ALL of these from the
/// structured fields alone — it derives each slot, Borsh-encodes each account,
/// rebuilds the Sparse Merkle Tree, and must arrive at the same `state_root` and
/// validate the same proofs byte-for-byte. That is the proof the second
/// implementation agrees with the node on authenticated world state, not just on
/// block/transaction hashing.
fn state_vector() -> Value {
    // The Merkle slot for an account id mirrors `Ledger::slot`: Blake3 of the id
    // bytes (no tag — account ids can't collide with the 0x01/0x02-tagged slots).
    let slot = |id: &AccountId| Hash::digest(id.as_str().as_bytes());
    let sov = |n: u128| Balance::from_sov(n).unwrap();

    // Account A — a plain keyed account holding a balance.
    let kp_a = Keypair::from_seed([10; 32]);
    let acct_a = Account::new(kp_a.public_key(), sov(1_000_000));

    // Account B — keyed, with a nonce and a vesting lockup released at a height.
    // Exercises every balance field.
    let kp_b = Keypair::from_seed([11; 32]);
    let mut acct_b = Account::new(kp_b.public_key(), sov(500));
    acct_b.nonce = 7;
    acct_b.locked = sov(25);
    acct_b.unlock_height = 99;

    // Account C — a keyless contract account carrying deployed code (Option<Vec<u8>>
    // = Some) and no public key (Option = None). Exercises both Option arms.
    let mut acct_c = Account::with_balance(sov(1));
    acct_c.code = Some((0u8..32).collect());

    let entries: Vec<(AccountId, Account)> = vec![
        (id("usa.reserve.sov"), acct_a),
        (id("treasury.sov"), acct_b),
        (id("counter.sov"), acct_c),
    ];

    let mut ledger = Ledger::new();
    for (account_id, account) in &entries {
        ledger.set_account(account_id, account.clone());
    }

    let account_json = |account_id: &AccountId, account: &Account| -> Value {
        json!({
            "id": account_id.as_str(),
            "nonce": account.nonce,
            "balance": account.balance.grains().to_string(),
            "locked": account.locked.grains().to_string(),
            "unlock_height": account.unlock_height,
            "public_key_hex": account.key.map(|k| format!("0x{}", k.to_hex())),
            "code_hex": account.code.as_ref().map(hex::encode),
            "slot": slot(account_id),
            "value_borsh_hex": hex::encode(borsh::to_vec(account).unwrap()),
        })
    };

    // Inclusion proof for a populated account, exclusion proof for an absent one.
    let included = id("treasury.sov");
    let inclusion = ledger.prove(&included);
    let included_account = &entries.iter().find(|(i, _)| *i == included).unwrap().1;
    let absent = id("absent.account.sov");
    let exclusion = ledger.prove(&absent);

    json!({
        "state_root": ledger.state_root(),
        "accounts": entries.iter().map(|(i, a)| account_json(i, a)).collect::<Vec<_>>(),
        "inclusion_proof": {
            "id": included.as_str(),
            "slot": slot(&included),
            "value_borsh_hex": hex::encode(borsh::to_vec(included_account).unwrap()),
            "leaf": inclusion.leaf,
            "siblings": inclusion.siblings,
        },
        "exclusion_proof": {
            "id": absent.as_str(),
            "slot": slot(&absent),
            "leaf": exclusion.leaf,
            "siblings": exclusion.siblings,
        },
    })
}

/// A state-transition known-answer vector: a real prior ledger, a real block of
/// signed transactions, and the REAL post-state the node's runtime produces by
/// executing them — the resulting `state_root`, `receipts_root`, account set, and
/// per-transaction receipts. It exercises the full deterministic transparent STF
/// with fees ON: a transfer, a vesting
/// claim, a contract deploy, an HTLC lock + claim (atomic-swap settlement), and a
/// transfer that FAILS for insufficient balance (a recorded `Failed` receipt).
///
/// The TS SDK's independent re-executor (`sdk/src/stf.ts`) applies the SAME prior
/// ledger and signed block and must DERIVE the same `state_root`, `receipts_root`,
/// accounts, and receipts byte-for-byte — proving the second implementation agrees
/// with the node on how value actually moves, not just on hashing a given state.
fn stf_vector() -> Value {
    let sov = |n: u128| Balance::from_sov(n).unwrap();
    let kp = |seed: u8| Keypair::from_seed([seed; 32]);
    let sign = |signer: &str, seed: u8, nonce: u64, action: Action| -> SignedTransaction {
        let k = kp(seed);
        SignedTransaction::sign(
            Transaction {
                signer: id(signer),
                public_key: k.public_key(),
                nonce,
                action,
            },
            &k,
        )
        .unwrap()
    };

    // Prior ledger: five keyed accounts (so their signatures authorize).
    let mut ledger = Ledger::new();
    ledger.set_account(
        &id("usa.reserve.sov"),
        Account::new(kp(1).public_key(), sov(1_000_000)),
    );
    ledger.set_account(
        &id("ecb.reserve.sov"),
        Account::new(kp(5).public_key(), sov(10)),
    );
    ledger.set_account(&id("bob.sov"), Account::new(kp(2).public_key(), sov(1)));
    ledger.set_account(&id("dev.sov"), Account::new(kp(4).public_key(), sov(10)));
    ledger.set_account(
        &id("foundation.sov"),
        Account {
            balance: sov(1),
            locked: sov(500),
            unlock_height: 500,
            key: Some(kp(3).public_key()),
            ..Account::default()
        },
    );

    let prev_accounts: Vec<Value> = {
        let mut entries: Vec<(AccountId, Account)> =
            ledger.iter().map(|(i, a)| (i.clone(), a.clone())).collect();
        entries.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        entries.iter().map(|(i, a)| account_fields(i, a)).collect()
    };

    // Fees ON: the mainnet-like mining policy. The block is at height 1000.
    let mining = MiningPolicy::mainnet_like();
    let height: u64 = 1_000;
    let prev_hash = Hash::digest(b"stf-kat-parent");
    let miner = id("miner.node.sov");

    // The HTLC lock transaction's id is the HTLC key the claim must reference.
    let secret: &[u8] = b"the-shared-atomic-swap-secret";
    let hashlock = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(secret);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    let lock_tx = sign(
        "usa.reserve.sov",
        1,
        1,
        Action::HtlcLock {
            recipient: id("bob.sov"),
            amount: sov(10),
            hashlock,
            timeout_height: 2_000,
        },
    );
    let htlc_id = lock_tx.id();

    let txs: Vec<SignedTransaction> = vec![
        // 1. A plain transfer (fee burned + tip split).
        sign(
            "usa.reserve.sov",
            1,
            0,
            Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: sov(5),
            },
        ),
        // 2. The HTLC lock (escrows 10 SOV for bob).
        lock_tx.clone(),
        // 3. Bob claims the HTLC by revealing the preimage before the timeout.
        sign(
            "bob.sov",
            2,
            0,
            Action::HtlcClaim {
                htlc_id,
                preimage: secret.to_vec(),
            },
        ),
        // 4. Foundation claims its vested funds (unlocked at height 500 <= 1000).
        sign("foundation.sov", 3, 0, Action::ClaimVesting),
        // 5. A contract deploy (per-byte gas; commits code to the account).
        sign(
            "dev.sov",
            4,
            0,
            Action::Deploy {
                code: (0u8..48).collect(),
            },
        ),
        // 6. A transfer that FAILS for insufficient balance — a recorded receipt.
        sign(
            "ecb.reserve.sov",
            5,
            0,
            Action::Transfer {
                to: id("usa.reserve.sov"),
                amount: sov(999_999),
            },
        ),
    ];

    let ctx = BlockContext {
        height,
        prev_hash,
        mining: &mining,
        gas_price: mining.gas_price,
        miner: miner.clone(),
        pq: None,
    };
    // The full block state transition the node performs: the coinbase mints the
    // scheduled subsidy to the miner FIRST (Bitcoin issuance), then the
    // transactions execute. The SDK's second client mirrors both.
    let coinbase_reward = apply_coinbase(&mut ledger, &ctx).unwrap();
    let receipts = apply_transactions(&mut ledger, &txs, &ctx).unwrap();

    let post_accounts: Vec<Value> = {
        let mut entries: Vec<(AccountId, Account)> =
            ledger.iter().map(|(i, a)| (i.clone(), a.clone())).collect();
        entries.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        entries.iter().map(|(i, a)| account_fields(i, a)).collect()
    };

    // Emit each transaction in the SDK's signed-transaction JSON shape.
    let tx_json = |stx: &SignedTransaction| -> Value {
        let t = &stx.transaction;
        let action = match &t.action {
            Action::Transfer { to, amount } => {
                json!({ "type": "transfer", "to": to.as_str(), "amount": amount.grains().to_string() })
            }
            Action::ClaimVesting => json!({ "type": "claim_vesting" }),
            Action::Deploy { code } => json!({ "type": "deploy", "code": code }),
            Action::HtlcLock {
                recipient,
                amount,
                hashlock,
                timeout_height,
            } => json!({
                "type": "htlc_lock",
                "recipient": recipient.as_str(),
                "amount": amount.grains().to_string(),
                "hashlock": format!("0x{}", hex::encode(hashlock)),
                "timeout_height": timeout_height,
            }),
            Action::HtlcClaim { htlc_id, preimage } => json!({
                "type": "htlc_claim",
                "htlc_id": format!("0x{}", hex::encode(htlc_id.as_bytes())),
                "preimage": preimage,
            }),
            other => panic!("unsupported action in STF vector: {other:?}"),
        };
        json!({
            "transaction": {
                "signer": t.signer.as_str(),
                "public_key": format!("0x{}", t.public_key.to_hex()),
                "nonce": t.nonce,
                "action": action,
            },
            "signature": format!("0x{}", stx.signature.to_hex()),
        })
    };

    json!({
        "policy": {
            "gas_price": mining.gas_price.grains().to_string(),
            "tax_primary_bps": mining.tax_primary_bps,
            "tax_secondary_bps": mining.tax_secondary_bps,
            "tax_primary_recipient": mining.tax_primary_recipient.as_str(),
            "tax_secondary_recipient": mining.tax_secondary_recipient.as_str(),
            "max_code_bytes": mining.max_code_bytes,
            // Emission schedule: the SDK reproduces the coinbase from these —
            // 12.5-XUS base, halving every 840,000 blocks, full-cap budget.
            "base_reward": mining.base_reward.grains().to_string(),
            "halving_interval_blocks": mining.halving_interval_blocks,
            "mining_budget_grains": mining.mining_budget_grains.to_string(),
        },
        "context": {
            "height": height,
            "prev_hash": prev_hash,
            "miner": miner.as_str(),
        },
        // The coinbase the node minted before the transactions: the subsidy at
        // this height to the miner. The SDK must derive the same amount.
        "coinbase": {
            "miner": miner.as_str(),
            "reward": coinbase_reward.grains().to_string(),
        },
        "prev_accounts": prev_accounts,
        "transactions": txs.iter().map(tx_json).collect::<Vec<_>>(),
        "post_state_root": ledger.state_root(),
        "post_receipts_root": serde_json::to_value(sov_types::receipts_root(&receipts)).unwrap(),
        "post_accounts": post_accounts,
        "receipts": receipts.iter().map(|r| serde_json::to_value(r).unwrap()).collect::<Vec<_>>(),
    })
}

fn main() {
    // `sov-katgen block` emits the block vector, `state` the world-state vector,
    // `stf` the state-transition vector; otherwise the transaction vectors.
    match std::env::args().nth(1).as_deref() {
        Some("block") => {
            println!("{}", serde_json::to_string_pretty(&block_vector()).unwrap());
            return;
        }
        Some("state") => {
            println!("{}", serde_json::to_string_pretty(&state_vector()).unwrap());
            return;
        }
        Some("stf") => {
            println!("{}", serde_json::to_string_pretty(&stf_vector()).unwrap());
            return;
        }
        _ => {}
    }

    let grains = |sov: u128| Balance::from_sov(sov).unwrap();
    let grains_str = |b: Balance| b.grains().to_string();

    // A fixed, arbitrary opaque payload for the shielded vector. This pins the
    // shielded ACTION ENCODING (Borsh variant index + length-prefixed bytes),
    // which is independent of the bundle's content; real Halo2 shielded bundles
    // are exercised end-to-end by the Rust sov-shielded and runtime tests, not by
    // this wire-format vector.
    let shielded_bundle: Vec<u8> = (0u8..64).collect();

    let vectors = json!([
        vector(
            "transfer",
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: grains(5)
            },
            json!({ "type": "transfer", "to": "ecb.reserve.sov", "amount": grains_str(grains(5)) }),
        ),
        vector(
            "claim_vesting",
            [3; 32],
            "foundation.sov",
            0,
            Action::ClaimVesting,
            json!({ "type": "claim_vesting" }),
        ),
        vector(
            "call",
            [2; 32],
            "usa.reserve.sov",
            7,
            Action::Call {
                contract: id("counter.sov"),
                gas_limit: 1_000_000,
                calldata: vec![0xde, 0xad, 0xbe, 0xef]
            },
            json!({ "type": "call", "contract": "counter.sov", "gas_limit": 1_000_000, "calldata": [222, 173, 190, 239] }),
        ),
        vector(
            "shielded",
            [4; 32],
            "usa.reserve.sov",
            9,
            Action::Shielded {
                bundle: shielded_bundle.clone()
            },
            json!({ "type": "shielded", "bundle": shielded_bundle }),
        ),
    ]);

    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
