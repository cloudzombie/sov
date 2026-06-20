//! Known-answer-test (KAT) conformance vectors (Phase 7, p7-i5).
//!
//! The committed `vectors/transactions.json` was emitted by the real
//! `sov-katgen` tool from the real SOV types. This test re-derives every field of
//! every vector — public key, Borsh signing bytes, transaction id (Blake3),
//! Ed25519 signature, and full signed-transaction Borsh — with the real crates
//! and asserts **byte-for-byte equality**. It is the guard that the chain's
//! crypto and canonical serialization never change unintentionally: any drift in
//! Ed25519, Blake3, or Borsh layout breaks these vectors immediately.
//!
//! Regenerate the vectors (only when an intentional format change is made) with:
//!   cargo run -p sov-rpc --bin sov-katgen > crates/verify/tests/vectors/transactions.json

use serde_json::Value;
use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_types::{Action, SignedTransaction, Transaction};

const VECTORS: &str = include_str!("vectors/transactions.json");

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn grains(v: &Value) -> Balance {
    // Amounts are encoded as a decimal *grain* string (exact, JS-safe).
    Balance::from_grains(v.as_str().unwrap().parse::<u128>().unwrap())
}

fn action_from_json(a: &Value) -> Action {
    match a["type"].as_str().unwrap() {
        "transfer" => Action::Transfer {
            to: id(a["to"].as_str().unwrap()),
            amount: grains(&a["amount"]),
        },
        "claim_vesting" => Action::ClaimVesting,
        "call" => Action::Call {
            contract: id(a["contract"].as_str().unwrap()),
            gas_limit: a["gas_limit"].as_u64().unwrap(),
            calldata: a["calldata"]
                .as_array()
                .map(|v| v.iter().map(|b| b.as_u64().unwrap() as u8).collect())
                .unwrap_or_default(),
        },
        "shielded" => Action::Shielded {
            bundle: a["bundle"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_u64().unwrap() as u8)
                .collect(),
        },
        other => panic!("unknown action type in KAT vector: {other}"),
    }
}

#[test]
fn kat_vectors_are_reproduced_byte_for_byte() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("KAT vectors parse");
    assert!(!vectors.is_empty(), "KAT vector set must not be empty");

    for v in &vectors {
        let name = v["name"].as_str().unwrap();

        // Seed -> keypair. The committed public key must match exactly.
        let seed: [u8; 32] = hex::decode(v["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .expect("seed is 32 bytes");
        let kp = Keypair::from_seed(seed);
        assert_eq!(
            kp.public_key().to_hex(),
            v["public_key_hex"].as_str().unwrap(),
            "[{name}] public key"
        );

        // Rebuild the exact transaction and re-derive its canonical artifacts.
        let tx = Transaction {
            signer: id(v["signer"].as_str().unwrap()),
            public_key: kp.public_key(),
            nonce: v["nonce"].as_u64().unwrap(),
            action: action_from_json(&v["action"]),
        };
        let signing_bytes = tx.signing_bytes();
        assert_eq!(
            hex::encode(&signing_bytes),
            v["signing_bytes_hex"].as_str().unwrap(),
            "[{name}] Borsh signing bytes"
        );
        assert_eq!(
            hex::encode(tx.id().as_bytes()),
            v["tx_id_hex"].as_str().unwrap(),
            "[{name}] tx id (Blake3 of signing bytes)"
        );

        // Ed25519 signature is deterministic from (seed, message): same bytes,
        // and it genuinely verifies against the public key.
        let public_key = kp.public_key();
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        assert_eq!(
            hex::encode(borsh::to_vec(&signed.signature).unwrap()),
            v["signature_hex"].as_str().unwrap(),
            "[{name}] Ed25519 signature"
        );
        assert!(
            public_key.verify(&signing_bytes, &signed.signature),
            "[{name}] signature must verify against the public key"
        );
        assert_eq!(
            hex::encode(borsh::to_vec(&signed).unwrap()),
            v["signed_tx_borsh_hex"].as_str().unwrap(),
            "[{name}] full signed-transaction Borsh"
        );
    }
}
