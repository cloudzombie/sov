//! KATs and end-to-end tests for the PQ shielded pool prototype.
//!
//! The KAT pins the full deterministic chain seed → note → commitment →
//! tree root → nullifier as hex digests: ANY change to the hash convention,
//! commitment layout, tree shape, or nullifier PRF changes these bytes and
//! this test screams.

use sov_shielded_pq::air::SpendPublicInputs;
use sov_shielded_pq::auth::AuthKeypair;
use sov_shielded_pq::bundle::{
    bundle_digest, verify_bundle, BundleError, OutputDescription, SpendBundle, SpendDescription,
};
use sov_shielded_pq::encrypt::{encrypt_note, EncryptionKeypair};
use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::note::{derive_rho, Note, SpendingKey};
use sov_shielded_pq::prover::{prove_spend, verify_spend};
use sov_shielded_pq::tree::CommitmentTree;

const KAT_SEED: [u8; 32] = [0x42; 32];
const KAT_VALUE: u64 = 1_250_000_000; // 12.5 XUS in grains

/// Deterministic fixture: one owned note at position 1 of a 3-leaf tree.
fn kat_fixture() -> (SpendingKey, Note, CommitmentTree) {
    let key = SpendingKey::from_seed(&KAT_SEED);
    let note = Note::new(KAT_VALUE, key.owner_tag(), derive_rho(&KAT_SEED, 1)).expect("note");
    let mut tree = CommitmentTree::new();
    // Two decoy notes around ours so the path is non-trivial.
    let decoy0 = Note::new(1, key.owner_tag(), derive_rho(&KAT_SEED, 0)).expect("note");
    let decoy2 = Note::new(2, key.owner_tag(), derive_rho(&KAT_SEED, 2)).expect("note");
    tree.append(decoy0.commitment()).expect("append");
    tree.append(note.commitment()).expect("append");
    tree.mark().expect("mark");
    tree.append(decoy2.commitment()).expect("append");
    (key, note, tree)
}

#[test]
fn kat_pinned_digests() {
    let (key, note, tree) = kat_fixture();
    assert_eq!(
        note.commitment().to_hex(),
        "dc95a87fc231317df22af7191589af1786eb0ad35efb5bb39efc72e7e6846db9",
        "note commitment KAT drifted"
    );
    assert_eq!(
        tree.root().to_hex(),
        "a5ca3f07e1ad248b2f95b8bc3f6628b0c66f5e23121d2035d5412ddb448001fc",
        "tree root KAT drifted"
    );
    assert_eq!(
        key.nullifier(note.rho).to_hex(),
        "0e4d9f05dacd859b7232fbbbb7d0985619e6359a9b1a98acf05dd7ed56b4c998",
        "nullifier KAT drifted"
    );
}

#[test]
fn kat_proof_verifies() {
    let (key, note, tree) = kat_fixture();
    let (path, anchor) = tree.witness(1).expect("witness");
    let (proof, pub_inputs) = prove_spend(&key, &note, &path).expect("prove");
    assert_eq!(pub_inputs.root, anchor);
    assert_eq!(pub_inputs.nullifier, key.nullifier(note.rho));
    assert_eq!(pub_inputs.value_grains, KAT_VALUE);
    verify_spend(&proof, &pub_inputs).expect("KAT proof must verify");
}

#[test]
fn tampered_public_inputs_rejected() {
    let (key, note, tree) = kat_fixture();
    let (path, _) = tree.witness(1).expect("witness");
    let (proof, pub_inputs) = prove_spend(&key, &note, &path).expect("prove");

    // Tampered nullifier REJECTED.
    let mut bad = pub_inputs.clone();
    bad.nullifier = PqDigest([1, 2, 3, 4]);
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered nullifier accepted"
    );

    // Tampered value REJECTED.
    let mut bad = pub_inputs.clone();
    bad.value_grains += 1;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered value accepted"
    );

    // Tampered root REJECTED.
    let mut bad = pub_inputs.clone();
    bad.root = PqDigest([9, 9, 9, 9]);
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered root accepted"
    );

    // Truncated / bit-flipped proof REJECTED. (Flip in the proof BODY: a
    // flip inside the serialized ProofOptions header trips an assert/panic
    // inside winterfell's deserializer rather than an Err — a known
    // robustness wart to handle before any consensus exposure; see the
    // design doc.)
    let mut flipped = proof.clone();
    let mid = proof.len() / 2;
    flipped[mid] ^= 0x01;
    assert!(
        verify_spend(&flipped, &pub_inputs).is_err(),
        "flipped proof accepted"
    );
    assert!(
        verify_spend(&proof[..proof.len() - 10], &pub_inputs).is_err(),
        "truncated proof accepted"
    );
}

#[test]
fn wrong_merkle_path_rejected() {
    let (key, note, tree) = kat_fixture();
    // A witness for a DIFFERENT leaf: proving with it yields a root/leaf
    // mismatch, so the honest prover cannot even build a proof for our
    // note's public root — the resulting public root differs.
    let (wrong_path, _) = tree.witness(0).expect("witness");
    let (proof, pub_inputs) = prove_spend(&key, &note, &wrong_path).expect("prove");
    // The trace commits to whatever root the wrong path produces — it must
    // NOT be the real tree root, and substituting the real root must fail.
    assert_ne!(
        pub_inputs.root,
        tree.root(),
        "wrong path reproduced the true root"
    );
    let mut forged = pub_inputs.clone();
    forged.root = tree.root();
    assert!(
        verify_spend(&proof, &forged).is_err(),
        "proof with wrong Merkle path accepted under the true root"
    );
}

#[test]
fn foreign_note_cannot_be_spent() {
    // The sender knows the recipient's full note opening but not nsk: the
    // witness check refuses, and there is no way to derive the recipient's
    // nullifier without nsk (owner_tag binds it in-circuit).
    let (_, note, tree) = kat_fixture();
    let thief = SpendingKey::from_seed(&[0x66; 32]);
    let (path, _) = tree.witness(1).expect("witness");
    assert!(prove_spend(&thief, &note, &path).is_err());
}

#[test]
fn bundle_end_to_end() {
    let (key, note, tree) = kat_fixture();
    let (path, anchor) = tree.witness(1).expect("witness");
    let (proof, pub_inputs) = prove_spend(&key, &note, &path).expect("prove");

    // Output: pay 1.0 XUS-grains-worth to a recipient, keep change, pay fee.
    let recipient = EncryptionKeypair::generate().expect("keygen");
    let recipient_spend = SpendingKey::from_seed(&[0x77; 32]);
    let fee = 1_000;
    let out_value = 400_000_000;
    let change = KAT_VALUE - out_value - fee;
    let out_note = Note::new(
        out_value,
        recipient_spend.owner_tag(),
        derive_rho(&[0x55; 32], 0),
    )
    .expect("note");
    let change_note = Note::new(change, key.owner_tag(), derive_rho(&KAT_SEED, 100)).expect("note");

    let outputs = vec![
        OutputDescription {
            note: out_note,
            commitment: out_note.commitment(),
            ciphertext: encrypt_note(&recipient.public_bytes(), &out_note).expect("encrypt"),
        },
        OutputDescription {
            note: change_note,
            commitment: change_note.commitment(),
            ciphertext: encrypt_note(&recipient.public_bytes(), &change_note).expect("encrypt"),
        },
    ];
    let spends = vec![SpendDescription {
        anchor,
        nullifier: pub_inputs.nullifier,
        value_grains: pub_inputs.value_grains,
        proof_bytes: proof,
    }];
    let auth = AuthKeypair::from_seed(&KAT_SEED);
    let digest = bundle_digest(&spends, &outputs, fee);
    let bundle = SpendBundle {
        spends,
        outputs,
        fee_grains: fee,
        auth_pk: auth.public_bytes(),
        auth_sig: auth.sign(&digest).expect("sign"),
    };
    verify_bundle(&bundle, anchor).expect("bundle verifies");

    // Recipient decrypts their note.
    let recovered = recipient
        .decrypt(&bundle.outputs[0].ciphertext)
        .expect("decrypt");
    assert_eq!(recovered, out_note);

    // Conservation violation REJECTED.
    let mut bad = SpendBundle {
        spends: bundle.spends.clone(),
        outputs: bundle.outputs.clone(),
        fee_grains: fee + 1,
        auth_pk: bundle.auth_pk,
        auth_sig: bundle.auth_sig,
    };
    assert!(matches!(
        verify_bundle(&bad, anchor),
        Err(BundleError::Conservation)
    ));

    // Bad ML-DSA signature REJECTED.
    bad.fee_grains = fee;
    bad.auth_sig[0] ^= 1;
    assert!(matches!(
        verify_bundle(&bad, anchor),
        Err(BundleError::Auth)
    ));

    // Tampered output commitment REJECTED.
    let mut bad2 = SpendBundle {
        spends: bundle.spends.clone(),
        outputs: bundle.outputs.clone(),
        fee_grains: fee,
        auth_pk: bundle.auth_pk,
        auth_sig: bundle.auth_sig,
    };
    bad2.outputs[0].commitment = PqDigest([5, 5, 5, 5]);
    assert!(matches!(
        verify_bundle(&bad2, anchor),
        Err(BundleError::OutputCommitment(0))
    ));
}

/// Honest measurement of prove/verify time and proof size on this machine.
/// Run with `cargo test -p sov-shielded-pq --release -- benchmark --nocapture`.
#[test]
fn benchmark_spend_proof() {
    use std::time::Instant;
    let (key, note, tree) = kat_fixture();
    let (path, _) = tree.witness(1).expect("witness");

    // Warm-up + correctness.
    let (proof, pub_inputs) = prove_spend(&key, &note, &path).expect("prove");
    verify_spend(&proof, &pub_inputs).expect("verify");

    const N: usize = 5;
    let t0 = Instant::now();
    let mut last: Option<(Vec<u8>, SpendPublicInputs)> = None;
    for _ in 0..N {
        last = Some(prove_spend(&key, &note, &path).expect("prove"));
    }
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0 / N as f64;
    let (proof, pub_inputs) = last.expect("proved");

    let t1 = Instant::now();
    for _ in 0..N {
        verify_spend(&proof, &pub_inputs).expect("verify");
    }
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / N as f64;

    let parsed = winterfell::Proof::from_bytes(&proof).expect("parse");
    println!("--- sov-shielded-pq spend proof benchmark (this machine) ---");
    println!("prove:      {prove_ms:.1} ms (avg of {N})");
    println!("verify:     {verify_ms:.2} ms (avg of {N})");
    println!("proof size: {} bytes", proof.len());
    println!(
        "security:   {} bits (conjectured)",
        parsed
            .conjectured_security::<winterfell::crypto::hashers::Blake3_256<
                sov_shielded_pq::hash::Felt,
            >>()
            .bits()
    );
}
