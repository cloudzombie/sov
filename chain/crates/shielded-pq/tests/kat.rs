//! KATs, end-to-end tests, and one negative test PER CONSTRAINT FAMILY for
//! the 4-in/4-out PQ bundle circuit.
//!
//! The KAT pins the full deterministic chain seed → note → commitment →
//! tree root → nullifier as hex digests: ANY change to the hash convention,
//! domain constants, commitment layout, tree shape, or nullifier PRF
//! changes these bytes and this test screams.
//!
//! # How witness-side negative tests reject
//!
//! Constraint families that bind PUBLIC inputs (anchors, nullifiers,
//! output commitments, the balance legs, dummy flags) are broken by
//! proving honestly and verifying against tampered publics: the verifier
//! must return `Err`.
//!
//! Constraint families over pure WITNESS data (range-check bits, dummy
//! value-zero, register consistency) are broken by tampering trace cells
//! directly via [`build_bundle_columns`] and attempting to prove. In debug
//! builds winterfell validates the trace against the AIR and panics on the
//! violated constraint (caught — that IS the reject); in release builds
//! the prover emits an unsound proof that the verifier must reject. Either
//! way [`expect_circuit_reject`] fails the test if the forgery survives.

use sov_shielded_pq::air::{
    rc_base, BundlePublicInputs, ACTIVE_ROWS, NSK_COL, NUM_SLOTS, RC_ACC_COL, RC_BIT_COL, RHO_COL,
    VAL_COL,
};
use sov_shielded_pq::auth::AuthKeypair;
use sov_shielded_pq::bundle::{bundle_digest, verify_bundle, BundleError, SpendBundle};
use sov_shielded_pq::domains::B3_TEST;
use sov_shielded_pq::encrypt::{encrypt_note, EncryptionKeypair, NoteCiphertext};
use sov_shielded_pq::hash::{digest_from_bytes, Felt, PqDigest};
use sov_shielded_pq::note::{derive_rho, Note, SpendingKey, MAX_NOTE_VALUE, VALUE_BITS};
use sov_shielded_pq::prover::{
    build_bundle_columns, prove_bundle, verify_spend, BundleProver, BundleSpend, SpendProofError,
};
use sov_shielded_pq::tree::CommitmentTree;
use winter_math::FieldElement;
use winterfell::{Prover, TraceTable};

const KAT_SEED: [u8; 32] = [0x42; 32];
const KAT_VALUE_0: u64 = 1_250_000_000; // 12.5 XUS in grains
const KAT_VALUE_1: u64 = 300_000_000;
const KAT_FEE: u64 = 1_000;
const KAT_T_OUT: u64 = 50_000_000; // partial unshield leg

/// Deterministic fixture: two owned notes (positions 1 and 3) in a 4-leaf
/// tree.
fn kat_fixture() -> (SpendingKey, [Note; 2], CommitmentTree) {
    let key = SpendingKey::from_seed(&KAT_SEED);
    let note0 = Note::new(KAT_VALUE_0, key.owner_tag(), derive_rho(&KAT_SEED, 1)).expect("note");
    let note1 = Note::new(KAT_VALUE_1, key.owner_tag(), derive_rho(&KAT_SEED, 3)).expect("note");
    let decoy0 = Note::new(1, key.owner_tag(), derive_rho(&KAT_SEED, 0)).expect("note");
    let decoy2 = Note::new(2, key.owner_tag(), derive_rho(&KAT_SEED, 2)).expect("note");
    let mut tree = CommitmentTree::new();
    tree.append(decoy0.commitment()).expect("append");
    tree.append(note0.commitment()).expect("append");
    tree.mark().expect("mark");
    tree.append(decoy2.commitment()).expect("append");
    tree.append(note1.commitment()).expect("append");
    tree.mark().expect("mark");
    (key, [note0, note1], tree)
}

/// The KAT bundle: 2 real spends + 2 real outputs (payment + change) +
/// fee + a partial unshield (`t_out`). Slots 2/3 on both sides are
/// dummies.
fn kat_bundle_witness() -> (Vec<BundleSpend>, Vec<Note>, CommitmentTree) {
    let (key, notes, tree) = kat_fixture();
    let recipient = SpendingKey::from_seed(&[0x77; 32]);
    let out_value = 400_000_000;
    let change = KAT_VALUE_0 + KAT_VALUE_1 - out_value - KAT_FEE - KAT_T_OUT;
    let out_note =
        Note::new(out_value, recipient.owner_tag(), derive_rho(&[0x55; 32], 0)).expect("note");
    let change_note = Note::new(change, key.owner_tag(), derive_rho(&KAT_SEED, 100)).expect("note");
    let spends = vec![
        BundleSpend {
            key: key.clone(),
            note: notes[0],
            path: tree.witness(1).expect("witness").0,
        },
        BundleSpend {
            key,
            note: notes[1],
            path: tree.witness(3).expect("witness").0,
        },
    ];
    (spends, vec![out_note, change_note], tree)
}

fn kat_prove() -> (Vec<u8>, BundlePublicInputs) {
    let (spends, outputs, _) = kat_bundle_witness();
    prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("prove")
}

#[test]
fn kat_pinned_digests() {
    let (key, notes, tree) = kat_fixture();
    assert_eq!(
        notes[0].commitment().to_hex(),
        "d9312a5e7d7d1d3b0e0ab2d3470d933c021f3b058c4fc56516cd1a653a2495ec",
        "note commitment KAT drifted"
    );
    assert_eq!(
        tree.root().to_hex(),
        "0fc7b7717c6e446b9eae13e0475689a7ca3b48c2bf8d0d03e68a038736c2e16e",
        "tree root KAT drifted"
    );
    assert_eq!(
        key.nullifier(notes[0].rho).to_hex(),
        "399741356fb66da96dcacd36791a5c89c37284dda9ac2245fd372613515a7cad",
        "nullifier KAT drifted"
    );
    assert_eq!(
        key.owner_tag().to_hex(),
        "181661771e0d93b850e80ee0af068572d8b4008df37c0e523147511693fa7aa2",
        "owner tag KAT drifted"
    );
}

#[test]
fn kat_bundle_proof_verifies() {
    let (proof, pub_inputs) = kat_prove();
    let (_, notes, tree) = kat_fixture();
    let key = SpendingKey::from_seed(&KAT_SEED);
    assert_eq!(pub_inputs.anchors[0], tree.root());
    assert_eq!(pub_inputs.anchors[1], tree.root());
    assert_eq!(pub_inputs.nullifiers[0], key.nullifier(notes[0].rho));
    assert_eq!(pub_inputs.nullifiers[1], key.nullifier(notes[1].rho));
    assert_eq!(pub_inputs.input_dummy, [false, false, true, true]);
    assert_eq!(pub_inputs.output_dummy, [false, false, true, true]);
    // Dummy slots surface only zero digests.
    for i in 2..NUM_SLOTS {
        assert_eq!(pub_inputs.anchors[i], PqDigest::ZERO);
        assert_eq!(pub_inputs.nullifiers[i], PqDigest::ZERO);
        assert_eq!(pub_inputs.output_commitments[i], PqDigest::ZERO);
    }
    // NOTE VALUES APPEAR NOWHERE IN THE PUBLIC INPUTS — only the
    // transparent legs do.
    assert_eq!(pub_inputs.transparent_in, 0);
    assert_eq!(pub_inputs.transparent_out, KAT_T_OUT);
    assert_eq!(pub_inputs.fee_grains, KAT_FEE);
    verify_spend(&proof, &pub_inputs).expect("KAT bundle proof must verify");
}

#[test]
fn full_4in_4out_with_distinct_anchors_verifies() {
    // D5: inputs in ONE bundle may be witnessed against DIFFERENT anchors.
    let key = SpendingKey::from_seed(&[0x21; 32]);
    let mut tree = CommitmentTree::new();
    let mut notes = Vec::new();
    let mut spends = Vec::new();
    for i in 0..4u64 {
        let n = Note::new(1_000 + i, key.owner_tag(), derive_rho(&[0x21; 32], i)).expect("note");
        tree.append(n.commitment()).expect("append");
        notes.push(n);
    }
    // Witness inputs 0/1 against the 4-leaf root, then grow the tree and
    // witness inputs 2/3 against the 5-leaf root.
    for (i, note) in notes.iter().enumerate().take(2) {
        spends.push(BundleSpend {
            key: key.clone(),
            note: *note,
            path: tree.witness(i as u64).expect("witness").0,
        });
    }
    let anchor_a = tree.root();
    tree.append(digest_from_bytes(B3_TEST, b"growth"))
        .expect("append");
    for (i, note) in notes.iter().enumerate().take(4).skip(2) {
        spends.push(BundleSpend {
            key: key.clone(),
            note: *note,
            path: tree.witness(i as u64).expect("witness").0,
        });
    }
    let anchor_b = tree.root();
    assert_ne!(anchor_a, anchor_b);
    let total: u64 = (0..4).map(|i| 1_000 + i).sum();
    let fee = 10;
    // Three equal outputs plus a remainder output so the bundle conserves.
    let split = total / 4;
    let remainder = total - 3 * split - fee;
    let outs: Vec<Note> = (0..4u64)
        .map(|j| {
            Note::new(
                if j == 0 { remainder } else { split },
                key.owner_tag(),
                derive_rho(&[0x22; 32], j),
            )
            .expect("note")
        })
        .collect();
    let (proof, pub_inputs) = prove_bundle(&spends, &outs, 0, 0, fee).expect("prove");
    assert_eq!(pub_inputs.anchors[0], anchor_a);
    assert_eq!(pub_inputs.anchors[2], anchor_b);
    assert_eq!(pub_inputs.input_dummy, [false; 4]);
    assert_eq!(pub_inputs.output_dummy, [false; 4]);
    verify_spend(&proof, &pub_inputs).expect("4-in/4-out proof must verify");
}

#[test]
fn shield_only_bundle_verifies() {
    // 0 real inputs, 1 real output, funded by the transparent leg.
    let key = SpendingKey::from_seed(&[0x31; 32]);
    let note = Note::new(5_000, key.owner_tag(), derive_rho(&[0x31; 32], 0)).expect("note");
    let (proof, pub_inputs) = prove_bundle(&[], &[note], 5_100, 0, 100).expect("prove");
    assert_eq!(pub_inputs.input_dummy, [true; 4]);
    verify_spend(&proof, &pub_inputs).expect("shield-only proof must verify");
}

// --- Negative tests: PUBLIC-input binding, one per family. -------------

#[test]
fn tampered_public_inputs_rejected() {
    let (proof, pub_inputs) = kat_prove();

    // WRONG VALUE SUM: the fee appears ONLY in the in-circuit balance
    // constraint, so this isolates value conservation. REJECT.
    let mut bad = pub_inputs.clone();
    bad.fee_grains += 1;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "wrong value sum accepted"
    );

    // Same for each transparent leg. REJECT.
    let mut bad = pub_inputs.clone();
    bad.transparent_out += 1;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered t_out accepted"
    );
    let mut bad = pub_inputs.clone();
    bad.transparent_in += 1;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered t_in accepted"
    );

    // WRONG ANCHOR: membership was proven under a different root. REJECT.
    let mut bad = pub_inputs.clone();
    bad.anchors[0] = digest_from_bytes(B3_TEST, b"other root");
    assert!(verify_spend(&proof, &bad).is_err(), "wrong anchor accepted");

    // Tampered nullifier. REJECT.
    let mut bad = pub_inputs.clone();
    bad.nullifiers[0] = PqDigest([1, 2, 3, 4]);
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered nullifier accepted"
    );

    // TAMPERED OUTPUT COMMITMENT. REJECT.
    let mut bad = pub_inputs.clone();
    bad.output_commitments[0] = PqDigest([5, 5, 5, 5]);
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "tampered output commitment accepted"
    );

    // Flipped dummy flags (real -> dummy and dummy -> real): the flag set
    // is bound into the transcript, the assertion set, and the nullifier
    // domain. REJECT.
    let mut bad = pub_inputs.clone();
    bad.input_dummy[0] = true;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "real->dummy flip accepted"
    );
    let mut bad = pub_inputs.clone();
    bad.input_dummy[2] = false;
    assert!(
        verify_spend(&proof, &bad).is_err(),
        "dummy->real flip accepted"
    );

    // Public legs above the no-wrap bound: typed native reject.
    let mut bad = pub_inputs.clone();
    bad.transparent_in = MAX_NOTE_VALUE + 1;
    assert!(matches!(
        verify_spend(&proof, &bad),
        Err(SpendProofError::PublicInput(_))
    ));

    // Bit-flipped / truncated proof bytes. REJECT.
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
    // A witness for a DIFFERENT leaf yields a different implied root; the
    // real root cannot be substituted. REJECT.
    let (key, notes, tree) = kat_fixture();
    let wrong_path = tree.witness(0).expect("witness").0;
    let spends = vec![BundleSpend {
        key,
        note: notes[0],
        path: wrong_path,
    }];
    let (proof, pub_inputs) = prove_bundle(&spends, &[], 0, KAT_VALUE_0 - 7, 7).expect("prove");
    assert_ne!(
        pub_inputs.anchors[0],
        tree.root(),
        "wrong path reproduced the true root"
    );
    let mut forged = pub_inputs.clone();
    forged.anchors[0] = tree.root();
    assert!(
        verify_spend(&proof, &forged).is_err(),
        "proof with wrong Merkle path accepted under the true root"
    );
}

#[test]
fn foreign_note_cannot_be_spent() {
    // The sender knows the recipient's full note opening but not nsk.
    let (_, notes, tree) = kat_fixture();
    let thief = SpendingKey::from_seed(&[0x66; 32]);
    let spends = vec![BundleSpend {
        key: thief,
        note: notes[0],
        path: tree.witness(1).expect("witness").0,
    }];
    assert!(matches!(
        prove_bundle(&spends, &[], 0, KAT_VALUE_0, 0),
        Err(SpendProofError::InvalidWitness(_))
    ));
}

#[test]
fn unbalanced_witness_refused_by_builder() {
    let (spends, outputs, _) = kat_bundle_witness();
    assert!(matches!(
        prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE + 1),
        Err(SpendProofError::InvalidWitness("value conservation"))
    ));
}

// --- Negative tests: WITNESS-side constraint families. ------------------

/// Attempt to prove tampered columns; the constraint system must reject in
/// every profile (see the module docs). In debug builds `expected_violation`
/// must appear in winterfell's validation panic, proving the EXACT
/// constraint under test fired (not some unrelated failure).
fn expect_circuit_reject(
    cols: Vec<Vec<Felt>>,
    pub_inputs: &BundlePublicInputs,
    expected_violation: &str,
    what: &str,
) {
    let pi = pub_inputs.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let trace = TraceTable::init(cols);
        BundleProver::new(pi.clone()).prove(trace)
    }));
    match outcome {
        // Debug-mode trace validation caught a violated constraint: it must
        // be the one under test.
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic>");
            assert!(
                msg.contains(expected_violation),
                "{what}: rejected, but by {msg:?} instead of {expected_violation:?}"
            );
        }
        // The prover itself refused.
        Ok(Err(_)) => {}
        // A proof came out anyway (release profile): it must not verify.
        Ok(Ok(proof)) => assert!(
            verify_spend(&proof.to_bytes(), pub_inputs).is_err(),
            "{what}: forged proof accepted"
        ),
    }
}

/// Re-run one 8-row Rescue hash cycle in the trace columns (test-side twin
/// of the builder's cycle filler) and return the output digest.
fn fill_hash_cycle(cols: &mut [Vec<Felt>], cycle: usize, mut state: [Felt; 12]) -> [Felt; 4] {
    use winter_crypto::hashers::Rp64_256;
    let base = cycle * 8;
    for (j, s) in state.iter().enumerate() {
        cols[j][base] = *s;
    }
    for round in 0..7 {
        Rp64_256::apply_round(&mut state, round);
        for (j, s) in state.iter().enumerate() {
            cols[j][base + round + 1] = *s;
        }
    }
    state[4..8].try_into().expect("4 elements")
}

/// Sponge init state for a domain-separated 2-to-1 merge.
fn sponge_init(domain: u64, left: [Felt; 4], right: [Felt; 4]) -> [Felt; 12] {
    let mut state = [Felt::ZERO; 12];
    state[0] = Felt::new(8);
    state[1] = Felt::new(domain);
    state[4..8].copy_from_slice(&left);
    state[8..12].copy_from_slice(&right);
    state
}

/// Rewrite value `m`'s range-check segment for an arbitrary MSB-first
/// digit vector (field arithmetic, so non-boolean digits stay consistent
/// with the accumulator recurrence — only the boolean constraint can
/// catch them).
fn refill_rc_segment(cols: &mut [Vec<Felt>], m: usize, digits: &[u64]) {
    assert_eq!(digits.len(), VALUE_BITS);
    let base = rc_base(m);
    let mut acc = Felt::ZERO;
    cols[RC_ACC_COL][base] = Felt::ZERO;
    for (t, &d) in digits.iter().enumerate() {
        acc = acc + acc + Felt::new(d);
        cols[RC_BIT_COL][base + t + 1] = Felt::new(d);
        cols[RC_ACC_COL][base + t + 1] = acc;
    }
}

fn msb_bits(v: u64) -> Vec<u64> {
    (0..VALUE_BITS)
        .map(|t| (v >> (VALUE_BITS - 1 - t)) & 1)
        .collect()
}

#[test]
fn non_boolean_range_check_digit_rejected() {
    // OUT-OF-RANGE / RANGE-CHECK family: encode input 0's value with a
    // digit of 2 (…, b_{k}=1, b_{k-1}=0 → b_{k}=0, b_{k-1}=2 — same
    // accumulator landing, so ONLY the bit-boolean constraint can object).
    // If any claimed bit were unconstrained this forgery would pass. REJECT.
    let (spends, outputs, _) = kat_bundle_witness();
    let (mut cols, pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    let v = KAT_VALUE_0;
    let k = v.trailing_zeros() as usize;
    assert!(k >= 1, "fixture value must have its lowest set bit above 0");
    let mut digits = msb_bits(v);
    digits[VALUE_BITS - 1 - k] = 0; // clear bit k
    digits[VALUE_BITS - k] = 2; // digit 2 at weight 2^(k-1)
    refill_rc_segment(&mut cols, 0, &digits);
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 119", // the bit-boolean constraint
        "non-boolean range-check digit",
    );
}

#[test]
fn range_check_landing_must_match_value_register() {
    // OUT-OF-RANGE family: output 0 claims the value 2^61 with a FULLY
    // consistent forgery — hash segment recomputed for 2^61, commitment
    // public updated to match, register updated, balance compensated
    // through t_in (input note = MAX_NOTE_VALUE, so MAX + 1 = 2^61 holds
    // in the field). The ONLY objection left is the range-check landing:
    // no 61-digit boolean decomposition reaches 2^61. REJECT.
    use sov_shielded_pq::domains::{RESCUE_DOMAIN_COMMIT_STAGE1, RESCUE_DOMAIN_COMMIT_STAGE2};
    let seed = [0x51u8; 32];
    let key = SpendingKey::from_seed(&seed);
    let big = Note::new(MAX_NOTE_VALUE, key.owner_tag(), derive_rho(&seed, 0)).expect("note");
    let mut tree = CommitmentTree::new();
    tree.append(big.commitment()).expect("append");
    let path = tree.witness(0).expect("witness").0;
    let spends = vec![BundleSpend {
        key: key.clone(),
        note: big,
        path,
    }];
    let out_note = Note::new(MAX_NOTE_VALUE, key.owner_tag(), derive_rho(&seed, 1)).expect("note");
    let (mut cols, mut pub_inputs) =
        build_bundle_columns(&spends, &[out_note], 0, 0, 0).expect("build");
    // Rebuild output 0's segment (cycles 96/97) for value 2^61.
    let too_big = Felt::new(1u64 << VALUE_BITS);
    let vpad = [too_big, Felt::ZERO, Felt::ZERO, Felt::ZERO];
    let d1 = fill_hash_cycle(
        &mut cols,
        96,
        sponge_init(
            RESCUE_DOMAIN_COMMIT_STAGE1,
            vpad,
            out_note.owner_tag.to_elements(),
        ),
    );
    let cm = fill_hash_cycle(
        &mut cols,
        97,
        sponge_init(RESCUE_DOMAIN_COMMIT_STAGE2, d1, out_note.rho.to_elements()),
    );
    pub_inputs.output_commitments[0] = PqDigest::from_elements(cm);
    cols[VAL_COL + NUM_SLOTS][..ACTIVE_ROWS].fill(too_big);
    // Best boolean decomposition a cheater can offer: all ones = 2^61 - 1.
    refill_rc_segment(&mut cols, NUM_SLOTS, &vec![1u64; VALUE_BITS]);
    // Balance: MAX + t_in(1) = 2^61 + 0 + 0 — satisfied in the field.
    pub_inputs.transparent_in = 1;
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 124", // the range-check landing for output 0
        "out-of-range value register",
    );
}

#[test]
fn dummy_with_nonzero_value_rejected() {
    // DUMMY family: rebuild dummy input slot 2 as a fully-consistent
    // value-5 segment (hash chain, register, range check all agree; the
    // public t_out is raised by 5 so even the balance constraint is
    // happy). The ONLY thing left objecting is the dummy value-zero
    // assertion — exactly the constraint under test. REJECT.
    let (spends, outputs, _) = kat_bundle_witness();
    let smuggled = 5u64;
    let (mut cols, mut pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    assert!(pub_inputs.input_dummy[2]);

    // Re-run the dummy slot's hash segment with value = 5 (nsk = rho = 0,
    // zero path, dummy nullifier domain), exactly as the builder would for
    // a real value-5 witness.
    let seg_cycle = 2 * 24;
    let run_cycle = fill_hash_cycle;
    let init = sponge_init;
    use sov_shielded_pq::domains::{
        RESCUE_DOMAIN_COMMIT_STAGE1, RESCUE_DOMAIN_COMMIT_STAGE2, RESCUE_DOMAIN_DUMMY_NULLIFIER,
        RESCUE_DOMAIN_MERKLE_NODE, RESCUE_DOMAIN_OWNER_TAG,
    };
    let zero4 = [Felt::ZERO; 4];
    let tag = run_cycle(
        &mut cols,
        seg_cycle,
        init(RESCUE_DOMAIN_OWNER_TAG, zero4, zero4),
    );
    let vpad = [Felt::new(smuggled), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    let d1 = run_cycle(
        &mut cols,
        seg_cycle + 1,
        init(RESCUE_DOMAIN_COMMIT_STAGE1, vpad, tag),
    );
    let mut acc = run_cycle(
        &mut cols,
        seg_cycle + 2,
        init(RESCUE_DOMAIN_COMMIT_STAGE2, d1, zero4),
    );
    for level in 0..20 {
        acc = run_cycle(
            &mut cols,
            seg_cycle + 3 + level,
            init(RESCUE_DOMAIN_MERKLE_NODE, acc, zero4),
        );
    }
    run_cycle(
        &mut cols,
        seg_cycle + 23,
        init(RESCUE_DOMAIN_DUMMY_NULLIFIER, zero4, zero4),
    );
    // Value register + range check for the smuggled value.
    cols[VAL_COL + 2][..ACTIVE_ROWS].fill(Felt::new(smuggled));
    refill_rc_segment(&mut cols, 2, &msb_bits(smuggled));
    // Balance the smuggled value through the public unshield leg.
    pub_inputs.transparent_out += smuggled;
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "assertion main_trace(23, 0)", // the dummy value-zero assertion, VAL_COL + 2
        "dummy with nonzero value",
    );
}

#[test]
fn inconsistent_value_register_rejected() {
    // VALUE-BINDING family: the register claims v+1 (range check made
    // consistent) while the hash absorbed v — the commitment-absorption
    // wiring must object. REJECT.
    let (spends, outputs, _) = kat_bundle_witness();
    let (mut cols, mut pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    cols[VAL_COL][..ACTIVE_ROWS].fill(Felt::new(KAT_VALUE_0 + 1));
    refill_rc_segment(&mut cols, 0, &msb_bits(KAT_VALUE_0 + 1));
    // Compensate the balance publicly so ONLY the commitment-absorption
    // wiring (register vs the value the hash actually committed) objects.
    pub_inputs.transparent_out += 1;
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 55", // tag-injection value absorb, input 0
        "value register vs absorbed value",
    );
}

// --- Constancy families (audit S1 follow-up: the mint / double-spend guards). --
// These three transition-constraint families were flagged by the S1 audit as
// defended-but-untested. Each test isolates its constraint by perturbing a
// single register cell at the balance row (row 0), where the register is held
// (not hash-injected), so the constancy constraint is the FIRST — and lowest-
// indexed — objection winterfell's debug validation raises. Without the
// constraint, each perturbation would MINT or DOUBLE-SPEND.

#[test]
fn value_register_non_constant_rejected() {
    // MINT vector: inflate input 0's value register at the balance row ONLY
    // and withdraw the surplus through the public unshield leg, so the balance
    // constraint stays satisfied and the commitment hash (absorbed on a later
    // row) still commits the honest value. The ONLY objection is value-register
    // constancy (constraint 20). Absent it, this mints `surplus` grains.
    let (spends, outputs, _) = kat_bundle_witness();
    let (mut cols, mut pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    let surplus = 7u64;
    cols[VAL_COL][0] += Felt::new(surplus);
    pub_inputs.transparent_out += surplus;
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 20",
        "value-register non-constant (mint)",
    );
}

#[test]
fn nsk_register_non_constant_rejected() {
    // DOUBLE-SPEND vector: `nsk` must be constant across input 0's segment —
    // it binds the owner tag (ownership) AND the nullifier to the SAME secret.
    // Perturbing the nsk register breaks nsk-constancy (constraint 16) before
    // any hash constraint; without it a prover could derive a SECOND, distinct
    // nullifier for an already-spent note. REJECT.
    let (spends, outputs, _) = kat_bundle_witness();
    let (mut cols, pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    cols[NSK_COL][0] += Felt::new(1);
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 16",
        "nsk-register non-constant (double-spend)",
    );
}

#[test]
fn rho_register_non_constant_rejected() {
    // The note randomness `rho` must be constant across input 0's segment (it
    // binds the commitment AND the nullifier). Perturbing the rho register
    // breaks rho-constancy (constraint 12). REJECT.
    let (spends, outputs, _) = kat_bundle_witness();
    let (mut cols, pub_inputs) =
        build_bundle_columns(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("build");
    cols[RHO_COL][0] += Felt::new(1);
    expect_circuit_reject(
        cols,
        &pub_inputs,
        "transition constraint 12",
        "rho-register non-constant",
    );
}

#[test]
fn verify_spend_rejects_nonzero_dummy_publics() {
    // Defense-in-depth (audit S1 #2): even bypassing `verify_bundle`, a dummy
    // slot presenting nonzero publics is refused by `verify_spend` BEFORE the
    // proof is checked.
    let (spends, outputs, _) = kat_bundle_witness();
    let (proof, pub_inputs) =
        prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("prove");
    verify_spend(&proof, &pub_inputs).expect("honest bundle verifies");
    let d = (0..NUM_SLOTS)
        .find(|&i| pub_inputs.input_dummy[i])
        .expect("a dummy input slot exists in the KAT bundle");
    let mut forged = pub_inputs.clone();
    forged.nullifiers[d] = PqDigest::from_elements([Felt::new(1); 4]);
    assert!(
        matches!(
            verify_spend(&proof, &forged),
            Err(SpendProofError::PublicInput(_))
        ),
        "nonzero dummy input publics must be refused pre-proof"
    );
}

#[test]
fn auth_pk_swap_rejected() {
    // Audit S1 #3: the carrier signature binds the AUTHORIZING KEY. Swapping
    // the public key (keeping the signature) changes the recomputed digest, so
    // `verify_bundle` refuses — the signature attests "THIS key authorized THIS
    // bundle", not mere well-formedness.
    let (mut bundle, anchors) = kat_carrier_bundle();
    verify_bundle(&bundle, &anchors).expect("honest carrier bundle verifies");
    let other = AuthKeypair::from_seed(&[0x99u8; 32]);
    bundle.auth_pk = other.public_bytes();
    assert!(matches!(
        verify_bundle(&bundle, &anchors),
        Err(BundleError::Auth)
    ));
}

// --- Bundle layer (carrier auth + native checks). -----------------------

fn kat_carrier_bundle() -> (SpendBundle, Vec<PqDigest>) {
    let (spends, outputs, tree) = kat_bundle_witness();
    let recipient_kem = EncryptionKeypair::generate().expect("keygen");
    let (proof, pub_inputs) =
        prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("prove");
    let cts: [Option<NoteCiphertext>; 4] = [
        Some(encrypt_note(&recipient_kem.public_bytes(), &outputs[0]).expect("encrypt")),
        Some(encrypt_note(&recipient_kem.public_bytes(), &outputs[1]).expect("encrypt")),
        None,
        None,
    ];
    let auth = AuthKeypair::from_seed(&KAT_SEED);
    let digest = bundle_digest(&pub_inputs, &cts, &auth.public_bytes());
    let bundle = SpendBundle {
        public_inputs: pub_inputs,
        proof_bytes: proof,
        output_ciphertexts: cts,
        auth_pk: auth.public_bytes(),
        auth_sig: auth.sign(&digest).expect("sign"),
    };
    (bundle, vec![tree.root()])
}

#[test]
fn bundle_end_to_end() {
    let (bundle, anchors) = kat_carrier_bundle();
    verify_bundle(&bundle, &anchors).expect("bundle verifies");

    // Anchor outside the caller's valid set. REJECT.
    assert!(matches!(
        verify_bundle(&bundle, &[digest_from_bytes(B3_TEST, b"ring")]),
        Err(BundleError::Anchor(0))
    ));

    // Bad ML-DSA signature. REJECT.
    let (mut bad, a) = kat_carrier_bundle();
    bad.auth_sig[0] ^= 1;
    assert!(matches!(verify_bundle(&bad, &a), Err(BundleError::Auth)));

    // Reshaping the publics under an existing signature (fee -> fee+1)
    // breaks BOTH the proof and the signature; the proof rejects first.
    let (mut bad, a) = kat_carrier_bundle();
    bad.public_inputs.fee_grains += 1;
    assert!(matches!(
        verify_bundle(&bad, &a),
        Err(BundleError::Proof(_))
    ));

    // Tampered (nonzero) output commitment: STARK assertion mismatch.
    let (mut bad, a) = kat_carrier_bundle();
    bad.public_inputs.output_commitments[0] = PqDigest([5, 5, 5, 5]);
    assert!(matches!(
        verify_bundle(&bad, &a),
        Err(BundleError::Proof(_))
    ));

    // Dummy-slot convention violations: typed rejects.
    let (mut bad, a) = kat_carrier_bundle();
    bad.public_inputs.nullifiers[2] = PqDigest([9, 9, 9, 9]);
    assert!(matches!(
        verify_bundle(&bad, &a),
        Err(BundleError::DummySlot(2))
    ));
    let (mut bad, a) = kat_carrier_bundle();
    bad.output_ciphertexts[2] = bad.output_ciphertexts[0].clone();
    assert!(matches!(
        verify_bundle(&bad, &a),
        Err(BundleError::DummySlot(2))
    ));
}

#[test]
fn duplicate_nullifier_in_bundle_rejected() {
    // Spend the SAME note in two slots: the circuit proves each slot
    // honestly, but the bundle layer must refuse the duplicate nullifier.
    let (key, notes, tree) = kat_fixture();
    let path = tree.witness(1).expect("witness").0;
    let spends = vec![
        BundleSpend {
            key: key.clone(),
            note: notes[0],
            path: path.clone(),
        },
        BundleSpend {
            key: key.clone(),
            note: notes[0],
            path,
        },
    ];
    let (proof, pub_inputs) = prove_bundle(&spends, &[], 0, 2 * KAT_VALUE_0, 0).expect("prove");
    let cts: [Option<NoteCiphertext>; 4] = [None, None, None, None];
    let auth = AuthKeypair::from_seed(&KAT_SEED);
    let digest = bundle_digest(&pub_inputs, &cts, &auth.public_bytes());
    let bundle = SpendBundle {
        public_inputs: pub_inputs,
        proof_bytes: proof,
        output_ciphertexts: cts,
        auth_pk: auth.public_bytes(),
        auth_sig: auth.sign(&digest).expect("sign"),
    };
    assert!(matches!(
        verify_bundle(&bundle, &[tree.root()]),
        Err(BundleError::DuplicateNullifier)
    ));
}

#[test]
fn recipient_decrypts_their_output() {
    let (_, outputs, _) = kat_bundle_witness();
    let recipient = EncryptionKeypair::generate().expect("keygen");
    let ct = encrypt_note(&recipient.public_bytes(), &outputs[0]).expect("encrypt");
    assert_eq!(recipient.decrypt(&ct).expect("decrypt"), outputs[0]);
}

/// Honest measurement of prove/verify time and proof size on this machine.
/// Run with `cargo test -p sov-shielded-pq --release -- benchmark --nocapture`.
#[test]
fn benchmark_bundle_proof() {
    use std::time::Instant;
    let (spends, outputs, _) = kat_bundle_witness();

    // Warm-up + correctness.
    let (proof, pub_inputs) =
        prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("prove");
    verify_spend(&proof, &pub_inputs).expect("verify");

    const N: usize = 3;
    let t0 = Instant::now();
    let mut last = None;
    for _ in 0..N {
        last = Some(prove_bundle(&spends, &outputs, 0, KAT_T_OUT, KAT_FEE).expect("prove"));
    }
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0 / N as f64;
    let (proof, pub_inputs) = last.expect("proved");

    let t1 = Instant::now();
    for _ in 0..N {
        verify_spend(&proof, &pub_inputs).expect("verify");
    }
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / N as f64;

    let parsed = winterfell::Proof::from_bytes(&proof).expect("parse");
    println!("--- sov-shielded-pq 4-in/4-out bundle proof benchmark (this machine) ---");
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
