//! MEASURED verification cost and wire size of a pool-v2 bundle.
//!
//! The transaction/block **weight** schedule (`sov_types::weight`) and the
//! `ShieldedV2` gas price (`sov_runtime::gas`) are both derived from two
//! numbers that must be measured, never guessed:
//!
//! 1. the serialized wire size of a realistic bundle, and
//! 2. the wall-clock cost of verifying its STARK proof.
//!
//! This test measures both and prints them, and asserts only the LOOSE
//! bounds the weight derivation actually relies on (a tight assertion on a
//! wall-clock number would be a flaky test on shared CI hardware). The
//! derivation itself, with the numbers this test produced, is written down
//! in `sov_types::weight`.
//!
//! Run with `cargo test -p sov-shielded-pq --release --test verify_cost -- --nocapture`
//! to see the measurement. Debug builds are ~50x slower for STARK work, so
//! the assertions below are sized for a debug run.

use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::note::{derive_rho, Note, SpendingKey};
use sov_shielded_pq::prover::{prove_bundle, verify_spend, BundleSpend};
use sov_shielded_pq::tree::CommitmentTree;
use std::time::Instant;

const SEED: [u8; 32] = [0x42; 32];
const VALUE_0: u64 = 1_250_000_000;
const VALUE_1: u64 = 300_000_000;
const FEE: u64 = 1_000;
const T_OUT: u64 = 50_000_000;

/// A realistic 2-in / 2-out bundle (the shape a wallet actually produces:
/// one payment + one change note), padded to the fixed 4-in/4-out arity
/// with in-circuit dummies.
fn realistic_bundle() -> (Vec<u8>, sov_shielded_pq::air::BundlePublicInputs) {
    let key = SpendingKey::from_seed(&SEED);
    let note0 = Note::new(VALUE_0, key.owner_tag(), derive_rho(&SEED, 1)).expect("note");
    let note1 = Note::new(VALUE_1, key.owner_tag(), derive_rho(&SEED, 3)).expect("note");
    let decoy0 = Note::new(1, key.owner_tag(), derive_rho(&SEED, 0)).expect("note");
    let decoy2 = Note::new(2, key.owner_tag(), derive_rho(&SEED, 2)).expect("note");
    let mut tree = CommitmentTree::new();
    tree.append(decoy0.commitment()).expect("append");
    tree.append(note0.commitment()).expect("append");
    tree.mark().expect("mark");
    tree.append(decoy2.commitment()).expect("append");
    tree.append(note1.commitment()).expect("append");
    tree.mark().expect("mark");

    let recipient = SpendingKey::from_seed(&[0x77; 32]);
    let out_value = 400_000_000;
    let change = VALUE_0 + VALUE_1 - out_value - FEE - T_OUT;
    let out_note =
        Note::new(out_value, recipient.owner_tag(), derive_rho(&[0x55; 32], 0)).expect("note");
    let change_note = Note::new(change, key.owner_tag(), derive_rho(&SEED, 100)).expect("note");
    let spends = vec![
        BundleSpend {
            key: key.clone(),
            note: note0,
            path: tree.witness(1).expect("witness").0,
        },
        BundleSpend {
            key,
            note: note1,
            path: tree.witness(3).expect("witness").0,
        },
    ];
    prove_bundle(&spends, &[out_note, change_note], 0, T_OUT, FEE).expect("prove")
}

#[test]
fn measure_v2_proof_size_and_verify_cost() {
    let (proof, publics) = realistic_bundle();

    // A verification must succeed before we time it — timing a failing path
    // would measure the wrong thing (an early reject is far cheaper).
    verify_spend(&proof, &publics).expect("the honest bundle verifies");

    // Warm up, then take the MEDIAN of an odd number of runs: a median is
    // robust to a single scheduler hiccup on a shared CI box, and (unlike a
    // mean) is an actually-observed sample.
    for _ in 0..3 {
        verify_spend(&proof, &publics).expect("verify");
    }
    let mut samples_us: Vec<u128> = Vec::new();
    for _ in 0..11 {
        let t = Instant::now();
        verify_spend(&proof, &publics).expect("verify");
        samples_us.push(t.elapsed().as_micros());
    }
    samples_us.sort_unstable();
    let median_us = samples_us[samples_us.len() / 2];

    println!("v2 proof bytes            = {}", proof.len());
    println!("v2 verify median          = {median_us} us");
    println!("v2 verify samples (us)    = {samples_us:?}");

    // The weight derivation relies on the proof fitting the wire codec's
    // 128 KiB `MAX_PROOF_LEN`, with real margin. Assert the bound, not the
    // exact size (the exact size is pinned by the KAT suite).
    assert!(
        proof.len() <= sov_shielded_pq::MAX_PROOF_LEN,
        "proof {} exceeds MAX_PROOF_LEN {}",
        proof.len(),
        sov_shielded_pq::MAX_PROOF_LEN
    );

    // The weight schedule budgets 32 ms of verification per v2 bundle (see
    // `sov_types::weight::SHIELDED_V2_VERIFY_WEIGHT`). A DEBUG build is
    // ~50x slower than the release build the fleet runs, so this test only
    // asserts a ceiling loose enough to pass unoptimized while still
    // catching a genuine order-of-magnitude regression.
    let ceiling_us = if cfg!(debug_assertions) {
        2_000_000
    } else {
        32_000
    };
    assert!(
        median_us <= ceiling_us,
        "v2 verify median {median_us} us exceeds the {ceiling_us} us budget \
         — the weight/gas schedule in sov_types::weight was derived from a \
         much cheaper verification and must be re-derived"
    );
}

#[test]
fn dummy_publics_are_zero_in_a_padded_bundle() {
    // The measured bundle is 2-in/2-out padded to 4/4; the padding slots
    // must carry the zero-digest convention the verifier enforces. This
    // pins that the thing we measured really is the padded shape (so the
    // measurement is of a full 4/4 trace, i.e. the WORST case per bundle,
    // not a cheaper narrow one).
    let (_, publics) = realistic_bundle();
    assert!(publics.input_dummy[2] && publics.input_dummy[3]);
    assert!(publics.output_dummy[2] && publics.output_dummy[3]);
    assert_eq!(publics.nullifiers[2], PqDigest::ZERO);
    assert_eq!(publics.output_commitments[3], PqDigest::ZERO);
}
