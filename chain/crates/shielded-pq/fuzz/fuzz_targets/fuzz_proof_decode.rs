//! Arbitrary bytes → the proof frame pre-validator + the guarded
//! winterfell decode boundary (S1c/D15).
//!
//! The first byte selects one of the 256 public dummy-flag patterns (the
//! expected proof context varies with it); the rest is the proof
//! candidate. Oracles:
//!
//! - `decode_proof` must never panic (libFuzzer flags it as a crash);
//! - the `catch_unwind` LAST line of defense must never fire: an input
//!   that passes the pre-validator and still panics inside winterfell
//!   yields `SpendProofError::DecodePanic`, which this target asserts
//!   into a crash — so a pre-validator gap is a fuzzing FINDING even
//!   though production would survive it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sov_shielded_pq::air::BundlePublicInputs;
use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::prover::{decode_proof, SpendProofError};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, proof_bytes)) = data.split_first() else {
        return;
    };
    // Nonzero digests/legs for the non-dummy slots so the shape is
    // realistic; the frame validator only depends on the flag pattern.
    let mut pub_inputs = BundlePublicInputs {
        anchors: [PqDigest::ZERO; 4],
        nullifiers: [PqDigest::ZERO; 4],
        input_dummy: [false; 4],
        output_commitments: [PqDigest::ZERO; 4],
        output_dummy: [false; 4],
        transparent_in: 1,
        transparent_out: 1,
        fee_grains: 0,
    };
    for i in 0..4 {
        pub_inputs.input_dummy[i] = sel & (1 << i) != 0;
        pub_inputs.output_dummy[i] = sel & (1 << (4 + i)) != 0;
        if !pub_inputs.input_dummy[i] {
            pub_inputs.anchors[i] = PqDigest([1, 2, 3, i as u64 + 1]);
            pub_inputs.nullifiers[i] = PqDigest([4, 5, 6, i as u64 + 1]);
        }
        if !pub_inputs.output_dummy[i] {
            pub_inputs.output_commitments[i] = PqDigest([7, 8, 9, i as u64 + 1]);
        }
    }
    if let Err(SpendProofError::DecodePanic) = decode_proof(proof_bytes, &pub_inputs) {
        panic!("pre-validated input panicked inside winterfell: pre-validator gap");
    }
});
