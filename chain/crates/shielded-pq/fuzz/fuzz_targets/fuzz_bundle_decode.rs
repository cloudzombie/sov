//! Arbitrary bytes → the TOTAL v1 bundle decoder (S1c).
//!
//! Oracle: `decode_bundle` must never panic (libFuzzer flags any panic as
//! a crash), and every ACCEPTED input must re-encode byte-identically
//! (the v1 wire format is canonical).

#![no_main]

use libfuzzer_sys::fuzz_target;
use sov_shielded_pq::wire::{decode_bundle, encode_bundle};

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = decode_bundle(data) {
        assert_eq!(
            encode_bundle(&bundle),
            data,
            "v1 wire format accepted a non-canonical encoding"
        );
    }
});
