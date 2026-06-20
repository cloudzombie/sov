#![no_main]
//! Fuzz: Borsh-decoding untrusted bytes into a [`SignedTransaction`] must only
//! ever return an error — never panic, never loop, never mis-decode.

use libfuzzer_sys::fuzz_target;
use sov_types::SignedTransaction;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<SignedTransaction>(data);
});
