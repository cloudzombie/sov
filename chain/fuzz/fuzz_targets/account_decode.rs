#![no_main]
//! Fuzz: Borsh-decoding untrusted bytes into an [`Account`] must only ever return
//! an error — never panic. Account records are read back from persisted state.

use libfuzzer_sys::fuzz_target;
use sov_state::Account;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<Account>(data);
});
