#![no_main]
//! Fuzz: account-name validation over arbitrary UTF-8 must never panic — it must
//! cleanly accept or reject every input.

use libfuzzer_sys::fuzz_target;
use sov_primitives::AccountId;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = AccountId::new(s);
    }
});
