#![no_main]
//! Fuzz: Borsh-decoding untrusted bytes into a [`Block`] must only ever return an
//! error — never panic. Blocks arrive from peers, so this is consensus-critical
//! attack surface.

use libfuzzer_sys::fuzz_target;
use sov_types::Block;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<Block>(data);
});
