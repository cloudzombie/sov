//! Example SOV smart contract: a persistent counter.
//!
//! Each `call()` reads the current count from storage, increments it, writes it
//! back, and returns the new value. State persists across calls (the host
//! commits storage on success), so successive calls return 1, 2, 3, …
//!
//! Written entirely in safe Rust against [`sov_sdk`]; it compiles to
//! `wasm32-unknown-unknown` and runs on the `sov-vm` runtime.

#![no_std]

extern crate alloc;

const COUNTER_KEY: &[u8] = b"count";

#[no_mangle]
pub extern "C" fn call() -> i32 {
    let current = match sov_sdk::get(COUNTER_KEY) {
        Some(bytes) if bytes.len() == 4 => {
            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
        _ => 0,
    };
    let next = current + 1;
    sov_sdk::set(COUNTER_KEY, &next.to_le_bytes());
    next
}
