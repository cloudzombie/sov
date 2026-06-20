//! End-to-end test: run a *real* compiled SOV contract on the VM.
//!
//! `counter.wasm` is built from `chain/contracts/counter` (Rust + sov-sdk) via
//! `cargo build --target wasm32-unknown-unknown --release`. This proves the full
//! authoring path — write a contract in Rust, compile to Wasm, execute on
//! `sov-vm` with real host storage — works, not just hand-written WAT.

use sov_vm::{execute, ContractStorage, ExecContext};

const COUNTER_WASM: &[u8] = include_bytes!("counter.wasm");

fn ctx() -> ExecContext {
    ExecContext {
        block_height: 1,
        ..ExecContext::default()
    }
}

#[test]
fn counter_contract_increments_and_persists() {
    let mut storage = ContractStorage::new();

    // Each call reads, increments, and writes the persisted counter.
    let first = execute(COUNTER_WASM, "call", 10_000_000, ctx(), &mut storage).unwrap();
    assert_eq!(first.status, 1);
    assert!(first.gas_used > 0);

    let second = execute(COUNTER_WASM, "call", 10_000_000, ctx(), &mut storage).unwrap();
    assert_eq!(second.status, 2);

    let third = execute(COUNTER_WASM, "call", 10_000_000, ctx(), &mut storage).unwrap();
    assert_eq!(third.status, 3);

    // The committed storage holds the latest count (4-byte little-endian 3).
    assert_eq!(storage.get(b"count"), Some(&3i32.to_le_bytes()[..]));
}
