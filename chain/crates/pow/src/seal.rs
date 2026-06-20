//! The proof-of-work **seal algorithm**: how a block header's bytes are hashed
//! to the value compared against the difficulty target.
//!
//! SOV's mainnet seal is **RandomX** — Monero's memory-hard, CPU-friendly
//! proof of work — so commodity machines (in particular Apple M-series metal)
//! get a fair shot and the network bootstraps without ASIC capture. A
//! development/test chain may instead use Bitcoin's fast **SHA-256d**, so the
//! test suite mines instantly; the choice is a genesis-fixed consensus
//! parameter on [`MiningPolicy`](../../mining), identical on every node.
//!
//! Neither algorithm is hand-rolled: SHA-256d uses `sha2`, and RandomX uses the
//! audited `randomx-rs` bindings to the reference C++ implementation.
//!
//! ## RandomX VM lifecycle
//!
//! A RandomX VM holds a large (~256 MiB) cache and a mutable scratchpad; it is
//! not thread-safe and its FFI handles are not `Send`/`Sync`. Rather than store
//! one in the (shared, `Send`+`Sync`) chain, each thread keeps its **own** VM in
//! thread-local storage, built lazily on first use and rebuilt only if the
//! RandomX key changes. So the seal function is a plain `fn` that any thread may
//! call, the VM never crosses a thread boundary, and no `unsafe` is needed.

use std::cell::RefCell;

use borsh::{BorshDeserialize, BorshSerialize};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};

use crate::algorithm::sha256d;

/// The proof-of-work seal algorithm a chain uses — a genesis-fixed consensus
/// parameter (all nodes must agree). Carried by `MiningPolicy`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PowAlgo {
    /// Bitcoin's double-SHA-256 — fast to compute and verify; used for
    /// development and the test suite so blocks mine instantly. NOT
    /// ASIC-resistant.
    Sha256d,
    /// Monero's **RandomX** — memory-hard and CPU-optimized, so commodity
    /// hardware (Apple M-series included) competes fairly and the chain resists
    /// ASIC capture. The mainnet seal.
    RandomX,
}

thread_local! {
    /// This thread's RandomX VM, paired with the key it was built for. Built on
    /// first RandomX seal and reused; rebuilt only when the key changes.
    static RANDOMX_VM: RefCell<Option<(Vec<u8>, RandomXVM)>> = const { RefCell::new(None) };
}

/// Hash `input` with this thread's RandomX VM for `key`, building/rebuilding the
/// VM as needed. `key` selects the RandomX dataset (a chain-wide consensus
/// value, e.g. the genesis hash); `input` is the header preimage.
fn randomx_hash(key: &[u8], input: &[u8]) -> [u8; 32] {
    RANDOMX_VM.with(|cell| {
        let mut slot = cell.borrow_mut();
        let needs_build = match slot.as_ref() {
            Some((existing_key, _)) => existing_key.as_slice() != key,
            None => true,
        };
        if needs_build {
            let flags = RandomXFlag::get_recommended_flags();
            let cache = RandomXCache::new(flags, key).expect("RandomX cache initialization");
            let vm = RandomXVM::new(flags, Some(cache), None).expect("RandomX VM initialization");
            *slot = Some((key.to_vec(), vm));
        }
        let (_, vm) = slot.as_ref().expect("VM is present after build");
        let digest = vm.calculate_hash(input).expect("RandomX hash");
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    })
}

/// Compute the proof-of-work seal of a header preimage under `algo`. The result
/// is the 32-byte value consensus compares against the difficulty target
/// (smaller = more work). `key` is the chain's RandomX key (ignored by
/// SHA-256d).
pub fn pow_seal(algo: PowAlgo, key: &[u8], input: &[u8]) -> [u8; 32] {
    match algo {
        PowAlgo::Sha256d => sha256d(input),
        PowAlgo::RandomX => randomx_hash(key, input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_seal_matches_double_sha256() {
        assert_eq!(pow_seal(PowAlgo::Sha256d, b"key", b"abc"), sha256d(b"abc"));
        // SHA-256d ignores the key.
        assert_eq!(
            pow_seal(PowAlgo::Sha256d, b"k1", b"abc"),
            pow_seal(PowAlgo::Sha256d, b"k2", b"abc")
        );
    }

    #[test]
    fn randomx_seal_is_deterministic_and_input_sensitive() {
        let key = b"sov-genesis-key";
        let a = pow_seal(PowAlgo::RandomX, key, b"header-bytes");
        let a2 = pow_seal(PowAlgo::RandomX, key, b"header-bytes");
        assert_eq!(a, a2, "same key+input is deterministic");
        assert_ne!(
            a,
            pow_seal(PowAlgo::RandomX, key, b"other-bytes"),
            "different input differs"
        );
        // A different key (dataset) gives a different hash for the same input.
        assert_ne!(a, pow_seal(PowAlgo::RandomX, b"other-key", b"header-bytes"));
        // And RandomX is not SHA-256d.
        assert_ne!(a, pow_seal(PowAlgo::Sha256d, key, b"header-bytes"));
    }
}
