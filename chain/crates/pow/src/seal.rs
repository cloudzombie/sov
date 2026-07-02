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
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
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
    /// This thread's LIGHT RandomX VM (cache-only, ~256 MiB), paired with the key it
    /// was built for. Used for VERIFICATION — one hash per block — so a non-mining node
    /// (RPC, explorer, small seed VPS) stays lean. Built lazily, rebuilt on key change.
    static RANDOMX_VM_LIGHT: RefCell<Option<(Vec<u8>, RandomXVM)>> = const { RefCell::new(None) };
    /// This thread's FAST RandomX VM (full ~2 GiB dataset, FLAG_FULL_MEM), for the
    /// MINING hot loop — roughly 10× the hash rate of light mode. Built lazily on the
    /// single mining thread; the ~2 GiB dataset is allocated once per key.
    static RANDOMX_VM_FAST: RefCell<Option<(Vec<u8>, RandomXVM)>> = const { RefCell::new(None) };
}

/// Build a RandomX VM for `key`. In `fast` mode it allocates the full ~2 GiB dataset
/// (`FLAG_FULL_MEM`) for ~10× the hash rate — used by the mining hot loop. If the
/// dataset can't be allocated (not enough RAM — e.g. a small seed VPS), it transparently
/// falls back to the light (cache-only) VM, so mining still works, just slower. `fast =
/// false` always builds the light VM. RandomX guarantees fast and light produce the
/// IDENTICAL hash, so a fast miner and a light verifier always agree (consensus-safe).
fn build_randomx_vm(key: &[u8], fast: bool) -> RandomXVM {
    if fast {
        let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
        // Each step can fail on a RAM-constrained host; on ANY failure fall through to
        // the light VM below rather than aborting the miner.
        if let Ok(cache) = RandomXCache::new(flags, key) {
            if let Ok(dataset) = RandomXDataset::new(flags, cache, 0) {
                if let Ok(vm) = RandomXVM::new(flags, None, Some(dataset)) {
                    return vm;
                }
            }
        }
    }
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).expect("RandomX cache initialization");
    RandomXVM::new(flags, Some(cache), None).expect("RandomX VM initialization")
}

/// Hash `input` with this thread's RandomX VM for `key`, building/rebuilding it as
/// needed. `fast` selects the mining (dataset) VM vs the verify (light) VM. `key`
/// selects the RandomX dataset (a chain-wide consensus value, e.g. the genesis hash).
fn randomx_hash(key: &[u8], input: &[u8], fast: bool) -> [u8; 32] {
    let tls = if fast {
        &RANDOMX_VM_FAST
    } else {
        &RANDOMX_VM_LIGHT
    };
    tls.with(|cell| {
        let mut slot = cell.borrow_mut();
        let needs_build = match slot.as_ref() {
            Some((existing_key, _)) => existing_key.as_slice() != key,
            None => true,
        };
        if needs_build {
            *slot = Some((key.to_vec(), build_randomx_vm(key, fast)));
        }
        let (_, vm) = slot.as_ref().expect("VM is present after build");
        let digest = vm.calculate_hash(input).expect("RandomX hash");
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    })
}

/// Compute the proof-of-work seal of a header preimage under `algo` — the VERIFY path
/// (light RandomX VM). The result is the 32-byte value consensus compares against the
/// difficulty target (smaller = more work). `key` is the chain's RandomX key (ignored
/// by SHA-256d).
pub fn pow_seal(algo: PowAlgo, key: &[u8], input: &[u8]) -> [u8; 32] {
    match algo {
        PowAlgo::Sha256d => sha256d(input),
        PowAlgo::RandomX => randomx_hash(key, input, false),
    }
}

/// The same seal as [`pow_seal`], but for the MINING hot loop: RandomX uses the fast
/// (full-dataset) VM, ~10× faster than light mode. The output is byte-identical to
/// [`pow_seal`] (RandomX guarantees fast == light), so blocks a fast miner finds always
/// verify under the light path. Falls back to light if the dataset can't be allocated.
pub fn pow_seal_mining(algo: PowAlgo, key: &[u8], input: &[u8]) -> [u8; 32] {
    match algo {
        PowAlgo::Sha256d => sha256d(input),
        PowAlgo::RandomX => randomx_hash(key, input, true),
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

    // CONSENSUS-CRITICAL: the mining (fast/dataset) VM and the verify (light/cache) VM
    // must produce byte-identical hashes — otherwise a fast miner would find blocks that
    // fail verification. RandomX guarantees this; we assert it. Ignored by default because
    // it allocates the full ~2 GiB dataset (~1 min); run with `--ignored` to verify.
    #[test]
    #[ignore = "allocates the ~2 GiB RandomX dataset; run explicitly with --ignored"]
    fn randomx_mining_and_verify_paths_agree() {
        let key = b"sov-genesis-key";
        // Real header preimages are never empty (RandomX rejects empty input).
        for input in [&b"header-bytes"[..], b"another-header", b"a"] {
            assert_eq!(
                pow_seal(PowAlgo::RandomX, key, input),
                pow_seal_mining(PowAlgo::RandomX, key, input),
                "fast (mining) and light (verify) RandomX MUST agree"
            );
        }
    }
}
