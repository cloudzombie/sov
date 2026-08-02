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

/// Bytes the FLAG_FULL_MEM RandomX dataset needs (~2080 MiB), plus headroom for the
/// node process itself, before we dare allocate it. Below this much *available* RAM we
/// use the light VM instead.
const FAST_DATASET_MIN_AVAIL_BYTES: u64 = 2_600 * 1024 * 1024; // ~2.6 GiB

/// True if the host has enough *available* memory to hold the ~2 GiB fast-mode dataset
/// without inviting the OOM killer. Reads `/proc/meminfo`'s `MemAvailable` on Linux; on
/// any platform without it (macOS/dev, or an unreadable/garbled file) it returns `true`
/// so those hosts keep the fast path — the guard only ever *demotes* a genuinely
/// RAM-starved Linux box to light mode.
fn host_has_ram_for_fast_dataset() -> bool {
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return true; // not Linux (e.g. macOS dev) → don't interfere
    };
    match parse_mem_available_kb(&meminfo) {
        Some(kb) => kb.saturating_mul(1024) >= FAST_DATASET_MIN_AVAIL_BYTES,
        None => true, // MemAvailable missing/garbled → don't block the fast path
    }
}

/// Parse the `MemAvailable` value (in kB) out of a `/proc/meminfo` body. Pure and
/// testable; returns `None` if the field is absent or unparseable.
fn parse_mem_available_kb(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?;
        rest.trim()
            .trim_end_matches("kB")
            .trim()
            .parse::<u64>()
            .ok()
    })
}

/// Build a RandomX VM for `key`. In `fast` mode it allocates the full ~2 GiB dataset
/// (`FLAG_FULL_MEM`) for ~10× the hash rate — used by the mining hot loop. On a
/// RAM-constrained host (e.g. a small seed VPS) it transparently uses the light
/// (cache-only) VM instead, so mining still works, just slower. `fast = false` always
/// builds the light VM. RandomX guarantees fast and light produce the IDENTICAL hash, so
/// a fast miner and a light verifier always agree — this choice is purely local and
/// performance-only, never consensus-affecting.
///
/// The demotion is decided PROACTIVELY by [`host_has_ram_for_fast_dataset`] rather than by
/// catching an allocation failure: on Linux the dataset alloc overcommits and the OOM
/// killer SIGKILLs the process mid-population, so the `Err` fallback below never fires on
/// a starved box. The `Ok`/`Err` chain is still kept as a second line of defense.
fn build_randomx_vm(key: &[u8], fast: bool) -> RandomXVM {
    if fast && host_has_ram_for_fast_dataset() {
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

    #[test]
    fn mem_available_is_parsed_from_a_real_meminfo() {
        let meminfo = "MemTotal:        1998255 kB\n\
                       MemFree:          103244 kB\n\
                       MemAvailable:    1500123 kB\n\
                       Buffers:            2048 kB\n";
        assert_eq!(parse_mem_available_kb(meminfo), Some(1_500_123));
        // Absent field → None (caller then keeps the fast path).
        assert_eq!(parse_mem_available_kb("MemTotal: 4096 kB\n"), None);
        // Garbled value → None, not a panic.
        assert_eq!(
            parse_mem_available_kb("MemAvailable: not-a-number kB\n"),
            None
        );
    }

    #[test]
    fn low_ram_demotes_to_light_high_ram_keeps_fast() {
        // The 1.9 GiB seed VPS that OOM-killed: ~1.5 GiB available < 2.6 GiB threshold.
        let low = parse_mem_available_kb("MemAvailable: 1500000 kB\n").unwrap();
        assert!(
            low.saturating_mul(1024) < FAST_DATASET_MIN_AVAIL_BYTES,
            "1.5 GiB → light"
        );
        // A 4 GiB box with ~3.5 GiB available clears the bar → fast mode.
        let ok = parse_mem_available_kb("MemAvailable: 3670016 kB\n").unwrap();
        assert!(
            ok.saturating_mul(1024) >= FAST_DATASET_MIN_AVAIL_BYTES,
            "3.5 GiB → fast"
        );
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
