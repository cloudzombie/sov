//! Startup RNG health self-test — the single entropy chokepoint for key and
//! seed generation.
//!
//! Every secret the chain mints (Ed25519/ML-DSA seeds, BIP-39 mnemonic
//! entropy, HTLC preimages, AEAD nonces) ultimately comes from the operating
//! system CSPRNG via `getrandom`. A conditioned OS CSPRNG essentially never
//! fails silently — but "essentially never" is not reserve-grade. A broken
//! virtualized entropy device, a misconfigured seccomp sandbox or an
//! exotic-platform stub can all degrade `getrandom` into something that
//! *returns success* while producing garbage (all-zeros, a stuck value, a
//! counter). NIST SP 800-90B §4.4 therefore requires entropy sources to run
//! **continuous health tests**; this module applies the startup flavor of
//! those tests once per process and *fails closed*:
//!
//! - [`fill_secure`] is the ONLY sanctioned way to draw generation entropy.
//!   On first use it draws a [`STARTUP_TEST_BYTES`] buffer from `getrandom`
//!   and runs [`health_check`] over it. The verdict is **latched**
//!   (`OnceLock`): if the source looks degraded, every future draw returns
//!   the same [`EntropyError`] and no key is ever generated from an
//!   unvalidated source.
//! - [`health_check`] itself is pure and deterministic (no I/O), so its
//!   detection and false-positive behavior are unit-tested with crafted
//!   buffers, not claimed.
//!
//! The tests treat each byte as one sample with an assumed min-entropy of
//! 8 bits/byte (the OS CSPRNG is a *conditioned* source, per SP 800-90B
//! §4.4's note on conditioned outputs), and each cutoff is sized so the
//! false-positive probability over one startup buffer is ≤ 2⁻³⁰ — a healthy
//! machine effectively never bricks key generation, while a stuck, biased or
//! counter-like source is rejected with certainty. The one deliberate
//! exception is the gross-bias monobit band, which is a wide 5σ catch-all
//! (per-buffer false-positive ≈ 5.7×10⁻⁷); see [`health_check`].

use std::sync::OnceLock;

/// Size in bytes of the one-shot startup buffer drawn from the OS and fed to
/// [`health_check`] before the first secret is generated.
pub const STARTUP_TEST_BYTES: usize = 8192;

/// Repetition Count Test cutoff (SP 800-90B §4.4.1): the health check rejects
/// a buffer in which any byte value occurs this many times **consecutively**.
///
/// Derivation: for full-entropy 8-bit samples, a run of length `C` starting at
/// a given position has probability `2^(-8·(C-1))`. Union-bounding over the
/// ≤ 8192 = 2¹³ starting positions of a startup buffer:
///
/// - `C = 7`: `2¹³ · 2⁻⁴⁸ = 2⁻³⁵ ≤ 2⁻³⁰`  ✓ (this cutoff)
/// - `C = 6`: `2¹³ · 2⁻⁴⁰ = 2⁻²⁷ > 2⁻³⁰`  ✗ (too tight)
///
/// so 7 is the smallest cutoff meeting the 2⁻³⁰ false-positive budget.
pub const RCT_CUTOFF: u32 = 7;

/// Adaptive Proportion Test window size in bytes (SP 800-90B §4.4.2). The
/// startup buffer is scanned in non-overlapping windows of this size.
pub const APT_WINDOW: usize = 512;

/// Adaptive Proportion Test cutoff (SP 800-90B §4.4.2): within any single
/// [`APT_WINDOW`]-byte window, no byte value may occur this many times.
///
/// Derivation: a given value's count in a window is `Binomial(512, 1/256)`,
/// mean 2 — accurately approximated by `Poisson(2)`. Tail values:
///
/// - `P(X ≥ 20) = e⁻² · Σₖ₌₂₀ 2ᵏ/k! ≈ 6.4×10⁻¹⁴ ≈ 2⁻⁴³·⁹`
/// - `P(X ≥ 19) ≈ 6.5×10⁻¹³ ≈ 2⁻⁴⁰·⁵`
///
/// One startup buffer performs 16 windows × 256 values = 2¹² such tests, so
/// the per-buffer false-positive probability is:
///
/// - `C = 20`: `2¹² · 2⁻⁴³·⁹ ≈ 2⁻³¹·⁹ ≤ 2⁻³⁰`  ✓ (this cutoff)
/// - `C = 19`: `2¹² · 2⁻⁴⁰·⁵ ≈ 2⁻²⁸·⁵ > 2⁻³⁰`  ✗ (too tight)
pub const APT_CUTOFF: u32 = 20;

/// Which startup health test rejected the entropy source. Named per test so a
/// failure report says *what* looked wrong, not just "RNG bad".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HealthFailure {
    /// The entire startup buffer is one repeated byte value (covers
    /// all-zeros and all-ones — the classic dead-device signatures).
    #[error("stuck source: the whole startup buffer is a single repeated byte")]
    Stuck,
    /// Repetition Count Test (SP 800-90B §4.4.1): some byte value occurred
    /// [`RCT_CUTOFF`] or more times consecutively.
    #[error("repetition count test (SP 800-90B 4.4.1): a byte value repeated {RCT_CUTOFF}+ times consecutively")]
    Repetition,
    /// Adaptive Proportion Test (SP 800-90B §4.4.2): some byte value occurred
    /// [`APT_CUTOFF`] or more times within one [`APT_WINDOW`]-byte window.
    #[error("adaptive proportion test (SP 800-90B 4.4.2): a byte value occurred {APT_CUTOFF}+ times in a {APT_WINDOW}-byte window")]
    Proportion,
    /// Coverage test: at least one of the 256 byte values never occurred in
    /// the startup buffer. A uniform 8192-byte draw misses a value with
    /// probability ≤ 256·(255/256)⁸¹⁹² ≈ 2⁻³⁸, but a short pattern tiled to
    /// fill the buffer (e.g. a repeated 32-byte block, which slips under the
    /// APT cutoff at 16 occurrences per window) covers only its own values.
    #[error("coverage test: at least one byte value never occurred in the startup buffer")]
    Coverage,
    /// First-difference (lag-1 delta) proportion test: the APT applied to the
    /// stream of consecutive-byte differences. Catches counter-like sources —
    /// an incrementing counter mod 256 sails through RCT/APT/coverage/monobit
    /// (every value appears, exactly twice per window, perfectly bit-balanced)
    /// but its delta stream is the constant 1.
    #[error("pattern test: first differences of the startup buffer are grossly non-uniform (counter-like source)")]
    Pattern,
    /// Monobit gross-bias test: the 1-bit count over the whole buffer fell
    /// outside a wide 5σ band around n/2.
    #[error("monobit test: gross 0/1 bit bias across the startup buffer")]
    Bias,
}

/// Error drawing generation entropy through [`fill_secure`]. `Clone` so a
/// latched startup failure can be returned verbatim on every subsequent draw.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntropyError {
    /// The operating-system RNG itself returned an error.
    #[error("the operating-system entropy source failed")]
    Source,
    /// The startup health test rejected the entropy source; the named test
    /// failed. Latched for the life of the process.
    #[error("startup RNG health test failed ({0}); refusing to generate key material")]
    HealthCheck(HealthFailure),
}

/// Fill `dest` with OS entropy, but only after the process-wide startup
/// health test has passed. This is the single entropy chokepoint for all
/// key/seed generation — call this, never `getrandom` directly.
///
/// Fails closed: if the startup test failed (or the OS RNG errors, at startup
/// or now), this returns `Err` and the caller must not fabricate a secret.
pub fn fill_secure(dest: &mut [u8]) -> Result<(), EntropyError> {
    ensure_healthy()?;
    getrandom::getrandom(dest).map_err(|_| EntropyError::Source)
}

/// The latched startup test: on the first call, draw [`STARTUP_TEST_BYTES`]
/// bytes from the OS and run [`health_check`]; cache the verdict in a
/// `OnceLock` so every later call returns the same result. An OS-RNG error
/// during the startup draw latches as a failure too — an unreadable source is
/// as disqualifying as a degraded one.
fn ensure_healthy() -> Result<(), EntropyError> {
    #[cfg(test)]
    if let Some(forced) = test_support::forced_failure() {
        return Err(EntropyError::HealthCheck(forced));
    }
    static STARTUP: OnceLock<Result<(), EntropyError>> = OnceLock::new();
    STARTUP
        .get_or_init(|| {
            let mut buf = [0u8; STARTUP_TEST_BYTES];
            getrandom::getrandom(&mut buf).map_err(|_| EntropyError::Source)?;
            health_check(&buf).map_err(EntropyError::HealthCheck)
        })
        .clone()
}

/// Deterministic startup health check over `samples` — pure, no I/O, so its
/// behavior is provable by unit test. Returns which test failed, if any.
///
/// Tests run cheapest/most-obvious first:
///
/// 1. **Stuck** — the whole buffer is one repeated byte (empty input is also
///    rejected here: zero evidence of health is not health).
/// 2. **Repetition Count Test** (SP 800-90B §4.4.1) — any value repeated
///    [`RCT_CUTOFF`]+ times consecutively; see the cutoff's derivation.
/// 3. **Adaptive Proportion Test** (SP 800-90B §4.4.2) — any value occurring
///    [`APT_CUTOFF`]+ times in a non-overlapping [`APT_WINDOW`]-byte window.
/// 4. **Coverage** — all 256 byte values must appear (buffers of at least
///    [`STARTUP_TEST_BYTES`] only, where a uniform miss has probability
///    ≈ 2⁻³⁸; shorter crafted test inputs would false-positive).
/// 5. **Pattern** — the APT re-run over the lag-1 difference stream
///    (`s[i+1] - s[i] mod 256`), which is itself uniform for a full-entropy
///    source (15 full windows × 256 values = 2¹¹·⁹ tests at 2⁻⁴³·⁹ each,
///    ≈ 2⁻³² per buffer). This is the check that catches an incrementing
///    counter, which passes tests 1–4 and 6 (documented on
///    [`HealthFailure::Pattern`]).
/// 6. **Monobit gross bias** — reject if `|ones − n_bits/2| > 5·√n_bits/2`,
///    i.e. 5 standard deviations of the fair-coin bit count. Deliberately a
///    wide band: per-buffer false-positive ≈ 5.7×10⁻⁷ (two-sided 5σ), while
///    a stuck-at-0/1 bit line or a source with per-bit bias ≳1% blows far
///    past it (the crafted test vector sits ≈32σ out).
pub fn health_check(samples: &[u8]) -> Result<(), HealthFailure> {
    // 1. Stuck / constant (also rejects an empty buffer, fail-closed).
    let Some(&first) = samples.first() else {
        return Err(HealthFailure::Stuck);
    };
    if samples.iter().all(|&b| b == first) {
        return Err(HealthFailure::Stuck);
    }

    // 2. Repetition Count Test, SP 800-90B §4.4.1.
    let mut run = 1u32;
    for pair in samples.windows(2) {
        if pair[0] == pair[1] {
            run += 1;
            if run >= RCT_CUTOFF {
                return Err(HealthFailure::Repetition);
            }
        } else {
            run = 1;
        }
    }

    // 3. Adaptive Proportion Test, SP 800-90B §4.4.2.
    if max_window_count(samples) >= APT_CUTOFF {
        return Err(HealthFailure::Proportion);
    }

    // 4. Coverage: every byte value must occur (full-size buffers only).
    if samples.len() >= STARTUP_TEST_BYTES {
        let mut seen = [false; 256];
        for &b in samples {
            seen[b as usize] = true;
        }
        if seen.contains(&false) {
            return Err(HealthFailure::Coverage);
        }
    }

    // 5. First-difference proportion test (counter catch).
    let deltas: Vec<u8> = samples
        .windows(2)
        .map(|pair| pair[1].wrapping_sub(pair[0]))
        .collect();
    if max_window_count(&deltas) >= APT_CUTOFF {
        return Err(HealthFailure::Pattern);
    }

    // 6. Monobit gross bias. `dev > 5·√n/2` ⇔ `4·dev² > 25·n`, kept in
    // integers to stay exact.
    let n_bits = (samples.len() as u64) * 8;
    let ones: u64 = samples.iter().map(|b| u64::from(b.count_ones())).sum();
    let dev = ones.abs_diff(n_bits / 2);
    if 4 * dev * dev > 25 * n_bits {
        return Err(HealthFailure::Bias);
    }

    Ok(())
}

/// The largest per-value occurrence count over all full non-overlapping
/// [`APT_WINDOW`]-byte windows of `samples` (the APT statistic).
fn max_window_count(samples: &[u8]) -> u32 {
    let mut max = 0u32;
    for window in samples.chunks_exact(APT_WINDOW) {
        let mut counts = [0u32; 256];
        for &b in window {
            counts[b as usize] += 1;
        }
        max = max.max(*counts.iter().max().expect("256 counters"));
    }
    max
}

/// Test-only seam letting this crate's unit tests force the chokepoint into a
/// failed (latched-equivalent) state without touching the real global latch —
/// production `ensure_healthy` semantics are unchanged.
#[cfg(test)]
pub(crate) mod test_support {
    use super::HealthFailure;
    use std::cell::Cell;

    thread_local! {
        static FORCED: Cell<Option<HealthFailure>> = const { Cell::new(None) };
    }

    /// The failure currently forced on this thread, if any.
    pub(crate) fn forced_failure() -> Option<HealthFailure> {
        FORCED.with(Cell::get)
    }

    /// Force (`Some`) or clear (`None`) a health failure for this thread.
    pub(crate) fn set_forced_failure(f: Option<HealthFailure>) {
        FORCED.with(|c| c.set(f));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64 — a tiny deterministic PRNG for *crafting* adversarial test
    /// vectors only. Never used as an entropy source.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The false-positive test — the reason the cutoffs are documented with
    /// arithmetic. 2000 real OS draws of the startup size must ALL pass; if
    /// this fails the cutoffs are too tight and must be re-derived (the test
    /// must not be weakened).
    #[test]
    fn real_os_entropy_passes() {
        let mut buf = [0u8; STARTUP_TEST_BYTES];
        for i in 0..2000 {
            getrandom::getrandom(&mut buf).expect("OS entropy available in tests");
            if let Err(failure) = health_check(&buf) {
                panic!("real OS entropy buffer #{i} rejected: {failure}");
            }
        }
    }

    #[test]
    fn all_zeros_rejected() {
        let buf = [0u8; STARTUP_TEST_BYTES];
        assert_eq!(health_check(&buf), Err(HealthFailure::Stuck));
    }

    #[test]
    fn all_ones_rejected() {
        let buf = [0xFFu8; STARTUP_TEST_BYTES];
        assert_eq!(health_check(&buf), Err(HealthFailure::Stuck));
    }

    #[test]
    fn empty_buffer_rejected() {
        assert_eq!(health_check(&[]), Err(HealthFailure::Stuck));
    }

    /// A short "random-looking" block tiled to fill the buffer — the
    /// signature of a wedged DMA buffer or a caching bug. 32 distinct bytes
    /// repeat 16× per 512-byte window, deliberately UNDER the APT cutoff of
    /// 20, so the coverage test is what must catch it.
    #[test]
    fn stuck_repeated_block_rejected() {
        let mut block = [0u8; 32];
        let mut s = 0x5EED_0001u64;
        // 32 distinct byte values, no adjacent equality once tiled.
        let mut i = 0;
        while i < 32 {
            let candidate = (splitmix64(&mut s) & 0xFF) as u8;
            if !block[..i].contains(&candidate) {
                block[i] = candidate;
                i += 1;
            }
        }
        let buf: Vec<u8> = block
            .iter()
            .copied()
            .cycle()
            .take(STARTUP_TEST_BYTES)
            .collect();
        assert_eq!(health_check(&buf), Err(HealthFailure::Coverage));
    }

    /// Mostly one value with a sprinkle of noise: three 0xAA bytes then one
    /// varying byte, so the longest run is 3 (under the RCT cutoff) and the
    /// Adaptive Proportion Test is the check that must fire (384 ≫ 20 per
    /// window).
    #[test]
    fn single_byte_biased_rejected() {
        let mut s = 0x5EED_0002u64;
        let buf: Vec<u8> = (0..STARTUP_TEST_BYTES)
            .map(|i| {
                if i % 4 == 3 {
                    let mut noise = (splitmix64(&mut s) & 0xFF) as u8;
                    if noise == 0xAA {
                        noise = 0x55;
                    }
                    noise
                } else {
                    0xAA
                }
            })
            .collect();
        assert_eq!(health_check(&buf), Err(HealthFailure::Proportion));
    }

    /// An incrementing counter mod 256. HONEST NOTE: this degenerate source
    /// passes the four headline checks — no runs (RCT ok), every value
    /// exactly twice per 512-byte window (APT ok), full coverage, and the
    /// 0..=255 cycle is exactly bit-balanced (monobit ok). That is precisely
    /// why the first-difference proportion test exists: the counter's delta
    /// stream is the constant 1, 511 occurrences per delta window.
    #[test]
    fn low_entropy_counter_rejected() {
        let buf: Vec<u8> = (0..STARTUP_TEST_BYTES).map(|i| i as u8).collect();
        assert_eq!(health_check(&buf), Err(HealthFailure::Pattern));
    }

    /// A counter with a stride co-prime to 256 is the same degenerate source
    /// in disguise (constant delta 0x4D); the delta test must catch it too.
    #[test]
    fn strided_counter_rejected() {
        let buf: Vec<u8> = (0..STARTUP_TEST_BYTES)
            .map(|i| (i as u8).wrapping_mul(0x4D))
            .collect();
        assert_eq!(health_check(&buf), Err(HealthFailure::Pattern));
    }

    /// Per-bit bias with everything else healthy-looking: each byte is
    /// `r1 | (r2 & r3 & r4)` over independent pseudorandom words, so every
    /// bit is 1 with probability 9/16. Expected ones ≈ 36864 vs the 33408
    /// rejection edge (5σ = 640 over n/2 = 32768) — ≈32σ out, while value
    /// frequencies stay far under the RCT/APT cutoffs and all 256 values
    /// remain present. The monobit test is the check that must fire.
    #[test]
    fn monobit_gross_bias_rejected() {
        let mut s = 0x5EED_0003u64;
        let mut buf = vec![0u8; STARTUP_TEST_BYTES];
        for chunk in buf.chunks_mut(8) {
            let r1 = splitmix64(&mut s);
            let r2 = splitmix64(&mut s);
            let r3 = splitmix64(&mut s);
            let r4 = splitmix64(&mut s);
            let biased = (r1 | (r2 & r3 & r4)).to_le_bytes();
            chunk.copy_from_slice(&biased[..chunk.len()]);
        }
        assert_eq!(health_check(&buf), Err(HealthFailure::Bias));
    }

    /// The complementary gross bias (bits stuck toward 0) must trip the same
    /// band on the low side.
    #[test]
    fn monobit_low_bias_rejected() {
        let mut s = 0x5EED_0004u64;
        let mut buf = vec![0u8; STARTUP_TEST_BYTES];
        for chunk in buf.chunks_mut(8) {
            let r1 = splitmix64(&mut s);
            let r2 = splitmix64(&mut s);
            let r3 = splitmix64(&mut s);
            let r4 = splitmix64(&mut s);
            let biased = (r1 & (r2 | r3 | r4)).to_le_bytes();
            chunk.copy_from_slice(&biased[..chunk.len()]);
        }
        assert_eq!(health_check(&buf), Err(HealthFailure::Bias));
    }

    /// The happy path: on a healthy machine the chokepoint fills buffers and
    /// two draws differ (256-bit collision is impossible in practice).
    #[test]
    fn fill_secure_draws_entropy() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_secure(&mut a).expect("healthy source fills");
        fill_secure(&mut b).expect("healthy source fills");
        assert_ne!(a, b);
    }

    /// Fail-closed + latched semantics at the chokepoint: while the health
    /// state is a failure, EVERY draw returns that same error — repeatedly —
    /// and no bytes are handed out.
    #[test]
    fn fill_secure_fails_closed_when_unhealthy() {
        test_support::set_forced_failure(Some(HealthFailure::Stuck));
        let mut buf = [0u8; 32];
        for _ in 0..3 {
            assert_eq!(
                fill_secure(&mut buf),
                Err(EntropyError::HealthCheck(HealthFailure::Stuck))
            );
            assert_eq!(buf, [0u8; 32], "no bytes may be written on failure");
        }
        test_support::set_forced_failure(None);
        fill_secure(&mut buf).expect("clears once healthy again");
    }
}
