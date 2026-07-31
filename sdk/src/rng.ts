/**
 * Startup RNG health self-test — the single entropy chokepoint for key and
 * seed generation. Byte-for-byte port of the Rust reference
 * (`chain/crates/crypto/src/rng.rs`): same tests, same constants, same order.
 *
 * Every secret the SDK mints (Ed25519/ML-DSA seeds, BIP-39 mnemonic entropy)
 * ultimately comes from the platform CSPRNG via `crypto.getRandomValues`. A
 * conditioned CSPRNG essentially never fails silently — but "essentially
 * never" is not reserve-grade. A broken virtualized entropy device, a
 * misconfigured sandbox or an exotic-platform stub can all degrade the source
 * into something that *returns success* while producing garbage (all-zeros, a
 * stuck value, a counter). NIST SP 800-90B §4.4 therefore requires entropy
 * sources to run **continuous health tests**; this module applies the startup
 * flavor of those tests once per process and *fails closed*:
 *
 * - {@link fillSecure} is the ONLY sanctioned way to draw generation entropy.
 *   On first use it draws a {@link STARTUP_TEST_BYTES} buffer from
 *   `crypto.getRandomValues` and runs {@link healthCheck} over it. The
 *   verdict is **latched** (a module-level once-cell): if the source looks
 *   degraded, every future draw throws the same {@link EntropyError} and no
 *   key is ever generated from an unvalidated source.
 * - {@link healthCheck} itself is pure and deterministic (no I/O), so its
 *   detection and false-positive behavior are unit-tested with crafted
 *   buffers, not claimed.
 *
 * The tests treat each byte as one sample with an assumed min-entropy of
 * 8 bits/byte (the platform CSPRNG is a *conditioned* source, per SP 800-90B
 * §4.4's note on conditioned outputs), and each cutoff is sized so the
 * false-positive probability over one startup buffer is ≤ 2⁻³⁰ — a healthy
 * machine effectively never bricks key generation, while a stuck, biased or
 * counter-like source is rejected with certainty. The one deliberate
 * exception is the gross-bias monobit band, which is a wide 5σ catch-all
 * (per-buffer false-positive ≈ 5.7×10⁻⁷); see {@link healthCheck}.
 */

/**
 * Size in bytes of the one-shot startup buffer drawn from the platform RNG
 * and fed to {@link healthCheck} before the first secret is generated.
 */
export const STARTUP_TEST_BYTES = 8192;

/**
 * Repetition Count Test cutoff (SP 800-90B §4.4.1): the health check rejects
 * a buffer in which any byte value occurs this many times **consecutively**.
 *
 * Derivation: for full-entropy 8-bit samples, a run of length `C` starting at
 * a given position has probability `2^(-8·(C-1))`. Union-bounding over the
 * ≤ 8192 = 2¹³ starting positions of a startup buffer:
 *
 * - `C = 7`: `2¹³ · 2⁻⁴⁸ = 2⁻³⁵ ≤ 2⁻³⁰`  ✓ (this cutoff)
 * - `C = 6`: `2¹³ · 2⁻⁴⁰ = 2⁻²⁷ > 2⁻³⁰`  ✗ (too tight)
 *
 * so 7 is the smallest cutoff meeting the 2⁻³⁰ false-positive budget.
 */
export const RCT_CUTOFF = 7;

/**
 * Adaptive Proportion Test window size in bytes (SP 800-90B §4.4.2). The
 * startup buffer is scanned in non-overlapping windows of this size.
 */
export const APT_WINDOW = 512;

/**
 * Adaptive Proportion Test cutoff (SP 800-90B §4.4.2): within any single
 * {@link APT_WINDOW}-byte window, no byte value may occur this many times.
 *
 * Derivation: a given value's count in a window is `Binomial(512, 1/256)`,
 * mean 2 — accurately approximated by `Poisson(2)`. Tail values:
 *
 * - `P(X ≥ 20) = e⁻² · Σₖ₌₂₀ 2ᵏ/k! ≈ 6.4×10⁻¹⁴ ≈ 2⁻⁴³·⁹`
 * - `P(X ≥ 19) ≈ 6.5×10⁻¹³ ≈ 2⁻⁴⁰·⁵`
 *
 * One startup buffer performs 16 windows × 256 values = 2¹² such tests, so
 * the per-buffer false-positive probability is:
 *
 * - `C = 20`: `2¹² · 2⁻⁴³·⁹ ≈ 2⁻³¹·⁹ ≤ 2⁻³⁰`  ✓ (this cutoff)
 * - `C = 19`: `2¹² · 2⁻⁴⁰·⁵ ≈ 2⁻²⁸·⁵ > 2⁻³⁰`  ✗ (too tight)
 */
export const APT_CUTOFF = 20;

/**
 * Which startup health test rejected the entropy source. Named per test so a
 * failure report says *what* looked wrong, not just "RNG bad". Mirrors the
 * Rust `HealthFailure` enum variants 1:1.
 *
 * - `"Stuck"` — the entire startup buffer is one repeated byte value (covers
 *   all-zeros and all-ones — the classic dead-device signatures). Empty
 *   input is also rejected here (zero evidence of health is not health).
 * - `"Repetition"` — Repetition Count Test (SP 800-90B §4.4.1): some byte
 *   value occurred {@link RCT_CUTOFF}+ times consecutively.
 * - `"Proportion"` — Adaptive Proportion Test (SP 800-90B §4.4.2): some byte
 *   value occurred {@link APT_CUTOFF}+ times within one
 *   {@link APT_WINDOW}-byte window.
 * - `"Coverage"` — at least one of the 256 byte values never occurred in the
 *   startup buffer. A uniform 8192-byte draw misses a value with probability
 *   ≤ 256·(255/256)⁸¹⁹² ≈ 2⁻³⁸, but a short pattern tiled to fill the buffer
 *   (e.g. a repeated 32-byte block, which slips under the APT cutoff at 16
 *   occurrences per window) covers only its own values.
 * - `"Pattern"` — first-difference (lag-1 delta) proportion test: the APT
 *   applied to the stream of consecutive-byte differences. Catches
 *   counter-like sources — an incrementing counter mod 256 sails through
 *   RCT/APT/coverage/monobit (every value appears, exactly twice per window,
 *   perfectly bit-balanced) but its delta stream is the constant 1.
 * - `"Bias"` — monobit gross-bias test: the 1-bit count over the whole
 *   buffer fell outside a wide 5σ band around n/2.
 */
export type HealthFailure =
  | "Stuck"
  | "Repetition"
  | "Proportion"
  | "Coverage"
  | "Pattern"
  | "Bias";

const FAILURE_MESSAGES: Record<HealthFailure, string> = {
  Stuck: "stuck source: the whole startup buffer is a single repeated byte",
  Repetition: `repetition count test (SP 800-90B 4.4.1): a byte value repeated ${RCT_CUTOFF}+ times consecutively`,
  Proportion: `adaptive proportion test (SP 800-90B 4.4.2): a byte value occurred ${APT_CUTOFF}+ times in a ${APT_WINDOW}-byte window`,
  Coverage: "coverage test: at least one byte value never occurred in the startup buffer",
  Pattern:
    "pattern test: first differences of the startup buffer are grossly non-uniform (counter-like source)",
  Bias: "monobit test: gross 0/1 bit bias across the startup buffer",
};

/**
 * Error thrown when generation entropy cannot be drawn through
 * {@link fillSecure}: the startup health test rejected the entropy source
 * (`kind` names the failed test) or the platform RNG itself errored
 * (`kind: "Source"`). A startup failure is latched for the life of the
 * process and rethrown verbatim on every subsequent draw.
 */
export class EntropyError extends Error {
  /** Which check failed — a {@link HealthFailure} name, or `"Source"`. */
  readonly kind: HealthFailure | "Source";

  constructor(kind: HealthFailure | "Source") {
    super(
      kind === "Source"
        ? "the platform entropy source failed"
        : `startup RNG health test failed (${FAILURE_MESSAGES[kind]}); refusing to generate key material`,
    );
    this.name = "EntropyError";
    this.kind = kind;
  }
}

/**
 * The largest per-value occurrence count over all full non-overlapping
 * {@link APT_WINDOW}-byte windows of `samples` (the APT statistic).
 */
function maxWindowCount(samples: Uint8Array): number {
  let max = 0;
  const full = samples.length - (samples.length % APT_WINDOW);
  for (let start = 0; start < full; start += APT_WINDOW) {
    const counts = new Uint32Array(256);
    for (let i = start; i < start + APT_WINDOW; i++) {
      counts[samples[i]!]!++;
    }
    for (let v = 0; v < 256; v++) {
      const c = counts[v]!;
      if (c > max) max = c;
    }
  }
  return max;
}

/** Population count of a byte (0..=255). */
function popcount8(b: number): number {
  let x = b - ((b >> 1) & 0x55);
  x = (x & 0x33) + ((x >> 2) & 0x33);
  return (x + (x >> 4)) & 0x0f;
}

/**
 * Deterministic startup health check over `samples` — pure, no I/O, so its
 * behavior is provable by unit test. Throws {@link EntropyError} naming the
 * failed test; returns normally on pass.
 *
 * Tests run cheapest/most-obvious first (same order as the Rust reference):
 *
 * 1. **Stuck** — the whole buffer is one repeated byte (empty input is also
 *    rejected here: zero evidence of health is not health).
 * 2. **Repetition Count Test** (SP 800-90B §4.4.1) — any value repeated
 *    {@link RCT_CUTOFF}+ times consecutively; see the cutoff's derivation.
 * 3. **Adaptive Proportion Test** (SP 800-90B §4.4.2) — any value occurring
 *    {@link APT_CUTOFF}+ times in a non-overlapping {@link APT_WINDOW}-byte
 *    window.
 * 4. **Coverage** — all 256 byte values must appear (buffers of at least
 *    {@link STARTUP_TEST_BYTES} only, where a uniform miss has probability
 *    ≈ 2⁻³⁸; shorter crafted test inputs would false-positive).
 * 5. **Pattern** — the APT re-run over the lag-1 difference stream
 *    (`s[i+1] - s[i] mod 256`), which is itself uniform for a full-entropy
 *    source (15 full windows × 256 values = 2¹¹·⁹ tests at 2⁻⁴³·⁹ each,
 *    ≈ 2⁻³² per buffer). This is the check that catches an incrementing
 *    counter, which passes tests 1–4 and 6.
 * 6. **Monobit gross bias** — reject if `|ones − n_bits/2| > 5·√n_bits/2`,
 *    i.e. 5 standard deviations of the fair-coin bit count. Deliberately a
 *    wide band: per-buffer false-positive ≈ 5.7×10⁻⁷ (two-sided 5σ), while
 *    a stuck-at-0/1 bit line or a source with per-bit bias ≳1% blows far
 *    past it (the crafted test vector sits ≈32σ out).
 */
export function healthCheck(samples: Uint8Array): void {
  // 1. Stuck / constant (also rejects an empty buffer, fail-closed).
  if (samples.length === 0) {
    throw new EntropyError("Stuck");
  }
  const first = samples[0];
  let allSame = true;
  for (let i = 1; i < samples.length; i++) {
    if (samples[i] !== first) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    throw new EntropyError("Stuck");
  }

  // 2. Repetition Count Test, SP 800-90B §4.4.1.
  let run = 1;
  for (let i = 1; i < samples.length; i++) {
    if (samples[i] === samples[i - 1]) {
      run += 1;
      if (run >= RCT_CUTOFF) {
        throw new EntropyError("Repetition");
      }
    } else {
      run = 1;
    }
  }

  // 3. Adaptive Proportion Test, SP 800-90B §4.4.2.
  if (maxWindowCount(samples) >= APT_CUTOFF) {
    throw new EntropyError("Proportion");
  }

  // 4. Coverage: every byte value must occur (full-size buffers only).
  if (samples.length >= STARTUP_TEST_BYTES) {
    const seen = new Uint8Array(256);
    for (let i = 0; i < samples.length; i++) {
      seen[samples[i]!] = 1;
    }
    for (let v = 0; v < 256; v++) {
      if (seen[v]! === 0) {
        throw new EntropyError("Coverage");
      }
    }
  }

  // 5. First-difference proportion test (counter catch).
  const deltas = new Uint8Array(Math.max(0, samples.length - 1));
  for (let i = 1; i < samples.length; i++) {
    deltas[i - 1] = (samples[i]! - samples[i - 1]!) & 0xff;
  }
  if (maxWindowCount(deltas) >= APT_CUTOFF) {
    throw new EntropyError("Pattern");
  }

  // 6. Monobit gross bias. `dev > 5·√n/2` ⇔ `4·dev² > 25·n`, kept in exact
  // integer arithmetic (values stay far below 2^53, so `number` is exact).
  const nBits = samples.length * 8;
  let ones = 0;
  for (let i = 0; i < samples.length; i++) {
    ones += popcount8(samples[i]!);
  }
  const dev = Math.abs(ones - Math.floor(nBits / 2));
  if (4 * dev * dev > 25 * nBits) {
    throw new EntropyError("Bias");
  }
}

/**
 * Latched startup verdict: `undefined` until the first draw, then the cached
 * result forever (`null` = healthy, an {@link EntropyError} = failed).
 */
let startupVerdict: EntropyError | null | undefined;

/**
 * Test-only seam letting unit tests force the chokepoint into a failed
 * (latched-equivalent) state without touching the real startup latch —
 * production {@link fillSecure} semantics are unchanged. NOT exported from
 * the package index; import directly from `src/rng.ts` in tests only.
 */
let forcedFailure: HealthFailure | null = null;

/** @internal Test-only. Force (`HealthFailure`) or clear (`null`) a failure. */
export function __forceUnhealthyForTests(failure: HealthFailure | null): void {
  forcedFailure = failure;
}

/**
 * The latched startup test: on the first call, draw
 * {@link STARTUP_TEST_BYTES} bytes from `crypto.getRandomValues` and run
 * {@link healthCheck}; cache the verdict so every later call returns the
 * same result. A platform-RNG error during the startup draw latches as a
 * failure too — an unreadable source is as disqualifying as a degraded one.
 */
function ensureHealthy(): void {
  if (forcedFailure !== null) {
    throw new EntropyError(forcedFailure);
  }
  if (startupVerdict === undefined) {
    startupVerdict = computeStartupVerdict();
  }
  if (startupVerdict !== null) {
    throw startupVerdict;
  }
}

function computeStartupVerdict(): EntropyError | null {
  const buf = new Uint8Array(STARTUP_TEST_BYTES);
  try {
    crypto.getRandomValues(buf);
  } catch {
    return new EntropyError("Source");
  }
  try {
    healthCheck(buf);
  } catch (err) {
    if (err instanceof EntropyError) return err;
    throw err;
  }
  return null;
}

/**
 * Fill `dest` with platform entropy, but only after the process-wide startup
 * health test has passed. This is the single entropy chokepoint for all
 * key/seed generation — call this, never `crypto.getRandomValues` directly.
 *
 * Fails closed: if the startup test failed (or the platform RNG errored, at
 * startup or now), this throws and the caller must not fabricate a secret.
 */
export function fillSecure(dest: Uint8Array): void {
  ensureHealthy();
  try {
    // The cast only widens the buffer parameter TypeScript infers for
    // `getRandomValues`; the bytes are written into `dest` in place.
    crypto.getRandomValues(dest as Uint8Array<ArrayBuffer>);
  } catch {
    throw new EntropyError("Source");
  }
}
