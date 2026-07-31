/**
 * Startup RNG health self-test — mirrors the Rust reference test suite
 * (`chain/crates/crypto/src/rng.rs`) 1:1: the same crafted adversarial
 * vectors must trip the same named checks, and 2000 real platform draws of
 * the startup size must all pass (false-positive budget).
 */
import { afterEach, describe, expect, it } from "vitest";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import {
  APT_CUTOFF,
  APT_WINDOW,
  EntropyError,
  RCT_CUTOFF,
  STARTUP_TEST_BYTES,
  __forceUnhealthyForTests,
  fillSecure,
  healthCheck,
  type HealthFailure,
} from "../src/rng.js";
import { Keypair } from "../src/keys.js";
import { HybridKeypair } from "../src/hybrid.js";
import { generateMnemonic, validateMnemonic } from "../src/hd.js";

/**
 * SplitMix64 — a tiny deterministic PRNG for *crafting* adversarial test
 * vectors only (same generator and seeds as the Rust reference tests).
 * Never used as an entropy source.
 */
const MASK64 = (1n << 64n) - 1n;
function makeSplitmix64(seed: bigint): () => bigint {
  let state = seed & MASK64;
  return () => {
    state = (state + 0x9e3779b97f4a7c15n) & MASK64;
    let z = state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    return (z ^ (z >> 31n)) & MASK64;
  };
}

/** Assert `healthCheck` rejects `buf` with exactly the named failure. */
function expectFailure(buf: Uint8Array, kind: HealthFailure): void {
  let caught: unknown;
  try {
    healthCheck(buf);
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(EntropyError);
  expect((caught as EntropyError).kind).toBe(kind);
}

afterEach(() => {
  __forceUnhealthyForTests(null);
});

describe("rng constants match the Rust reference", () => {
  it("pins the SP 800-90B cutoffs", () => {
    expect(STARTUP_TEST_BYTES).toBe(8192);
    expect(RCT_CUTOFF).toBe(7);
    expect(APT_WINDOW).toBe(512);
    expect(APT_CUTOFF).toBe(20);
  });
});

describe("healthCheck", () => {
  /**
   * The false-positive test — the reason the cutoffs are documented with
   * arithmetic. 2000 real platform draws of the startup size must ALL pass;
   * if this fails the cutoffs are too tight and must be re-derived (the test
   * must not be weakened).
   */
  it("real entropy passes (2000 startup-size buffers, zero rejections)", () => {
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let i = 0; i < 2000; i++) {
      crypto.getRandomValues(buf);
      try {
        healthCheck(buf);
      } catch (err) {
        throw new Error(`real entropy buffer #${i} rejected: ${(err as Error).message}`);
      }
    }
  });

  it("rejects all-zeros (Stuck)", () => {
    expectFailure(new Uint8Array(STARTUP_TEST_BYTES), "Stuck");
  });

  it("rejects all-0xFF (Stuck)", () => {
    expectFailure(new Uint8Array(STARTUP_TEST_BYTES).fill(0xff), "Stuck");
  });

  it("rejects an empty buffer (Stuck — zero evidence of health is not health)", () => {
    expectFailure(new Uint8Array(0), "Stuck");
  });

  /**
   * A short "random-looking" block tiled to fill the buffer — the signature
   * of a wedged DMA buffer or a caching bug. 32 distinct bytes repeat 16x
   * per 512-byte window, deliberately UNDER the APT cutoff of 20, so the
   * coverage test is what must catch it.
   */
  it("rejects a stuck repeated 32-byte block (Coverage)", () => {
    const next = makeSplitmix64(0x5eed0001n);
    const block: number[] = [];
    while (block.length < 32) {
      const candidate = Number(next() & 0xffn);
      if (!block.includes(candidate)) block.push(candidate);
    }
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let i = 0; i < buf.length; i++) buf[i] = block[i % 32];
    expectFailure(buf, "Coverage");
  });

  /**
   * Mostly one value with a sprinkle of noise: three 0xAA bytes then one
   * varying byte, so the longest run is 3 (under the RCT cutoff) and the
   * Adaptive Proportion Test is the check that must fire (384 >> 20 per
   * window).
   */
  it("rejects a single-byte-biased source (Proportion)", () => {
    const next = makeSplitmix64(0x5eed0002n);
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let i = 0; i < buf.length; i++) {
      if (i % 4 === 3) {
        let noise = Number(next() & 0xffn);
        if (noise === 0xaa) noise = 0x55;
        buf[i] = noise;
      } else {
        buf[i] = 0xaa;
      }
    }
    expectFailure(buf, "Proportion");
  });

  /**
   * An incrementing counter mod 256. HONEST NOTE: this degenerate source
   * passes the four headline checks — no runs (RCT ok), every value exactly
   * twice per 512-byte window (APT ok), full coverage, and the 0..=255 cycle
   * is exactly bit-balanced (monobit ok). That is precisely why the
   * first-difference proportion test exists: the counter's delta stream is
   * the constant 1, 511 occurrences per delta window.
   */
  it("rejects an incrementing counter mod 256 (Pattern)", () => {
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
    expectFailure(buf, "Pattern");
  });

  /**
   * A counter with a stride co-prime to 256 is the same degenerate source in
   * disguise (constant delta 0x4D); the delta test must catch it too.
   */
  it("rejects a strided counter (Pattern)", () => {
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let i = 0; i < buf.length; i++) buf[i] = ((i & 0xff) * 0x4d) & 0xff;
    expectFailure(buf, "Pattern");
  });

  /**
   * Per-bit bias with everything else healthy-looking: each byte is
   * `r1 | (r2 & r3 & r4)` over independent pseudorandom words, so every bit
   * is 1 with probability 9/16. Expected ones ~= 36864 vs the 33408
   * rejection edge (5 sigma = 640 over n/2 = 32768) — ~32 sigma out, while
   * value frequencies stay far under the RCT/APT cutoffs and all 256 values
   * remain present. The monobit test is the check that must fire.
   */
  it("rejects gross monobit bias toward 1 (Bias)", () => {
    const next = makeSplitmix64(0x5eed0003n);
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let off = 0; off < buf.length; off += 8) {
      const biased = (next() | (next() & next() & next())) & MASK64;
      for (let j = 0; j < 8; j++) {
        buf[off + j] = Number((biased >> BigInt(8 * j)) & 0xffn);
      }
    }
    expectFailure(buf, "Bias");
  });

  /** The complementary gross bias (bits stuck toward 0), same band low side. */
  it("rejects gross monobit bias toward 0 (Bias)", () => {
    const next = makeSplitmix64(0x5eed0004n);
    const buf = new Uint8Array(STARTUP_TEST_BYTES);
    for (let off = 0; off < buf.length; off += 8) {
      const biased = (next() & (next() | next() | next())) & MASK64;
      for (let j = 0; j < 8; j++) {
        buf[off + j] = Number((biased >> BigInt(8 * j)) & 0xffn);
      }
    }
    expectFailure(buf, "Bias");
  });
});

describe("fillSecure chokepoint", () => {
  it("fills buffers with fresh entropy on a healthy source", () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    fillSecure(a);
    fillSecure(b);
    // 256-bit collision is impossible in practice.
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("fails closed and latched: every draw rethrows the same failure, no bytes written", () => {
    __forceUnhealthyForTests("Stuck");
    const buf = new Uint8Array(32);
    for (let i = 0; i < 3; i++) {
      let caught: unknown;
      try {
        fillSecure(buf);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(EntropyError);
      expect((caught as EntropyError).kind).toBe("Stuck");
      expect(buf.every((x) => x === 0)).toBe(true);
    }
    __forceUnhealthyForTests(null);
    fillSecure(buf); // clears once healthy again
  });
});

describe("generation fails closed on a degraded source", () => {
  it("Keypair.generate, HybridKeypair.generate and generateMnemonic all throw", () => {
    __forceUnhealthyForTests("Pattern");
    expect(() => Keypair.generate()).toThrowError(EntropyError);
    expect(() => HybridKeypair.generate()).toThrowError(EntropyError);
    expect(() => generateMnemonic()).toThrowError(EntropyError);
    __forceUnhealthyForTests(null);
    // And all three recover once the source is healthy again.
    expect(Keypair.generate().publicKey.bytes.length).toBe(32);
    expect(HybridKeypair.generate().publicKey).toBeDefined();
    expect(validateMnemonic(generateMnemonic())).toBe(true);
  });
});

describe("outputs unchanged", () => {
  it("fixed entropy maps to the standard BIP-39 phrase via the new path", () => {
    // BIP-39 reference vector: 16 zero bytes.
    const zero16 = new Uint8Array(16);
    expect(entropyToMnemonic(zero16, wordlist)).toBe(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    // Deterministic: the same entropy always yields the same phrase.
    const e = new Uint8Array(32).map((_, i) => (i * 37 + 5) & 0xff);
    expect(entropyToMnemonic(e, wordlist)).toBe(entropyToMnemonic(Uint8Array.from(e), wordlist));
  });

  it("generateMnemonic keeps the strength signature and produces valid phrases", () => {
    expect(generateMnemonic().split(" ").length).toBe(24); // default 256-bit
    expect(generateMnemonic(128).split(" ").length).toBe(12);
    expect(validateMnemonic(generateMnemonic(160))).toBe(true);
  });
});
