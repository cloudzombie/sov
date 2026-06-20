import { describe, expect, it } from "vitest";
import {
  AmountError,
  DECIMALS,
  GRAINS_PER_SOV,
  MAX_SUPPLY_GRAINS,
  MAX_SUPPLY_SOV,
  assertWithinCap,
  grainsToSov,
  grainsToSovTrimmed,
  isWithinCap,
  sovToGrains,
} from "../src/units.js";

describe("constants match the chain", () => {
  it("8 decimals, 10^8 grains/SOV, 21M cap", () => {
    expect(DECIMALS).toBe(8);
    expect(GRAINS_PER_SOV).toBe(100_000_000n);
    expect(MAX_SUPPLY_SOV).toBe(21_000_000n);
    // 21,000,000 * 100,000,000
    expect(MAX_SUPPLY_GRAINS).toBe(2_100_000_000_000_000n);
  });
});

describe("sovToGrains", () => {
  it("converts whole and fractional SOV", () => {
    expect(sovToGrains("1")).toBe(100_000_000n);
    expect(sovToGrains("1.00000000")).toBe(100_000_000n);
    expect(sovToGrains("0")).toBe(0n);
    expect(sovToGrains("1.5")).toBe(150_000_000n);
    // Smallest unit: 1 grain.
    expect(sovToGrains("0.00000001")).toBe(1n);
    // Trailing/leading whitespace tolerated.
    expect(sovToGrains("  2.25  ")).toBe(225_000_000n);
  });

  it("accepts exactly the hard cap", () => {
    expect(sovToGrains("21000000")).toBe(MAX_SUPPLY_GRAINS);
    expect(sovToGrains("21000000.00000000")).toBe(MAX_SUPPLY_GRAINS);
  });

  it("rejects amounts over the cap", () => {
    expect(() => sovToGrains("21000001")).toThrow(AmountError);
    expect(() => sovToGrains("21000000.00000001")).toThrow(/exceeds the hard cap/);
  });

  it("rejects negative amounts", () => {
    expect(() => sovToGrains("-1")).toThrow(/negative/);
    expect(() => sovToGrains("-0.5")).toThrow(AmountError);
  });

  it("rejects too many fractional digits", () => {
    expect(() => sovToGrains("0.000000001")).toThrow(/fractional digits/);
  });

  it("rejects malformed strings", () => {
    for (const bad of ["", "  ", "abc", "1.2.3", "1e9", "0x10", ".", "1.", ".5", "1,5"]) {
      expect(() => sovToGrains(bad)).toThrow(AmountError);
    }
  });

  it("uses bigint, never floats — large values are exact", () => {
    // 12,345,678.12345678 SOV
    expect(sovToGrains("12345678.12345678")).toBe(1_234_567_812_345_678n);
  });
});

describe("grainsToSov", () => {
  it("formats with fixed 8 decimals", () => {
    expect(grainsToSov(100_000_000n)).toBe("1.00000000");
    expect(grainsToSov(1n)).toBe("0.00000001");
    expect(grainsToSov(0n)).toBe("0.00000000");
    expect(grainsToSov(150_000_000n)).toBe("1.50000000");
    expect(grainsToSov(MAX_SUPPLY_GRAINS)).toBe("21000000.00000000");
  });

  it("rejects negative grains", () => {
    expect(() => grainsToSov(-1n)).toThrow(AmountError);
  });

  it("round-trips with sovToGrains", () => {
    for (const s of ["0.00000000", "1.00000000", "1.50000000", "21000000.00000000"]) {
      expect(grainsToSov(sovToGrains(s))).toBe(s);
    }
  });
});

describe("grainsToSovTrimmed", () => {
  it("trims trailing fractional zeros like the Rust Display", () => {
    expect(grainsToSovTrimmed(700_000_000n)).toBe("7");
    expect(grainsToSovTrimmed(150_000_000n)).toBe("1.5");
    expect(grainsToSovTrimmed(1n)).toBe("0.00000001");
    expect(grainsToSovTrimmed(0n)).toBe("0");
  });
});

describe("cap predicates", () => {
  it("isWithinCap", () => {
    expect(isWithinCap(0n)).toBe(true);
    expect(isWithinCap(MAX_SUPPLY_GRAINS)).toBe(true);
    expect(isWithinCap(MAX_SUPPLY_GRAINS + 1n)).toBe(false);
    expect(isWithinCap(-1n)).toBe(false);
  });

  it("assertWithinCap throws past the cap", () => {
    expect(() => assertWithinCap(MAX_SUPPLY_GRAINS + 1n)).toThrow(AmountError);
    expect(() => assertWithinCap(0n)).not.toThrow();
  });
});
