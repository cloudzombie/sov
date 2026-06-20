/**
 * SOV unit math: conversion between whole SOV and the smallest indivisible
 * unit, the *grain*.
 *
 * Mirrors `chain/crates/primitives/src/amount.rs` exactly:
 *   - 1 SOV = 10^8 grains (DECIMALS = 8 — Bitcoin/Zcash precision).
 *   - hard supply cap = 21,000,000 SOV = 2,100,000,000,000,000 grains.
 *
 * Grains are always carried as `bigint`. A grain count can exceed JavaScript's
 * safe-integer limit (2^53), so a `number` would silently corrupt large values.
 * No floating-point arithmetic ever touches an amount.
 */

/** Number of decimal places. 1 SOV = 10^DECIMALS grains. */
export const DECIMALS = 8;

/** Grains per whole SOV (10^8). */
export const GRAINS_PER_SOV = 100_000_000n;

/** The hard cap on total supply, in whole SOV. */
export const MAX_SUPPLY_SOV = 21_000_000n;

/** The hard cap on total supply, in grains. */
export const MAX_SUPPLY_GRAINS = MAX_SUPPLY_SOV * GRAINS_PER_SOV;

/** Error thrown when an amount is malformed or out of range. */
export class AmountError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AmountError";
  }
}

/**
 * Parse a decimal XUS string (e.g. "1.5", "0.00000001", "21000000") into a
 * grain count.
 *
 * Rules:
 *   - at most {@link DECIMALS} fractional digits;
 *   - no negative values;
 *   - the result must not exceed the supply cap;
 *   - only an optional single '.' and ASCII digits are accepted.
 */
export function sovToGrains(sov: string): bigint {
  if (typeof sov !== "string") {
    throw new AmountError("XUS amount must be a string");
  }
  const trimmed = sov.trim();
  if (trimmed.length === 0) {
    throw new AmountError("empty XUS amount");
  }
  if (trimmed.startsWith("-")) {
    throw new AmountError(`negative amounts are not allowed: ${sov}`);
  }
  // Allow an optional leading '+'.
  const unsigned = trimmed.startsWith("+") ? trimmed.slice(1) : trimmed;

  if (!/^[0-9]+(\.[0-9]+)?$/.test(unsigned)) {
    throw new AmountError(`invalid XUS decimal string: ${sov}`);
  }

  const dotIdx = unsigned.indexOf(".");
  const wholePart = dotIdx === -1 ? unsigned : unsigned.slice(0, dotIdx);
  const fracPart = dotIdx === -1 ? "" : unsigned.slice(dotIdx + 1);
  if (fracPart.length > DECIMALS) {
    throw new AmountError(
      `too many fractional digits (max ${DECIMALS}): ${sov}`,
    );
  }

  const whole = BigInt(wholePart);
  const fracPadded = fracPart.padEnd(DECIMALS, "0");
  const frac = fracPadded.length === 0 ? 0n : BigInt(fracPadded);

  const grains = whole * GRAINS_PER_SOV + frac;
  if (grains > MAX_SUPPLY_GRAINS) {
    throw new AmountError(
      `amount ${sov} XUS exceeds the hard cap of ${MAX_SUPPLY_SOV} XUS`,
    );
  }
  return grains;
}

/**
 * Format a grain count as a fixed 8-decimal XUS string (e.g. "1.00000000").
 * Rejects negative grains; does not enforce the supply cap (a raw grain count
 * from elsewhere may legitimately be inspected), use {@link assertWithinCap}.
 */
export function grainsToSov(grains: bigint): string {
  if (typeof grains !== "bigint") {
    throw new AmountError("grains must be a bigint");
  }
  if (grains < 0n) {
    throw new AmountError(`negative grain count: ${grains}`);
  }
  const whole = grains / GRAINS_PER_SOV;
  const frac = grains % GRAINS_PER_SOV;
  const fracStr = frac.toString().padStart(DECIMALS, "0");
  return `${whole.toString()}.${fracStr}`;
}

/**
 * Like {@link grainsToSov} but trims trailing fractional zeros (and a bare
 * trailing '.'), matching the Rust `Display` impl's human-readable form
 * (e.g. 100000000n -> "1", 150000000n -> "1.5").
 */
export function grainsToSovTrimmed(grains: bigint): string {
  const fixed = grainsToSov(grains);
  const [whole, frac = ""] = fixed.split(".");
  const trimmedFrac = frac.replace(/0+$/, "");
  return trimmedFrac.length === 0 ? whole! : `${whole}.${trimmedFrac}`;
}

/** Whether a grain count is within the protocol supply cap. */
export function isWithinCap(grains: bigint): boolean {
  return grains >= 0n && grains <= MAX_SUPPLY_GRAINS;
}

/** Throw {@link AmountError} unless `grains` is in `[0, MAX_SUPPLY_GRAINS]`. */
export function assertWithinCap(grains: bigint): void {
  if (!isWithinCap(grains)) {
    throw new AmountError(
      `grain count ${grains} is outside [0, ${MAX_SUPPLY_GRAINS}]`,
    );
  }
}
