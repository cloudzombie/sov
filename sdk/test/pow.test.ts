/**
 * Cross-implementation PROOF-OF-WORK SEAL verification: from the published
 * `pow.json` alone, the SDK reconstructs the header, Borsh-encodes it (the PoW
 * preimage), SHA-256d's it at each nonce, and checks `hash <= target` (Bitcoin
 * compact nBits) — and must match the node bit-for-bit. This is the seal contract
 * every miner shares; a single-bit divergence here forks the chain. The mainnet
 * seal is RandomX (a memory-hard VM, delegated like Halo2), but its INPUT is this
 * same Borsh preimage, so a RandomX miner reuses `pow_preimage_hex`.
 * Vector: `cargo run -p sov-rpc --bin sov-katgen -- pow > sdk/vectors/pow.json`.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha256.js";
import { encodeBlockHeader, bytesToHex, hexToBytes } from "../src/borsh.js";
import type { BlockHeader } from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));

interface PowVector {
  algo: string;
  header: BlockHeader;
  pow_preimage_hex: string;
  seal_samples: { nonce: number; pow_hash_hex: string }[];
  target_checks: {
    name: string;
    bits: number;
    target_hex: string;
    probe_hash_hex: string;
    meets_target: boolean;
  }[];
}

const vec: PowVector = JSON.parse(readFileSync(join(here, "..", "vectors", "pow.json"), "utf8"));

/** SHA-256d — Bitcoin's double SHA-256, the testnet PoW seal. */
const sha256d = (b: Uint8Array): Uint8Array => sha256(sha256(b));

/**
 * Bitcoin SetCompact: decode nBits to a 32-byte big-endian target. Mirrors
 * `sov_pow::Target::from_compact` for the canonical targets these vectors pin.
 */
function targetFromCompact(bits: number): Uint8Array {
  if ((bits & 0x00800000) !== 0) throw new Error("negative target");
  const out = new Uint8Array(32);
  const size = bits >>> 24;
  let mantissa = bits & 0x007fffff;
  if (mantissa === 0) return out;
  if (size <= 3) {
    mantissa = mantissa >>> (8 * (3 - size));
    out[29] = (mantissa >>> 16) & 0xff;
    out[30] = (mantissa >>> 8) & 0xff;
    out[31] = mantissa & 0xff;
  } else {
    const b = [(mantissa >>> 16) & 0xff, (mantissa >>> 8) & 0xff, mantissa & 0xff];
    for (let k = 0; k < 3; k++) {
      const idx = 32 + k - size;
      if (idx >= 0 && idx < 32) out[idx] = b[k];
    }
  }
  return out;
}

/** `hash <= target`, both 32-byte big-endian (mirror `Target::is_met_by`). */
function meets(hashHex: string, target: Uint8Array): boolean {
  const h = hexToBytes(hashHex);
  for (let i = 0; i < 32; i++) {
    if (h[i] < target[i]) return true;
    if (h[i] > target[i]) return false;
  }
  return true;
}

describe("proof-of-work seal cross-impl KAT", () => {
  it(`header Borsh PoW preimage (${vec.algo})`, () => {
    expect(bytesToHex(encodeBlockHeader(vec.header))).toBe(vec.pow_preimage_hex);
  });

  for (const s of vec.seal_samples) {
    it(`sha256d seal at nonce ${s.nonce}`, () => {
      const header: BlockHeader = { ...vec.header, nonce: s.nonce };
      expect(bytesToHex(sha256d(encodeBlockHeader(header)))).toBe(s.pow_hash_hex);
    });
  }

  for (const c of vec.target_checks) {
    it(`target "${c.name}": from_compact round-trip + hash<=target`, () => {
      const target = targetFromCompact(c.bits);
      expect(bytesToHex(target)).toBe(c.target_hex);
      expect(meets(c.probe_hash_hex, target)).toBe(c.meets_target);
    });
  }
});
