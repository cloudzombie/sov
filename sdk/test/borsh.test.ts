/**
 * Known-answer tests: the SDK's Borsh encoding, transaction id, and signature
 * must equal, byte-for-byte, the vectors generated from the Rust node
 * (`cargo run -p sov-rpc --bin sov-katgen > sdk/vectors/transactions.json`).
 * This is the proof that transactions built by the SDK are wire-compatible.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { encodeSignedTransaction, encodeTransaction, transactionIdBytes } from "../src/borsh.js";
import { Keypair } from "../src/keys.js";
import type { Action, Transaction } from "../src/types.js";

interface Vector {
  name: string;
  seed_hex: string;
  signer: string;
  public_key_hex: string;
  public_key_json: string;
  nonce: number;
  action: Action;
  signing_bytes_hex: string;
  tx_id_hex: string;
  signature_hex: string;
  signed_tx_borsh_hex: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors: Vector[] = JSON.parse(
  readFileSync(join(here, "..", "vectors", "transactions.json"), "utf8"),
);

const toHex = (b: Uint8Array): string => {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
};
const seedBytes = (hex: string): Uint8Array => {
  const o = new Uint8Array(hex.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return o;
};

describe("Borsh known-answer vectors (byte-for-byte parity with the Rust node)", () => {
  it("loads vectors", () => expect(vectors.length).toBeGreaterThan(0));

  for (const v of vectors) {
    describe(v.name, () => {
      const kp = Keypair.fromSeed(seedBytes(v.seed_hex));
      const tx: Transaction = {
        signer: v.signer,
        public_key: v.public_key_json,
        nonce: v.nonce,
        action: v.action,
      };

      it("derives the same public key", () => {
        expect(kp.publicKey.toHex()).toBe(v.public_key_hex);
      });
      it("encodes identical Borsh signing bytes", () => {
        expect(toHex(encodeTransaction(tx))).toBe(v.signing_bytes_hex);
      });
      it("computes the same Blake3 transaction id", () => {
        expect(toHex(transactionIdBytes(tx))).toBe(v.tx_id_hex);
      });
      it("produces the same Ed25519 signature (canonical scheme-tagged encoding)", () => {
        // The vector carries the canonical Borsh signature: scheme byte 0x00
        // (Ed25519) followed by the 64 raw signature bytes.
        expect("00" + kp.sign(encodeTransaction(tx)).toHex()).toBe(v.signature_hex);
      });
      it("encodes the same full signed-transaction Borsh", () => {
        const sig = kp.sign(encodeTransaction(tx));
        const signed = { transaction: tx, signature: sig.toJSON() };
        expect(toHex(encodeSignedTransaction(signed))).toBe(v.signed_tx_borsh_hex);
      });
    });
  }
});
