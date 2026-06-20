import { describe, expect, it } from "vitest";
import { encodeTransaction } from "../src/borsh.js";
import { Keypair } from "../src/keys.js";
import type { Transaction } from "../src/types.js";

// The shielded action is Borsh variant 4, carrying the bundle as a Vec<u8>
// (u32-le length prefix + bytes) — the same primitives the node uses and that
// the Deploy action's known-answer vectors already pin byte-for-byte.
describe("shielded action encoding", () => {
  it("encodes as variant 4 + length-prefixed bundle bytes", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(1));
    const tx: Transaction = {
      signer: "usa.reserve.sov",
      public_key: kp.publicKey.toJSON(),
      nonce: 0,
      action: { type: "shielded", bundle: [0xaa, 0xbb, 0xcc] },
    };
    // The action is the final encoded field, so the tail is the action bytes.
    const tail = Array.from(encodeTransaction(tx).slice(-8));
    expect(tail).toEqual([4, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);
  });

  it("length-prefixes larger bundles correctly (little-endian u32)", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(2));
    const bundle = Array.from({ length: 300 }, (_, i) => i % 256);
    const tx: Transaction = {
      signer: "usa.reserve.sov",
      public_key: kp.publicKey.toJSON(),
      nonce: 5,
      action: { type: "shielded", bundle },
    };
    const bytes = encodeTransaction(tx);
    const tail = Array.from(bytes.slice(-(300 + 5)));
    // 300 = 0x012C -> [0x2c, 0x01, 0x00, 0x00].
    expect(tail.slice(0, 5)).toEqual([4, 0x2c, 0x01, 0x00, 0x00]);
    expect(tail.length).toBe(305);
  });
});
