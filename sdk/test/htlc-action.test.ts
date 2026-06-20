import { describe, expect, it } from "vitest";
import { encodeTransaction } from "../src/borsh.js";
import { Keypair } from "../src/keys.js";
import type { Action, Transaction } from "../src/types.js";

// HTLC actions are the SOV half of trustless cross-chain atomic swaps. These
// pin their Borsh encoding (variant index + field layout) using the same
// primitives the other actions' known-answer vectors already prove byte-exact.
const kp = Keypair.fromSeed(new Uint8Array(32).fill(1));
const tx = (action: Action): Transaction => ({
  signer: "usa.reserve.sov",
  public_key: kp.publicKey.toJSON(),
  nonce: 0,
  action,
});

describe("HTLC action encoding", () => {
  it("htlc_lock = variant 5 + recipient + amount(u128) + hashlock(32) + timeout(u64)", () => {
    const bytes = encodeTransaction(
      tx({
        type: "htlc_lock",
        recipient: "bob.sov",
        amount: "500000000", // 5 SOV in grains
        hashlock: "11".repeat(32),
        timeout_height: 100,
      }),
    );
    // tail: [5] | len(7) "bob.sov" | u128(5e8) | hashlock[32] | u64(100)
    const tailLen = 1 + 4 + 7 + 16 + 32 + 8;
    const tail = Array.from(bytes.slice(-tailLen));
    expect(tail[0]).toBe(5);
    expect(tail.slice(1, 5)).toEqual([7, 0, 0, 0]);
    expect(tail.slice(28, 60)).toEqual(new Array(32).fill(0x11));
    expect(tail.slice(60)).toEqual([100, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("htlc_claim = variant 6 + htlc_id(32) + preimage(vec)", () => {
    const bytes = encodeTransaction(
      tx({ type: "htlc_claim", htlc_id: "22".repeat(32), preimage: [1, 2, 3] }),
    );
    const tail = Array.from(bytes.slice(-(1 + 32 + 4 + 3)));
    expect(tail[0]).toBe(6);
    expect(tail.slice(1, 33)).toEqual(new Array(32).fill(0x22));
    expect(tail.slice(33, 37)).toEqual([3, 0, 0, 0]); // vec length
    expect(tail.slice(37)).toEqual([1, 2, 3]);
  });

  it("htlc_refund = variant 7 + htlc_id(32)", () => {
    const bytes = encodeTransaction(tx({ type: "htlc_refund", htlc_id: "33".repeat(32) }));
    const tail = Array.from(bytes.slice(-(1 + 32)));
    expect(tail[0]).toBe(7);
    expect(tail.slice(1)).toEqual(new Array(32).fill(0x33));
  });
});
