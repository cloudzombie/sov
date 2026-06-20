// Cross-implementation KAT for the SOV address tiers: the vector strings below
// were produced by the REAL Rust wallet (`sov-wallet keygen` with seed
// 0xabab…ab, account alice.actor.sov) — this TS decoder must agree with the
// Rust encoder byte-for-byte, exactly like the transaction KATs.
import { describe, expect, it } from "vitest";
import {
  decodeShielded,
  decodeUnified,
  parseAddress,
  preferredReceiver,
} from "../src/address.js";
import { Wallet } from "../src/wallet.js";
import { Keypair } from "../src/keys.js";

const RUST_SHIELDED =
  "xus15ydu29kslfum829htllqfvgknj20d89la76hvnu8lu64w48s4xle7vrz6eznfzgn649t2xsmqeh";
const RUST_UNIFIED =
  "uxus1qq8kzmrfvdjjuctrw3hhytnndamqz2apr0z3d5860xe63d6llcztz95ujnmfe0l0k4mylpllx4t4fu9fh70nqckkg56gjy74f26s7nntk4";

describe("SOV address tiers (Rust-produced KAT vectors)", () => {
  it("decodes the Rust xus1… shielded address to a 43-byte receiver", () => {
    const receiver = decodeShielded(RUST_SHIELDED);
    expect(receiver.length).toBe(43);
    // Case-insensitive per bech32m.
    expect(decodeShielded(RUST_SHIELDED.toUpperCase())).toEqual(receiver);
  });

  it("decodes the Rust uxus1… UA and its receivers match the standalone forms", () => {
    const ua = decodeUnified(RUST_UNIFIED);
    expect(ua.transparent).toBe("alice.actor.sov");
    // The UA's embedded shielded receiver is byte-identical to the xus1… form.
    expect(ua.shielded).toEqual(decodeShielded(RUST_SHIELDED));
  });

  it("routes privacy-first and never guesses at garbage", () => {
    expect(preferredReceiver(parseAddress("alice.actor.sov"))).toEqual({
      kind: "transparent",
      account: "alice.actor.sov",
    });
    expect(preferredReceiver(parseAddress(RUST_UNIFIED)).kind).toBe("shielded");
    expect(preferredReceiver(parseAddress(RUST_SHIELDED)).kind).toBe("shielded");
    expect(() => parseAddress("Not An Address!")).toThrow();
    expect(() => parseAddress("xus1qqqqqq")).toThrow(); // bad checksum
  });

  it("detects tampering via the bech32m checksum", () => {
    const tampered =
      RUST_SHIELDED.slice(0, -1) + (RUST_SHIELDED.endsWith("s") ? "q" : "s");
    expect(() => decodeShielded(tampered)).toThrow();
  });

  it("wallet.transfer refuses a shielded route honestly (no silent downgrade)", async () => {
    const wallet = new Wallet({} as never, "alice.actor.sov", Keypair.fromSeed(new Uint8Array(32).fill(1)));
    await expect(async () => wallet.transfer(RUST_SHIELDED, "1")).rejects.toThrow(/Halo2|shielded/i);
    await expect(async () => wallet.transfer(RUST_UNIFIED, "1")).rejects.toThrow(/Halo2|shielded/i);
  });
});
