import { describe, expect, it } from "vitest";
import { KeyError, Keypair, PublicKey, Signature } from "../src/keys.js";

const enc = (s: string) => new TextEncoder().encode(s);

describe("deterministic key derivation", () => {
  it("same 32-byte seed yields the same public key", () => {
    const a = Keypair.fromSeed(new Uint8Array(32).fill(9)).publicKey;
    const b = Keypair.fromSeed(new Uint8Array(32).fill(9)).publicKey;
    expect(a.toHex()).toBe(b.toHex());
  });

  it("public key is 32 bytes / 64 hex chars", () => {
    const pk = Keypair.fromSeed(new Uint8Array(32).fill(7)).publicKey;
    expect(pk.bytes.length).toBe(32);
    expect(pk.toHex()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("seed of seven matches the standard Ed25519 vector for this seed", () => {
    // RFC 8032 Ed25519: the seed IS the signing key; getPublicKey([7;32]) is
    // deterministic and standard. Pinning it guards against an accidental API
    // or curve change. (This is the @noble output, which is the audited impl.)
    const pk = Keypair.fromSeed(new Uint8Array(32).fill(7)).publicKey;
    expect(pk.toHex()).toBe(
      "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    );
  });

  it("rejects a wrong-length seed", () => {
    expect(() => Keypair.fromSeed(new Uint8Array(31))).toThrow(KeyError);
  });

  it("generate() produces distinct keys", () => {
    const a = Keypair.generate().publicKey.toHex();
    const b = Keypair.generate().publicKey.toHex();
    expect(a).not.toBe(b);
  });
});

describe("sign / verify", () => {
  it("round-trips a signature", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(7));
    const msg = enc("transfer 5 SOV to ecb.reserve.sov");
    const sig = kp.sign(msg);
    expect(sig.bytes.length).toBe(64);
    expect(kp.publicKey.verify(msg, sig)).toBe(true);
  });

  it("rejects a tampered message", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(7));
    const sig = kp.sign(enc("send 5"));
    expect(kp.publicKey.verify(enc("send 6"), sig)).toBe(false);
  });

  it("rejects a wrong key", () => {
    const signer = Keypair.fromSeed(new Uint8Array(32).fill(1));
    const other = Keypair.fromSeed(new Uint8Array(32).fill(2)).publicKey;
    const msg = enc("vote yes");
    const sig = signer.sign(msg);
    expect(other.verify(msg, sig)).toBe(false);
  });

  it("signatures are deterministic (Ed25519)", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(3));
    const msg = enc("deterministic");
    expect(kp.sign(msg).toHex()).toBe(kp.sign(msg).toHex());
  });
});

describe("hex encodings (matching the node's conventions)", () => {
  it("PublicKey.toString is ed25519:0x<hex>, toJSON is 0x<hex>", () => {
    const pk = Keypair.fromSeed(new Uint8Array(32).fill(7)).publicKey;
    expect(pk.toString()).toBe(`ed25519:0x${pk.toHex()}`);
    expect(pk.toJSON()).toBe(`0x${pk.toHex()}`);
  });

  it("PublicKey.fromHex accepts ed25519: and 0x prefixes and round-trips", () => {
    const pk = Keypair.fromSeed(new Uint8Array(32).fill(5)).publicKey;
    expect(PublicKey.fromHex(pk.toHex()).toHex()).toBe(pk.toHex());
    expect(PublicKey.fromHex(pk.toJSON()).toHex()).toBe(pk.toHex());
    expect(PublicKey.fromHex(pk.toString()).toHex()).toBe(pk.toHex());
  });

  it("Signature toString/toJSON is 0x<hex> and round-trips via fromHex", () => {
    const kp = Keypair.fromSeed(new Uint8Array(32).fill(8));
    const sig = kp.sign(enc("x"));
    expect(sig.toString()).toBe(`0x${sig.toHex()}`);
    expect(Signature.fromHex(sig.toJSON()).toHex()).toBe(sig.toHex());
  });

  it("rejects malformed hex and wrong-length material", () => {
    expect(() => PublicKey.fromHex("0xzz")).toThrow(KeyError);
    expect(() => new PublicKey(new Uint8Array(31))).toThrow(KeyError);
    expect(() => new Signature(new Uint8Array(63))).toThrow(KeyError);
  });
});
