import { describe, expect, it } from "vitest";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha512.js";
import {
  HdWallet,
  HARDENED_OFFSET,
  SOV_COIN_TYPE,
  generateMnemonic,
  parsePath,
  sovPath,
  sovPathString,
  validateMnemonic,
} from "../src/hd.js";
import { Keypair, KeyError } from "../src/keys.js";

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// The canonical BIP-39 reference vector (Trezor): the all-"abandon"/"about"
// 12-word phrase with passphrase "TREZOR" maps to this 64-byte seed. Pins our
// mnemonic->seed path (PBKDF2-HMAC-SHA512) against the published standard.
const TREZOR_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TREZOR_SEED =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

// SLIP-0010 specification, test vector 1 for ed25519 (seed below). Pins our
// hierarchical derivation against the published standard, byte-for-byte.
const SLIP10_SEED = "000102030405060708090a0b0c0d0e0f";
const SLIP10_M_PRIV = "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7";
const SLIP10_M_PUB = "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed";
const SLIP10_M0H_PRIV = "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3";
const SLIP10_M0H_PUB = "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c";

describe("BIP-39 mnemonic -> seed", () => {
  it("matches the Trezor reference vector", () => {
    const w = HdWallet.fromMnemonic(TREZOR_MNEMONIC, "TREZOR");
    expect(hex(w.exportSeed())).toBe(TREZOR_SEED);
  });

  it("generates and round-trips a valid 24-word mnemonic", () => {
    const m = generateMnemonic(256);
    expect(m.trim().split(/\s+/).length).toBe(24);
    expect(validateMnemonic(m)).toBe(true);
  });

  it("rejects a mnemonic with a bad checksum", () => {
    const bad =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    expect(validateMnemonic(bad)).toBe(false);
    expect(() => HdWallet.fromMnemonic(bad)).toThrow(KeyError);
  });

  it("a passphrase changes the derived seed", () => {
    const a = HdWallet.fromMnemonic(TREZOR_MNEMONIC, "");
    const b = HdWallet.fromMnemonic(TREZOR_MNEMONIC, "TREZOR");
    expect(hex(a.exportSeed())).not.toBe(hex(b.exportSeed()));
  });
});

describe("SLIP-0010 Ed25519 derivation (spec test vector 1)", () => {
  const wallet = HdWallet.fromSeed(fromHex(SLIP10_SEED));

  it("master node matches the spec (private + public)", () => {
    const kp = wallet.deriveKeypairAtPath("m");
    expect(hex(kp.exportSeed())).toBe(SLIP10_M_PRIV);
    expect(kp.publicKey.toHex()).toBe(SLIP10_M_PUB);
  });

  it("m/0H matches the spec (private + public)", () => {
    const kp = wallet.deriveKeypairAtPath("m/0'");
    expect(hex(kp.exportSeed())).toBe(SLIP10_M0H_PRIV);
    expect(kp.publicKey.toHex()).toBe(SLIP10_M0H_PUB);
  });

  it("master key equals the independent HMAC-SHA512 of the seed (no hand-rolled formula)", () => {
    // SLIP-0010 master: I = HMAC-SHA512(key="ed25519 seed", data=seed); I_L is key.
    const i = hmac(sha512, new TextEncoder().encode("ed25519 seed"), fromHex(SLIP10_SEED));
    expect(hex(wallet.deriveKeypairAtPath("m").exportSeed())).toBe(hex(i.slice(0, 32)));
  });
});

describe("SOV BIP-44 paths and HdWallet", () => {
  it("builds the standard hardened SOV path", () => {
    expect(sovPathString(0, 0)).toBe(`m/44'/${SOV_COIN_TYPE}'/0'/0'/0'`);
    expect(sovPath(2, 7)).toEqual([
      44 + HARDENED_OFFSET,
      SOV_COIN_TYPE + HARDENED_OFFSET,
      2 + HARDENED_OFFSET,
      0 + HARDENED_OFFSET,
      7 + HARDENED_OFFSET,
    ]);
    // deriveKeypair(account, index) is exactly the standard-path derivation.
    const w = HdWallet.fromMnemonic(TREZOR_MNEMONIC);
    expect(w.deriveKeypair(2, 7).publicKey.toHex()).toBe(
      w.deriveKeypairAtPath(sovPathString(2, 7)).publicKey.toHex(),
    );
  });

  it("is deterministic: one mnemonic always yields the same account key", () => {
    const a = HdWallet.fromMnemonic(TREZOR_MNEMONIC).deriveKeypair(0, 0);
    const b = HdWallet.fromMnemonic(TREZOR_MNEMONIC).deriveKeypair(0, 0);
    expect(a.publicKey.toHex()).toBe(b.publicKey.toHex());
  });

  it("matches the Rust cross-impl vector (same mnemonic -> same SOV key)", () => {
    // The Rust HD wallet (chain/crates/wallet/src/hd.rs) asserts this exact key
    // for the Trezor mnemonic at m/44'/SOV'/0'/0'/0' — byte-for-byte HD parity.
    const kp = HdWallet.fromMnemonic(TREZOR_MNEMONIC).deriveKeypair(0, 0);
    expect(kp.publicKey.toHex()).toBe(
      "cfedb9535588130e7215859f1346fce339c40c6601196d465fea5c7d43f14464",
    );
  });

  it("derives distinct keys per account and per address index", () => {
    const w = HdWallet.fromMnemonic(TREZOR_MNEMONIC);
    const keys = [w.deriveKeypair(0, 0), w.deriveKeypair(0, 1), w.deriveKeypair(1, 0)].map((k) =>
      k.publicKey.toHex(),
    );
    expect(new Set(keys).size).toBe(3);
  });

  it("derived keypair signs and verifies — it is a usable account-controlling key", () => {
    const kp = HdWallet.fromMnemonic(TREZOR_MNEMONIC).deriveKeypair(0, 0);
    const msg = new TextEncoder().encode("bind this key to usa.reserve.sov");
    const sig = kp.sign(msg);
    expect(kp.publicKey.verify(msg, sig)).toBe(true);
    // The public key is the value an account is provisioned with on-chain.
    expect(kp.publicKey.bytes.length).toBe(32);
  });
});

describe("HD path validation (Ed25519 is hardened-only)", () => {
  it("rejects a non-hardened component", () => {
    expect(() => parsePath("m/44'/0/0'")).toThrow(KeyError);
  });
  it("rejects a path that does not start with m", () => {
    expect(() => parsePath("44'/0'")).toThrow(KeyError);
  });
  it("rejects deriving at a non-hardened raw index array", () => {
    const w = HdWallet.fromMnemonic(TREZOR_MNEMONIC);
    expect(() => w.deriveKeypairAtPath([44])).toThrow(KeyError);
  });
  it("rejects a too-short raw seed", () => {
    expect(() => HdWallet.fromSeed(new Uint8Array(8))).toThrow(KeyError);
  });
});
