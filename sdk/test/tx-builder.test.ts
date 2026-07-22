import { describe, expect, it } from "vitest";
import { AccountIdError } from "../src/account.js";
import { bytesToHex, encodeTransaction, transactionId } from "../src/borsh.js";
import { Keypair } from "../src/keys.js";
import {
  TxBuildError,
  buildAndSign,
  buildTransaction,
  signTransaction,
  toWireSignedTransaction,
  transactionSigningBytes,
  verifyBuiltSignature,
} from "../src/tx-builder.js";
import type { Action } from "../src/types.js";
import { sovToGrains } from "../src/units.js";

const kp = () => Keypair.fromSeed(new Uint8Array(32).fill(1));

const transfer: Action = {
  type: "transfer",
  to: "ecb.reserve.sov",
  amount: sovToGrains("5").toString(),
};

describe("buildTransaction", () => {
  it("commits the signer, public key, nonce, and action", () => {
    const k = kp();
    const tx = buildTransaction({
      signer: "usa.reserve.sov",
      publicKey: k.publicKey,
      nonce: 0,
      action: transfer,
    });
    expect(tx.signer).toBe("usa.reserve.sov");
    expect(tx.public_key).toBe(k.publicKey.toJSON());
    expect(tx.nonce).toBe(0);
    expect(tx.action).toEqual(transfer);
  });

  it("rejects an invalid signer id", () => {
    expect(() =>
      buildTransaction({ signer: "BAD", publicKey: kp().publicKey, nonce: 0, action: transfer }),
    ).toThrow(/invalid character/);
  });

  it("rejects an invalid recipient in a transfer", () => {
    expect(() =>
      buildTransaction({
        signer: "usa.reserve.sov",
        publicKey: kp().publicKey,
        nonce: 0,
        action: { type: "transfer", to: "BAD", amount: "1" },
      }),
    ).toThrow(AccountIdError);
  });

  it("rejects an over-cap transfer amount", () => {
    expect(() =>
      buildTransaction({
        signer: "usa.reserve.sov",
        publicKey: kp().publicKey,
        nonce: 0,
        action: { type: "transfer", to: "ecb.reserve.sov", amount: "2100000000000001" },
      }),
    ).toThrow(/outside/);
  });

  it("rejects a negative or non-integer nonce", () => {
    expect(() =>
      buildTransaction({ signer: "usa.reserve.sov", publicKey: kp().publicKey, nonce: -1, action: transfer }),
    ).toThrow(/nonce/);
    expect(() =>
      buildTransaction({ signer: "usa.reserve.sov", publicKey: kp().publicKey, nonce: 1.5, action: transfer }),
    ).toThrow(/nonce/);
  });

  it("supports claim_vesting / call / deploy actions", () => {
    const pk = kp().publicKey;
    const base = { signer: "usa.reserve.sov", publicKey: pk, nonce: 0 };
    expect(() => buildTransaction({ ...base, action: { type: "claim_vesting" } })).not.toThrow();
    expect(() => buildTransaction({ ...base, action: { type: "call", contract: "vault.sov", gas_limit: 1000 } })).not.toThrow();
    expect(() => buildTransaction({ ...base, action: { type: "deploy", code: [0, 1, 2] } })).not.toThrow();
    expect(() => buildTransaction({ ...base, action: { type: "call", contract: "BAD", gas_limit: 1 } })).toThrow(AccountIdError);
  });
});

describe("signTransaction (canonical Borsh)", () => {
  it("produces a verifiable signed transaction with a canonical id", () => {
    const signed = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 0, action: transfer });
    expect(verifyBuiltSignature(signed)).toBe(true);
    expect(signed.id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signed.id).toBe(transactionId(signed.transaction));
  });

  it("matches the Rust known-answer vector exactly (id + signature)", () => {
    // seed [1;32], signer usa.reserve.sov, nonce 0, transfer 5 SOV -> ecb.reserve.sov.
    const signed = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 0, action: transfer });
    expect(signed.id).toBe("0xf20fe8e431eb688f037140b6d81727653974cd07827c130f8f9cec5ee7766e8e");
    expect(signed.signature).toBe(
      "0x7d42c424c304b57aa3b731b714b3babac4454f7c26e3ca4252caf7a0081e9cb5d0185b2c8e0eb89a1aee92f19b7c7ee1d476e536e3fb8db00395c43eb2367e0a",
    );
  });

  it("refuses to sign when the key does not match the committed public key", () => {
    const tx = buildTransaction({ signer: "usa.reserve.sov", publicKey: kp().publicKey, nonce: 0, action: transfer });
    const attacker = Keypair.fromSeed(new Uint8Array(32).fill(2));
    expect(() => signTransaction(tx, attacker)).toThrow(/does not match/);
  });

  it("tampering with the body invalidates the signature", () => {
    const signed = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 0, action: transfer });
    const tampered = { ...signed, transaction: { ...signed.transaction, nonce: 99 } };
    expect(verifyBuiltSignature(tampered)).toBe(false);
  });

  it("is deterministic (Ed25519) and nonce-sensitive", () => {
    const a = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 7, action: transfer });
    const b = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 7, action: transfer });
    expect(a.signature).toBe(b.signature);
    const c = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 8, action: transfer });
    expect(a.signature).not.toBe(c.signature);
  });

  it("toWireSignedTransaction drops the SDK-only id field", () => {
    const signed = buildAndSign({ signer: "usa.reserve.sov", keypair: kp(), nonce: 0, action: transfer });
    const wire = toWireSignedTransaction(signed);
    expect(Object.keys(wire).sort()).toEqual(["signature", "transaction"]);
    expect("id" in wire).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// tx-domain fork: network-bound signing (`sov:tx:v1` framing)
// ---------------------------------------------------------------------------

describe("transactionSigningBytes (tx-domain binding)", () => {
  // KAT pinned in LOCK-STEP with the Rust side
  // (chain/crates/rpc/src/client.rs, `bound_signing_preimage_matches_the_sdk_kat`):
  // same seed, transaction, and domain — both suites assert this exact hex, so a
  // TS-framed bound signature verifies byte-for-byte on a Rust node.
  const seed = new Uint8Array(32).fill(7);
  const katKp = () => Keypair.fromSeed(seed);
  const katSigner = "ad3981e8399e9d5f30346e336d66f70e1d9df9ae712362f4e3d6fed28967f719";
  const katDomain = { chainId: "sov-mainnet", genesis: "22".repeat(32) };
  const katTx = () =>
    buildTransaction({
      signer: katSigner,
      publicKey: katKp().publicKey,
      nonce: 7,
      action: { type: "transfer", to: "treasury.sov", amount: "42" },
    });
  const KAT_BOUND_PREIMAGE_HEX =
    "736f763a74783a763100736f762d6d61696e6e6574002222222222222222222222222222222222222222222222222222222222222222400000006164333938316538333939653964356633303334366533333664363666373065316439646639616537313233363266346533643666656432383936376637313900ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0700000000000000000c00000074726561737572792e736f762a000000000000000000000000000000";

  it("frames the bound preimage byte-for-byte like Rust `signing_bytes_in`", () => {
    // The key itself must match the Rust `Keypair::from_seed([7; 32])`.
    expect(katKp().publicKey.toJSON()).toBe(
      "0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    );
    expect(bytesToHex(transactionSigningBytes(katTx(), katDomain))).toBe(KAT_BOUND_PREIMAGE_HEX);
  });

  it("without a domain (dormant fork) the preimage IS the bare Borsh bytes", () => {
    const tx = katTx();
    expect(bytesToHex(transactionSigningBytes(tx))).toBe(bytesToHex(encodeTransaction(tx)));
    expect(bytesToHex(transactionSigningBytes(tx, null))).toBe(bytesToHex(encodeTransaction(tx)));
  });

  it("a bound signature verifies only under its domain; the tx id never changes", () => {
    const bound = signTransaction(katTx(), katKp(), katDomain);
    expect(verifyBuiltSignature(bound, katDomain)).toBe(true);
    expect(verifyBuiltSignature(bound)).toBe(false); // not a legacy signature
    expect(
      verifyBuiltSignature(bound, { chainId: "sov-testnet", genesis: katDomain.genesis }),
    ).toBe(false); // and never valid on another network

    const legacy = signTransaction(katTx(), katKp());
    expect(verifyBuiltSignature(legacy)).toBe(true);
    expect(verifyBuiltSignature(legacy, katDomain)).toBe(false);
    // The id hashes the UN-framed bytes: identical with or without the domain.
    expect(bound.id).toBe(legacy.id);
  });

  it("rejects a malformed domain genesis", () => {
    expect(() => transactionSigningBytes(katTx(), { chainId: "sov-mainnet", genesis: "2222" })).toThrow(
      /32 bytes/,
    );
  });
});
