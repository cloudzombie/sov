/**
 * SOV address tiers — parsing and routing (mirror of the Rust
 * `sov_shielded::address` module, byte-for-byte on the wire):
 *
 * - **Transparent** — a named account, used as-is: `alice.actor.sov`.
 * - **Shielded** — `xus1…`: bech32m (BIP-350) over the 43-byte Orchard
 *   receiver. Decoded and validated here; *paying* one requires a Halo2
 *   prover, which this SDK deliberately does not re-implement (the same
 *   delegated-verification boundary as `SECOND-CLIENT.md`) — the Rust wallet
 *   (`sov-wallet transfer`) is the shielded-send path.
 * - **Unified** — `uxus1…`: TLV carrying a named account and/or a shielded
 *   receiver. Routing is privacy-first: a UA with a shielded receiver routes
 *   shielded. This SDK never silently downgrades a shielded route to a
 *   transparent send — that choice is always the caller's, explicitly.
 *
 * Encoding via `@scure/base` (audited, same author as the noble crypto this
 * SDK already builds on) — nothing hand-rolled.
 */

import { bech32m } from "@scure/base";

/** The bech32m prefix of a shielded address. */
const HRP_SHIELDED = "xus";
/** The bech32m prefix of a unified address. */
const HRP_UNIFIED = "uxus";
/** Unified-address TLV typecode: transparent account id (UTF-8). */
const UA_TYPE_TRANSPARENT = 0x00;
/** Unified-address TLV typecode: 43-byte Orchard shielded receiver. */
const UA_TYPE_SHIELDED = 0x01;
/** Account-id charset, mirroring `sov_primitives::AccountId`. */
const ACCOUNT_RE = /^[a-z0-9][a-z0-9\-_.]*$/;

/** A parsed recipient of any tier. */
export type AnyAddress =
  | { kind: "transparent"; account: string }
  | { kind: "shielded"; receiver: Uint8Array }
  | { kind: "unified"; transparent?: string; shielded?: Uint8Array };

/** The receiver a sender should pay, privacy-first. */
export type Receiver =
  | { kind: "transparent"; account: string }
  | { kind: "shielded"; receiver: Uint8Array };

function decodeBech32m(s: string, expectHrp: string): Uint8Array {
  const { prefix, words } = bech32m.decode(s as `${string}1${string}`, 1023);
  if (prefix.toLowerCase() !== expectHrp) {
    throw new Error(`wrong address kind: expected ${expectHrp}1…, got ${prefix}1…`);
  }
  return bech32m.fromWords(words);
}

/** Decode a `xus1…` shielded address to its 43-byte Orchard receiver. */
export function decodeShielded(s: string): Uint8Array {
  const payload = decodeBech32m(s, HRP_SHIELDED);
  if (payload.length !== 43) throw new Error("shielded receiver must be 43 bytes");
  return payload;
}

/** Decode a `uxus1…` unified address (unknown receiver types are skipped). */
export function decodeUnified(s: string): Extract<AnyAddress, { kind: "unified" }> {
  const payload = decodeBech32m(s, HRP_UNIFIED);
  let transparent: string | undefined;
  let shielded: Uint8Array | undefined;
  let i = 0;
  while (i < payload.length) {
    if (i + 2 > payload.length) throw new Error("malformed unified address TLV");
    // Guarded by the bounds check above, so both indices are present.
    const ty = payload[i] as number;
    const len = payload[i + 1] as number;
    i += 2;
    if (i + len > payload.length) throw new Error("malformed unified address TLV");
    const value = payload.slice(i, i + len);
    i += len;
    if (ty === UA_TYPE_TRANSPARENT) {
      if (transparent !== undefined) throw new Error("unified address duplicates the transparent receiver");
      const name = new TextDecoder().decode(value);
      if (!ACCOUNT_RE.test(name)) throw new Error("unified address carries an invalid account id");
      transparent = name;
    } else if (ty === UA_TYPE_SHIELDED) {
      if (shielded !== undefined) throw new Error("unified address duplicates the shielded receiver");
      if (value.length !== 43) throw new Error("unified shielded receiver must be 43 bytes");
      shielded = value;
    }
    // Unknown receiver kinds from a future wallet: skipped (forward compat).
  }
  if (transparent === undefined && shielded === undefined) {
    throw new Error("unified address carries no known receiver");
  }
  // Build with only the present receivers (exactOptionalPropertyTypes: no
  // explicit `undefined` on optional fields).
  const out: Extract<AnyAddress, { kind: "unified" }> = { kind: "unified" };
  if (transparent !== undefined) out.transparent = transparent;
  if (shielded !== undefined) out.shielded = shielded;
  return out;
}

/** Parse a recipient string of any tier. Garbage is rejected, never guessed at. */
export function parseAddress(s: string): AnyAddress {
  const lower = s.toLowerCase();
  if (lower.startsWith("xus1")) return { kind: "shielded", receiver: decodeShielded(s) };
  if (lower.startsWith("uxus1")) return decodeUnified(s);
  if (!ACCOUNT_RE.test(s)) throw new Error(`invalid recipient: ${s}`);
  return { kind: "transparent", account: s };
}

/**
 * The receiver a sender should pay — **shielded whenever the address carries
 * one** (privacy by default), the named account otherwise.
 */
export function preferredReceiver(address: AnyAddress): Receiver {
  switch (address.kind) {
    case "transparent":
      return { kind: "transparent", account: address.account };
    case "shielded":
      return { kind: "shielded", receiver: address.receiver };
    case "unified":
      if (address.shielded) return { kind: "shielded", receiver: address.shielded };
      return { kind: "transparent", account: address.transparent! };
  }
}
