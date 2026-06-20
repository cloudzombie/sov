/**
 * Ed25519 key material: generation, deterministic seed derivation, signing and
 * verification.
 *
 * Backed by @noble/ed25519 — an audited, dependency-light implementation of
 * RFC 8032 Ed25519. The SOV node uses ed25519-dalek
 * (`chain/crates/crypto/src/keys.rs`); both implement the same standard, so a
 * key derived from a given 32-byte seed and the signature it produces over a
 * given message are interoperable with the node's verification.
 *
 * Conventions mirrored from the Rust crate:
 *   - a public key is 32 bytes, exposed as lowercase hex (no 0x prefix) by
 *     {@link PublicKey.toHex}; {@link PublicKey.toString} renders the
 *     `ed25519:0x<hex>` display form used by `PublicKey`'s `Display`.
 *   - a signature is 64 bytes.
 *   - `from_seed(seed: [u8; 32])` derives a keypair deterministically: in
 *     Ed25519 the 32-byte seed *is* the signing key, so this matches
 *     `SigningKey::from_bytes` used by `Keypair::from_seed`.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512.js";

// @noble/ed25519 v2 needs a synchronous SHA-512 hook for its sync sign/verify
// API. We wire it to @noble/hashes (the audited companion library). This is set
// once at module load and is idempotent.
ed.etc.sha512Sync = (...msgs: Uint8Array[]): Uint8Array =>
  sha512(ed.etc.concatBytes(...msgs));

const PUBLIC_KEY_LEN = 32;
const SECRET_KEY_LEN = 32;
const SIGNATURE_LEN = 64;

/** Error thrown for malformed key/seed/signature material. */
export class KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyError";
  }
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function fromHex(hex: string): Uint8Array {
  let s = hex;
  if (s.startsWith("ed25519:")) s = s.slice("ed25519:".length);
  if (s.startsWith("0x")) s = s.slice(2);
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) {
    throw new KeyError(`invalid hex string: ${hex}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** A 32-byte Ed25519 public (verifying) key. */
export class PublicKey {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (bytes.length !== PUBLIC_KEY_LEN) {
      throw new KeyError(`public key must be ${PUBLIC_KEY_LEN} bytes, got ${bytes.length}`);
    }
    this.bytes = Uint8Array.from(bytes);
  }

  /** Parse a public key from hex, accepting optional `ed25519:` and `0x` prefixes. */
  static fromHex(hex: string): PublicKey {
    return new PublicKey(fromHex(hex));
  }

  /** Lowercase hex, no `0x` prefix (matches Rust `PublicKey::to_hex`). */
  toHex(): string {
    return toHex(this.bytes);
  }

  /** The `ed25519:0x<hex>` display form (matches Rust `PublicKey`'s `Display`). */
  toString(): string {
    return `ed25519:0x${this.toHex()}`;
  }

  /** JSON encoding mirrors the node: `0x<hex>`. */
  toJSON(): string {
    return `0x${this.toHex()}`;
  }

  /**
   * Verify a detached signature over `message`. Returns `false` for any
   * failure (malformed signature, mismatch) — never throws — mirroring the
   * Rust `PublicKey::verify` single yes/no contract.
   */
  verify(message: Uint8Array, signature: Signature): boolean {
    try {
      return ed.verify(signature.bytes, message, this.bytes);
    } catch {
      return false;
    }
  }
}

/** A 64-byte detached Ed25519 signature. */
export class Signature {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (bytes.length !== SIGNATURE_LEN) {
      throw new KeyError(`signature must be ${SIGNATURE_LEN} bytes, got ${bytes.length}`);
    }
    this.bytes = Uint8Array.from(bytes);
  }

  static fromHex(hex: string): Signature {
    return new Signature(fromHex(hex));
  }

  /** Lowercase hex, no `0x` prefix. */
  toHex(): string {
    return toHex(this.bytes);
  }

  /** The `0x<hex>` display/JSON form (matches Rust `Signature`'s `Display`). */
  toString(): string {
    return `0x${this.toHex()}`;
  }

  toJSON(): string {
    return this.toString();
  }
}

/**
 * An Ed25519 signing keypair. Holds secret seed material; never serialized.
 */
export class Keypair {
  /** The 32-byte secret seed (the Ed25519 signing key). Kept private to spending. */
  private readonly seed: Uint8Array;
  /** Cached public key. */
  readonly publicKey: PublicKey;

  private constructor(seed: Uint8Array, publicKey: PublicKey) {
    this.seed = Uint8Array.from(seed);
    this.publicKey = publicKey;
  }

  /** Generate a fresh keypair from cryptographically secure OS entropy. */
  static generate(): Keypair {
    const seed = new Uint8Array(SECRET_KEY_LEN);
    crypto.getRandomValues(seed);
    return Keypair.fromSeed(seed);
  }

  /**
   * Deterministically derive a keypair from a 32-byte seed. In Ed25519 the seed
   * is the signing key, so this matches the node's `Keypair::from_seed`.
   */
  static fromSeed(seed: Uint8Array): Keypair {
    if (seed.length !== SECRET_KEY_LEN) {
      throw new KeyError(`seed must be ${SECRET_KEY_LEN} bytes, got ${seed.length}`);
    }
    const pub = ed.getPublicKey(seed);
    return new Keypair(seed, new PublicKey(pub));
  }

  /** Sign `message`, producing a detached 64-byte signature. */
  sign(message: Uint8Array): Signature {
    return new Signature(ed.sign(message, this.seed));
  }

  /** Best-effort: expose the raw seed bytes (handle with care; secret material). */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.seed);
  }
}
