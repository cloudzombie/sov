/**
 * Hybrid post-quantum keys: Ed25519 + ML-DSA-65 (FIPS 204) — SOV's DEFAULT
 * signing scheme (on-chain scheme byte `0x01`, display prefix `hybrid65:`).
 *
 * This is the byte-for-byte TypeScript twin of the node's
 * `Keypair::hybrid_from_seed` / `PublicKey::V2HybridMlDsa65`
 * (`chain/crates/crypto/src/keys.rs`):
 *
 *   - Both component keys derive from ONE 32-byte master seed under the SAME
 *     Blake3 domain tags (`sov:hybrid65:{ed25519,ml-dsa-65,ml-dsa-sign}:v1`).
 *   - ML-DSA-65 keygen/sign use the audited `@noble/post-quantum`, which matches
 *     the Rust `fips204` crate (pinned by the cross-impl KAT in
 *     `test/hybrid.test.ts` against `vectors/hybrid-key.json`).
 *   - Signing is DETERMINISTIC: the ML-DSA randomness is itself derived from the
 *     seed (domain `…ml-dsa-sign:v1`) and supplied as `extraEntropy`, with an
 *     empty context — exactly `try_sign_with_seed(sign_seed, msg, b"")` on the
 *     Rust side, so the two implementations produce identical signature bytes.
 *
 * Verification is a CONJUNCTION: a hybrid signature is valid only if BOTH the
 * Ed25519 and the ML-DSA-65 components verify, so forging it requires breaking
 * Ed25519 AND ML-DSA-65 simultaneously.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import * as ed from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

// Importing keys.js initializes @noble/ed25519's synchronous SHA-512 hook (set
// once at that module's load), which `ed.getPublicKey`/`ed.sign` need here too.
import { KeyError } from "./keys.js";

const ED_PUB_LEN = 32;
const ED_SIG_LEN = 64;
/** ML-DSA-65 (FIPS 204) public key length. */
const MLDSA_PUB_LEN = 1952;
/** ML-DSA-65 (FIPS 204) signature length. */
const MLDSA_SIG_LEN = 3309;
const SEED_LEN = 32;

const DOMAIN_ED25519 = "sov:hybrid65:ed25519:v1";
const DOMAIN_MLDSA = "sov:hybrid65:ml-dsa-65:v1";
const DOMAIN_MLDSA_SIGN = "sov:hybrid65:ml-dsa-sign:v1";

const SCHEME_PREFIX = "hybrid65:";

const textEncoder = new TextEncoder();

/** Blake3 with a domain-separation tag — `blake3(domain ‖ seed)`, 32-byte
 * output. Matches the node's `derive_seed` (`chain/crates/crypto/src/keys.rs`). */
function deriveSeed(domain: string, seed: Uint8Array): Uint8Array {
  const tag = textEncoder.encode(domain);
  const input = new Uint8Array(tag.length + seed.length);
  input.set(tag, 0);
  input.set(seed, tag.length);
  return blake3(input);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Decode the concatenated component hex of a hybrid key/signature, accepting an
 * optional `hybrid65:` prefix and `0x`. */
function fromHybridHex(hex: string): Uint8Array {
  let s = hex;
  if (s.startsWith(SCHEME_PREFIX)) s = s.slice(SCHEME_PREFIX.length);
  if (s.startsWith("0x")) s = s.slice(2);
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) {
    throw new KeyError(`invalid hybrid hex string: ${hex}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * A hybrid Ed25519 + ML-DSA-65 public key. Its on-chain/JSON form is
 * `hybrid65:0x<ed25519 ‖ ml-dsa-65>` (32 + 1952 bytes), exactly the node's
 * `PublicKey::V2HybridMlDsa65` serde encoding.
 */
export class HybridPublicKey {
  /** The 32-byte Ed25519 component. */
  readonly ed25519: Uint8Array;
  /** The 1952-byte ML-DSA-65 component. */
  readonly mlDsa: Uint8Array;
  /** The scheme name, matching Rust `PublicKey::scheme`. */
  readonly scheme = "hybrid65";

  constructor(ed25519: Uint8Array, mlDsa: Uint8Array) {
    if (ed25519.length !== ED_PUB_LEN) {
      throw new KeyError(`hybrid ed25519 key must be ${ED_PUB_LEN} bytes, got ${ed25519.length}`);
    }
    if (mlDsa.length !== MLDSA_PUB_LEN) {
      throw new KeyError(`hybrid ml-dsa key must be ${MLDSA_PUB_LEN} bytes, got ${mlDsa.length}`);
    }
    this.ed25519 = Uint8Array.from(ed25519);
    this.mlDsa = Uint8Array.from(mlDsa);
  }

  /** Parse from the `hybrid65:0x<hex>` form (prefix optional). */
  static fromHex(hex: string): HybridPublicKey {
    const bytes = fromHybridHex(hex);
    if (bytes.length !== ED_PUB_LEN + MLDSA_PUB_LEN) {
      throw new KeyError(
        `hybrid65 key must be ${ED_PUB_LEN + MLDSA_PUB_LEN} bytes, got ${bytes.length}`,
      );
    }
    return new HybridPublicKey(bytes.slice(0, ED_PUB_LEN), bytes.slice(ED_PUB_LEN));
  }

  /** Lowercase hex of the concatenated components, no prefix (matches Rust `to_hex`). */
  toHex(): string {
    return toHex(this.ed25519) + toHex(this.mlDsa);
  }

  /** The `hybrid65:0x<hex>` display form (matches Rust `PublicKey`'s `Display`). */
  toString(): string {
    return `${SCHEME_PREFIX}0x${this.toHex()}`;
  }

  /** JSON/wire encoding: the mandatory scheme-prefixed `hybrid65:0x<hex>`. */
  toJSON(): string {
    return this.toString();
  }

  /**
   * Verify a detached hybrid signature over `message`. Returns `false` for any
   * failure — never throws. The check is a CONJUNCTION: both the Ed25519 and the
   * ML-DSA-65 components must verify (mirrors Rust `PublicKey::verify`).
   */
  verify(message: Uint8Array, signature: HybridSignature): boolean {
    try {
      return (
        ed.verify(signature.ed25519, message, this.ed25519) &&
        ml_dsa65.verify(signature.mlDsa, message, this.mlDsa)
      );
    } catch {
      return false;
    }
  }

  /**
   * This key's **implicit account id**: lowercase hex of `blake3` over the V2
   * public-key encoding (`0x01 ‖ ed25519 ‖ ml_dsa`). Matches Rust
   * `PublicKey::implicit_account_id` — the account a hybrid key controls.
   */
  accountId(): string {
    const enc = new Uint8Array(1 + this.ed25519.length + this.mlDsa.length);
    enc[0] = 1; // V2 (hybrid) discriminant
    enc.set(this.ed25519, 1);
    enc.set(this.mlDsa, 1 + this.ed25519.length);
    return toHex(blake3(enc));
  }
}

/**
 * A hybrid detached signature: a 64-byte Ed25519 signature and a 3309-byte
 * ML-DSA-65 signature. Wire form `hybrid65:0x<ed25519 ‖ ml-dsa-65>`, exactly the
 * node's `Signature::V2HybridMlDsa65` encoding.
 */
export class HybridSignature {
  /** The 64-byte Ed25519 component. */
  readonly ed25519: Uint8Array;
  /** The 3309-byte ML-DSA-65 component. */
  readonly mlDsa: Uint8Array;
  /** The scheme name. */
  readonly scheme = "hybrid65";

  constructor(ed25519: Uint8Array, mlDsa: Uint8Array) {
    if (ed25519.length !== ED_SIG_LEN) {
      throw new KeyError(`hybrid ed25519 sig must be ${ED_SIG_LEN} bytes, got ${ed25519.length}`);
    }
    if (mlDsa.length !== MLDSA_SIG_LEN) {
      throw new KeyError(`hybrid ml-dsa sig must be ${MLDSA_SIG_LEN} bytes, got ${mlDsa.length}`);
    }
    this.ed25519 = Uint8Array.from(ed25519);
    this.mlDsa = Uint8Array.from(mlDsa);
  }

  /** Parse from the `hybrid65:0x<hex>` form (prefix optional). */
  static fromHex(hex: string): HybridSignature {
    const bytes = fromHybridHex(hex);
    if (bytes.length !== ED_SIG_LEN + MLDSA_SIG_LEN) {
      throw new KeyError(
        `hybrid65 signature must be ${ED_SIG_LEN + MLDSA_SIG_LEN} bytes, got ${bytes.length}`,
      );
    }
    return new HybridSignature(bytes.slice(0, ED_SIG_LEN), bytes.slice(ED_SIG_LEN));
  }

  /** Lowercase hex of the concatenated components, no prefix. */
  toHex(): string {
    return toHex(this.ed25519) + toHex(this.mlDsa);
  }

  /** The `hybrid65:0x<hex>` display form. */
  toString(): string {
    return `${SCHEME_PREFIX}0x${this.toHex()}`;
  }

  /** JSON/wire encoding. */
  toJSON(): string {
    return this.toString();
  }
}

/**
 * A hybrid Ed25519 + ML-DSA-65 signing keypair, derived deterministically from a
 * 32-byte master seed. Holds secret material; never serialized. Interoperable
 * with the node's `Keypair::hybrid_from_seed`.
 */
export class HybridKeypair {
  /** The 32-byte master seed this keypair derives from (secret). */
  private readonly seed: Uint8Array;
  /** The derived Ed25519 signing seed (secret). */
  private readonly edSeed: Uint8Array;
  /** The derived ML-DSA-65 secret key (secret). */
  private readonly mlSecret: Uint8Array;
  /** The derived deterministic ML-DSA signing seed / `rnd` (secret). */
  private readonly signSeed: Uint8Array;
  /** The public key. */
  readonly publicKey: HybridPublicKey;

  private constructor(
    seed: Uint8Array,
    edSeed: Uint8Array,
    mlSecret: Uint8Array,
    signSeed: Uint8Array,
    publicKey: HybridPublicKey,
  ) {
    this.seed = Uint8Array.from(seed);
    this.edSeed = Uint8Array.from(edSeed);
    this.mlSecret = Uint8Array.from(mlSecret);
    this.signSeed = Uint8Array.from(signSeed);
    this.publicKey = publicKey;
  }

  /**
   * Deterministically derive a hybrid keypair from a 32-byte master seed. The
   * same seed always yields the same keypair, identical to the node's
   * `Keypair::hybrid_from_seed`.
   */
  static fromSeed(seed: Uint8Array): HybridKeypair {
    if (seed.length !== SEED_LEN) {
      throw new KeyError(`hybrid seed must be ${SEED_LEN} bytes, got ${seed.length}`);
    }
    const edSeed = deriveSeed(DOMAIN_ED25519, seed);
    const xi = deriveSeed(DOMAIN_MLDSA, seed);
    const signSeed = deriveSeed(DOMAIN_MLDSA_SIGN, seed);
    const edPub = ed.getPublicKey(edSeed);
    const { publicKey: mlPub, secretKey: mlSecret } = ml_dsa65.keygen(xi);
    const publicKey = new HybridPublicKey(edPub, mlPub);
    return new HybridKeypair(seed, edSeed, mlSecret, signSeed, publicKey);
  }

  /** Generate a fresh hybrid keypair from cryptographically secure OS entropy. */
  static generate(): HybridKeypair {
    const seed = new Uint8Array(SEED_LEN);
    crypto.getRandomValues(seed);
    return HybridKeypair.fromSeed(seed);
  }

  /**
   * Sign `message`, producing both component signatures. The ML-DSA half uses
   * FIPS 204 with the seed-derived `rnd` and an empty context, so the output is
   * deterministic and byte-identical to the node's hybrid `sign`.
   */
  sign(message: Uint8Array): HybridSignature {
    const edSig = ed.sign(message, this.edSeed);
    const mlSig = ml_dsa65.sign(message, this.mlSecret, { extraEntropy: this.signSeed });
    return new HybridSignature(edSig, mlSig);
  }

  /** Best-effort: expose the raw 32-byte master seed (handle with care; secret). */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.seed);
  }
}
