/**
 * Hierarchical-deterministic (HD) wallets for SOV.
 *
 * SOV signs with Ed25519, so HD follows the Ed25519 standards rather than
 * BIP-32's secp256k1 elliptic-curve math:
 *
 *   - **BIP-39** turns a human mnemonic phrase into a 512-bit seed
 *     (PBKDF2-HMAC-SHA512, 2048 rounds), via the audited `@scure/bip39`.
 *   - **SLIP-0010** derives a tree of Ed25519 keys from that seed using
 *     HMAC-SHA512 (the audited `@noble/hashes` primitive). Ed25519 supports
 *     *hardened* derivation only, so every path component is hardened.
 *   - **BIP-44** gives the path layout: `m / 44' / coin' / account' / change' /
 *     index'`.
 *
 * The 32-byte key SLIP-0010 produces at a leaf *is* an Ed25519 seed, so it feeds
 * directly into {@link Keypair.fromSeed} — and the resulting public key is the
 * one bound to a named account on-chain (an account's controlling / access key:
 * see `chain/crates/state/src/account.rs` `Account.key` and the runtime's
 * authorization check in `chain/crates/runtime/src/execution.rs`). One mnemonic
 * therefore deterministically controls a whole family of named SOV accounts.
 *
 * SCHEME NOTE: {@link HdWallet.deriveKeypair} derives the **classical Ed25519**
 * key (scheme `0x00`), a valid on-chain account key. SOV's *default* and
 * recommended scheme is the **hybrid Ed25519 + ML-DSA-65** post-quantum key —
 * use {@link HdWallet.deriveHybridKeypair}, which expands the identical
 * SLIP-0010 leaf via `@noble/post-quantum` and is byte-for-byte identical to the
 * node's `sov-wallet import` / `Keypair::hybrid_from_seed` (pinned by the
 * cross-impl KAT in `test/hybrid.test.ts`).
 *
 * No derivation logic is hand-rolled beyond SLIP-0010's HMAC chaining; the hash
 * primitives are audited libraries, and correctness is pinned against the
 * SLIP-0010 specification's official Ed25519 test vectors in `test/hd.test.ts`.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha512.js";
import {
  generateMnemonic as scureGenerateMnemonic,
  mnemonicToSeedSync,
  validateMnemonic as scureValidateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

import { Keypair, KeyError } from "./keys.js";
import { HybridKeypair } from "./hybrid.js";

/** The hardened-derivation offset, 2^31. SLIP-0010 Ed25519 requires every
 * path component to be hardened, i.e. `>= HARDENED_OFFSET`. */
export const HARDENED_OFFSET = 0x8000_0000;

/** BIP-44 purpose constant. */
const PURPOSE = 44;

/**
 * SOV's BIP-44 coin type.
 *
 * PROVISIONAL: SOV is not (yet) registered in SLIP-0044, so this is a chosen,
 * fixed value rather than an assigned slot. It encodes the ASCII bytes `"SOV"`
 * (0x534F56) so it is memorable and self-documenting, and is `< 2^31` so it is a
 * valid hardened path index. It is fixed here so every SOV wallet derives the
 * same addresses; changing it would fork all derivation paths, so treat it as
 * stable and only revisit under a coordinated migration if a SLIP-0044 slot is
 * formally assigned.
 */
export const SOV_COIN_TYPE = 0x53_4f_56; // "SOV" — provisional, not yet SLIP-0044 registered

/** SLIP-0010 master HMAC key for the Ed25519 curve. */
const ED25519_CURVE = new TextEncoder().encode("ed25519 seed");

/** A node in the SLIP-0010 key tree: a 32-byte key and its 32-byte chain code. */
interface Slip10Node {
  /** The 32-byte derived key. At a leaf this is an Ed25519 seed. */
  readonly key: Uint8Array;
  /** The 32-byte chain code carried to children. */
  readonly chainCode: Uint8Array;
}

/** Big-endian 4-byte serialization of a u32 index (SLIP-0010 `ser32`). */
function ser32(index: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (index >>> 24) & 0xff;
  out[1] = (index >>> 16) & 0xff;
  out[2] = (index >>> 8) & 0xff;
  out[3] = index & 0xff;
  return out;
}

/** Derive the SLIP-0010 Ed25519 master node from a seed. */
function slip10Master(seed: Uint8Array): Slip10Node {
  const i = hmac(sha512, ED25519_CURVE, seed);
  return { key: i.slice(0, 32), chainCode: i.slice(32, 64) };
}

/**
 * SLIP-0010 Ed25519 hardened child derivation. Unlike BIP-32/secp256k1, the
 * child key is `I_L` directly (no scalar addition of the parent key), and only
 * hardened indices are defined.
 */
function slip10CkdPriv(parent: Slip10Node, index: number): Slip10Node {
  if (index < HARDENED_OFFSET) {
    throw new KeyError(
      `SLIP-0010 Ed25519 supports hardened derivation only; index ${index} is not hardened`,
    );
  }
  // data = 0x00 || ser256(k_par) || ser32(index)
  const data = new Uint8Array(1 + 32 + 4);
  data[0] = 0x00;
  data.set(parent.key, 1);
  data.set(ser32(index), 33);
  const i = hmac(sha512, parent.chainCode, data);
  return { key: i.slice(0, 32), chainCode: i.slice(32, 64) };
}

/** Walk a path of (hardened) indices from the master node derived from `seed`. */
function derivePath(indices: readonly number[], seed: Uint8Array): Slip10Node {
  let node = slip10Master(seed);
  for (const index of indices) {
    node = slip10CkdPriv(node, index);
  }
  return node;
}

/**
 * Parse a SLIP-0010 path string like `m/44'/5459798'/0'/0'/0'` into hardened
 * indices. Every component must be hardened (suffix `'`, `h`, or `H`), because
 * Ed25519 derivation defines only hardened children. Throws {@link KeyError}.
 */
export function parsePath(path: string): number[] {
  const parts = path.trim().split("/");
  if (parts[0] !== "m") {
    throw new KeyError(`HD path must start with "m": ${path}`);
  }
  return parts.slice(1).map((p) => {
    const hardened = p.endsWith("'") || p.endsWith("h") || p.endsWith("H");
    if (!hardened) {
      throw new KeyError(
        `SLIP-0010 Ed25519 requires hardened path components; "${p}" is not (append ')`,
      );
    }
    const numStr = p.slice(0, -1);
    const n = Number(numStr);
    if (!Number.isInteger(n) || n < 0 || n >= HARDENED_OFFSET || !/^\d+$/.test(numStr)) {
      throw new KeyError(`invalid HD path component: "${p}"`);
    }
    return n + HARDENED_OFFSET;
  });
}

/**
 * The standard SOV BIP-44 derivation indices for a given account and address
 * index: `m / 44' / SOV_COIN_TYPE' / account' / 0' / index'` (all hardened).
 */
export function sovPath(account = 0, index = 0): number[] {
  assertIndex("account", account);
  assertIndex("index", index);
  return [
    PURPOSE + HARDENED_OFFSET,
    SOV_COIN_TYPE + HARDENED_OFFSET,
    account + HARDENED_OFFSET,
    0 + HARDENED_OFFSET,
    index + HARDENED_OFFSET,
  ];
}

/** Human-readable form of {@link sovPath}, e.g. `m/44'/5459798'/0'/0'/0'`. */
export function sovPathString(account = 0, index = 0): string {
  assertIndex("account", account);
  assertIndex("index", index);
  return `m/${PURPOSE}'/${SOV_COIN_TYPE}'/${account}'/0'/${index}'`;
}

function assertIndex(label: string, n: number): void {
  if (!Number.isInteger(n) || n < 0 || n >= HARDENED_OFFSET) {
    throw new KeyError(`${label} must be an integer in [0, 2^31); got ${n}`);
  }
}

/**
 * Generate a fresh BIP-39 mnemonic from secure entropy (default 24 words /
 * 256-bit). The audited `@scure/bip39` draws from `crypto.getRandomValues`.
 */
export function generateMnemonic(strength: 128 | 160 | 192 | 224 | 256 = 256): string {
  return scureGenerateMnemonic(wordlist, strength);
}

/** Whether `mnemonic` is a valid BIP-39 phrase (wordlist + checksum). */
export function validateMnemonic(mnemonic: string): boolean {
  return scureValidateMnemonic(mnemonic, wordlist);
}

/**
 * A hierarchical-deterministic SOV wallet: one BIP-39 seed from which an entire
 * tree of Ed25519 {@link Keypair}s is derived deterministically. The seed is
 * held privately and never serialized.
 */
export class HdWallet {
  private readonly seed: Uint8Array;

  private constructor(seed: Uint8Array) {
    this.seed = Uint8Array.from(seed);
  }

  /**
   * Build a wallet from a BIP-39 mnemonic (optionally salted by a passphrase —
   * the BIP-39 "25th word"). Rejects a phrase that fails the wordlist/checksum.
   */
  static fromMnemonic(mnemonic: string, passphrase = ""): HdWallet {
    if (!validateMnemonic(mnemonic)) {
      throw new KeyError("invalid BIP-39 mnemonic (wordlist or checksum)");
    }
    return new HdWallet(mnemonicToSeedSync(mnemonic.normalize("NFKD"), passphrase));
  }

  /**
   * Build a wallet directly from a raw BIP-39 seed (>= 16 bytes), for callers
   * that already hold seed material. Most users should use {@link fromMnemonic}.
   */
  static fromSeed(seed: Uint8Array): HdWallet {
    if (seed.length < 16) {
      throw new KeyError(`HD seed must be at least 16 bytes, got ${seed.length}`);
    }
    return new HdWallet(seed);
  }

  /** Derive the keypair at an explicit SLIP-0010 path (all components hardened). */
  deriveKeypairAtPath(path: string | readonly number[]): Keypair {
    const indices = typeof path === "string" ? parsePath(path) : path;
    const node = derivePath(indices, this.seed);
    return Keypair.fromSeed(node.key);
  }

  /**
   * Derive the **classical Ed25519** keypair for a SOV `account` and address
   * `index` on the standard BIP-44 path `m/44'/SOV_COIN_TYPE'/account'/0'/index'`.
   * A valid on-chain key; for SOV's default post-quantum scheme use
   * {@link deriveHybridKeypair}.
   */
  deriveKeypair(account = 0, index = 0): Keypair {
    return this.deriveKeypairAtPath(sovPath(account, index));
  }

  /**
   * The raw 32-byte SLIP-0010 **leaf seed** for an `account`/`index` — the
   * deterministic, scheme-agnostic HD output (identical to the node's
   * `HdWallet::derive_seed`). Feed it to either key scheme.
   */
  deriveSeed(account = 0, index = 0): Uint8Array {
    return Uint8Array.from(derivePath(sovPath(account, index), this.seed).key);
  }

  /** Derive the hybrid post-quantum keypair at an explicit SLIP-0010 path. */
  deriveHybridKeypairAtPath(path: string | readonly number[]): HybridKeypair {
    const indices = typeof path === "string" ? parsePath(path) : path;
    return HybridKeypair.fromSeed(derivePath(indices, this.seed).key);
  }

  /**
   * Derive the **hybrid Ed25519 + ML-DSA-65** (post-quantum) keypair for a SOV
   * `account`/`index` on the standard BIP-44 path — SOV's default scheme, and
   * byte-for-byte identical to the node's `sov-wallet import`. The same mnemonic
   * restores the same hybrid key, every time.
   */
  deriveHybridKeypair(account = 0, index = 0): HybridKeypair {
    return this.deriveHybridKeypairAtPath(sovPath(account, index));
  }

  /** Expose the raw BIP-39 seed bytes (handle with care; secret material). */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.seed);
  }
}
