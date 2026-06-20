/**
 * An independent Sparse Merkle Tree (SMT) — the authenticated-state primitive
 * SOV commits to with `state_root`.
 *
 * This is a byte-for-byte TypeScript port of `chain/crates/state/src/smt.rs`,
 * sharing NO code with the Rust node. A second validating client needs to
 * reconstruct and verify the world-state commitment itself, not trust the node's
 * word for it; this module is that foundation. `test/state.test.ts` proves it
 * reproduces a real node-generated `state_root` (and its inclusion/exclusion
 * proofs) byte-for-byte.
 *
 * Construction (identical to the Rust side):
 *   - fixed depth 256 over a 256-bit key space; empty subtrees collapse to
 *     precomputed default hashes so only populated paths are materialized;
 *   - leaves are `blake3(0x00 ++ value)`, internal nodes `blake3(0x01 ++ l ++ r)`
 *     (the same domain separation used for the transaction Merkle tree);
 *   - the empty-leaf placeholder is 32 zero bytes (`Hash::ZERO`), NOT a hash;
 *   - keys descend MSB-first: bit i is bit `7 - (i % 8)` of byte `i / 8`.
 */

import { bytesToHex, hashLeaf, hashNode } from "./borsh.js";

/** Depth of the tree: 256-bit keys ⇒ 256 branch decisions root→leaf. */
export const TREE_HEIGHT = 256;

/** The empty-leaf / empty-subtree-base placeholder (`Hash::ZERO`). */
const ZERO = new Uint8Array(32);

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** The i-th bit of `key`, MSB-first. False ⇒ descend left, true ⇒ right. */
function bit(key: Uint8Array, i: number): boolean {
  const byte = key[Math.floor(i / 8)] as number;
  return ((byte >> (7 - (i % 8))) & 1) === 1;
}

/**
 * Default (empty-subtree) hash for every height `0..=TREE_HEIGHT`. `[0]` is the
 * empty leaf; each higher level hashes two empty subtrees of the level below.
 */
function computeDefaults(): Uint8Array[] {
  const defaults: Uint8Array[] = [ZERO];
  for (let h = 1; h <= TREE_HEIGHT; h++) {
    const below = defaults[h - 1] as Uint8Array;
    defaults.push(hashNode(below, below));
  }
  return defaults;
}

/** A Merkle proof for one key: the sibling at each level (top-down) + the leaf. */
export interface MerkleProof {
  /** The leaf commitment at the key's slot (`ZERO` if the key is absent). */
  leaf: Uint8Array;
  /** Sibling hashes from the root level down to the leaf level (`TREE_HEIGHT`). */
  siblings: Uint8Array[];
}

/**
 * Verify a Merkle proof against `root` for `key`. Pass the committed `value` for
 * an inclusion proof, or `null` for an exclusion proof. Byte-identical to the
 * Rust `MerkleProof::verify`.
 */
export function verifyMerkleProof(
  root: Uint8Array,
  key: Uint8Array,
  value: Uint8Array | null,
  proof: MerkleProof,
): boolean {
  if (proof.siblings.length !== TREE_HEIGHT) return false;
  const expectedLeaf = value === null ? ZERO : hashLeaf(value);
  if (!bytesEqual(proof.leaf, expectedLeaf)) return false;
  let node = proof.leaf;
  for (let level = 1; level <= TREE_HEIGHT; level++) {
    const sibling = proof.siblings[TREE_HEIGHT - level] as Uint8Array;
    node = bit(key, TREE_HEIGHT - level) ? hashNode(sibling, node) : hashNode(node, sibling);
  }
  return bytesEqual(node, root);
}

/**
 * An in-memory Sparse Merkle Tree. Internal nodes are content-addressed by their
 * hash; empty subtrees are implied by the defaults and never stored. Maps are
 * keyed by hex strings because `Uint8Array` is compared by identity in JS.
 */
export class SparseMerkleTree {
  private nodes = new Map<string, [Uint8Array, Uint8Array]>();
  private valueStore = new Map<string, Uint8Array>();
  private readonly defaults = computeDefaults();
  private rootHash: Uint8Array;

  constructor() {
    this.rootHash = this.defaults[TREE_HEIGHT] as Uint8Array;
  }

  /** The current root hash, committing to all key/value pairs. */
  root(): Uint8Array {
    return this.rootHash;
  }

  /** The value stored at `key`, if any. */
  get(key: Uint8Array): Uint8Array | undefined {
    return this.valueStore.get(bytesToHex(key));
  }

  /** Children of `node` at `level`; an unstored node is an empty subtree. */
  private children(node: Uint8Array, level: number): [Uint8Array, Uint8Array] {
    const entry = this.nodes.get(bytesToHex(node));
    if (entry) return entry;
    const d = this.defaults[level - 1] as Uint8Array;
    return [d, d];
  }

  /** Sibling hashes along `key`'s path, root level down to leaf. */
  private siblingsFor(key: Uint8Array): Uint8Array[] {
    const siblings: Uint8Array[] = [];
    let cur = this.rootHash;
    for (let level = TREE_HEIGHT; level >= 1; level--) {
      const [l, r] = this.children(cur, level);
      if (bit(key, TREE_HEIGHT - level)) {
        siblings.push(l);
        cur = r;
      } else {
        siblings.push(r);
        cur = l;
      }
    }
    return siblings;
  }

  /** Recompute the path from a (possibly empty) leaf to a new root, storing nodes. */
  private recompute(key: Uint8Array, leaf: Uint8Array, siblings: Uint8Array[]): void {
    let node = leaf;
    for (let level = 1; level <= TREE_HEIGHT; level++) {
      const sibling = siblings[TREE_HEIGHT - level] as Uint8Array;
      const [l, r] = bit(key, TREE_HEIGHT - level) ? [sibling, node] : [node, sibling];
      const parent = hashNode(l, r);
      if (!bytesEqual(parent, this.defaults[level] as Uint8Array)) {
        this.nodes.set(bytesToHex(parent), [l, r]);
      }
      node = parent;
    }
    this.rootHash = node;
  }

  /** Insert or overwrite `key` with `value`. */
  insert(key: Uint8Array, value: Uint8Array): void {
    const siblings = this.siblingsFor(key);
    const leaf = hashLeaf(value);
    this.valueStore.set(bytesToHex(key), value);
    this.recompute(key, leaf, siblings);
  }

  /** Produce a Merkle proof for `key` (inclusion or exclusion). */
  prove(key: Uint8Array): MerkleProof {
    const siblings = this.siblingsFor(key);
    const stored = this.valueStore.get(bytesToHex(key));
    const leaf = stored === undefined ? ZERO : hashLeaf(stored);
    return { leaf, siblings };
  }
}
