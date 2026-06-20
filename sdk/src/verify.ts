/**
 * Independent consensus verifier — the first component of a second, independent
 * SOV client.
 *
 * This re-derives a block's consensus-critical commitments (block id, transaction
 * Merkle root, per-transaction ids) in TypeScript — with NO shared code with the
 * Rust node — and cross-checks them against what the node serves. Anything that
 * disagrees byte-for-byte is a consensus divergence: exactly the class of bug a
 * second implementation exists to catch.
 *
 * SCOPE (honest): this verifies block/transaction *hashing and encoding*, plus
 * independent reconstruction of the authenticated state commitment
 * (`state_root`) from account state via {@link verifyStateRoot}. It does NOT yet
 * re-execute the full state-transition function (applying transfers/fees/staking
 * to derive the next state) or independently verify Halo2 shielded proofs —
 * those are the larger remaining pieces of a full second client.
 */

import { blockHash, computeTxRoot, transactionId } from "./borsh.js";
import type { BlockDigest, SovClient } from "./rpc.js";
import { computeStateRoot, type NamedAccount, type ReservedEntry } from "./state.js";
import type { Block } from "./types.js";

/** The result of independently verifying one block against the node's digest. */
export interface BlockVerification {
  /** True when every recomputed commitment matched the node. */
  ok: boolean;
  /** The block's height. */
  height: number;
  /** The block id we independently recomputed (`0x<hex>`). */
  blockHash: string;
  /** The transaction Merkle root we independently recomputed (`0x<hex>`). */
  txRoot: string;
  /** Human-readable divergences; empty when `ok`. */
  issues: string[];
}

/** Normalize a hash hex for comparison (drop `0x`, lowercase). */
function norm(h: string): string {
  return (h.startsWith("0x") ? h.slice(2) : h).toLowerCase();
}

/**
 * Independently re-derive `block`'s commitments and cross-check them against the
 * node's `digest` for the same height. Checks, in order: the per-transaction ids
 * (and their count), the transaction Merkle root (recomputed vs the header's
 * `tx_root`), and the block id (recomputed header hash vs the digest hash).
 */
export function verifyBlockDigest(block: Block, digest: BlockDigest): BlockVerification {
  const issues: string[] = [];
  const txs = block.transactions.map((s) => s.transaction);

  // 1. Transaction ids match the node's digest, in order.
  const ids = txs.map(transactionId);
  if (ids.length !== digest.txIds.length) {
    issues.push(`transaction count ${ids.length} != digest ${digest.txIds.length}`);
  } else {
    ids.forEach((id, i) => {
      const want = digest.txIds[i];
      if (want === undefined || norm(id) !== norm(want)) {
        issues.push(`tx[${i}] id mismatch: recomputed ${id} != digest ${want}`);
      }
    });
  }

  // 2. Recomputed tx Merkle root matches the header's tx_root.
  const txRoot = computeTxRoot(txs);
  if (norm(txRoot) !== norm(block.header.tx_root)) {
    issues.push(`tx_root mismatch: recomputed ${txRoot} != header ${block.header.tx_root}`);
  }

  // 3. Recomputed block id matches the node's digest hash (and the digest hash is
  //    the hash of THIS header, so this binds the body to the header too).
  const bh = blockHash(block.header);
  if (norm(bh) !== norm(digest.hash)) {
    issues.push(`block hash mismatch: recomputed ${bh} != digest ${digest.hash}`);
  }

  return { ok: issues.length === 0, height: block.header.height, blockHash: bh, txRoot, issues };
}

/** The result of independently reconstructing a block's `state_root`. */
export interface StateRootVerification {
  /** True when the recomputed root matched the expected one. */
  ok: boolean;
  /** The state root we independently recomputed from the account set (`0x<hex>`). */
  computed: string;
  /** The expected state root (e.g. a block header's `state_root`). */
  expected: string;
}

/**
 * Independently reconstruct `state_root` from the node's non-empty account set
 * (and any reserved scalar slots) and cross-check it against `expected` — for
 * instance a block header's `state_root`. This derives every Sparse Merkle Tree
 * slot and Borsh-encodes every account in TypeScript, with no shared code with
 * the node, so a mismatch is a genuine divergence on authenticated world state.
 */
export function verifyStateRoot(
  accounts: NamedAccount[],
  expected: string,
  reserved: ReservedEntry[] = [],
): StateRootVerification {
  const computed = computeStateRoot(accounts, reserved);
  return { ok: norm(computed) === norm(expected), computed, expected };
}

/**
 * Independently verify a contiguous range of blocks `[fromHeight, toHeight]` against
 * a live node: fetch each block and its digest, re-derive the commitments, and
 * return one [`BlockVerification`] per height (stopping at the chain tip). A second
 * client running this over a node's history detects any consensus-hash divergence.
 */
export async function verifyRange(
  client: SovClient,
  fromHeight: number,
  toHeight: number,
): Promise<BlockVerification[]> {
  const results: BlockVerification[] = [];
  for (let h = fromHeight; h <= toHeight; h++) {
    const [block, digest] = await Promise.all([
      client.getBlockByHeight(h),
      client.getBlockDigest(h),
    ]);
    if (!block || !digest) break; // past the tip
    results.push(verifyBlockDigest(block, digest));
  }
  return results;
}
