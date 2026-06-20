/**
 * Independent re-derivation of SOV's authenticated world state.
 *
 * Mirrors `chain/crates/state/src/ledger.rs` and `account.rs` with NO shared code
 * with the Rust node. Given the structured account states the node exposes, this
 * module derives each Sparse Merkle Tree slot, Borsh-encodes each account exactly
 * as the node commits it, and rebuilds the tree to recompute `state_root`. A
 * second validating client can thus verify the state commitment in a block header
 * itself rather than trusting the node.
 *
 * Slot derivation (matching `Ledger::slot` / `reserved_slot` / `contract_slot`):
 *   - account slot     = blake3(utf8(id))
 *   - reserved scalar  = blake3(0x02 ++ utf8(name))   (mined/burned/…)
 *   - contract storage = blake3(utf8(id) ++ 0x01 ++ key)
 * The 0x01/0x02 tags can never collide with an account id (its charset excludes
 * both bytes), so the three slot families are disjoint.
 *
 * Account Borsh layout (declaration order, little-endian):
 *   nonce u64, balance u128, locked u128,
 *   unlock_height u64, key Option<(0x00 ++ [u8;32])> (scheme-tagged), code Option<Vec<u8>>.
 * Borsh encodes `Option` as a 1-byte tag (0 = None, 1 = Some) then the payload.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { BorshWriter, bytesToHex, hexToBytes } from "./borsh.js";
import { SparseMerkleTree } from "./smt.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** The Sparse Merkle Tree slot for an account: blake3 of its id bytes. */
export function accountSlot(id: string): Uint8Array {
  return blake3(utf8(id));
}

/** The reserved slot for a protocol scalar (e.g. "sov:burned"): blake3(0x02 ++ name). */
export function reservedSlot(name: string): Uint8Array {
  const n = utf8(name);
  const buf = new Uint8Array(1 + n.length);
  buf[0] = 0x02;
  buf.set(n, 1);
  return blake3(buf);
}

/** The slot for a contract storage entry: blake3(id ++ 0x01 ++ key). */
export function contractSlot(id: string, key: Uint8Array): Uint8Array {
  const idb = utf8(id);
  const buf = new Uint8Array(idb.length + 1 + key.length);
  buf.set(idb, 0);
  buf[idb.length] = 0x01;
  buf.set(key, idb.length + 1);
  return blake3(buf);
}

/**
 * A single account's on-chain state. Balances are grain counts (u128) as a
 * decimal string or bigint; heights and the nonce are u64. `publicKey` is a
 * 32-byte hex string (with or without `0x`) or null for a keyless account;
 * `code` is the deployed contract bytecode or null.
 */
export interface AccountState {
  nonce: number | bigint;
  balance: string | bigint;
  locked: string | bigint;
  unlockHeight: number | bigint;
  publicKey?: string | null;
  code?: Uint8Array | number[] | null;
}

/** Byte-exact Borsh encoding of an account, as committed to the state root. */
export function encodeAccount(a: AccountState): Uint8Array {
  const w = new BorshWriter();
  w.u64(a.nonce)
    .u128(BigInt(a.balance))
    .u128(BigInt(a.locked))
    .u64(a.unlockHeight);
  if (a.publicKey) {
    // Option tag, then the versioned key: scheme byte 0x00 (Ed25519) + 32 bytes.
    w.u8(1).u8(0).fixed(hexToBytes(a.publicKey), 32);
  } else {
    w.u8(0);
  }
  if (a.code !== null && a.code !== undefined) {
    w.u8(1).vecU8(a.code instanceof Uint8Array ? a.code : Uint8Array.from(a.code));
  } else {
    w.u8(0);
  }
  return w.bytes();
}

/** An account paired with its id, as the node exposes its non-empty account set. */
export interface NamedAccount {
  id: string;
  account: AccountState;
}

/** An extra protocol scalar slot (a reserved counter) committed alongside accounts. */
export interface ReservedEntry {
  /** Reserved slot name, e.g. "sov:burned" or "sov:mined_emitted". */
  name: string;
  /** The already-encoded value bytes committed at the slot. */
  value: Uint8Array;
}

/**
 * Rebuild the Sparse Merkle Tree from the node's non-empty account set (and any
 * reserved scalar slots) and return its root as `0x<hex>`. The accounts must be
 * the node's committed (non-empty) set; an empty account commits to nothing.
 */
export function computeStateRoot(
  accounts: NamedAccount[],
  reserved: ReservedEntry[] = [],
): string {
  const tree = new SparseMerkleTree();
  for (const { id, account } of accounts) {
    tree.insert(accountSlot(id), encodeAccount(account));
  }
  for (const { name, value } of reserved) {
    tree.insert(reservedSlot(name), value);
  }
  return `0x${bytesToHex(tree.root())}`;
}
