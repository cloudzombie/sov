/**
 * Independent re-execution of SOV's transparent state-transition function — the
 * core of a second, independent validating client.
 *
 * This applies a block's transactions to a prior ledger and DERIVES the next
 * `state_root` and `receipts_root`, in TypeScript, sharing NO code with the Rust
 * node. It is the step beyond verification in `verify.ts`: that module checks a
 * given commitment; this one independently *recomputes* the post-state a block
 * claims to produce. A second client running this over a node's history detects
 * any divergence in how value moves — the exact class of bug a second
 * implementation exists to catch.
 *
 * Byte-for-byte port of `chain/crates/runtime/src/execution.rs` (+ `gas.rs`,
 * the coinbase) and the ledger commitment rules in `state/src/ledger.rs`.
 * `test/stf.test.ts` proves it against a node-generated scenario vector.
 *
 * SCOPE (honest, and the inherent boundary of a TS client). It re-executes the
 * full DETERMINISTIC TRANSPARENT STF: Transfer, ClaimVesting,
 * Deploy, HtlcLock/Claim/Refund, the fee model (5%/2% tax to the founder/dev
 * recipients, miner keeps the rest; no burn), and authentication/authorization/
 * nonce/replay checks. It
 * does NOT re-execute the three actions that depend on an audited external engine
 * the project deliberately delegates to (re-implementing them in TS would
 * duplicate that audited crate and violate SOV's "never hand-roll crypto" rule):
 *   - `Call`  — runs a metered wasmi WASM VM (`sov-vm`);
 *   - `Shielded` — verify a Halo2 zk-SNARK (`sov-shielded`).
 * Issuance IS reproduced: {@link applyCoinbase} mints the Bitcoin-schedule
 * subsidy to the miner before the transactions, exactly as the node's chain
 * layer does, so a second client agrees on the full state transition including
 * emission.
 * A block containing one of these is reported as `requiresDelegatedVerification`
 * rather than silently mis-executed. See sdk/SECOND-CLIENT.md.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha256.js";
import {
  BorshWriter,
  bytesToHex,
  encodeTransaction,
  hexToBytes,
  merkleRoot,
  transactionIdBytes,
} from "./borsh.js";
import { PublicKey, Signature } from "./keys.js";
import { SparseMerkleTree } from "./smt.js";
import { accountSlot, encodeAccount, reservedSlot, type AccountState } from "./state.js";
import type { Action, Receipt, SignedTransaction } from "./types.js";

// --- Policy & context ------------------------------------------------------

/** The block-level context execution needs (mirror `runtime::BlockContext`). */
export interface BlockContext {
  height: number | bigint;
  /** Per-gas price in grains; `0n` disables fees. */
  gasPrice: bigint;
  /** Basis points of every coinbase and fee paid to the primary tax recipient. */
  taxPrimaryBps: number;
  /** Basis points of every coinbase and fee paid to the secondary tax recipient. */
  taxSecondaryBps: number;
  /** BIP-110 cap on `Deploy` code bytes; `0` disables the cap. */
  maxCodeBytes: number;
  /** Primary tax recipient (founder) — a cut of every coinbase and fee. */
  taxPrimaryRecipient: string;
  /** Secondary tax recipient (dev fund) — a cut of every coinbase and fee. */
  taxSecondaryRecipient: string;
  /** The block's miner — collects the miner share of fees AND the coinbase. */
  miner: string;
  /** Coinbase base subsidy in grains (height-1 reward before any halving). */
  baseReward?: bigint;
  /** Blocks between subsidy halvings (Bitcoin: 210,000). */
  halvingIntervalBlocks?: bigint;
  /** Hard ceiling (grains) on cumulative PoW issuance — the budget backstop. */
  miningBudgetGrains?: bigint;
}

// --- Errors ----------------------------------------------------------------

/** Why a transaction was *rejected* (not admitted — makes the whole block invalid). */
export type RejectKind =
  | "invalid_signature"
  | "unauthorized"
  | "bad_nonce"
  | "cannot_afford_fee"
  | "data_too_large"
  | "requires_delegated_verification";

/** A rejected transaction. Mirrors `runtime::ExecutionError` (block-invalidating). */
export class TransactionRejected extends Error {
  constructor(
    readonly kind: RejectKind,
    message: string,
  ) {
    super(message);
    this.name = "TransactionRejected";
  }
}

// --- Internal account (bigint arithmetic) ----------------------------------

interface Acct {
  nonce: bigint;
  balance: bigint;
  locked: bigint;
  unlockHeight: bigint;
  publicKey: string | null;
  code: Uint8Array | null;
}

const emptyAcct = (): Acct => ({
  nonce: 0n,
  balance: 0n,
  locked: 0n,
  unlockHeight: 0n,
  publicKey: null,
  code: null,
});

const acctIsEmpty = (a: Acct): boolean =>
  a.nonce === 0n &&
  a.balance === 0n &&
  a.locked === 0n &&
  a.unlockHeight === 0n &&
  a.publicKey === null &&
  a.code === null;

const fromState = (s: AccountState): Acct => ({
  nonce: BigInt(s.nonce),
  balance: BigInt(s.balance),
  locked: BigInt(s.locked),
  unlockHeight: BigInt(s.unlockHeight),
  publicKey: s.publicKey ?? null,
  code: s.code == null ? null : s.code instanceof Uint8Array ? s.code : Uint8Array.from(s.code),
});

/** An open hash-time-locked contract (mirror `state::Htlc`). */
export interface Htlc {
  locker: string;
  recipient: string;
  amount: bigint;
  hashlock: Uint8Array;
  timeoutHeight: bigint;
}

// --- Ledger ----------------------------------------------------------------

/** Reserved scalar-slot names (mirror `ledger.rs` constants). */
const MINED = "sov:mined_emitted";
const SHIELDED_VALUE = "sov:shielded_value";
const HTLC_LOCKED = "sov:htlc_locked";
const HTLCS = "sov:htlcs";

function encodeHtlc(h: Htlc): Uint8Array {
  return new BorshWriter()
    .string(h.locker)
    .string(h.recipient)
    .u128(h.amount)
    .fixed(h.hashlock, 32)
    .u64(h.timeoutHeight)
    .bytes();
}

/**
 * An independent in-memory ledger. Tracks the logical state (accounts, open
 * HTLCs, and the protocol counters) and recomputes `state_root` on demand by the
 * same Sparse Merkle Tree commitment rules as the node — zero/empty slots are
 * absent, so the root depends only on final state, not on history.
 */
export class Ledger {
  private accounts = new Map<string, Acct>();
  private htlcs = new Map<string, Htlc>();
  private minedEmitted = 0n;
  private shieldedValue = 0n;
  private htlcLocked = 0n;

  /** Seed the ledger from a prior account set (the node's non-empty accounts). */
  static fromAccounts(accounts: { id: string; account: AccountState }[]): Ledger {
    const l = new Ledger();
    for (const { id, account } of accounts) l.accounts.set(id, fromState(account));
    return l;
  }

  /** Optionally seed protocol counters (e.g. when resuming mid-chain). */
  setCounters(c: {
    mined?: bigint;
    shieldedValue?: bigint;
  }): void {
    if (c.mined !== undefined) this.minedEmitted = c.mined;
    if (c.shieldedValue !== undefined) this.shieldedValue = c.shieldedValue;
  }

  /** The account at `id`, or a fresh empty account (reads never fail). */
  account(id: string): Acct {
    return this.accounts.get(id) ?? emptyAcct();
  }

  /** Write `account` to `id`; an empty account is removed (keeps the root canonical). */
  setAccount(id: string, account: Acct): void {
    if (acctIsEmpty(account)) this.accounts.delete(id);
    else this.accounts.set(id, account);
  }

  /** Credit `amount` to `id`'s liquid balance (a fresh read-modify-write). */
  credit(id: string, amount: bigint): void {
    if (amount === 0n) return;
    const a = this.account(id);
    a.balance += amount;
    this.setAccount(id, a);
  }

  /** Cumulative proof-of-work issuance so far (the `sov:mined_emitted` counter). */
  minedEmittedGrains(): bigint {
    return this.minedEmitted;
  }
  /** Record `amount` of freshly minted coinbase (mirror `add_mined_emitted`). */
  addMinedEmitted(amount: bigint): void {
    this.minedEmitted += amount;
  }
  shieldedValueGrains(): bigint {
    return this.shieldedValue;
  }

  htlc(id: string): Htlc | undefined {
    return this.htlcs.get(id);
  }
  /** Escrow a new HTLC keyed by the lock tx's id. Fails on a duplicate id. */
  lockHtlc(id: string, htlc: Htlc): boolean {
    if (this.htlcs.has(id)) return false;
    this.htlcs.set(id, htlc);
    this.htlcLocked += htlc.amount;
    return true;
  }
  /** Settle (remove) an HTLC, decrementing the escrow counter. */
  settleHtlc(id: string): void {
    const h = this.htlcs.get(id);
    if (!h) return;
    this.htlcs.delete(id);
    this.htlcLocked -= h.amount;
  }

  /** The digest committed at the `sov:htlcs` slot: blake3 of the Borsh-encoded,
   * key-sorted entry list (mirrors `recommit_htlcs`). */
  private htlcsDigest(): Uint8Array {
    const keys = [...this.htlcs.keys()].sort(); // hex sort == 32-byte lexicographic sort
    const w = new BorshWriter();
    w.u32(keys.length);
    for (const k of keys) {
      w.fixed(hexToBytes(k), 32);
      w.raw(encodeHtlc(this.htlcs.get(k) as Htlc));
    }
    return blake3(w.bytes());
  }

  /** The authenticated state root over all accounts, counters, and open HTLCs. */
  stateRoot(): string {
    const tree = new SparseMerkleTree();
    for (const [id, a] of this.accounts) {
      tree.insert(accountSlot(id), encodeAccount(a as AccountState));
    }
    const counter = (name: string, value: bigint): void => {
      if (value !== 0n) tree.insert(reservedSlot(name), new BorshWriter().u128(value).bytes());
    };
    counter(MINED, this.minedEmitted);
    counter(SHIELDED_VALUE, this.shieldedValue);
    counter(HTLC_LOCKED, this.htlcLocked);
    if (this.htlcs.size > 0) tree.insert(reservedSlot(HTLCS), this.htlcsDigest());
    return `0x${bytesToHex(tree.root())}`;
  }

  /** A snapshot of the non-empty account set as `AccountState` (for inspection). */
  accountStates(): { id: string; account: AccountState }[] {
    return [...this.accounts.entries()].map(([id, a]) => ({
      id,
      account: {
        nonce: a.nonce,
        balance: a.balance,
        locked: a.locked,
        unlockHeight: a.unlockHeight,
        publicKey: a.publicKey,
        code: a.code,
      },
    }));
  }
}

// --- Gas (mirror runtime/gas.rs) -------------------------------------------

const INTRINSIC_GAS = 21_000n;
const STAKE_GAS = 30_000n;
const DEPLOY_GAS_PER_BYTE = 200n;
const SHIELDED_VERIFY_GAS = 500_000n;

/** Intrinsic (non-VM) gas of an action. Mirrors `gas_for`. */
export function gasFor(action: Action): bigint {
  switch (action.type) {
    case "transfer":
    case "claim_vesting":
    case "call":
      return INTRINSIC_GAS;
    case "htlc_lock":
    case "htlc_claim":
    case "htlc_refund":
      return INTRINSIC_GAS + STAKE_GAS;
    case "deploy":
      return INTRINSIC_GAS + BigInt(action.code.length) * DEPLOY_GAS_PER_BYTE;
    case "shielded":
      return INTRINSIC_GAS + SHIELDED_VERIFY_GAS;
    default: {
      const _never: never = action;
      throw new Error(`unknown action: ${JSON.stringify(_never)}`);
    }
  }
}

// --- Execution (mirror runtime/execution.rs) -------------------------------

const ok = (): Receipt["status"] => ({ status: "success" });
const failed = (reason: string): Receipt["status"] => ({ status: "failed", reason });

/**
 * Apply one signed transaction to `ledger` in `ctx`, returning its receipt.
 * Throws {@link TransactionRejected} only if the transaction is *rejected* (bad
 * signature/key/nonce/fee/data, or an action requiring a delegated verifier).
 */
export function applyTransaction(
  ledger: Ledger,
  stx: SignedTransaction,
  ctx: BlockContext,
): Receipt {
  const tx = stx.transaction;
  const height = BigInt(ctx.height);

  // 1. Authentication: the signature must verify against the tx's public key.
  const signingBytes = encodeTransaction(tx);
  const pk = PublicKey.fromHex(tx.public_key);
  if (!pk.verify(signingBytes, Signature.fromHex(stx.signature))) {
    throw new TransactionRejected("invalid_signature", "invalid transaction signature");
  }
  const txId = `0x${bytesToHex(transactionIdBytes(tx))}`;

  // Actions that depend on an audited external engine are out of scope (see file
  // header). A block carrying one cannot be independently re-executed here.
  if (tx.action.type === "shielded" || tx.action.type === "call") {
    throw new TransactionRejected(
      "requires_delegated_verification",
      `action '${tx.action.type}' requires a delegated verifier (PoW/WASM/zk) outside the transparent STF`,
    );
  }

  const signer = ledger.account(tx.signer);

  // 2. Authorization: a keyed account must be addressed by its registered key.
  // (Keyless accounts can only be claimed via RotateKey, which is out of scope
  // for the transparent STF subset here.)
  if (signer.publicKey === null || signer.publicKey.toLowerCase().replace(/^0x/, "") !==
      tx.public_key.toLowerCase().replace(/^0x/, "")) {
    throw new TransactionRejected("unauthorized", `unauthorized: key does not control ${tx.signer}`);
  }

  // 3. Ordering / replay protection.
  if (BigInt(tx.nonce) !== signer.nonce) {
    throw new TransactionRejected(
      "bad_nonce",
      `bad nonce: account is at ${signer.nonce}, transaction used ${tx.nonce}`,
    );
  }

  // BIP-110: cap arbitrary data (contract code) a transaction may carry.
  if (tx.action.type === "deploy" && ctx.maxCodeBytes !== 0 && tx.action.code.length > ctx.maxCodeBytes) {
    throw new TransactionRejected(
      "data_too_large",
      `transaction data too large: limit ${ctx.maxCodeBytes} bytes, got ${tx.action.code.length}`,
    );
  }

  const gasUsed = gasFor(tx.action);

  // Transaction fee (gas × price). Must be affordable up front.
  const chargesFee = ctx.gasPrice !== 0n;
  const intrinsicFee = chargesFee ? gasUsed * ctx.gasPrice : 0n;
  if (intrinsicFee !== 0n && signer.balance < intrinsicFee) {
    throw new TransactionRejected("cannot_afford_fee", `account ${tx.signer} cannot afford the fee`);
  }

  // Admitted: consume the nonce regardless of whether the action then succeeds.
  signer.nonce += 1n;
  let feePaid = 0n;
  if (intrinsicFee !== 0n) {
    signer.balance -= intrinsicFee;
    feePaid = intrinsicFee;
  }

  const status = applyAction(ledger, tx.signer, tx.action, signer, height, ctx, txId);

  ledger.setAccount(tx.signer, signer);
  distributeFee(ledger, ctx, feePaid);
  return { tx_id: txId, status, gas_used: Number(gasUsed), return_data: [], events: [] };
}

function applyAction(
  ledger: Ledger,
  signerId: string,
  action: Action,
  signer: Acct,
  height: bigint,
  ctx: BlockContext,
  txId: string,
): Receipt["status"] {
  switch (action.type) {
    case "transfer": {
      const amount = BigInt(action.amount);
      if (signer.balance < amount) return failed("insufficient balance");
      if (action.to === signerId) return ok(); // self-transfer: funds stay put
      const recipient = ledger.account(action.to);
      signer.balance -= amount;
      recipient.balance += amount;
      ledger.setAccount(action.to, recipient);
      return ok();
    }
    case "claim_vesting": {
      if (!(signer.locked !== 0n && height >= signer.unlockHeight))
        return failed("no vested funds to claim yet");
      signer.balance += signer.locked;
      signer.locked = 0n;
      signer.unlockHeight = 0n;
      return ok();
    }
    case "deploy": {
      if (action.code.length === 0) return failed("empty contract code");
      signer.code = Uint8Array.from(action.code);
      return ok();
    }
    case "htlc_lock": {
      const amount = BigInt(action.amount);
      if (signer.balance < amount) return failed("insufficient balance");
      const htlc: Htlc = {
        locker: signerId,
        recipient: action.recipient,
        amount,
        hashlock: hexToBytes(action.hashlock),
        timeoutHeight: BigInt(action.timeout_height),
      };
      if (!ledger.lockHtlc(txId, htlc)) return failed("duplicate HTLC or escrow overflow");
      signer.balance -= amount;
      return ok();
    }
    case "htlc_claim": {
      const htlc = ledger.htlc(action.htlc_id);
      if (!htlc) return failed("no such HTLC");
      if (signerId !== htlc.recipient) return failed("only the recipient may claim");
      if (height >= htlc.timeoutHeight) return failed("HTLC has timed out");
      const preimage = action.preimage instanceof Uint8Array ? action.preimage : Uint8Array.from(action.preimage);
      if (bytesToHex(sha256(preimage)) !== bytesToHex(htlc.hashlock))
        return failed("preimage does not match hashlock");
      ledger.settleHtlc(action.htlc_id);
      signer.balance += htlc.amount;
      return ok();
    }
    case "htlc_refund": {
      const htlc = ledger.htlc(action.htlc_id);
      if (!htlc) return failed("no such HTLC");
      if (signerId !== htlc.locker) return failed("only the locker may refund");
      if (height < htlc.timeoutHeight) return failed("HTLC has not timed out yet");
      ledger.settleHtlc(action.htlc_id);
      signer.balance += htlc.amount;
      return ok();
    }
    default:
      // shielded/call are rejected earlier as delegated.
      throw new TransactionRejected(
        "requires_delegated_verification",
        `action '${action.type}' is not part of the transparent STF`,
      );
  }
}

/** Split `fee` 5%/2%/93% to the tax recipients and the miner. No burn. */
function distributeFee(ledger: Ledger, ctx: BlockContext, fee: bigint): void {
  if (fee === 0n) return;
  const primary = (fee * BigInt(ctx.taxPrimaryBps)) / 10_000n;
  const secondary = (fee * BigInt(ctx.taxSecondaryBps)) / 10_000n;
  const minerCut = fee - primary - secondary;
  ledger.credit(ctx.taxPrimaryRecipient, primary);
  ledger.credit(ctx.taxSecondaryRecipient, secondary);
  ledger.credit(ctx.miner, minerCut);
}

// --- Coinbase / emission (mirror mining/lib.rs + runtime apply_coinbase) ----

/**
 * The coinbase subsidy for the block at `height` given cumulative `mined`
 * issuance — **Bitcoin's height-keyed halving rule**, byte-for-byte with
 * `MiningPolicy::reward_at`:
 *
 *   subsidy(height) = baseReward >> ((height - 1) / halvingIntervalBlocks)
 *
 * clamped to the room left under the budget. Height 0 (genesis) mints nothing —
 * there is no pre-mine — and the reward is 0 once the budget is exhausted.
 */
export function rewardAt(height: bigint, mined: bigint, ctx: BlockContext): bigint {
  const base = ctx.baseReward ?? 0n;
  const interval = ctx.halvingIntervalBlocks && ctx.halvingIntervalBlocks > 0n
    ? ctx.halvingIntervalBlocks
    : 1n;
  const budget = ctx.miningBudgetGrains ?? 0n;
  if (height === 0n) return 0n; // genesis is never mined
  if (mined >= budget) return 0n;
  const halvings = (height - 1n) / interval;
  const scheduled = halvings >= 127n ? 0n : base >> halvings;
  const remaining = budget - mined;
  return scheduled < remaining ? scheduled : remaining;
}

/**
 * Apply the block coinbase: mint the scheduled subsidy to the miner and advance
 * the `mined_emitted` counter, BEFORE any transaction executes (mirror
 * `runtime::apply_coinbase`). Returns the minted amount (0 if issuance is off or
 * the budget is spent).
 */
export function applyCoinbase(ledger: Ledger, ctx: BlockContext): bigint {
  const reward = rewardAt(BigInt(ctx.height), ledger.minedEmittedGrains(), ctx);
  if (reward === 0n) return 0n;
  // The coinbase is taxed exactly like a fee; the whole reward is newly issued.
  const primary = (reward * BigInt(ctx.taxPrimaryBps)) / 10_000n;
  const secondary = (reward * BigInt(ctx.taxSecondaryBps)) / 10_000n;
  const minerCut = reward - primary - secondary;
  ledger.credit(ctx.taxPrimaryRecipient, primary);
  ledger.credit(ctx.taxSecondaryRecipient, secondary);
  ledger.credit(ctx.miner, minerCut);
  ledger.addMinedEmitted(reward);
  return reward;
}

/** Apply an ordered list of transactions, returning one receipt each. */
export function applyTransactions(
  ledger: Ledger,
  transactions: SignedTransaction[],
  ctx: BlockContext,
): Receipt[] {
  return transactions.map((stx) => applyTransaction(ledger, stx, ctx));
}

// --- Receipts root (mirror types/receipt.rs) -------------------------------

function encodeReceipt(r: Receipt): Uint8Array {
  const w = new BorshWriter();
  w.fixed(hexToBytes(r.tx_id), 32);
  if (r.status.status === "success") {
    w.u8(0);
  } else {
    w.u8(1).string(r.status.reason);
  }
  w.u64(r.gas_used);
  w.vecU8(Uint8Array.from(r.return_data));
  w.u32(r.events.length);
  for (const e of r.events) {
    w.vecU8(Uint8Array.from(e.topic));
    w.vecU8(Uint8Array.from(e.data));
  }
  return w.bytes();
}

/** The Merkle root committing to an ordered receipt list (mirror `receipts_root`). */
export function receiptsRoot(receipts: Receipt[]): string {
  const leaves = receipts.map((r) => blake3(encodeReceipt(r)));
  return `0x${bytesToHex(merkleRoot(leaves))}`;
}
