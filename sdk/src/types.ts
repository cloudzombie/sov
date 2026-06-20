/**
 * Plain-data TypeScript interfaces mirroring the SOV chain's wire types.
 *
 * These mirror the JSON (serde) representation used by the node's `types` and
 * `state` crates:
 *   - `chain/crates/state/src/account.rs`  -> {@link Account}
 *   - `chain/crates/types/src/transaction.rs` -> {@link Action}, {@link Transaction}, {@link SignedTransaction}
 *   - `chain/crates/types/src/block.rs`     -> {@link BlockHeader}, {@link Block}
 *   - `chain/crates/types/src/receipt.rs`   -> {@link Receipt}, {@link ExecutionStatus}
 *
 * IMPORTANT — encoding parity is NOT claimed. The node's *canonical* bytes for
 * hashing and signing are the Borsh encoding (deterministic, length-prefixed),
 * not JSON. We do not reproduce Borsh here and therefore do NOT assert that an
 * id/signing payload computed in JS equals the node's. These interfaces match
 * the JSON shapes for reading RPC responses and constructing request bodies;
 * byte-for-byte signing parity must be validated against known-answer vectors
 * once the Phase 8 RPC exists. See README.
 *
 * Conventions (all faithful to the serde impls):
 *   - Balances are decimal *grain* strings (u128 is JS-unsafe as a number).
 *   - Public keys are `0x<hex>` strings; signatures are `0x<hex>` strings.
 *   - Hashes are `0x<hex>` strings.
 *   - Action is a tagged union via `{ "type": "transfer" | ... }`.
 *   - ExecutionStatus is a tagged union via `{ "status": "success" | "failed" }`.
 */

/** A grain amount as a decimal string (matches the node's `Balance` JSON). */
export type GrainString = string;

/** A public key as `0x<hex>` (matches the node's `PublicKey` JSON). */
export type PublicKeyHex = string;

/** A signature as `0x<hex>` (matches the node's `Signature` JSON). */
export type SignatureHex = string;

/** A 32-byte hash as `0x<hex>` (matches the node's `Hash` JSON). */
export type HashHex = string;

/** A validated account id as a plain string. */
export type AccountIdStr = string;

/**
 * On-chain account state. Mirrors `state::Account`.
 * `key` is `null` for a keyless (receive-only) account; `code` is `null` for a
 * non-contract account (and a byte array when present).
 */
export interface Account {
  nonce: number;
  balance: GrainString;
  locked: GrainString;
  unlock_height: number;
  key: PublicKeyHex | null;
  code: number[] | null;
}

/** A transfer of `amount` grains to `to`. */
export interface TransferAction {
  type: "transfer";
  to: AccountIdStr;
  amount: GrainString;
}

/** Claim vested funds into the liquid balance. */
export interface ClaimVestingAction {
  type: "claim_vesting";
}

/** Deploy WASM `code` (byte array) to the signer's account. */
export interface DeployAction {
  type: "deploy";
  code: number[];
}

/**
 * Invoke a contract's `call` entry point with up to `gas_limit` gas and
 * `calldata` as the call's input bytes (ABI v2; readable in-contract via the
 * `calldata` host function). Omitting `calldata` encodes an empty input.
 */
export interface CallAction {
  type: "call";
  contract: AccountIdStr;
  gas_limit: number;
  calldata?: number[] | Uint8Array;
}

/**
 * A shielded-pool action carrying a serialized Orchard/Halo2 bundle — the
 * canonical bytes produced by the `sov-shielded` crate's `ShieldedBundle`. The
 * SDK relays the bundle bytes verbatim; it does not (yet) build proofs itself.
 */
export interface ShieldedAction {
  type: "shielded";
  bundle: number[] | Uint8Array;
}

/**
 * Lock funds in a hash-time-locked contract — the SOV half of a trustless
 * cross-chain atomic swap. `hashlock` is the 32-byte SHA-256 of the shared
 * secret (hex); `timeout_height` is the refund height.
 */
export interface HtlcLockAction {
  type: "htlc_lock";
  recipient: AccountIdStr;
  amount: GrainString;
  hashlock: string;
  timeout_height: number;
}

/** Claim an HTLC by revealing the preimage. `htlc_id` is the 32-byte id (hex) of
 * the `htlc_lock` transaction; `preimage` is the secret bytes. */
export interface HtlcClaimAction {
  type: "htlc_claim";
  htlc_id: string;
  preimage: number[] | Uint8Array;
}

/** Refund an HTLC to its locker after its timeout. */
export interface HtlcRefundAction {
  type: "htlc_refund";
  htlc_id: string;
}

/**
 * The closed set of transaction actions. Mirrors `types::Action`.
 *
 * Issuance is NOT an action: under Nakamoto consensus the block coinbase mints
 * the scheduled reward to the block's miner (the pre-Nakamoto Mine/MineShielded
 * mint transactions were removed from the protocol).
 */
export type Action =
  | TransferAction
  | ClaimVestingAction
  | DeployAction
  | CallAction
  | ShieldedAction
  | HtlcLockAction
  | HtlcClaimAction
  | HtlcRefundAction;

/** The unsigned body of a transaction. Mirrors `types::Transaction`. */
export interface Transaction {
  signer: AccountIdStr;
  public_key: PublicKeyHex;
  nonce: number;
  action: Action;
}

/** A transaction plus its authorizing signature. Mirrors `types::SignedTransaction`. */
export interface SignedTransaction {
  transaction: Transaction;
  signature: SignatureHex;
}

/** The authenticated header of a block. Mirrors `types::BlockHeader`. */
export interface BlockHeader {
  height: number;
  prev_hash: HashHex;
  tx_root: HashHex;
  receipts_root: HashHex;
  state_root: HashHex;
  timestamp_ms: number;
  proposer: AccountIdStr;
  /** BIP-9/8 miner-signaling version bits (0 = signals nothing). */
  version_bits?: number;
  /** Difficulty target in Bitcoin's compact "nBits" form (0 if unset). */
  bits?: number;
  /** Nakamoto proof-of-work nonce. */
  nonce?: number | bigint;
}

/** A block: header plus the transactions it commits to. Mirrors `types::Block`. */
export interface Block {
  header: BlockHeader;
  transactions: SignedTransaction[];
}

/** Successful execution. */
export interface ExecutionSuccess {
  status: "success";
}

/** Failed execution with a human-readable reason. */
export interface ExecutionFailed {
  status: "failed";
  reason: string;
}

/** The outcome of applying a transaction. Mirrors `types::ExecutionStatus`. */
export type ExecutionStatus = ExecutionSuccess | ExecutionFailed;

/** An event emitted by a contract call (ABI v2). Mirrors `types::Event`. */
export interface Event {
  topic: number[];
  data: number[];
}

/** The recorded result of one transaction. Mirrors `types::Receipt`. */
export interface Receipt {
  tx_id: HashHex;
  status: ExecutionStatus;
  gas_used: number;
  /** Return data set by a contract call (empty otherwise). */
  return_data: number[];
  /** Events emitted by a contract call (empty otherwise). */
  events: Event[];
}
