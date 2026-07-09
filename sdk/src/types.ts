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

/** Mint `amount` units of the signer's native asset `symbol` to `to`. */
export interface TokenIssueAction {
  type: "token_issue";
  symbol: string;
  amount: GrainString;
  to: AccountIdStr;
}

/** Move `amount` units of `asset` (32-byte id hex) from the signer to `to`. */
export interface TokenTransferAction {
  type: "token_transfer";
  asset: HashHex;
  to: AccountIdStr;
  amount: GrainString;
}

/** Burn `amount` units of `asset` from the signer's balance. */
export interface TokenBurnAction {
  type: "token_burn";
  asset: HashHex;
  amount: GrainString;
}

/** A native-asset transfer control (mirror `compliance::TransferControl`). */
export type TransferControl =
  | { type: "unrestricted" }
  | { type: "allow_list"; accounts: AccountIdStr[] }
  | { type: "deny_list"; accounts: AccountIdStr[] };

/** A per-window spend limit (mirror `compliance::SpendLimit`). */
export interface SpendLimit {
  max_per_window: GrainString;
  window_blocks: number;
}

/** An asset's compliance policy (mirror `compliance::CompliancePolicy`). */
export interface CompliancePolicy {
  frozen: boolean;
  transfer_control: TransferControl;
  spend_limit: SpendLimit | null;
}

/** Set (replace) the compliance policy of `asset`. Issuer-only. */
export interface TokenSetPolicyAction {
  type: "token_set_policy";
  asset: HashHex;
  policy: CompliancePolicy;
}

/** An intent's asset leg (mirror `intents::Asset`). */
export type IntentAsset = { type: "sov" } | { type: "token"; asset: HashHex };

/** A declarative swap intent (mirror `intents::Intent`). */
export interface Intent {
  owner: AccountIdStr;
  public_key: PublicKeyHex;
  nonce: number;
  give_asset: IntentAsset;
  give_amount: GrainString;
  want_asset: IntentAsset;
  min_receive: GrainString;
  expiry_height: number;
}

/** A signed intent (mirror `intents::SignedIntent`). */
export interface SignedIntent {
  intent: Intent;
  signature: SignatureHex;
}

/** A solver's settlement of a signed intent (mirror `intents::Settlement`). */
export interface Settlement {
  intent: SignedIntent;
  solver: AccountIdStr;
  deliver_amount: GrainString;
}

/** Atomically settle a signed swap intent. */
export interface IntentSettleAction {
  type: "intent_settle";
  settlement: Settlement;
}

/** Cancel one of the signer's own intents before it is filled. */
export interface IntentCancelAction {
  type: "intent_cancel";
  intent: Intent;
}

/** Re-key the signer's account to `new_key`, proving possession with `proof`. */
export interface RotateKeyAction {
  type: "rotate_key";
  new_key: PublicKeyHex;
  proof: SignatureHex;
}

/** Register a human-readable `*.sov` name bound to the signer's account. */
export interface RegisterNameAction {
  type: "register_name";
  name: string;
}

/** Reassign an owned name to `to`. */
export interface TransferNameAction {
  type: "transfer_name";
  name: string;
  to: AccountIdStr;
}

/** Mint a unique NFT `token_id` in the signer's collection `symbol`, owned by `to`. */
export interface NftMintAction {
  type: "nft_mint";
  symbol: string;
  token_id: number[] | Uint8Array;
  to: AccountIdStr;
  metadata: number[] | Uint8Array;
}

/** Transfer an NFT to `to`. */
export interface NftTransferAction {
  type: "nft_transfer";
  collection: HashHex;
  token_id: number[] | Uint8Array;
  to: AccountIdStr;
}

/** Replace an NFT's metadata. */
export interface NftSetMetaAction {
  type: "nft_set_meta";
  collection: HashHex;
  token_id: number[] | Uint8Array;
  metadata: number[] | Uint8Array;
}

/** Opt the signer's account into (or replace) M-of-N multisig. */
export interface SetMultisigAction {
  type: "set_multisig";
  signers: PublicKeyHex[];
  threshold: number;
}

/** One approval within a `MultisigExec` (mirror `types::MultisigApproval`). */
export interface MultisigApproval {
  signer: number;
  signature: SignatureHex;
}

/** Execute `action` on a multisig account with detached `approvals`. */
export interface MultisigExecAction {
  type: "multisig_exec";
  action: Action;
  approvals: MultisigApproval[];
}

/** Propose a spend from a multisig `account` (the member's tx signature is their approval). */
export interface ProposeMultisigAction {
  type: "propose_multisig";
  account: AccountIdStr;
  action: Action;
}

/** Approve a pending proposal on `account`. */
export interface ApproveMultisigAction {
  type: "approve_multisig";
  account: AccountIdStr;
  proposal: HashHex;
}

/** Cancel a pending proposal on `account`. */
export interface CancelMultisigAction {
  type: "cancel_multisig";
  account: AccountIdStr;
  proposal: HashHex;
}

/** Lock `amount` XUS collateral into the signer's xUSD vault. */
export interface VaultDepositAction {
  type: "vault_deposit";
  amount: GrainString;
}

/** Mint `amount` xUSD against the signer's vault collateral (≤ the 150% min ratio). */
export interface VaultMintAction {
  type: "vault_mint";
  amount: GrainString;
}

/** Burn `amount` xUSD to repay the signer's vault debt. */
export interface VaultBurnAction {
  type: "vault_burn";
  amount: GrainString;
}

/** Withdraw `amount` XUS collateral from the vault, staying over-collateralized. */
export interface VaultWithdrawAction {
  type: "vault_withdraw";
  amount: GrainString;
}

/** Publish an XUS/USD oracle price (authorized feed only). `price` is USD per XUS
 *  in 10^8 fixed point, as a decimal string. */
export interface OracleUpdateAction {
  type: "oracle_update";
  price: string;
}

/**
 * The closed set of transaction actions. Mirrors `types::Action` — all 30
 * variants, in Borsh-discriminant order (Transfer=0 … OracleUpdate=29).
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
  | HtlcRefundAction
  | TokenIssueAction
  | TokenTransferAction
  | TokenBurnAction
  | TokenSetPolicyAction
  | IntentSettleAction
  | IntentCancelAction
  | RotateKeyAction
  | RegisterNameAction
  | TransferNameAction
  | NftMintAction
  | NftTransferAction
  | NftSetMetaAction
  | SetMultisigAction
  | MultisigExecAction
  | ProposeMultisigAction
  | ApproveMultisigAction
  | CancelMultisigAction
  | VaultDepositAction
  | VaultMintAction
  | VaultBurnAction
  | VaultWithdrawAction
  | OracleUpdateAction;

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
