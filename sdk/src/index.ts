/**
 * @sov/sdk — high-level JavaScript/TypeScript client for the SOV blockchain.
 *
 * A complete client: SOV unit math, AccountId validation, Ed25519 keys, the wire
 * types, a Borsh transaction encoder/signer verified byte-for-byte against the
 * Rust node (known-answer vectors), a live JSON-RPC client, and a wallet helper.
 * Transactions built here are node-submittable; every RPC method returns real
 * chain data and never fabricates anything.
 */

export * from "./units.js";
export * from "./account.js";
export * from "./keys.js";
export * from "./hybrid.js";
export * from "./hd.js";
export * from "./types.js";
export * from "./borsh.js";
export * from "./tx-builder.js";
export * from "./rpc.js";
export * from "./wallet.js";
export * from "./smt.js";
export * from "./state.js";
export * from "./stf.js";
export * from "./verify.js";
export { parseAddress, preferredReceiver, decodeShielded, decodeUnified } from "./address.js";
export type { AnyAddress, Receiver } from "./address.js";
