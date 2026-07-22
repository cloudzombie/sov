/**
 * Transaction builder: assemble a {@link Transaction} for a signer + nonce +
 * action and produce a node-submittable {@link SignedTransaction}.
 *
 * The signature is over the node's CANONICAL Borsh signing bytes (see
 * {@link encodeTransaction}), and the transaction id is the Blake3 of those
 * bytes — both verified byte-for-byte against the Rust crates' known-answer
 * vectors (`test/borsh.test.ts`). Output is wire-compatible: a transaction built
 * here is accepted by a live node.
 */

import { assertValidAccountId } from "./account.js";
import { encodeTransaction, hexToBytes, transactionId } from "./borsh.js";
import { Keypair, PublicKey, Signature } from "./keys.js";
import { HybridKeypair, HybridPublicKey, HybridSignature } from "./hybrid.js";
import { assertWithinCap } from "./units.js";
import type { Action, SignedTransaction, SigningDomain, Transaction } from "./types.js";

/** Either signing scheme's public key (Ed25519 or hybrid post-quantum). */
export type AnyPublicKey = PublicKey | HybridPublicKey;
/** Either signing scheme's keypair. */
export type AnyKeypair = Keypair | HybridKeypair;
/** Either signing scheme's signature. */
export type AnySignature = Signature | HybridSignature;

/** Error thrown for malformed transaction inputs. */
export class TxBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TxBuildError";
  }
}

/**
 * A signed transaction produced by this builder: the wire {@link SignedTransaction}
 * plus the canonical transaction id (`0x<hex>`) as a convenience. Use
 * {@link toWireSignedTransaction} to get the plain wire shape for submission.
 */
export interface BuiltSignedTransaction extends SignedTransaction {
  /** The canonical transaction id (`0x<hex>`, Blake3 of the Borsh signing bytes). */
  id: string;
}

/** Validate an action's referenced accounts and amounts. */
function validateAction(action: Action): void {
  switch (action.type) {
    case "transfer":
      assertValidAccountId(action.to);
      assertWithinCap(BigInt(action.amount));
      break;
    case "call":
      assertValidAccountId(action.contract);
      break;
    case "htlc_lock":
      assertValidAccountId(action.recipient);
      assertWithinCap(BigInt(action.amount));
      break;
    // Token amounts are the asset's own denomination (not SOV-capped); validate the
    // recipient account where present.
    case "token_issue":
    case "token_transfer":
    case "transfer_name":
    case "nft_mint":
    case "nft_transfer":
      assertValidAccountId(action.to);
      break;
    case "propose_multisig":
    case "approve_multisig":
    case "cancel_multisig":
      assertValidAccountId(action.account);
      break;
    // Vault collateral is XUS (SOV-capped); mint/burn are xUSD (own denomination);
    // the node enforces the collateral ratio, oracle authorization, and limits.
    case "vault_deposit":
    case "vault_withdraw":
      assertWithinCap(BigInt(action.amount));
      break;
    case "vault_mint":
    case "vault_burn":
    case "oracle_update":
      break;
    case "deploy":
    case "claim_vesting":
    // Opaque or node-verified payloads (bundles, ids, policies, intents, keys, names).
    case "shielded":
    case "htlc_claim":
    case "htlc_refund":
    case "token_burn":
    case "token_set_policy":
    case "intent_settle":
    case "intent_cancel":
    case "rotate_key":
    case "register_name":
    case "nft_set_meta":
    case "set_multisig":
    case "multisig_exec":
      break;
    default: {
      const _never: never = action;
      throw new TxBuildError(`unknown action: ${JSON.stringify(_never)}`);
    }
  }
}

/**
 * Build the unsigned transaction body. Validates the signer id, nonce, and the
 * action's referenced accounts/amounts. The `publicKey` is committed into the
 * body exactly as the node requires.
 */
export function buildTransaction(params: {
  signer: string;
  publicKey: AnyPublicKey;
  nonce: number;
  action: Action;
}): Transaction {
  const { signer, publicKey, nonce, action } = params;
  assertValidAccountId(signer);
  if (!Number.isInteger(nonce) || nonce < 0) {
    throw new TxBuildError(`nonce must be a non-negative integer, got ${nonce}`);
  }
  validateAction(action);
  return {
    signer,
    public_key: publicKey.toJSON(),
    nonce,
    action,
  };
}

/**
 * Domain tag for transaction signatures under the miner-signaled `tx-domain`
 * hard fork — mirrors the node's `sov_types::TX_SIGNING_DOMAIN_TAG`.
 */
export const TX_SIGNING_DOMAIN_TAG = "sov:tx:v1";

/**
 * The signing preimage for `tx` under an optional network {@link SigningDomain}
 * — byte-for-byte the node's `Transaction::signing_bytes_in`.
 *
 * No domain (`undefined`/`null`, the dormant-fork case) yields exactly the
 * canonical Borsh bytes ({@link encodeTransaction}) — unchanged pre-fork
 * behavior. With a domain, the preimage is framed as
 * `"sov:tx:v1" ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh(Transaction)`
 * (the node's `SigningDomain::frame`), binding the signature to that network.
 * The transaction id is unaffected either way — it stays the Blake3 of the
 * un-framed Borsh bytes.
 */
export function transactionSigningBytes(
  tx: Transaction,
  domain?: SigningDomain | null,
): Uint8Array {
  const body = encodeTransaction(tx);
  if (!domain) return body;
  const genesis = hexToBytes(domain.genesis);
  if (genesis.length !== 32) {
    throw new TxBuildError(`signing-domain genesis must be 32 bytes, got ${genesis.length}`);
  }
  const tag = new TextEncoder().encode(TX_SIGNING_DOMAIN_TAG);
  const chainId = new TextEncoder().encode(domain.chainId);
  const out = new Uint8Array(tag.length + 1 + chainId.length + 1 + genesis.length + body.length);
  let at = 0;
  out.set(tag, at);
  at += tag.length;
  out[at++] = 0x00;
  out.set(chainId, at);
  at += chainId.length;
  out[at++] = 0x00;
  out.set(genesis, at);
  at += genesis.length;
  out.set(body, at);
  return out;
}

/**
 * Sign a transaction body over its canonical signing preimage, producing a
 * {@link BuiltSignedTransaction}. Refuses (like the node's
 * `SignedTransaction::sign`) to sign when the keypair's public key does not
 * match the transaction's committed `public_key`.
 *
 * `domain` is the network {@link SigningDomain} from the node's
 * `sov_getSigningDomain` ({@link SovClient.getSigningDomain}): omit it (or pass
 * `null`) while the `tx-domain` fork is dormant — the signature is then over the
 * bare Borsh bytes, byte-identical to before the fork existed. Pass the domain
 * once the fork is active to produce the network-bound signature the node
 * requires. The transaction id is identical in both cases.
 */
export function signTransaction(
  tx: Transaction,
  keypair: AnyKeypair,
  domain?: SigningDomain | null,
): BuiltSignedTransaction {
  if (keypair.publicKey.toJSON() !== tx.public_key) {
    throw new TxBuildError("signing key does not match the transaction's public key");
  }
  const signature = keypair.sign(transactionSigningBytes(tx, domain));
  return {
    transaction: tx,
    signature: signature.toJSON(),
    id: transactionId(tx),
  };
}

/** Convenience: build + sign in one call (see {@link signTransaction} for `domain`). */
export function buildAndSign(params: {
  signer: string;
  keypair: AnyKeypair;
  nonce: number;
  action: Action;
  domain?: SigningDomain | null;
}): BuiltSignedTransaction {
  const tx = buildTransaction({
    signer: params.signer,
    publicKey: params.keypair.publicKey,
    nonce: params.nonce,
    action: params.action,
  });
  return signTransaction(tx, params.keypair, params.domain);
}

/**
 * Verify a {@link BuiltSignedTransaction}'s signature against its committed
 * public key over the canonical signing preimage — the same check the node
 * performs. Pass `domain` to require a network-bound signature (post-activation
 * verification); omit it for the legacy (dormant-fork) preimage.
 */
export function verifyBuiltSignature(
  signed: BuiltSignedTransaction,
  domain?: SigningDomain | null,
): boolean {
  try {
    const message = transactionSigningBytes(signed.transaction, domain);
    // Scheme is selected by the committed public key's form (hybrid keys carry
    // the mandatory `hybrid65:` prefix); a hybrid signature is a conjunction.
    if (signed.transaction.public_key.startsWith("hybrid65:")) {
      const pk = HybridPublicKey.fromHex(signed.transaction.public_key);
      return pk.verify(message, HybridSignature.fromHex(signed.signature));
    }
    const pk = PublicKey.fromHex(signed.transaction.public_key);
    return pk.verify(message, Signature.fromHex(signed.signature));
  } catch {
    return false;
  }
}

/** Strip the SDK-only `id` field to get the plain wire shape for submission. */
export function toWireSignedTransaction(signed: BuiltSignedTransaction): SignedTransaction {
  return {
    transaction: signed.transaction,
    signature: signed.signature,
  };
}
