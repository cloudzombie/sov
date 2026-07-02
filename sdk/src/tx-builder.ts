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
import { encodeTransaction, transactionId } from "./borsh.js";
import { Keypair, PublicKey, Signature } from "./keys.js";
import { HybridKeypair, HybridPublicKey, HybridSignature } from "./hybrid.js";
import { assertWithinCap } from "./units.js";
import type { Action, SignedTransaction, Transaction } from "./types.js";

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
 * Sign a transaction body over its canonical Borsh bytes, producing a
 * {@link BuiltSignedTransaction}. Refuses (like the node's
 * `SignedTransaction::sign`) to sign when the keypair's public key does not
 * match the transaction's committed `public_key`.
 */
export function signTransaction(tx: Transaction, keypair: AnyKeypair): BuiltSignedTransaction {
  if (keypair.publicKey.toJSON() !== tx.public_key) {
    throw new TxBuildError("signing key does not match the transaction's public key");
  }
  const signature = keypair.sign(encodeTransaction(tx));
  return {
    transaction: tx,
    signature: signature.toJSON(),
    id: transactionId(tx),
  };
}

/** Convenience: build + sign in one call. */
export function buildAndSign(params: {
  signer: string;
  keypair: AnyKeypair;
  nonce: number;
  action: Action;
}): BuiltSignedTransaction {
  const tx = buildTransaction({
    signer: params.signer,
    publicKey: params.keypair.publicKey,
    nonce: params.nonce,
    action: params.action,
  });
  return signTransaction(tx, params.keypair);
}

/**
 * Verify a {@link BuiltSignedTransaction}'s signature against its committed
 * public key over the canonical Borsh bytes — the same check the node performs.
 */
export function verifyBuiltSignature(signed: BuiltSignedTransaction): boolean {
  try {
    const message = encodeTransaction(signed.transaction);
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
