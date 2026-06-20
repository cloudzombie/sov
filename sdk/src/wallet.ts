/**
 * High-level wallet & dApp helpers over a {@link SovClient}.
 *
 * A {@link Wallet} binds a keypair to an account and the node client, and offers
 * the everyday operations: read balance/nonce/state, build+sign+submit a
 * transfer (or any action) with automatic nonce selection, and await a
 * transaction's inclusion and finality. Every call is a real round-trip to the
 * node — no cached or fabricated state.
 */

import { parseAddress, preferredReceiver } from "./address.js";
import { Keypair } from "./keys.js";
import { SovClient } from "./rpc.js";
import { buildAndSign, toWireSignedTransaction } from "./tx-builder.js";
import { sovToGrains } from "./units.js";
import type { Account, Action, GrainString, HashHex } from "./types.js";

/** The outcome of submitting a transaction. */
export interface SubmitOutcome {
  /** Canonical transaction id (`0x<hex>`). */
  id: HashHex;
  /** The nonce the transaction was signed at. */
  nonce: number;
}

/** Where a transaction landed. */
export interface InclusionResult {
  height: number;
  blockHash: HashHex;
  final: boolean;
}

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class Wallet {
  constructor(
    readonly client: SovClient,
    readonly keypair: Keypair,
    readonly account: string,
  ) {}

  /** Construct a wallet from a 32-byte seed. */
  static fromSeed(client: SovClient, seed: Uint8Array, account: string): Wallet {
    return new Wallet(client, Keypair.fromSeed(seed), account);
  }

  /** This wallet's account id. */
  address(): string {
    return this.account;
  }

  /** This wallet's public key as `0x<hex>`. */
  publicKeyHex(): string {
    return this.keypair.publicKey.toJSON();
  }

  /** Live liquid balance (grains, decimal string). */
  balance(): Promise<GrainString> {
    return this.client.getBalance(this.account);
  }

  /** Next expected nonce. */
  nonce(): Promise<number> {
    return this.client.getNonce(this.account);
  }

  /** Full on-chain account state, or `null` if unfunded. */
  state(): Promise<Account | null> {
    return this.client.getAccount(this.account);
  }

  /**
   * Build, sign, and submit `action` from this wallet at its current nonce.
   * Throws if the node rejects the transaction.
   */
  async send(action: Action): Promise<SubmitOutcome> {
    const nonce = await this.client.getNonce(this.account);
    const built = buildAndSign({ signer: this.account, keypair: this.keypair, nonce, action });
    const res = await this.client.submitTransaction(toWireSignedTransaction(built));
    if (!res.accepted) throw new Error("node rejected the transaction");
    return { id: built.id, nonce };
  }

  /**
   * Transfer `amount` (a XUS decimal string, or grains as a bigint) to `to` —
   * a named account, a `xus1…` shielded address, or a `uxus1…` unified
   * address. Routing is privacy-first; a recipient that routes to the
   * shielded pool is **refused honestly** rather than silently downgraded:
   * this SDK does not re-implement the Halo2 prover (see SECOND-CLIENT.md),
   * so shielded sends go through the Rust wallet (`sov-wallet transfer`).
   */
  transfer(to: string, amount: string | bigint): Promise<SubmitOutcome> {
    const receiver = preferredReceiver(parseAddress(to));
    if (receiver.kind === "shielded") {
      throw new Error(
        "recipient routes to the SHIELDED pool; this SDK carries no Halo2 prover — " +
          "use the Rust wallet (`sov-wallet transfer`) for shielded sends, or address " +
          "the transparent account explicitly if you intend a public payment",
      );
    }
    const grains = typeof amount === "bigint" ? amount : sovToGrains(amount);
    return this.send({ type: "transfer", to: receiver.account, amount: grains.toString() });
  }

  /**
   * Poll for `txId`'s inclusion by scanning new blocks, returning the block it
   * landed in and whether that block is final. Rejects after `timeoutMs`.
   */
  async awaitInclusion(
    txId: HashHex,
    opts: { timeoutMs?: number; pollMs?: number } = {},
  ): Promise<InclusionResult> {
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const pollMs = opts.pollMs ?? 400;
    const deadline = Date.now() + timeoutMs;
    // Start a few blocks back in case it was already included before we polled.
    let from = Math.max(0, (await this.client.getHeight()) - 3);
    while (Date.now() < deadline) {
      const head = await this.client.getHeight();
      for (let h = from; h <= head; h++) {
        const digest = await this.client.getBlockDigest(h);
        if (digest && digest.txIds.includes(txId)) {
          const final = await this.client.isFinal(digest.hash).catch(() => false);
          return { height: h, blockHash: digest.hash, final };
        }
      }
      from = head + 1;
      await delay(pollMs);
    }
    throw new Error(`transaction ${txId} not included within ${timeoutMs}ms`);
  }
}
