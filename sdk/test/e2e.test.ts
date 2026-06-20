/**
 * End-to-end test against a LIVE SOV node. Skipped unless `SOV_RPC` is set, so
 * the normal `npm test` runs offline. To run it:
 *
 *   # 1. start a devnet node (see ../explorer/devnet/gen-devnet.mjs + sov-rpcd)
 *   # 2. point the SDK at it; SOV_SEED is the treasury seed (usa.reserve.sov)
 *   SOV_RPC=http://127.0.0.1:8645 \
 *   SOV_SEED=0202020202020202020202020202020202020202020202020202020202020202 \
 *     npx vitest run test/e2e.test.ts
 *
 * It proves the SDK's transactions are wire-compatible: a transfer it builds and
 * signs is accepted by the node, included in a block, and reflected in balances.
 */

import { describe, expect, it } from "vitest";
import { SovClient } from "../src/rpc.js";
import { Wallet } from "../src/wallet.js";

const endpoint = process.env.SOV_RPC;
const suite = endpoint ? describe : describe.skip;

suite("e2e against a live SOV node", () => {
  const seedHex = process.env.SOV_SEED ?? "02".repeat(32);
  const seed = Uint8Array.from(
    seedHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );

  it("reports chain id and height", async () => {
    const client = new SovClient({ endpoint: endpoint! });
    expect(typeof (await client.chainId())).toBe("string");
    expect(await client.getHeight()).toBeGreaterThanOrEqual(0);
  });

  it("builds, signs, and submits a transfer the node accepts and includes", async () => {
    const client = new SovClient({ endpoint: endpoint! });
    const wallet = Wallet.fromSeed(client, seed, "usa.reserve.sov");

    const recipientBefore = BigInt(await client.getBalance("ecb.reserve.sov"));
    const out = await wallet.transfer("ecb.reserve.sov", "1");
    expect(out.id).toMatch(/^0x[0-9a-f]{64}$/);

    const inclusion = await wallet.awaitInclusion(out.id, { timeoutMs: 20_000 });
    expect(inclusion.height).toBeGreaterThan(0);

    const block = await client.getBlockByHeight(inclusion.height);
    expect(block!.transactions.some((t) => t.transaction.signer === "usa.reserve.sov")).toBe(true);

    const recipientAfter = BigInt(await client.getBalance("ecb.reserve.sov"));
    expect(recipientAfter - recipientBefore).toBe(100_000_000n); // +1 SOV
  });
});
