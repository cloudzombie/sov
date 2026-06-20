import { describe, expect, it } from "vitest";
import { SovClient } from "../src/rpc.js";
import { Wallet } from "../src/wallet.js";

describe("Wallet", () => {
  it("transfer fetches the nonce, signs canonically, and submits the wire tx", async () => {
    const seen: { submitted?: any } = {};
    const client = new SovClient({
      endpoint: "http://x",
      transport: async (method, params: any) => {
        if (method === "sov_getNonce") return 4;
        if (method === "sov_submitTransaction") {
          seen.submitted = params;
          return { accepted: true, txId: "00" };
        }
        throw new Error(`unexpected ${method}`);
      },
    });
    const w = Wallet.fromSeed(client, new Uint8Array(32).fill(1), "usa.reserve.sov");

    const out = await w.transfer("ecb.reserve.sov", "5");
    expect(out.nonce).toBe(4);
    expect(out.id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(seen.submitted.transaction.nonce).toBe(4);
    expect(seen.submitted.transaction.signer).toBe("usa.reserve.sov");
    expect(seen.submitted.transaction.action).toEqual({
      type: "transfer",
      to: "ecb.reserve.sov",
      amount: "500000000",
    });
    expect("id" in seen.submitted).toBe(false); // wire shape only
  });

  it("awaitInclusion scans new block digests for the transaction id", async () => {
    const height = 2;
    const txId = "0xabc";
    const client = new SovClient({
      endpoint: "http://x",
      transport: async (method, params: any) => {
        if (method === "sov_getHeight") return height;
        if (method === "sov_getBlockDigest") {
          return params.height === 2 ? { hash: "0xblock", txIds: [txId] } : { hash: `0x${params.height}`, txIds: [] };
        }
        if (method === "sov_isFinal") return true;
        throw new Error(`unexpected ${method}`);
      },
    });
    const w = Wallet.fromSeed(client, new Uint8Array(32).fill(1), "a.sov");
    const res = await w.awaitInclusion(txId, { timeoutMs: 1000, pollMs: 10 });
    expect(res).toEqual({ height: 2, blockHash: "0xblock", final: true });
  });

  it("send throws when the node rejects the transaction", async () => {
    const client = new SovClient({
      endpoint: "http://x",
      transport: async (method) => {
        if (method === "sov_getNonce") return 0;
        if (method === "sov_submitTransaction") return { accepted: false, txId: "" };
        throw new Error(`unexpected ${method}`);
      },
    });
    const w = Wallet.fromSeed(client, new Uint8Array(32).fill(1), "a.sov");
    await expect(w.transfer("b.sov", "1")).rejects.toThrow(/rejected/);
  });
});
