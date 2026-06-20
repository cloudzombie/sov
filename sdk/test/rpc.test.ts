import { describe, expect, it } from "vitest";
import { RpcError, SovClient } from "../src/rpc.js";

const stub = (transport: (m: string, p: unknown) => Promise<unknown>) =>
  new SovClient({ endpoint: "http://localhost:8645", transport });

describe("SovClient", () => {
  it("requires an endpoint", () => {
    // @ts-expect-error intentionally bad input
    expect(() => new SovClient({})).toThrow(/endpoint/);
    expect(() => new SovClient({ endpoint: "" })).toThrow(/endpoint/);
  });

  it("sends the named-object params the node expects", async () => {
    const calls: Array<{ method: string; params: unknown }> = [];
    const c = stub(async (method, params) => {
      calls.push({ method, params });
      switch (method) {
        case "sov_getHeight":
          return 7;
        case "sov_getBalance":
          return "100";
        case "sov_getNonce":
          return 3;
        case "sov_isFinal":
          return true;
        default:
          return null;
      }
    });
    await c.getHeight();
    await c.getBalance("usa.reserve.sov");
    await c.getNonce("usa.reserve.sov");
    await c.getAccount("usa.reserve.sov");
    await c.getBlockByHeight(5);
    await c.getBlockDigest(5);
    await c.isFinal("0xabc");
    expect(calls).toEqual([
      { method: "sov_getHeight", params: {} },
      { method: "sov_getBalance", params: { account: "usa.reserve.sov" } },
      { method: "sov_getNonce", params: { account: "usa.reserve.sov" } },
      { method: "sov_getAccount", params: { account: "usa.reserve.sov" } },
      { method: "sov_getBlockByHeight", params: { height: 5 } },
      { method: "sov_getBlockDigest", params: { height: 5 } },
      { method: "sov_isFinal", params: { hash: "0xabc" } },
    ]);
  });

  it("typed reads return the transport result", async () => {
    const c = stub(async (method) => (method === "sov_getHeight" ? 42 : null));
    await expect(c.getHeight()).resolves.toBe(42);
  });

  it("submitTransaction passes the signed tx as params and normalizes the id to 0x", async () => {
    let sent: { method: string; params: unknown } | null = null;
    const c = stub(async (method, params) => {
      sent = { method, params };
      return { accepted: true, txId: "deadbeef" };
    });
    const signed = {
      transaction: { signer: "a.sov", public_key: "0x00", nonce: 0, action: { type: "claim_vesting" } },
      signature: "0x00",
    } as never;
    const r = await c.submitTransaction(signed);
    expect(sent!.method).toBe("sov_submitTransaction");
    expect(sent!.params).toBe(signed);
    expect(r).toEqual({ accepted: true, txId: "0xdeadbeef" });
  });

  it("propagates JSON-RPC errors", async () => {
    const c = stub(async () => {
      throw new RpcError(-32601, "method not found");
    });
    await expect(c.getHeight()).rejects.toThrow(RpcError);
  });
});
