/**
 * Typed JSON-RPC 2.0 client for a live SOV node (`sov-rpcd`).
 *
 * Every method maps to a real `sov_*` endpoint. The node takes named-object
 * parameters (e.g. `{ account }`, `{ height }`) and returns real chain state —
 * this client never fabricates data. The transport defaults to the Node 18+
 * global `fetch`, and is injectable for testing.
 */

import type {
  Account,
  Block,
  GrainString,
  HashHex,
  SignedTransaction,
  SigningDomain,
} from "./types.js";

/** A JSON-RPC error response. */
export class RpcError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(`JSON-RPC error ${code}: ${message}`);
    this.name = "RpcError";
    this.code = code;
    this.data = data;
  }
}

/**
 * Transport hook: given a method and its params object, perform the JSON-RPC
 * call and resolve the `result` (or throw {@link RpcError}). Injectable so tests
 * can drive the typed methods without a network.
 */
export type RpcTransport = (method: string, params: unknown) => Promise<unknown>;

/** Configuration for a {@link SovClient}. */
export interface SovClientOptions {
  /** The node JSON-RPC endpoint URL, e.g. `http://127.0.0.1:8645`. */
  endpoint: string;
  /** Optional transport override; defaults to a `fetch`-based transport. */
  transport?: RpcTransport;
  /** Per-request timeout in milliseconds (default 15000). */
  timeoutMs?: number;
}

/** Current supply, in decimal grains. Mirrors `sov_getSupply`. */
export interface Supply {
  total: GrainString;
  mined: GrainString;
}

/** Proof-of-work difficulty targets (decimal strings). Mirrors `sov_getDifficulty`. */
export interface Difficulty {
  sha256d: string;
}

/** A block's content-derived hash and its transactions' canonical ids. */
export interface BlockDigest {
  hash: HashHex;
  txIds: HashHex[];
}

/** The result of `sov_submitTransaction`. */
export interface SubmitResult {
  accepted: boolean;
  txId: HashHex;
}

let nextRequestId = 1;

function fetchTransport(endpoint: string, timeoutMs: number): RpcTransport {
  return async (method, params) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: nextRequestId++, method, params }),
        signal: controller.signal,
      });
      if (!res.ok) throw new RpcError(-32000, `HTTP ${res.status} from ${endpoint}`);
      const json = (await res.json()) as { result?: unknown; error?: { code: number; message: string; data?: unknown } };
      if (json.error) throw new RpcError(json.error.code, json.error.message, json.error.data);
      return json.result;
    } finally {
      clearTimeout(timer);
    }
  };
}

/** A typed client targeting a SOV node's JSON-RPC endpoint. */
export class SovClient {
  readonly endpoint: string;
  private readonly transport: RpcTransport;

  constructor(options: SovClientOptions) {
    if (!options || typeof options.endpoint !== "string" || options.endpoint.length === 0) {
      throw new Error("SovClient requires an endpoint URL");
    }
    this.endpoint = options.endpoint;
    this.transport = options.transport ?? fetchTransport(options.endpoint, options.timeoutMs ?? 15000);
  }

  /** Low-level JSON-RPC invocation: returns the typed `result`. */
  async call<T>(method: string, params: unknown = {}): Promise<T> {
    return (await this.transport(method, params)) as T;
  }

  // --- reads ---------------------------------------------------------------

  /** The chain id (network identifier). */
  chainId(): Promise<string> {
    return this.call<string>("sov_chainId");
  }

  /** The current head height. */
  getHeight(): Promise<number> {
    return this.call<number>("sov_getHeight");
  }

  /** Total / mined supply (decimal grains). */
  getSupply(): Promise<Supply> {
    return this.call<Supply>("sov_getSupply");
  }

  /** Full account state, or `null` if the account holds no on-chain state. */
  getAccount(account: string): Promise<Account | null> {
    return this.call<Account | null>("sov_getAccount", { account });
  }

  /** Liquid balance (grains, decimal string). */
  getBalance(account: string): Promise<GrainString> {
    return this.call<GrainString>("sov_getBalance", { account });
  }

  /** Next expected nonce for `account`. */
  getNonce(account: string): Promise<number> {
    return this.call<number>("sov_getNonce", { account });
  }

  /** Block at `height`, or `null` if it does not exist. */
  getBlockByHeight(height: number): Promise<Block | null> {
    return this.call<Block | null>("sov_getBlockByHeight", { height });
  }

  /** Block with header hash `hash`, or `null`. */
  getBlockByHash(hash: HashHex): Promise<Block | null> {
    return this.call<Block | null>("sov_getBlockByHash", { hash });
  }

  /** A block's hash and its transactions' canonical ids, or `null`. */
  getBlockDigest(height: number): Promise<BlockDigest | null> {
    return this.call<BlockDigest | null>("sov_getBlockDigest", { height });
  }

  /** The chain head block. */
  getHead(): Promise<Block> {
    return this.call<Block>("sov_getHead");
  }

  /** The committed state root (`0x<hex>`). */
  getStateRoot(): Promise<HashHex> {
    return this.call<HashHex>("sov_getStateRoot");
  }

  /** Current proof-of-work difficulty targets. */
  getDifficulty(): Promise<Difficulty> {
    return this.call<Difficulty>("sov_getDifficulty");
  }

  /** Number of pending transactions in the node's mempool. */
  getMempoolSize(): Promise<number> {
    return this.call<number>("sov_getMempoolSize");
  }

  /** Whether the block with header hash `hash` has reached finality. */
  isFinal(hash: HashHex): Promise<boolean> {
    return this.call<boolean>("sov_isFinal", { hash });
  }

  /**
   * The network {@link SigningDomain} a NEW transaction's signature must bind
   * to (`sov_getSigningDomain`), or `null` while the miner-signaled `tx-domain`
   * hard fork is dormant — sign the legacy (un-bound) way then, byte-identical
   * to pre-fork behavior. A node too old to know the method (`-32601`
   * method-not-found) is by definition pre-fork, so it also maps to `null`.
   */
  async getSigningDomain(): Promise<SigningDomain | null> {
    let r: { active?: boolean; chainId?: string | null; genesis?: string | null };
    try {
      r = await this.call<typeof r>("sov_getSigningDomain");
    } catch (e) {
      if (e instanceof RpcError && e.code === -32601) return null;
      throw e;
    }
    if (!r || r.active !== true) return null;
    if (typeof r.chainId !== "string" || typeof r.genesis !== "string") {
      throw new RpcError(-32000, "active signing domain missing chainId/genesis");
    }
    return { chainId: r.chainId, genesis: r.genesis };
  }

  // --- write ---------------------------------------------------------------

  /** Submit a signed transaction; returns acceptance + the canonical tx id. */
  async submitTransaction(signed: SignedTransaction): Promise<SubmitResult> {
    const r = await this.call<{ accepted: boolean; txId: string }>("sov_submitTransaction", signed);
    const txId = r.txId.startsWith("0x") ? r.txId : `0x${r.txId}`;
    return { accepted: r.accepted, txId };
  }
}
