// Drives the Store from a live node: backfills a recent window of history, then
// follows the head, keeping finality, supply, difficulty, and miners fresh. Every
// datum comes from the node over JSON-RPC; the indexer only re-derives, never
// invents. It is resilient to transient RPC errors — a failed tick is retried on
// the next interval.

/** Turn a raw RPC block + digest into the store's normalized record. */
export function normalizeBlock(block, digest, final) {
  const h = block.header;
  const height = h.height;
  const hash = digest.hash;
  const txIds = digest.txIds ?? [];
  const transactions = block.transactions.map((stx, index) => ({
    id: txIds[index] ?? null,
    index,
    signer: stx.transaction.signer,
    publicKey: stx.transaction.public_key,
    nonce: stx.transaction.nonce,
    action: stx.transaction.action,
    signature: stx.signature,
    sizeBytes: Buffer.byteLength(JSON.stringify(stx)),
    blockHeight: height,
    blockHash: hash,
    timestampMs: h.timestamp_ms,
  }));
  return {
    height,
    hash,
    prevHash: h.prev_hash,
    txRoot: h.tx_root,
    receiptsRoot: h.receipts_root,
    stateRoot: h.state_root,
    timestampMs: h.timestamp_ms,
    proposer: h.proposer,
    // The coinbase: this block's real issuance (height-keyed subsidy) and its
    // 93/5/2 miner/founder/dev split, computed by the node. Null for genesis.
    coinbase: digest.coinbase ?? null,
    txCount: transactions.length,
    sizeBytes: Buffer.byteLength(JSON.stringify(block)),
    transactions,
    final: !!final,
  };
}

export class Indexer {
  constructor(rpc, store, opts = {}) {
    this.rpc = rpc;
    this.store = store;
    this.backfill = opts.backfill ?? 2000;
    this.finalityWindow = opts.finalityWindow ?? 64;
    this.onBlock = opts.onBlock ?? null;
    this.onTx = opts.onTx ?? null;
    this.onReset = opts.onReset ?? null;
    this._running = false;
    this._timer = null;
  }

  /** Learn the chain id and genesis hash before the first sync. */
  async init() {
    this.store.chainId = await this.rpc.chainId();
    const g = await this.rpc.blockDigest(0);
    if (g) this.store.genesisHash = g.hash;
  }

  /** Fetch, normalize, and index the block at `height`. Returns the record. */
  async indexBlock(height) {
    const [block, digest] = await Promise.all([
      this.rpc.blockByHeight(height),
      this.rpc.blockDigest(height),
    ]);
    if (!block || !digest) return null;
    const final = await this.rpc.isFinal(digest.hash).catch(() => false);
    const isNew = !this.store.blocksByHeight.has(height);
    const rec = normalizeBlock(block, digest, final);
    this.store.addBlock(rec);
    if (isNew) {
      if (this.onBlock) this.onBlock(rec);
      if (this.onTx) for (const tx of rec.transactions) this.onTx(tx);
    }
    return rec;
  }

  /** Detect that the node is now serving a DIFFERENT chain than what we indexed —
   * i.e. a regenesis (new genesis hash) or a rollback below our tip — so the
   * stored blocks describe a dead chain and must be discarded. */
  async chainWasReset(head) {
    if (this.store.tipHeight < 0) return false; // nothing indexed yet
    // (a) The genesis block hash changed → a brand-new chain.
    if (this.store.genesisHash) {
      const g = await this.rpc.blockDigest(0).catch(() => null);
      if (g?.hash && g.hash !== this.store.genesisHash) return true;
    }
    // (b) The node's head is BELOW our tip → a reset/deep rollback (our tip can't
    // exist on the live chain).
    if (head < this.store.tipHeight) return true;
    // (c) Same height, different hash at our tip → a reorg replaced our history.
    const stored = this.store.blocksByHeight.get(this.store.tipHeight);
    if (stored) {
      const live = await this.rpc.blockDigest(this.store.tipHeight).catch(() => null);
      if (live?.hash && live.hash !== stored.hash) return true;
    }
    return false;
  }

  /** One full pass: index new blocks, refresh finality and chain stats. */
  async syncOnce() {
    if (!this.store.chainId) await this.init(); // recover if the node was down at boot
    const head = await this.rpc.height();
    // Self-heal across a regenesis/rollback: wipe the dead index and rebuild from
    // the live chain's genesis so we never serve stale blocks.
    if (await this.chainWasReset(head)) {
      this.store.reset();
      await this.init();
      if (this.onReset) this.onReset();
    }
    const from = this.store.tipHeight < 0 ? Math.max(0, head - this.backfill) : this.store.tipHeight + 1;
    for (let h = from; h <= head; h++) {
      await this.indexBlock(h);
    }
    await this.refreshFinality();
    await this.refreshChainStats(head);
  }

  /** Re-check finality for the most recent not-yet-final blocks. */
  async refreshFinality() {
    const top = this.store.tipHeight;
    const floor = Math.max(this.store.minHeight, top - this.finalityWindow + 1);
    for (let h = top; h >= floor; h--) {
      const b = this.store.blocksByHeight.get(h);
      if (!b || b.final) continue;
      const final = await this.rpc.isFinal(b.hash).catch(() => false);
      if (final) b.final = true;
    }
  }

  async refreshChainStats(height) {
    try {
      const [supply, difficulty, miners, mempool] = await Promise.all([
        this.rpc.supply(),
        this.rpc.difficulty(),
        this.rpc.miners(),
        this.rpc.mempoolSize(),
      ]);
      this.store.recordSupply(supply, height);
      this.store.difficulty = difficulty;
      this.store.miners = miners;
      this.store.mempoolSize = mempool;
    } catch {
      // Transient RPC hiccup; the next tick retries.
    }
  }

  start(intervalMs = 1000) {
    if (this._running) return;
    this._running = true;
    const tick = async () => {
      if (!this._running) return;
      try {
        await this.syncOnce();
      } catch (e) {
        if (process?.env?.DEBUG) console.error('[indexer]', e.message);
      }
      if (this._running) this._timer = setTimeout(tick, intervalMs);
    };
    tick();
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
  }
}
