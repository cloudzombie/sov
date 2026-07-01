// In-memory, queryable index of Sovereign chain data, built by the Indexer from a live
// node over JSON-RPC. The node is the source of truth; this store is a derived,
// fully re-buildable view — nothing in it is fabricated. It keeps the most recent
// `maxBlocks` blocks (a ring), bounding memory on a long-lived chain.

const GRAINS_PER_XUS = 100_000_000n; // 8 decimals
const SUPPLY_CAP_GRAINS = 21_000_000n * GRAINS_PER_XUS;

/** The account a transaction touches besides its signer, if any. */
export function txCounterparty(action) {
  if (!action || typeof action !== 'object') return null;
  switch (action.type) {
    case 'transfer':
      return action.to ?? null;
    case 'call':
      return action.contract ?? null;
    default:
      return null;
  }
}

export class Store {
  constructor({ maxBlocks = 10_000 } = {}) {
    this.maxBlocks = maxBlocks;
    this.chainId = null;
    this.genesisHash = null;
    this.tipHeight = -1;
    this.minHeight = Infinity;
    this.blocksByHeight = new Map(); // height -> block record
    this.heightByHash = new Map(); // block hash -> height
    this.txById = new Map(); // tx id -> tx record
    this.txIdsByAccount = new Map(); // account -> tx id[] (insertion order)
    this.proposers = new Map(); // header proposer/miner account -> { blocks, lastHeight }
    this.miners = [];
    this.supply = null; // { total, mined } (decimal-grain strings)
    this.difficulty = null; // { sha256d } (the difficulty scalar; mainnet seal is RandomX)
    this.mempoolSize = 0;
    this.supplySeries = []; // [{ height, total, mined, timestampMs }]
    this.totalTxIndexed = 0;
    this.totalBlockBytesIndexed = 0;
  }

  /** Drop all indexed chain data so the index can be rebuilt from genesis. Used
   * when the node's chain is replaced (a regenesis) or rolls back below our tip —
   * the old blocks describe a dead chain and must not be served. `chainId` and
   * `genesisHash` are refreshed by the indexer's `init()` right after. */
  reset() {
    this.tipHeight = -1;
    this.minHeight = Infinity;
    this.blocksByHeight.clear();
    this.heightByHash.clear();
    this.txById.clear();
    this.txIdsByAccount.clear();
    this.proposers.clear();
    this.miners = [];
    this.supply = null;
    this.difficulty = null;
    this.mempoolSize = 0;
    this.supplySeries = [];
    this.totalTxIndexed = 0;
    this.totalBlockBytesIndexed = 0;
  }

  /** Insert (or replace, e.g. on a finality refresh) a normalized block record. */
  addBlock(rec) {
    const existing = this.blocksByHeight.has(rec.height);
    this.blocksByHeight.set(rec.height, rec);
    this.heightByHash.set(rec.hash, rec.height);
    if (rec.height > this.tipHeight) this.tipHeight = rec.height;
    if (rec.height < this.minHeight) this.minHeight = rec.height;
    if (existing) return; // re-index: per-tx / miner indices already populated
    this.totalBlockBytesIndexed += rec.sizeBytes ?? 0;

    const p = this.proposers.get(rec.proposer) ?? { blocks: 0, lastHeight: -1 };
    p.blocks += 1;
    p.lastHeight = Math.max(p.lastHeight, rec.height);
    this.proposers.set(rec.proposer, p);

    for (const tx of rec.transactions) {
      this.txById.set(tx.id, tx);
      this.totalTxIndexed += 1;
      this._tagAccount(tx.signer, tx.id);
      const cp = txCounterparty(tx.action);
      if (cp && cp !== tx.signer) this._tagAccount(cp, tx.id);
    }
    this._evict();
  }

  _tagAccount(account, txId) {
    let arr = this.txIdsByAccount.get(account);
    if (!arr) {
      arr = [];
      this.txIdsByAccount.set(account, arr);
    }
    arr.push(txId);
  }

  _evict() {
    while (this.blocksByHeight.size > this.maxBlocks) {
      const rec = this.blocksByHeight.get(this.minHeight);
      this.blocksByHeight.delete(this.minHeight);
      if (rec) {
        this.heightByHash.delete(rec.hash);
        for (const tx of rec.transactions) this.txById.delete(tx.id);
        this.totalBlockBytesIndexed = Math.max(
          0,
          this.totalBlockBytesIndexed - (rec.sizeBytes ?? 0),
        );
      }
      this.minHeight += 1;
      // Account-index arrays are filtered against `txById` on read, so stale ids
      // left here are harmless and cleaned up lazily.
    }
  }

  block(idOrHeight) {
    if (typeof idOrHeight === 'number') return this.blocksByHeight.get(idOrHeight) ?? null;
    const h = this.heightByHash.get(idOrHeight);
    return h === undefined ? null : this.blocksByHeight.get(h);
  }

  tx(id) {
    return this.txById.get(id) ?? null;
  }

  recentBlocks(limit = 20) {
    const out = [];
    for (let h = this.tipHeight; h >= this.minHeight && out.length < limit; h--) {
      const b = this.blocksByHeight.get(h);
      if (b) out.push(b);
    }
    return out;
  }

  recentTxs(limit = 20) {
    const out = [];
    for (let h = this.tipHeight; h >= this.minHeight && out.length < limit; h--) {
      const b = this.blocksByHeight.get(h);
      if (!b) continue;
      for (let i = b.transactions.length - 1; i >= 0 && out.length < limit; i--) {
        out.push(b.transactions[i]);
      }
    }
    return out;
  }

  accountTxs(account, limit = 50) {
    const ids = this.txIdsByAccount.get(account) ?? [];
    const out = [];
    for (let i = ids.length - 1; i >= 0 && out.length < limit; i--) {
      const tx = this.txById.get(ids[i]);
      if (tx) out.push(tx);
    }
    return out;
  }

  /** Observed miner activity: who actually produced the blocks we indexed. */
  observedMiners() {
    return [...this.proposers.entries()]
      .map(([account, s]) => ({ account, blocksMined: s.blocks, blocksProposed: s.blocks, lastHeight: s.lastHeight }))
      .sort((a, b) => b.blocksMined - a.blocksMined);
  }

  /** Backward-compatible name for older clients. */
  validators() {
    return this.observedMiners();
  }

  recordSupply(supply, height) {
    this.supply = supply;
    const last = this.supplySeries[this.supplySeries.length - 1];
    if (!last || last.height !== height) {
      this.supplySeries.push({
        height,
        total: supply.total,
        mined: supply.mined,
        timestampMs: Date.now(),
      });
      if (this.supplySeries.length > 5000) this.supplySeries.shift();
    }
  }

  transparentVolumeGrains(action) {
    if (!action || typeof action !== 'object') return 0n;
    try {
      switch (action.type) {
        case 'transfer':
        case 'htlc_lock':
          return BigInt(action.amount ?? 0);
        default:
          return 0n;
      }
    } catch {
      return 0n;
    }
  }

  windowStats(windowMs, now = Date.now()) {
    const cutoff = now - windowMs;
    let blocks = 0;
    let transactions = 0;
    let volume = 0n;
    let txBytes = 0;

    for (const block of this.blocksByHeight.values()) {
      if ((block.timestampMs ?? 0) < cutoff) continue;
      blocks += 1;
      for (const tx of block.transactions ?? []) {
        transactions += 1;
        txBytes += tx.sizeBytes ?? 0;
        volume += this.transparentVolumeGrains(tx.action);
      }
    }

    return {
      transactions,
      transactionsPerSecond: transactions / Math.max(1, windowMs / 1000),
      blocks,
      volumeGrains: volume.toString(),
      medianTransactionFeeUsd: null,
      averageTransactionFeeUsd: null,
      hashrate: this.difficulty?.hashrate ?? null,
      indexedTransactionBytes: txBytes,
    };
  }

  /** Classify a free-text query into a block / tx / account / raw-hash lookup. */
  search(query) {
    const s = String(query ?? '').trim();
    if (!s) return { kind: 'empty' };
    if (/^\d+$/.test(s)) {
      const h = Number(s);
      return { kind: 'block', ref: h, known: this.blocksByHeight.has(h) };
    }
    if (/^0x[0-9a-fA-F]{64}$/.test(s)) {
      const lower = s.toLowerCase();
      if (this.heightByHash.has(lower)) return { kind: 'block', ref: this.heightByHash.get(lower), known: true };
      if (this.txById.has(lower)) return { kind: 'tx', ref: lower, known: true };
      return { kind: 'hash', ref: lower, known: false };
    }
    return { kind: 'account', ref: s, known: this.txIdsByAccount.has(s) };
  }

  /** Aggregate chain statistics, all derived from real indexed/observed data. */
  stats() {
    const grains = (v) => {
      try {
        return BigInt(v ?? 0);
      } catch {
        return 0n;
      }
    };
    const mined = grains(this.supply?.mined);
    const ratio = (a, b) => (b > 0n ? Number((a * 1_000_000n) / b) / 1_000_000 : 0);
    const last24h = this.windowStats(24 * 60 * 60 * 1000);
    return {
      chainId: this.chainId,
      genesisHash: this.genesisHash,
      tipHeight: this.tipHeight,
      blocksIndexed: this.blocksByHeight.size,
      transactionsIndexed: this.totalTxIndexed,
      minersObserved: this.proposers.size,
      miners: this.miners.length,
      mempoolSize: this.mempoolSize,
      supply: this.supply,
      difficulty: this.difficulty,
      allTime: {
        circulationGrains: this.supply?.total ?? null,
        marketCapUsd: null,
        marketDominance: null,
        blockchainSizeBytes: this.totalBlockBytesIndexed,
        networkNodes: this.miners.length || null,
        difficulty: this.difficulty?.sha256d ?? null,
      },
      last24h,
      mempool: {
        transactions: this.mempoolSize,
        transactionsPerSecond: null,
        outputs: null,
        feeTotalUsd: null,
        sizeBytes: null,
      },
      mintedOfCap: ratio(mined, SUPPLY_CAP_GRAINS),
      supplyCapGrains: SUPPLY_CAP_GRAINS.toString(),
    };
  }
}
