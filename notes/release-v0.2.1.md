# SOV v0.2.1 — release notes

**Consensus is UNCHANGED from v0.2.0 and v0.1.99.** Genesis
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` remains
frozen; a v0.2.1 node validates byte-identically to a v0.2.0 node. This is a
drop-in binary swap — no fork, no new deployment bit, no signaling, no data
migration, no resync.

Everything below is **node-local RPC and mempool policy**.

## What this release is for

XUS Miner has shipped a multi-block mempool backlog view since v0.1.7, and its
block-flow strip has expected an "upgraded node" template since v0.1.4. Neither
could ever render, because the RPCs they read did not exist on any node. This
release serves that data.

## New read-only RPC

- **`sov_getMempoolHistogram`** — effective-tip fee-rate buckets of the ready
  (mineable) mempool, highest first, so a client can pack them into successive
  projected blocks using the node's own `maxBlockTxs`. Bounded: the response
  carries at most a fixed number of buckets whatever the pool holds, with the
  cheapest tail merged into the last bucket. Deterministic — the shape depends
  only on pooled tips, never on a clock.

  The fee-rate key is the **absolute per-transaction effective tip**, because
  that is this node's actual auction key: `Mempool::select` orders by
  `effective_tip` and the next-block floor is the marginal `effective_tip`.
  Bucketing per byte would sort the backlog in an order the node does not use
  and would therefore mispredict inclusion. Size is not ignored — every bucket
  reports `totalBytes` and the response reports `maxBlockBytes`, so a client
  packs projected blocks against whichever limit binds first.

- **`sov_getBlockTemplate` gains `txCount` and `txIds`** — the template's
  transaction list, bounded and never silently truncated. The template `blob`
  and `nonceOffset` are untouched: miners hash that blob and mutate only the
  trailing nonce, so changing it would stop the network mining.

- **`sov_getBlockByHeight` / `sov_getBlockByHash` gain `header.hash`** — the
  block's own id (the blake3 header hash the node already computes, the same id
  `sov_submitBlock` replies with and fork choice keys on). It is content-derived
  and not part of the serialized block, so previously a client either paid a
  second `sov_getBlockDigest` round-trip or fell back to matching blocks by
  HEIGHT — and a height match cannot distinguish a block a miner produced from a
  same-height reorg replacement it did not. Serving the id lets a client prove
  identity rather than infer it.

- **Auction floors** on the fee estimate (`floorGrains`, `nextBlockFloorGrains`,
  `poolFloorGrains`) — what it actually costs to make the next block right now.

All of the above are **additive**: no existing method, field name, type,
presence, or meaning changed, so existing clients decode unchanged.

## Mempool policy

- **Queued future-nonce region.** Previously a transaction whose nonce sat
  beyond the sender's contiguous pending run was rejected outright as
  `NonceGap`, so one missing transaction stalled that account entirely and the
  sender had to resubmit. Such a transaction is now parked in a bounded queued
  region and promoted automatically when the gap fills. Admission discloses
  `queued: true`.

  Queued entries are bounded per sender and globally, are evicted on reorg or
  when the account's on-chain nonce passes them, are TTL-evicted if they never
  become promotable, never inflate the mineable count, and are never proposed in
  a block — the existing invariant that a producer never proposes a transaction
  that would be rejected for a nonce gap still holds.

  This removes head-of-line blocking. It does **not** give one account
  Bitcoin-style independent ordering: account nonces are strictly sequential by
  construction, so a sender's transactions remain a chain.

## Upgrading

Drop-in from v0.2.0. Existing shielded notes, balances, and chain data are
unaffected. Once a node runs v0.2.1, a connected XUS Miner v0.1.7 stops
reporting "HISTOGRAM UNAVAILABLE" and begins showing real backlog depth.

## Not in this release

The post-quantum shielded pool remains **dormant and incomplete**: signal bit 2
is defined but NOT armed, and there is no `ShieldedV2` action reachable on any
chain. Pool-v2 consensus work is in progress and gated behind an external audit
before it can be armed.
