# Sovereign Block Explorer

A block explorer for **Sovereign**. It indexes a live Sovereign node over JSON-RPC
and serves a REST API, a GraphQL endpoint, a WebSocket live feed, and a web UI.

It is its own project, separate from the Rust chain workspace, and has **zero
runtime dependencies** — only the Node.js standard library. Everything it shows
is **real chain data read from a node**; nothing is simulated or fabricated. When
the indexer is empty, the UI is empty.

## Architecture

```
 Sovereign node ──JSON-RPC──▶ Indexer ──▶ Store ──▶ REST / GraphQL / WebSocket ──▶ Web UI
```

| File | Role |
|---|---|
| `src/rpc.js` | JSON-RPC 2.0 client for the node. |
| `src/indexer.js` | Backfills from genesis, follows the head, refreshes finality + supply/miners. |
| `src/store.js` | In-memory, ring-capped index with search indices (block height/hash, tx id, account). |
| `src/rest.js` | REST endpoints over the store. |
| `src/graphql.js` | A compact, dependency-free GraphQL engine (lexer + parser + executor). |
| `src/ws.js` | A hand-rolled RFC 6455 WebSocket hub for the live feed. |
| `src/server.js` | `std`-http server wiring REST + GraphQL + WS + static UI, running the indexer. |
| `web/` | The self-contained single-page UI (no framework, no CDN). |

The store is a derived, re-buildable view: the node is always the source of
truth, so a restart simply re-indexes.

## Run it

Requires **Node.js ≥ 18** and a Sovereign node to index.

### 1. Start a node (a local devnet)

Generate a devnet, then launch your local Sovereign RPC daemon from the chain workspace:

```bash
node devnet/gen-devnet.mjs                       # writes chain-spec / config / keystore
cd ../chain
<sovereign-rpc-daemon> \
  ../explorer/devnet/node-config.json \
  ../explorer/devnet/chain-spec.json \
  ../explorer/devnet/keystore.json                 # JSON-RPC on 127.0.0.1:8645
```

Submit a real transfer so the node produces a block (the daemon produces blocks
when the mempool is non-empty):

```bash
<sovereign-wallet> 127.0.0.1:8645 \
  transfer 0202…02 usa.reserve.sovereign ecb.reserve.sovereign 100
```

### 2. Start the explorer

```bash
cd ../explorer
SOVEREIGN_RPC=http://127.0.0.1:8645 PORT=8730 npm start
# open http://127.0.0.1:8730
```

`SOVEREIGN_RPC` (default `http://127.0.0.1:8645`) and `PORT` (default `8730`) are also
accepted as positional args: `node src/server.js <rpc_url> <port>`.

## API

### REST

| Endpoint | Returns |
|---|---|
| `GET /api/status` | Chain id, height, supply, difficulty, mined-of-cap, and Blockchair-style explorer stats. |
| `GET /api/blocks?limit=N` | Recent blocks (newest first). |
| `GET /api/block/:heightOrHash` | One block with its transactions, roots, and finality. |
| `GET /api/tx/:id` | One transaction. |
| `GET /api/account/:id` | Live account state (from the node) + indexed transaction history. |
| `GET /api/supply` | Total / mined supply (decimal grains). |
| `GET /api/observed-miners` | Observed block miners in the indexed window. |
| `GET /api/validators` | Deprecated compatibility alias for observed miners. |
| `GET /api/miners` | Proof-of-work miner registry. |
| `GET /api/analytics` | Aggregate stats + the live-sampled supply series. |
| `GET /api/search?q=` | Classify a query into block / tx / account. |

### GraphQL

`POST /graphql` with `{ "query": "..." }` (or a raw query string body). Example:

```graphql
{
  head { height hash txCount final }
  supply { total mined }
  account(id: "usa.reserve.sovereign") { balance nonce }
}
```

Root fields: `head`, `block(height|hash)`, `transaction(id)`, `account(id)`,
`supply`, `stats`, `observedMiners`, `miners`, `search(q)`. The engine supports
queries with arguments, nested selections, and aliases. Mutations, variables,
fragments, and directives are intentionally out of scope (the explorer is
read-only).

### WebSocket

Connect to `ws://<host>/ws`. The server pushes `{type:"block", …}` and
`{type:"tx", …}` messages as the indexer ingests them. `devnet/ws-check.mjs` is a
small smoke-test client.

## A note on the node RPC

The explorer relies on one additive, non-breaking node method,
**block digest by height**, which returns a block's hash and its
transactions' canonical ids. These are computed from content (Blake3 over Borsh)
and are not part of the serialized block, so a client cannot recompute them
without re-implementing the chain's hashing — hence the node exposes them.

## Hard rule

Like the rest of Sovereign, the explorer shows **only what it reads from a real node** —
no fabricated blocks, sample transactions, or placeholder accounts. When the node
is unreachable or lacks the data asked for, the explorer says so.

## Tests

```bash
npm test     # node --test — store/search, GraphQL engine, normalization (no node needed)
```

The full stack is additionally proven end-to-end against a live devnet: a real
signed transfer is indexed and served correctly over REST,
GraphQL, and the WebSocket feed.

## Related

- [`../chain/`](../chain/README.md) — the Sovereign blockchain (Rust workspace); the explorer's only upstream.
- [`../sdk/`](../sdk/README.md) — typed client.
- [`../dashboard/phases.json`](../dashboard/phases.json) — the canonical roadmap.
