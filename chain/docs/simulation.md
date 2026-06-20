# SOV Live Simulation — Run a Real Multi-Node Network From Your Laptop

One command boots a **real** 3-validator SOV network on loopback, drives
**real signed traffic** of every kind the chain supports, streams the live
state of every node, and dumps **every raw artifact** — keys, wire-format
transactions, blocks, contract bytecode — to disk where you can open them.
Nothing is simulated *about* the chain: these are the production binaries,
real entropy keys, real Noise+ML-KEM encrypted P2P, real BFT finality, real
SHA-256d proof-of-work. "Simulation" refers only to the traffic driver.

```sh
cd chain
cargo build --release -p sov-rpc --bins
./target/release/sov-testnet sim --out simnet --rounds 4
```

## What you watch happen, live

Per round, the driver submits and the console streams per-node
height / finality / mempool plus balances:

| Lane | What actually happens |
|---|---|
| `transfer` | alice → bob, 5 SOV, hybrid (Ed25519+ML-DSA-65) signed |
| `token-issue` / `token-transfer` | alice issues 1,000 USD1 (issuer-bound asset id), then moves it |
| `htlc-lock` / `htlc-claim` | a real SHA-256 hashlock escrow, claimed by revealing the preimage on-chain |
| `intent-offer` / `intent-settle` | alice signs a declarative swap offer **off-chain**; bob fills it atomically on-chain (USD1 ↔ SOV) |
| `deploy` / `call` | a real WASM contract (bytecode on disk) deployed and called with calldata; it stores, emits an event, returns |
| `pow-mine` | real SHA-256d proof-of-work over RPC — `miner.actor.sov` does not exist at genesis and bootstraps itself with its first mint, then earns the coinbase every round |

The run ends with an **inclusion report**: every submitted transaction id is
checked against the committed blocks — the claim is inclusion-proven, not
assumed (the command fails if anything went missing).

## The raw files (open them)

Everything below is written under `--out` (default `simnet/`):

| Path | What it is |
|---|---|
| `chain-spec.json` | The genesis: every account, balance, stake, and full `hybrid65:0x…` public key |
| `sim-actors.json` | **The Ethereum-keystore analog**: alice/bob/carol with their real 32-byte seeds (hex) and hybrid public keys. Whoever holds a seed controls the account. Plaintext by design here; `encrypt-keystore` exists for anything real |
| `node-K/keystore.json` | Each validator's signing seed + scheme |
| `node-K/data/blocks.log` | The raw append-only block log: `[len][BLAKE3 checksum][Borsh block]` records, fsynced |
| `node-K/data/approvals.log` | The raw finality evidence (signed BFT approvals) |
| `artifacts/contract.wat` / `.wasm` / `.hex` | The contract source and its **real compiled bytecode**, raw and hex |
| `artifacts/txs/NNN-<kind>-<txid>.json` | **Every signed transaction in wire JSON** — signer, full hybrid public key, nonce, action, dual signature |
| `artifacts/txs/NNN-intent-offer.json` | The off-chain signed swap offer exactly as the owner authorized it |
| `artifacts/blocks/block-NNNNN.json` | Every committed block: header (roots, proposer, version bits) + full transactions |

## The live web view

The nodes keep running after the sim. Point the explorer (zero-dependency
Node project at `explorer/`) at any of them:

```sh
cd explorer
SOV_RPC=http://127.0.0.1:8645 PORT=8730 node src/server.js
# open http://127.0.0.1:8730  — blocks, txs, accounts, validators, supply,
# REST + GraphQL + a WebSocket live feed pushing new blocks as they commit.
```

## Continuous production, the shielded round-trip, and the heartbeat

**The chain advances like Bitcoin's: continuously.** The scheduled proposer
produces a block every `block_time_ms` (1s in the sim), **empty or not** — an
empty block is a normal block, carrying the timestamp/difficulty machinery
forward. (This also means exactly one node produces per height — the
schedule, not a race.) Watch heights climb with zero traffic submitted.

```sh
# A REAL zero-knowledge shielded round-trip on the running net: shield 25 SOV
# into the pool (real Halo2 proof), then de-shield it back (a second real
# proof). Both bundles land as artifacts/txs/shield-*.json / deshield-*.json —
# the bundle bytes ARE the proofs.
./target/release/sov-testnet shielded --out simnet --sov 25

# Keep visible VALUE flowing too (the chain ticks regardless): a real 0.01-SOV
# transfer every 3s plus a real PoW mint every 5th tick. Ctrl-C stops it.
./target/release/sov-testnet heartbeat --out simnet --interval-ms 3000
```

Useful while it runs:

```sh
./target/release/sov-testnet status --out simnet     # heights/finality/balances
curl -s http://127.0.0.1:8730/api/status             # indexed chain summary
./target/release/sov-testnet down --out simnet       # stop the network
```

## Honest notes

- The seeds in `sim-actors.json` and `keystore.json` are real signing keys in
  plaintext — a deliberate choice so you can SEE them, never a mainnet
  practice (`sov-testnet encrypt-keystore` is the sealed path).
- Receipts (contract return data/events) are committed under each block's
  `receipts_root` and re-derived by every node on import; the RPC surface
  does not yet expose individual receipts — the block artifacts carry the
  transactions, and the roots prove the outcomes.
- Three validators on one laptop is a topology simulation, not a latency or
  adversarial-network one; the cross-machine (Mac + Windows) bring-up is the
  next operational step and uses the exact same tooling.
