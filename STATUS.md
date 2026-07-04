# SOV — Project Status

_Ticker **XUS**. Pure Nakamoto proof-of-work, post-quantum, privacy-enabled Layer-1 in Rust._
_Last updated: 2026-07-04._

## 🎇 Mainnet is LIVE

Fair-launch genesis at **midnight, July 4 2026 CDT** (America's 250th birthday). No pre-mine — every coin mined.

| | |
|---|---|
| **Genesis hash** | `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` — **frozen, never to change** |
| **Genesis timestamp** | `1783141200000` (2026-07-04 00:00:00 CDT) — gated the launch (no valid block until midnight) |
| **First block** | mined by an operator laptop at 00:05:35 CDT (not the seed, not a public wallet) |
| **Seal** | RandomX (ASIC-resistant) · **Supply** 21,000,000, zero pre-mine · **Emission** 12.5 XUS/block, halving every 840,000 (~4 yr) · **Block time** 2.5 min (LWMA) · 100% of coinbase + fees to the miner |

## Live infrastructure

| Service | URL / address | Host |
|---|---|---|
| **Mainnet seed** (relay-only) | `64.225.10.34:9645` (P2P) · `:8645` (RPC) | DO droplet `582172987`, s-1vcpu-2gb |
| **Testnet seed** | `159.203.109.204:9645` · `:8645` | DO droplet `581931537` |
| **Block explorer** | **https://sovxus.org** (testnet + mainnet) | DO droplet `581936353`, nginx + Let's Encrypt |
| **Gotomarket site** | **https://sovxus.com** | Vercel (repo `cloudzombie/gotomarket`) |
| **Exchange one-pager** | **https://sovxus.com/onepage/** | bundled in the gotomarket build |

Both seeds are **relay/bootstrap** nodes (like Bitcoin's DNS seeds), not the chain — if a seed dies the chain continues; every miner holds the full history. Adding more seeds for bootstrap resilience is a networking-only change (genesis-safe).

## Components

- **Chain** — `chain/` (Rust workspace, 20 crates). Consensus frozen: emission, difficulty, gas, elastic block size, all borsh encodings, `DATA_SCHEMA_VERSION=1`.
- **sov-station** — `node/` (eframe/egui desktop wallet + mining node). Embeds the chain specs at build time; released as macOS DMG / Windows zip / Linux tarball.
- **SDK** — `sdk/` (TypeScript, zero-dep) — independent second client (KAT-verified: block hashes, emission, STF).
- **Explorer** — separate repo `cloudzombie/sov-explorer` (Node, multi-network). Pages to genesis, live WS updates (no refresh), visible timestamps.
- **Gotomarket** — separate repo `cloudzombie/gotomarket` (Vite/React on Vercel).
- **One-pager** — `~/github/onepage/` (self-contained HTML, engraved reserve-note design).

## Latest releases (tags `vX-testnet`)

- **v0.1.72** — multi-note de-shield (wallet combines notes in one Orchard bundle; genesis-safe).
- **v0.1.71** — mainnet de-shield limit → 21,000,000 SOV (runtime spec override; genesis unchanged).
- **v0.1.70** — mainnet launch genesis (July-4 timestamp) + relay-only seed.
- **v0.1.69** — hardcoded the public testnet seed into `testnet-1.json`.

## Non-negotiable rules

- **The genesis hash (`cb0272ff` mainnet / `4d7d9123` testnet-1) must never change.** No rollback; chain state is always retained. Consensus *rules* can change via coordinated upgrade (e.g. the de-shield limit) as long as the genesis block/state — and thus the hash — is untouched, verified by the frozen-genesis tests.
- No pre-mine, no founder cut, no tax, nothing burned.
- Honesty: mainnet is new and **unaudited**; external audit + public bug bounty + more hashrate are the road to hardening.

## Open / recommended

- External audit + public bug bounty (pre-code-freeze maturity).
- 2–3 additional mainnet seeds (bootstrap resilience).
- Deferred perf: incremental reorg (O(N) rebuild-from-genesis), batch×100 ledger-scan RPC amplification.
