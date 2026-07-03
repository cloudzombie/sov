# SOV — A Sovereign Reserve Asset

> A sovereign-grade monetary system, built in the open: pure Nakamoto proof-of-work,
> a hard 21-million cap with **no pre-mine**, ASIC-resistant mining, post-quantum
> signatures, and a shielded pool — with a second, independent client that
> re-checks the chain byte-for-byte.

SOV is a from-scratch Layer 1 written in Rust. Consensus is **only hashpower** — no
stake, no committee, no foundation switch. Every coin is mined; the supply schedule is
Bitcoin's, verbatim. The ticker shown to users is **XUS**; the chain, crates, and paths
stay `sov`.

---

## Contents

- [At a glance](#at-a-glance)
- [Consensus](#consensus)
- [The 21M economic model](#the-21m-economic-model)
- [Post-quantum & privacy](#post-quantum--privacy)
- [Architecture](#architecture)
- [Clients](#clients)
- [Build, run, mine](#build-run-mine)
- [JSON-RPC](#json-rpc)
- [Assurance](#assurance)
- [Non-negotiable rules](#non-negotiable-rules)

---

## At a glance

| | |
|---|---|
| **Consensus** | Pure Nakamoto proof-of-work; heaviest-work fork choice; 6-confirmation finality |
| **Seal** | RandomX (ASIC-resistant) on mainnet; SHA-256d for dev/test |
| **Difficulty** | Per-block LWMA-1; retargets to a 2.5-minute block time |
| **Supply** | 21,000,000 hard cap, **zero pre-mine** — every coin is mined |
| **Emission** | 12.5 XUS/block, halving every 840,000 blocks (~4-year cadence) |
| **Fees** | 100% of the coinbase **and** every fee go to the block's miner — no tax, no burn |
| **Signatures** | Hybrid Ed25519 + ML-DSA-65 (FIPS-204) |
| **Transport** | Noise + X25519 + ML-KEM-768 (FIPS-203), ChaCha20-Poly1305 |
| **Privacy** | Orchard/Halo2 shielded pool (zk-SNARK, no trusted setup) |
| **Block size** | Elastic cap: 2× the median of the last 100 blocks, 1 MiB floor / 4 MiB ceiling |

Also on-chain: native tokens (with issuer compliance policies), NFTs, SNS names,
M-of-N multisig with on-chain proposals, HTLC atomic swaps, signed swap intents, and
metered WASM contracts.

---

## Consensus

SOV is **pure Bitcoin-style proof-of-work**. There is no stake, no committee, no
quorum, and no privileged key.

- **Fork choice** is heaviest cumulative work; ties break deterministically (smaller
  block hash wins), so independent miners converge on one chain.
- **Finality** is probabilistic — a block is reported *final* at 6-confirmation depth.
- **The seal** is **RandomX** on mainnet (Monero's memory-hard, CPU-friendly PoW), so
  commodity hardware competes fairly and the chain resists ASIC capture. Mining uses
  RandomX's fast (full-dataset) mode; verification uses light mode, so non-mining nodes
  stay lean. Dev/test chains use fast **SHA-256d** so the suite mines instantly. The
  algorithm is a genesis-fixed consensus parameter — identical on every node.
- **Difficulty** retargets every block via LWMA-1 (Monero/Zcash family), tracking live
  hashrate toward the target block time without oscillation.
- **Block size** is bounded by an elastic cap that grows and shrinks with demand within
  fixed guardrails, so no miner can force the network to accept an oversized block.

Peers authenticate into the network by presenting the right `chain_id` + genesis hash
over an encrypted, post-quantum-hybrid transport, then discover the rest gossip-style. A
joining node syncs to the network tip **before** it mines, so it never mines its own fork.

---

## The 21M economic model

Bitcoin's emission, verbatim — and **no pre-mine**.

```
subsidy(height) = 12.5 XUS >> ((height - 1) / 840_000)
```

- Height 0 (genesis) mints nothing.
- The block subsidy halves every 840,000 blocks and is clamped to the room left under
  the cap, so cumulative issuance approaches — and never exceeds — **21,000,000 XUS**.
- Genesis allocates **zero** balance: the mining budget equals the full cap, so any
  pre-mined balance would fail the supply check arithmetically. Every coin enters
  through a block coinbase.
- The **entire** coinbase and **every** transaction fee are paid to the block's miner.
  There is no founder tax, no dev tax, and nothing is burned.

Balances are integers in *grains* (1 XUS = 10⁸ grains). Supply conservation is checked
after every block: `sum(balances) + shielded + escrowed == mined`.

---

## Post-quantum & privacy

- **Signatures** are hybrid **Ed25519 + ML-DSA-65** (FIPS-204): a transaction is valid
  only if *both* verify, so it stays secure as long as *either* primitive holds. The
  scheme is committed inside the signed payload, so there is no cross-scheme replay.
- **Transport** is Noise (XX) with a hybrid **X25519 + ML-KEM-768** (FIPS-203) key
  exchange and ChaCha20-Poly1305 — encrypted and post-quantum from the first byte.
- **Privacy** is an Orchard/Halo2 **shielded pool** (zk-SNARK, no trusted setup) with a
  de-shield drain limiter as defense-in-depth. The shielded pool is *not* post-quantum
  (Halo2/Pallas) — this is disclosed honestly; transparent funds are unaffected either way.

---

## Architecture

A layered workspace of **20 crates** under [`chain/crates/`](chain/crates), plus the
desktop station, the SDK, and the explorer.

| Layer | Crates | Role |
|---|---|---|
| **Foundations** | `primitives` · `crypto` · `types` · `state` · `mempool` | Amounts, hashing, keys, wire types, the Sparse-Merkle-Tree world state |
| **Protocol** | `pow` · `mining` · `chain` · `verify` · `node` | RandomX/SHA-256d seal, difficulty & emission, fork choice & import, invariant checks, the node engine |
| **Execution & privacy** | `runtime` · `vm` · `shielded` | The state-transition function, the metered WASM VM, the zk shielded pool |
| **Assets & interop** | `compliance` · `intents` · `reserve` · `governance` | Token compliance policies, signed swap intents, reserve modeling, miner-signaled upgrades |
| **Interface** | `network` · `rpc` · `wallet` | P2P transport, JSON-RPC + daemon, HD wallet |

State lives in a Sparse Merkle Tree: each feature commits to its own domain-separated,
absent-when-empty slot, so adding a feature never changes the state root of a chain that
doesn't use it. The encoding is Borsh — deterministic and length-prefixed — so two
correct nodes on any platform compute identical block hashes and state roots.

---

## Clients

- **`sov-station`** ([`node/`](node)) — the native desktop wallet + mining node
  (eframe/egui). Generate/import wallets, run an in-process node, and mine to your
  wallet on testnet or mainnet, all from one window.
- **Block explorer** ([cloudzombie/sov-explorer](https://github.com/cloudzombie/sov-explorer)) —
  its own project. Indexes a live node's RPC (with a seamless testnet/mainnet switch) and
  serves REST + GraphQL + a WebSocket feed + a web UI; nothing is simulated.
- **TypeScript SDK** ([`sdk/`](sdk)) — an *independent second client*. It re-derives
  block hashes, transaction roots, and the emission schedule from raw bytes with no
  shared code, and re-executes the transparent state-transition function (transfers,
  vesting, HTLCs, native tokens) to confirm the node's state root byte-for-byte. Actions
  that need an audited external engine (WASM, zk) are reported as requiring delegated
  verification rather than mis-executed.

---

## Build, run, mine

Requires a recent stable Rust toolchain and `cmake` + a C++ compiler (for RandomX).

```sh
# From chain/ — builds sov-rpcd, sov-testnet, sov-wallet, sov-rpc-miner, sov-katgen
cargo build --release -p sov-rpc --bins
export PATH="$PWD/target/release:$PATH"

# Whole-workspace tests
cargo test --workspace
```

**A local devnet on one machine:**

```sh
sov-testnet gen    --miners 2 --out ./tn   # mint keys + genesis + per-node configs
sov-testnet up     --out ./tn              # launch node-1 (seed) + node-2 (peer)
sov-testnet status --out ./tn              # height / head / final-depth / balances
sov-testnet down   --out ./tn
```

**The desktop station** (wallet + in-process miner):

```sh
cargo run --manifest-path node/Cargo.toml
```

**A public seed node** (headless, under systemd) and **joining an existing network** are
covered in [`chain/testnet/RUNBOOK.md`](chain/testnet/RUNBOOK.md).

**Binaries** (`chain/crates/rpc/src/bin/`): `sov-rpcd` (the long-running node daemon),
`sov-testnet` (mint/launch/monitor a network), `sov-wallet` (transfers, balances,
keygen), `sov-rpc-miner` (mine against a node's RPC), `sov-katgen` (emit cross-impl
known-answer vectors).

---

## JSON-RPC

A node exposes an unauthenticated JSON-RPC surface (keep it on loopback or firewalled;
it only reads state and submits already-signed transactions — it never holds keys).

```sh
curl -s -X POST http://127.0.0.1:8645 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"sov_health","params":[]}'
```

Selected methods:

| Group | Methods |
|---|---|
| Chain | `sov_health` · `sov_chainId` · `sov_getHeight` · `sov_getHead` · `sov_getStateRoot` · `sov_getDifficulty` · `sov_getSupply` · `sov_getMintReward` |
| Blocks & txs | `sov_getBlockByHeight` · `sov_getBlockByHash` · `sov_getBlockDigest` · `sov_getReceipt` · `sov_getBlockReceipts` · `sov_getConfirmations` · `sov_isFinal` · `sov_submitTransaction` · `sov_estimateFee` |
| Accounts | `sov_getAccount` · `sov_getBalance` · `sov_getNonce` |
| Assets & names | `sov_listTokens` · `sov_getTokenInfo` · `sov_getTokenBalances` · `sov_listNfts` · `sov_getNft` · `sov_resolveName` · `sov_listNames` |
| Multisig & swaps | `sov_getMultisigProposals` · `sov_getHtlc` · `sov_getShieldedInfo` |
| Network | `sov_getPeerInfo` · `sov_getMiners` · `sov_getMempoolSize` |

---

## Assurance

A reserve asset cannot be "probably correct." SOV is checked several independent ways:

- **Exact-integer invariants** — supply conservation, per-asset conservation, and the
  no-pre-mine bound are enforced in consensus with checked 128/256-bit integer math; a
  block that would break one is rejected.
- **Deterministic replay** — every block is Borsh-encoded and `fsync`'d before it's
  acknowledged, so a node replays its log on boot and resumes bit-for-bit; a reorg
  disconnects in O(depth) via an in-memory undo log.
- **Known-answer vectors** — `sov-katgen` emits byte-exact vectors (encoding, PoW,
  emission, state, and full STF scenarios) that the TypeScript SDK re-derives
  independently, catching any cross-implementation divergence.
- **Property tests & fuzzing, reproducible builds, and CI** across Linux, macOS, and
  Windows keep the three platforms consensus-identical.

---

## Non-negotiable rules

- **No hand-rolled cryptography.** Signatures, hashes, KDFs, the zk system, and RandomX
  all come from audited, standard implementations.
- **No pre-mine, no tax, no burn.** Every coin is mined; miners keep 100% of coinbase
  and fees.
- **Only hashpower decides.** Upgrades are miner-signaled (BIP-9/BIP-8 over header
  bits) — not holders, not a foundation.
- **No fabricated data.** The explorer, dashboards, and tools read real chain state.

---

*SOV is experimental software. Run it, read it, mine it — and verify everything yourself.*
