# SOV — Sovereign Digital Reserve Asset (chain)

[![CI](https://github.com/sov/chain/actions/workflows/ci.yml/badge.svg)](../.github/workflows/ci.yml)

The Rust implementation of the **SOV** layer-1 blockchain.

SOV is a sovereign reserve-asset L1: **no premine, no investor allocation** —
every coin is mined. Consensus is **pure Nakamoto proof-of-work** — Bitcoin's
model, verbatim: blocks are sealed by proof of work, the heaviest-work chain
wins, finality is confirmation depth, and the block **coinbase is the only
issuance path** (genesis supply is exactly zero). The entire coinbase **and** every
fee go to the block's miner — no tax, no burn, a pure Bitcoin-style fair launch;
nothing is pre-mined and the 21M cap is absolute. The mainnet
seal is **RandomX** (Monero's memory-hard,
CPU-optimized algorithm) so commodity machines — **Apple M-series included** —
mine fairly and the chain resists ASIC capture. On top of that sound-money base
the chain ships, as native primitives: a Zcash-grade **shielded pool** (Halo2,
no trusted setup), **post-quantum-native** keys + transport, trustless **HTLC
atomic swaps**, native **assets** with issuer compliance, **atomic intent
settlement**, and a deterministic WebAssembly **smart-contract** runtime.

There is **no proof-of-stake, no validator committee, and no BFT** of any kind —
security is hashpower. The honest framing: the cypherpunk reserve-asset vision
done right — sovereign-grade, auditable, no hand-rolled cryptography, no
fabricated data anywhere.

---

## Status

| Field | Value |
|---|---|
| Workspace | 20 active crates (Cargo, edition 2021, MSRV **1.85**) |
| Guest workspace | `chain/contracts/` — separate `no_std` / `wasm32` workspace, excluded from the host build |
| Tests | All passing (see `dashboard/status.js` for the latest count — `chain.tests`) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` clean |
| Format | `cargo fmt --all -- --check` clean |
| `unsafe` | Forbidden via `#![forbid(unsafe_code)]` on every crate, also enforced as a per-crate `[lints.rust] unsafe_code = "forbid"` |
| CI | Lint on Linux + build/test matrix on Linux, macOS, Windows ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) |
| Roadmap | Tracked in [`../dashboard/phases.json`](../dashboard/phases.json), rendered by [`../dashboard/index.html`](../dashboard/index.html) |

> `dashboard/status.js` is regenerated from real `cargo test --workspace`
> output and a recursive Rust LOC scan. Treat it as the source of truth for
> headline numbers; do not paraphrase numbers that may have drifted.

---

## Quick start

Prereqs: Rust **stable ≥ 1.85**, `git`. The chain is pure Rust with std-only
networking; no external system libraries are required.

```sh
git clone <repo>
cd sov/chain

# Full workspace test + lint cycle.
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Single-node transfer devnet — boots a real chain, signs real
# transactions, prints real hashes and balances.
cargo run -p sov-node

# Real CPU SHA-256d miner — does genuine PoW against the live difficulty,
# mints under the 21M cap, writes your real session to
# `../dashboard/chain-status.js`. Release mode matters: mining is real work.
cargo run --release -p sov-node --bin sov-miner            # forever
cargo run --release -p sov-node --bin sov-miner 5          # mine 5 blocks
```

CI runs the lint job on `ubuntu-latest` and then a build+test matrix on
`ubuntu-latest`, `macos-latest`, and `windows-latest` on every push — clients
are proven cross-platform on every commit.

---

## The 21M economic model

| Constant | Value | Source |
|---|---|---|
| `DECIMALS` | `8` | [`crates/primitives/src/amount.rs`](crates/primitives/src/amount.rs) |
| `GRAINS_PER_SOV` | `100_000_000` | same |
| `MAX_SUPPLY_SOV` | `21_000_000` | same |
| `MAX_SUPPLY_GRAINS` | `2_100_000_000_000_000` | same |

All amounts are integer `u128` counts of the smallest indivisible unit, the
**grain** — exactly Bitcoin / Zcash precision (`1.00000000`). No floating
point ever touches a balance, and every arithmetic operation is checked.

Emission is **Bitcoin's, verbatim**, and there is exactly **one** issuance
source — the block coinbase. There is no staking, no second mint, and **no
pre-mine**: on mainnet the mining budget IS the full 21M cap, so genesis
arithmetically rejects any funded balance or vesting grant — genesis supply is
exactly zero and every coin is mined.

| Parameter | `mainnet_like()` value | Source |
|---|---|---|
| Block subsidy (height 1) | `12.5` XUS | [`MiningPolicy`](crates/mining/src/lib.rs) |
| Halving interval | `840_000` blocks (~4 years) | same |
| Target block time | `150_000` ms (2.5 minutes) | same |
| Mining budget (`mining_budget_grains`) | the FULL `21_000_000` XUS cap | same |
| Genesis allocation | `0` (any allocation breaches the cap) | [`GenesisConfig::build`](crates/chain/src/genesis.rs) |

The coinbase is keyed on **block height** (Bitcoin's halving rule at Zcash's
cadence): [`MiningPolicy::reward_at(height, mined)`] pays
`12.5 >> ((height − 1) / 840_000)` XUS, clamped to the room left in the mining
budget. Because `base × interval = 10,500,000 XUS` (half the cap), the geometric
series sums to **20,999,999.9076 XUS** — strictly under the 21M cap — so the
budget backstop is never actually reached; after the subsidy decays the chain
runs on fees. At the 2.5-minute cadence a halving falls roughly every 4 years,
and half of all SOV is mined in the first ~4 years. Every coinbase **and** every
fee goes **entirely to the block's miner** — no tax, no burn (pure Nakamoto).

Emission is driven by one monotonic, **state-root-committed** counter,
`mined_emitted` ([`crates/state/src/ledger.rs`](crates/state/src/ledger.rs)) —
first-class consensus state because it cannot be recovered from balances once
minted coins move. With checked `Balance` arithmetic throughout, total supply is
**`supply == genesis + mined`** and `≤ MAX_SUPPLY_GRAINS` by
construction — and on mainnet `genesis == 0`.

---

## Crate map (20 active crates)

The host workspace is split by responsibility, bottom-up. Each crate's
description below is its real `Cargo.toml` `description` line — verifiable
with `grep -A1 ^name crates/*/Cargo.toml`.

### Foundations

| Crate | Purpose |
|---|---|
| [`sov-primitives`](crates/primitives/src/lib.rs) | Core value types for the SOV protocol: hashes, account ids, balances, heights. |
| [`sov-crypto`](crates/crypto/src/lib.rs) | Signing and authenticated data structures: Ed25519 keys/signatures and Merkle roots. |
| [`sov-types`](crates/types/src/lib.rs) | Core ledger types: transactions, blocks, and receipts. |
| [`sov-state`](crates/state/src/lib.rs) | Authenticated world state: a Sparse Merkle Tree, accounts, and the ledger over them. |
| [`sov-wallet`](crates/wallet/src/lib.rs) | Key management and transaction building: holds keypairs and constructs signed transactions. |

### Protocol (Nakamoto proof-of-work)

| Crate | Purpose |
|---|---|
| [`sov-runtime`](crates/runtime/src/lib.rs) | The execution layer: applies the coinbase + transactions to the ledger, meters gas, and produces receipts. |
| [`sov-mempool`](crates/mempool/src/lib.rs) | The transaction pool: validated, nonce-ordered pending transactions awaiting inclusion. |
| [`sov-pow`](crates/pow/src/lib.rs) | Proof-of-work primitives: the **RandomX** (mainnet) / SHA-256d (dev) seal as a genesis-fixed `PowAlgo`, 256-bit difficulty `Target`s with Bitcoin's compact **nBits** codec, and meets-target verification. |
| [`sov-mining`](crates/mining/src/lib.rs) | Mining policy: the difficulty target, **height-keyed coinbase emission** (12.5 SOV halving every 840,000 blocks, budget-capped, no pre-mine), and cumulative proof-of-work (`Work`) accounting for fork choice. |
| [`sov-network`](crates/network/src/lib.rs) | Peer-to-peer layer: Noise-encrypted gossip transport (blocks, transactions) with channel binding and DoS guards. |
| [`sov-node`](crates/node/src/lib.rs) | The node: drives mempool, continuous mining, and block import into a running chain; ships a local devnet binary. |
| [`sov-chain`](crates/chain/src/lib.rs) | Genesis construction + the validated block-import state machine: **heaviest-work fork choice with reorg**, confirmation-depth finality, and the seal/difficulty rules tying state, execution, and consensus together. |

### Privacy

| Crate | Purpose |
|---|---|
| [`sov-shielded`](crates/shielded/src/lib.rs) | Zcash-grade shielded pool: Orchard / Halo2 zero-knowledge notes with **no trusted setup**, a committed note-commitment tree + nullifier set, a proven supply turnstile, and a de-shield rate limiter. |

### Smart contracts, assets & interop

| Crate | Purpose |
|---|---|
| [`sov-vm`](crates/vm/src/lib.rs) | WebAssembly smart-contract runtime: a deterministic `wasmi` interpreter with gas-metered execution and host storage (ABI v2: calldata, events, token host functions). |
| [`sov-compliance`](crates/compliance/src/lib.rs) | Issuer-sovereign compliance for **native assets**: regulator freeze, allow/deny counterparty controls, and spend-velocity limits — applied to tokens only; native SOV is never regulable. |
| [`sov-intents`](crates/intents/src/lib.rs) | Atomic intent settlement: a user signs one intent; solvers settle it on-chain over native SOV and on-chain tokens. (Cross-chain is the trustless HTLC atomic-swap path, in `sov-types`/`sov-runtime`.) |

### RPC

| Crate | Purpose |
|---|---|
| [`sov-rpc`](crates/rpc/src/lib.rs) | JSON-RPC server for a SOV node: a real std-only HTTP/1.1 + JSON-RPC 2.0 server over a shared `Node` (query height/supply/accounts/blocks/state, difficulty, miner stats, `getConfirmations`/`isFinal`, and `submitTransaction`) with a worker pool and graceful shutdown. Also ships the `sov-katgen` KAT-vector generator the JS/TS SDK consumes. |

### Governance & reserve

| Crate | Purpose |
|---|---|
| [`sov-governance`](crates/governance/src/lib.rs) | Bitcoin-style, miner-signaled governance: the BIP-9 version-bits activation state machine plus BIP-8 mandatory activation. Hashpower decides upgrades — there is no stake- or holder-weighted vote. |
| [`sov-reserve`](crates/reserve/src/lib.rs) | Sovereign reserve modeling: deterministic emission / float / lock projections from the real mining policy under explicit, labeled assumptions (every figure tagged Real vs Assumed). |

### Verification

| Crate | Purpose |
|---|---|
| [`sov-verify`](crates/verify/src/lib.rs) | Verification & validity assurance: exact-integer protocol invariants (21M cap, value conservation `supply == genesis + mined`, no unauthorized mint, per-asset conservation), deterministic replay + cross-node state-root agreement, heaviest-work fork-choice chaos/fault tests, state-transition conformance, known-answer-test vectors, and property-based tests. See [`docs/state-transition.md`](docs/state-transition.md). |

### Guest (separate workspace)

[`chain/contracts/`](contracts/README.md) is a **separate** `no_std`,
`wasm32-unknown-unknown` workspace, excluded from the host build via
`exclude = ["contracts"]` in [`Cargo.toml`](Cargo.toml). It contains:

- **`sov-sdk`** — the guest SDK contracts are written against: safe wrappers
  over the host ABI (`get`, `set`, `current_height`), a bump allocator, and a
  panic handler.
- **`counter`** — an example contract exporting `call() -> i32`.

Built artifact: `target/wasm32-unknown-unknown/release/counter.wasm`, which
is committed as [`crates/vm/tests/counter.wasm`](crates/vm/tests/counter.wasm)
and exercised end-to-end by `sov-vm`'s integration test.

---

## Architecture walkthrough — how a transaction flows

The chain separates *producing* a block from *importing* one, and routes both
through the same validation. A node validates its own proposed blocks
exactly as it validates a peer's — there is no trusted path. (See the
module-level doc-comment at the top of
[`crates/chain/src/blockchain.rs`](crates/chain/src/blockchain.rs).)

1. **Submission.** A client uses `sov-wallet` to build and sign a
   [`SignedTransaction`](crates/types/src/lib.rs), then submits it. The
   `sov-mempool` rejects it cheaply if the signature does not verify, the
   nonce is stale, or the pool is full; it does **not** check balances —
   affordability is the execution layer's call.
2. **Block production (mining).** Any node may mine — there is no proposer
   schedule and no permission. `Blockchain::produce_block` pulls a
   nonce-ordered batch from the pool, applies the **coinbase first** then the
   transactions via [`sov_runtime`](crates/runtime/src/execution.rs), commits
   the resulting state, and **grinds the header's nonce** until its seal
   (RandomX on mainnet, SHA-256d on dev) meets the branch-required difficulty.
   The header commits to `state_root`, `tx_root`, `receipts_root`, the
   coinbase recipient (`proposer`), and the difficulty (`bits`, Bitcoin's nBits).
3. **Import.** `Blockchain::import_block` runs the **same** validation on
   every block, peer or self-produced: it checks the committed difficulty and
   proof of work, then re-executes the coinbase + every transaction against a
   *clone* of the ledger and refuses to commit unless the recomputed
   `state_root` and `receipts_root` match the header. A block can never install
   state it didn't legitimately compute.
4. **Fork choice & finality.** The active chain is always the one with the most
   cumulative **work**; a strictly heavier side branch triggers a **reorg**
   (replayed from the genesis ledger and adopted only if valid end-to-end, so an
   invalid heavier branch can never displace a valid head). Finality is
   **confirmation depth**: a block is reported final once buried 6 deep
   (Bitcoin's convention), probabilistic and a pure function of chain state.
   There are no validators, votes, or slashing.

The execution function `apply_transaction`
([`crates/runtime/src/execution.rs`](crates/runtime/src/execution.rs))
enforces, in order:

1. **Authentication** — Ed25519 signature must verify against the tx's pubkey.
2. **Authorization** — that pubkey must be the signer's registered key.
3. **Ordering / replay protection** — nonce must equal the signer's current.
4. **Execution** — once admitted, the nonce is consumed even if the inner
   action then fails (e.g. insufficient funds), so a rejected payment still
   cannot be replayed.

A transfer only ever moves value between existing balances; nothing in
execution mints SOV, so total supply is conserved by construction and the
21M cap holds inductively over every block.

---

## State model

[`Ledger`](crates/state/src/ledger.rs) keeps two synchronized views of the
same data:

- a `BTreeMap<AccountId, Account>` — the queryable state store; and
- a [`SparseMerkleTree`](crates/state/src/smt.rs) — the authenticated
  commitment, yielding a 32-byte `state_root` and Merkle proofs.

Every mutation updates both, so the root always reflects the stored state.
Per-contract key/value storage is also committed under domain-separated SMT
slots, so contract state is part of the authenticated `state_root`.

An `Account` carries: nonce, liquid balance, vesting lock + unlock-height
metadata, the controlling public key, and optional contract code
(`Option<Vec<u8>>`). (There is no `staked` balance — SOV has no proof-of-stake.) `Ledger::save` / `Ledger::load` persist the full
state and reproduce the exact `state_root` on reload — snapshot-based today;
an incremental on-disk backend (e.g. RocksDB) is a future optimization, not
a correctness gap.

---

## Proof-of-work — Nakamoto consensus

PoW **is** the consensus (Bitcoin's model, verbatim): blocks are sealed by
proof of work, the heaviest-work chain wins, finality is confirmation depth, and
the block coinbase is the only issuance path. There is no proof-of-stake, no
committee, and no second issuance mechanism.

- **Seal algorithm — RandomX (mainnet).** The header seal is a genesis-fixed
  [`PowAlgo`](crates/pow/src/seal.rs): **RandomX** (Monero's memory-hard,
  CPU-optimized, ASIC-resistant PoW) on mainnet — so commodity machines, Apple
  M-series included, mine fairly and the chain resists ASIC capture — verified
  via the audited [`randomx-rs`](https://crates.io/crates/randomx-rs) reference
  bindings, keyed by the genesis hash. `Sha256d` (Bitcoin's double-SHA-256) is
  selectable for fast dev/test chains. The difficulty/work/fork-choice stack is
  hash-agnostic.
- **Committed difficulty (Bitcoin's nBits).** Each header carries its difficulty
  in compact `nBits`; consensus rejects any header whose bits differ from the
  retarget-required value, then checks the seal against the decoded
  [`Target`](crates/pow/src/target.rs).
- **Diminishing capped emission (no pre-mine).**
  [`MiningPolicy::reward_at`](crates/mining/src/lib.rs) pays a 12.5-XUS coinbase
  halving every 840,000 blocks (~4 years at 2.5-minute blocks — Zcash's cadence),
  clamped to the mining budget; on mainnet the budget IS the full 21M
  cap, so genesis allocates
  nothing — every coin is mined.
- **Real difficulty retargeting.** `Blockchain` retargets once per 2016-block
  epoch from the branch's actual-vs-expected timespan (Bitcoin-style, 4×-clamped).

Run a real CPU miner against the live difficulty:

```sh
cargo run --release -p sov-node --bin sov-miner [blocks]
```

The miner mints under the cap and writes the operator's **own** real
session to `../dashboard/chain-status.js`. It reports nothing else — the
miner panel says "you are not mining" until you actually run it.

---

## Trustless cross-chain — HTLC atomic swaps

Cross-chain settlement is **trustless**, with no custodian, oracle, bridge,
liquidity pool, or committee — exactly the Bitcoin/Zcash model. Three consensus
actions in [`sov-types`](crates/types/src/lib.rs), executed by
[`sov-runtime`](crates/runtime/src/execution.rs):

- **`HtlcLock`** escrows SOV under a SHA-256 hashlock and a height timeout (the
  escrow is committed in `state_root` and counted in total supply, so a lock is
  supply-neutral).
- **`HtlcClaim`** pays the recipient on revealing a preimage whose SHA-256
  (Bitcoin/Zcash-compatible `OP_SHA256`) matches the hashlock, before the timeout.
- **`HtlcRefund`** returns the funds to the locker after the timeout.

The **same** preimage unlocks the counterparty's BTC/ZEC HTLC, so a swap is
atomic across chains with zero trusted parties. (The earlier committee-attested
cross-chain *pool* — `sov-bridge` — and the `sov-mpc`/`sov-confidential`/
`sov-sharding` crates were **removed** in the consensus migration: SOV is pure
proof-of-work, only hashpower.)

---

## Smart contracts

[`sov-vm`](crates/vm/src/lib.rs) is a deterministic WebAssembly runtime
built on the pure-Rust [`wasmi`](https://crates.io/crates/wasmi) interpreter:

- **Deterministic** — an interpreter (no JIT) executes identically on every
  node and platform, so consensus never diverges over a contract's result.
- **Portable** — pure Rust, no native codegen, so the same VM runs on the
  macOS, Windows, and Linux clients.
- **Gas-metered** via `wasmi` fuel: every contract call has a budget; each
  Wasm op consumes fuel; exceeding the budget traps with `VmError::OutOfGas`.
- **Explicit host ABI** (module `env`): `storage_read` / `storage_write` and
  block-context reads. No ambient authority — a contract can touch nothing
  the host did not hand it.

The on-chain integration is wired end-to-end: `Account` carries optional
`code: Option<Vec<u8>>`, the ledger carries per-contract storage committed
to `state_root`, and `sov-types` defines `Action::Deploy { code }` and
`Action::Call { contract, gas_limit }`. The runtime charges the caller
`vm_gas_used × gas_price`, paid entirely to the miner — no tax, nothing is burned.

Guest contracts live in the separate [`chain/contracts/`](contracts/) `no_std`
workspace; the committed [`crates/vm/tests/counter.wasm`](crates/vm/tests/counter.wasm)
is the example contract's release build, run end-to-end by the integration
test.

---

## Accounts & compliance

- **Named accounts** — SOV's transparent tier is human-readable account ids
  (e.g. `usa.reserve.sov`), cryptographically bound to a keypair on-chain. (The
  earlier NEAR-style account-abstraction crate `sov-accounts` — registry,
  delegated sub-accounts, access keys — was removed; named accounts are plain,
  key-controlled `AccountId`s.)
- **Issuer-sovereign compliance** ([`sov-compliance`](crates/compliance/src/lib.rs))
  applies to **native assets** only and is **wired into the runtime** (Phase 17):
  an asset issuer can freeze, allow/deny counterparties, and impose a rolling
  spend-velocity limit on its own token, enforced on every token-moving path —
  including the contract token bridge. **Native SOV is never regulable.**

> The previously-"unwired subsystem" seams are gone: the bridge consensus pool,
> MPC custody, confidential intents, and sharding were **removed** in the
> consensus migration (pure proof-of-work, only hashpower), and compliance +
> intents are now live in the runtime. There is no isolated-but-unwired backlog.

---

## Running a devnet

```sh
# Real transfer devnet: boots a real chain, real signed txs, real receipts.
cargo run -p sov-node

# Real CPU miner — your machine does genuine PoW; writes your real session
# to ../dashboard/chain-status.js. Reports only the miner you actually run.
cargo run --release -p sov-node --bin sov-miner [blocks]
```

Both binaries are deliberately small drivers wrapping the same
[`Blockchain`](crates/chain/src/blockchain.rs) every test exercises.

---

## Roadmap

The kanban-style roadmap lives in
[`../dashboard/phases.json`](../dashboard/phases.json) and is rendered by
[`../dashboard/index.html`](../dashboard/index.html). The numbers on the
dashboard come from [`../dashboard/gen-status.mjs`](../dashboard/gen-status.mjs),
which runs **real** `cargo test --workspace` and a recursive Rust LOC scan;
it never fabricates numbers.

Phases 0–20 built the full stack (foundations, runtime, verification, node +
JSON-RPC, explorer, SDK, shielded pool, HD wallets, HTLC atomic swaps, economics,
testnet failsafe hardening, native assets, post-quantum resistance), and **Phase
21 — the Nakamoto migration** then made the chain pure proof-of-work and removed
everything that wasn't sound money: proof-of-stake, the BFT/validator committee,
the cross-chain consensus pool + MPC custody, sharding, confidential intents, the
compute marketplace, and equihash were all deleted; the mainnet seal became
**RandomX** (ASIC-resistant) and emission became Bitcoin's coinbase with no
pre-mine. Persistence survives restart (block log; finality is a pure function of
chain state). The JS/TS SDK ([`../sdk/`](../sdk/README.md)) is a second,
independent client pinned byte-for-byte by KAT vectors.

`sov-verify` carries the validity assurance: exact-integer invariants
(`supply == genesis + mined`, 21M cap, no unauthorized mint, per-asset
conservation), deterministic replay + cross-node state-root agreement,
heaviest-work fork-choice chaos/fault tests, the normative state-transition spec,
KAT vectors, and property/fuzz tests.

The remaining gates to a live mainnet are **operational, not code**: an external
third-party audit, a public testnet shakeout with independent miners, and real
mining hashrate (RandomX keeps mining open to commodity / M-series CPUs). See
[`../dashboard/phases.json`](../dashboard/phases.json) and
[`docs/improvements-ledger.md`](docs/improvements-ledger.md).

---

## Audited external dependencies

SOV does **not** roll its own cryptography. Every primitive sits behind a
public, audited crate; this crate's job is to compose them.

| Dependency | Purpose | Used by |
|---|---|---|
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | Ed25519 sign / verify | `sov-crypto`, `sov-wallet` |
| [`blake3`](https://crates.io/crates/blake3) | 32-byte hash used for ids, state roots, Merkle leaves | `sov-primitives`, `sov-crypto`, `sov-state` |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256d seal (dev/test) + HTLC hashlocks + hashing | `sov-pow`, `sov-runtime` |
| [`randomx-rs`](https://crates.io/crates/randomx-rs) (Monero) | RandomX memory-hard ASIC-resistant PoW seal (mainnet) | `sov-pow` |
| [`fips204`](https://crates.io/crates/fips204) | ML-DSA-65 post-quantum signatures (hybrid with Ed25519) | `sov-crypto` |
| [`fips203`](https://crates.io/crates/fips203) | ML-KEM-768 post-quantum key encapsulation (transport) | `sov-network` |
| [`orchard` / `halo2`](https://crates.io/crates/orchard) (Zcash) | Halo2 zero-knowledge shielded pool (no trusted setup) | `sov-shielded` |
| [`wasmi`](https://crates.io/crates/wasmi) | Pure-Rust deterministic Wasm interpreter | `sov-vm` |
| [`borsh`](https://crates.io/crates/borsh) | Canonical deterministic binary encoding | workspace-wide |
| [`serde`](https://crates.io/crates/serde) | JSON encoding for RPC + tooling | workspace-wide |

---

## Hard rules

These are non-negotiable:

- **No `unsafe`.** `#![forbid(unsafe_code)]` on every crate, plus
  `[lints.rust] unsafe_code = "forbid"` per crate `Cargo.toml`.
- **No fabricated data, ever.** Balances, miners, deposits, oracle prices,
  block counts, test counts — everything you see is derived from real
  state. Empty / disconnected states are reported honestly.
- **No hand-rolled cryptography.** Every primitive sits behind an audited
  crate.
- **Cross-platform clients.** The node, miner, and wallet must run on
  macOS, Windows, and Linux. CI builds and tests every push on all three.
- **Pure-Rust, std-only networking.** Keeps the cross-platform promise
  cheap and the dependency surface auditable.

---

## License

[Apache-2.0](Cargo.toml).
