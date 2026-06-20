# SOV second client (independent verification & re-execution)

A blockchain that depends on a *single* implementation has a single point of
consensus failure: any bug in that code is, by definition, "correct" — there is
nothing to disagree with it. A second, independent implementation in a different
language, sharing no code, is the standard defense (Bitcoin Core ↔ btcd,
Geth ↔ Nethermind, …). This SDK is SOV's second implementation.

It is built bottom-up, each layer proven **byte-for-byte** against vectors the
Rust node generates from its own production types (`sov-katgen`). "Byte-for-byte"
is the bar: anything the TS client computes that differs from the node by a
single bit is a consensus divergence, which is exactly what a second client
exists to surface.

## What the second client independently computes

| Layer | TS module | Proven against | What it establishes |
|-------|-----------|----------------|---------------------|
| **Transaction encoding & id** | `borsh.ts` | `vectors/transactions.json` | Canonical Borsh signing bytes + Blake3 tx id match the node. |
| **Block hashing** | `borsh.ts`, `verify.ts` | `vectors/block.json` | Block id, transaction Merkle root, per-tx ids re-derived from raw bytes. |
| **Authenticated state (SMT)** | `smt.ts`, `state.ts`, `verify.ts` | `vectors/state.json` | Independent Sparse Merkle Tree: derives every slot, Borsh-encodes every account, reconstructs `state_root`, and verifies/regenerates inclusion & exclusion proofs. |
| **State-transition re-execution** | `stf.ts` | `vectors/stf.json` | Applies a real block to a prior ledger and **derives** the next `state_root`, `receipts_root`, accounts, and receipts — independently re-running consensus. |
| **Proof-of-work seal & difficulty** | `borsh.ts` + SHA-256d | `vectors/pow.json` | The header's Borsh PoW preimage, the SHA-256d seal over a range of nonces, and the `hash ≤ target` threshold (Bitcoin compact nBits round-trip) — the mining contract every miner must match bit-for-bit. |
| **Emission schedule** | subsidy math | `vectors/emission.json` | `reward_at(height, mined_supply)` across halving boundaries, the budget backstop, and decay to zero — the coinbase subsidy every miner must agree on. |

Every layer runs with no shared code with the node: hashing is `@noble/hashes`
(Blake3/SHA-256), signatures are `@noble/ed25519`, and all SOV-specific logic
(Borsh layout, the SMT, the STF, the fee model) is re-implemented here and pinned
by the KATs.

## The state-transition function the second client re-executes

`stf.ts` re-executes the full **deterministic transparent STF**, byte-for-byte
with `chain/crates/runtime/src/execution.rs`:

- **Authentication / authorization / replay** — Ed25519 signature check, the
  account's registered key must control it, strict nonce ordering.
- **Value movement** — `Transfer`, `Stake` (with the lock-weighted minted
  reward, clamped to the staking budget), `Unstake`, `ClaimVesting`.
- **Contracts (state only)** — `Deploy` (commits code; per-byte gas).
- **Atomic swaps** — `HtlcLock` / `HtlcClaim` (SHA-256 preimage) / `HtlcRefund`,
  including the open-HTLC-set digest committed in the state root.
- **Fee economics** — `gas_used × gas_price`, base fraction **burned**
  (deflationary), the tip **split** between the block's miner and proposer; a
  failed action still consumes its nonce and fee.

It reproduces both `state_root` **and** `receipts_root` (including the exact
failure-reason strings the node commits to).

## The deliberate boundary (delegated to audited engines)

Three actions are **not** re-executed in TypeScript. Re-implementing them would
mean duplicating an audited engine the project deliberately delegates to —
directly against SOV's standing rule "never hand-roll crypto; delegate to audited
crates." For these, `stf.ts` returns `requiresDelegatedVerification` rather than
silently mis-executing a block:

- **`Call`** — runs a metered **wasmi** WASM VM (`sov-vm`). Bit-exact gas
  metering would require re-implementing that VM.
- **`Shielded` / `MineShielded`** — verify an Orchard/**Halo2** zk-SNARK
  (`sov-shielded`). There is no audited TypeScript Halo2 verifier; hand-rolling
  one is exactly what the no-hand-rolled-crypto rule forbids. (Note: the
  conservation/turnstile invariant means even an unsound proof system cannot
  *manufacture supply* — a shielded credit must be matched by a transparent
  debit/emission — so the worst case is bounded.)
- **`Mine`** — the **Sha256d** seal, the header preimage, the difficulty target
  (compact nBits ↔ 256-bit), and the emission subsidy are all reproducible and now
  pinned (`vectors/pow.json`, `vectors/emission.json`). Only the **mainnet RandomX**
  seal is delegated to `sov-pow` (a memory-hard VM, like Halo2 above): its INPUT is
  the same Borsh header preimage the vector pins, so a RandomX miner reuses
  `pow_preimage_hex` and runs the standard RandomX over it.

This boundary is inherent to "a second client in TypeScript," not an unfinished
TODO: the audited Rust crates *are* the dependency, and there is no second
audited implementation of a WASM VM or a Halo2 verifier to cross-check against.
The independent re-execution covers every part of consensus that is not one of
those delegated engines, which is the entire transparent economic core.

## Regenerating the vectors

The node is the single source of truth (`sov-katgen`). Each vector is committed in
two places, kept identical: `sdk/vectors/` (consumed by this TS client) and
`chain/crates/rpc/tests/vectors/` (where the node's own `sov-katgen` unit tests pin
them, so a consensus change that isn't accompanied by a vector regen FAILS the Rust
build — the published contract can never silently drift from the node).

```
cd chain
KG="cargo run -q -p sov-rpc --bin sov-katgen --"
# transactions.json is pinned in sov-verify (independent re-derivation) + the SDK:
$KG          | tee crates/verify/tests/vectors/transactions.json > ../sdk/vectors/transactions.json
# block/state/stf/pow/emission are pinned by sov-katgen's own tests + the SDK:
for v in block state stf pow emission; do
  $KG $v | tee crates/rpc/tests/vectors/$v.json > ../sdk/vectors/$v.json
done
cargo test -p sov-rpc --bin sov-katgen   # drift guard: vectors match the generators
cd ../sdk && npm test                    # the TS second client reproduces them
```
