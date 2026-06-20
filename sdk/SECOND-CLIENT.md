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
- **`Mine`** — verifies a proof-of-work solution (`sov-pow`). The PoW math is
  reproducible, but solution verification is delegated to the same crate the node
  uses.

This boundary is inherent to "a second client in TypeScript," not an unfinished
TODO: the audited Rust crates *are* the dependency, and there is no second
audited implementation of a WASM VM or a Halo2 verifier to cross-check against.
The independent re-execution covers every part of consensus that is not one of
those delegated engines, which is the entire transparent economic core.

## Regenerating the vectors

```
cd chain
cargo run -p sov-rpc --bin sov-katgen        > ../sdk/vectors/transactions.json
cargo run -p sov-rpc --bin sov-katgen -- block > ../sdk/vectors/block.json
cargo run -p sov-rpc --bin sov-katgen -- state > ../sdk/vectors/state.json
cargo run -p sov-rpc --bin sov-katgen -- stf   > ../sdk/vectors/stf.json
cd ../sdk && npm test
```
