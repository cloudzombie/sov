# SOV VM + token composability — reference notes

Answering: *what is our scripting language / VM, and how is the token WASM-composable?*
All verified against `chain/crates/vm/src/lib.rs` and `chain/crates/runtime/src/execution.rs`.

## The VM / "scripting language"

- **WebAssembly (WASM)**, run on **`wasmi`** — a pure-Rust, deterministic WASM interpreter
  (`chain/crates/vm`). No JIT, no native codegen → the same bytes produce the same result on
  every node, which is what makes it consensus-safe.
- **Gas-metered via wasmi "fuel":** every `Call` gets a fuel budget (`gas_limit`); running out
  is a clean, deterministic failure, not a hang. Storage writes and payload bytes are priced.
- **Contract language = anything that compiles to WASM:** Rust (the natural fit),
  AssemblyScript, C/C++, Zig, TinyGo, etc. There is no bespoke DSL — the "scripting language"
  is WASM itself.
- **Contract shape:** a WASM module that exports `memory` and an **entry point with signature
  `() -> i32`** (returns a status code). Lifecycle actions:
  - `Deploy { code }` — upload a contract; it gets a deterministic on-chain address.
  - `Call { contract, gas_limit, calldata }` — invoke it with input bytes and a gas cap.

## Host ABI (module `env`) — what a contract can do

The runtime exposes exactly these host functions to the guest (nothing else — capability-
scoped by construction):

| Host fn | Purpose |
|---|---|
| `storage_read` / `storage_write` | per-contract key→value storage (size-capped, priced) |
| `calldata` | the input bytes of this call |
| `caller` | the account that invoked the call |
| `address` | the contract's own address |
| `block_height` | current chain height |
| `set_return` | set the call's return data |
| `emit` | emit an event/log |
| **`token_balance(asset)`** | read the contract's OWN balance of a token |
| **`token_transfer(asset, to, amount)`** | queue a transfer of the contract's OWN tokens |

## How the token is composable with WASM

- **Native tokens are first-class**, separate from the VM: issued via `TokenIssue` (32-byte
  asset id, issuer-bound), moved via `TokenTransfer`, plus the native XUS coin. This is the
  asset layer; WASM is the programmability layer over it.
- **A contract is a first-class token holder + mover.** Inside a `Call`, a contract can:
  1. `token_balance(asset)` — see how much of a token it holds, and
  2. `token_transfer(asset, to, amount)` — move its own tokens. Insufficient funds returns
     `-1` (graceful) — a contract **can never queue an overspend** (the working balance is
     debited on the spot; self-transfers net to zero).
- **Atomic settlement:** transfers are QUEUED during execution and applied together AFTER, by
  `settle_contract_token_transfers` — all-or-nothing, re-validated against real balances. If
  the call fails, none apply.
- **Scoping:** a contract can only read/move **its own** token balances (not arbitrary
  accounts'), and is capped at `MAX_TOKEN_TRANSFERS_PER_CALL`. Users fund a contract by a
  normal `TokenTransfer` to the contract's address.

**Net:** issue a token → hand it to a contract → the contract programmatically holds and
moves it under gas + determinism. That composability enables DEXes, escrows, vaults, payment
streams, vesting, etc., with the token system as the settlement primitive and WASM as the
logic.

## Important boundary (for the TS SDK / swap work)

The TypeScript `@sov/sdk` is a byte-identical *second client* for tx building/signing and the
transparent STF, but it does **NOT** re-implement `Call` (wasmi), `Shielded` (Halo2), or
mainnet mining (RandomX) — those are Rust-node-only. The SDK can *build* a `Deploy`/`Call`
transaction, but only the Rust node executes contract code.

## Open follow-ups worth a look tomorrow

- Is there **cross-contract calls** (a contract calling another contract), or is it single-
  call only? (Check for a `call_contract` host fn — the ABI above suggests NOT yet.)
- Contract-held **native XUS** (vs issued tokens) — can a contract move XUS, or only
  `TokenIssue`-tokens? (`token_transfer` is asset-id-keyed; confirm whether XUS has an asset
  id here.)
- Gas schedule / pricing surface for `Call` — is it tuned for real contract workloads?
