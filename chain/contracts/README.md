# SOV smart contracts (guest)

Guest-side code that compiles to `wasm32-unknown-unknown` and runs on the
`sov-vm` runtime. This is a **separate workspace** from the host chain (guest
code is `no_std`), and is excluded from the host build.

- **`sov-sdk/`** — the guest SDK contracts are written against: safe wrappers
  over the host ABI (`get`, `set`, `current_height`), a bump allocator, and a
  panic handler.
- **`counter/`** — an example contract: a persistent counter exporting
  `call() -> i32`.

## Build

```sh
rustup target add wasm32-unknown-unknown   # once
cd chain/contracts
cargo build --target wasm32-unknown-unknown --release
# -> target/wasm32-unknown-unknown/release/counter.wasm
```

The committed `chain/crates/vm/tests/counter.wasm` is this artifact; the
`sov-vm` integration test runs it end-to-end. Rebuild and copy it if you change
the example:

```sh
cp target/wasm32-unknown-unknown/release/counter.wasm ../crates/vm/tests/counter.wasm
```
