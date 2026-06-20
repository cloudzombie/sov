# SOV fuzzing (Phase 7 · p7-i3)

Coverage-guided [libFuzzer](https://llvm.org/docs/LibFuzzer.html) targets, via
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), for the untrusted-input
surface: Borsh decoding of the consensus types and account-name validation.
Decoding attacker-controlled bytes must only ever return an error — never panic,
loop, or mis-decode.

## Targets

| Target | Surface |
|---|---|
| `signedtx_decode` | `SignedTransaction` Borsh decode (mempool / RPC input) |
| `block_decode` | `Block` Borsh decode (peer gossip / sync input) |
| `account_decode` | `Account` Borsh decode (persisted-state read-back) |
| `accountid_validate` | `AccountId::new` over arbitrary UTF-8 |

## Run (requires nightly + cargo-fuzz)

```sh
cargo install cargo-fuzz
cd chain
cargo +nightly fuzz run signedtx_decode
cargo +nightly fuzz run block_decode
cargo +nightly fuzz run account_decode
cargo +nightly fuzz run accountid_validate
```

These are **not** part of `cargo test` — libFuzzer needs the nightly toolchain
and runs unbounded. The **stable-Rust counterpart** lives in
[`../crates/verify/tests/properties.rs`](../crates/verify/tests/properties.rs)
(`decoding_arbitrary_bytes_never_panics`), which fuzzes the same decoders with
`proptest` on every CI run, so the surface is exercised continuously even without
nightly. This directory is a **detached workspace**, excluded from the host build.
