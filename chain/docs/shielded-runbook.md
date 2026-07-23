# Shielded-pool operator runbook (`sov-wallet`)

The full SHIELDED (z-) lifecycle as deterministic CLI commands — the same
library path SOV Station's GUI drives (`recover_outputs`/`NoteStore` scanning,
Halo2 proving, receipt-confirmed submission), captured so an operator never has
to rediscover it. Everything below is client-side tooling against a node's
JSON-RPC; nothing here touches consensus.

Conventions used throughout:

- `<rpc>` — the node's RPC address, e.g. `127.0.0.1:8645`.
- `<seed_hex>` — the wallet's 32-byte signing seed, 64 hex chars (the same
  Station-importable seed kept in `~/Desktop/keys/*.txt`). Seeds are only ever
  passed on argv and are never echoed back in any output.
- Amounts are whole XUS.
- The wallet's addresses come from `sov-wallet keygen <seed_hex> [name]`:
  the transparent `public_key`, the `shielded` `xus1…` address, and (with a
  name) the `uxus1…` unified address.
- Hybrid post-quantum signing is the default everywhere; add `--ed25519` for a
  legacy-keyed account (matching how the account's key was registered).

## 0. One-time: know your addresses

```
sov-wallet keygen <seed_hex> my-account
```

Prints `public_key`, `shielded : xus1…`, `unified : uxus1…`. The `xus1…`
address is where value enters the pool for THIS seed; the seed alone recovers
the notes (scanning is deterministic — no extra wallet file is needed).

## 1. SHIELD — move transparent XUS into the pool

Shielding is the existing `transfer` with a shielded (`xus1…`) or unified
(`uxus1…`) recipient:

```
sov-wallet <rpc> transfer <seed_hex> <from_account> xus1... 40
```

Expected output:

```
recipient routes to the SHIELDED pool — building the Halo2 prover (one-time, then proving; ~30s total)...
submitted: <from_account> -> xus1... 40 XUS (tx <64-hex txid>)
```

Notes:
- The ~30s is real Halo2 prover construction + proving (release build). Do not
  interrupt it.
- `transfer` returns at SUBMIT time; the shield is final once mined. Verify
  with step 2 after a block or two.

## 2. CHECK — `z-balance`

```
sov-wallet <rpc> z-balance <seed_hex>
```

Scans the chain from genesis for the seed's notes (receipt-verified, exactly
like Station: bundles from mined-but-FAILED transactions are never credited;
nullifier accounting drops SPENT notes), then prints the wallet view plus the
pool's live state:

```
scanning blocks 1..=<tip> for shielded notes...
shielded address : xus1...
scanned height   : <tip>
unspent notes    : 1
  note 1         : 40 XUS
shielded balance : 40 XUS
pool value       : 40
deshieldable now : <n> XUS
drain limiter    : <limit> XUS per <w> blocks (window resets at height <h>)
```

Deterministic and read-only; run it as often as you like. The scan is stateless
(full pass each run), so expect it to take longer on a long chain.

## 3. UNSHIELD — move pool value back to a transparent account

```
sov-wallet <rpc> unshield <seed_hex> <to_transparent_account> 15
```

`<to_transparent_account>` is the carrier-tx signer and the account the chain
credits — it MUST be controlled by this seed's key (a named account registered
with the seed's public key, or the seed's implicit account id).

Expected output:

```
scanning blocks 1..=<tip> for shielded notes...
proving the de-shield of 1 note(s) — building the Halo2 prover then proving (~30s total)...
submitted — waiting for on-chain confirmation...
unshielded 15 XUS -> <to_transparent_account> (tx <txid>)
```

Semantics (all mirrored from Station):

- **Note selection**: largest-first until the amount is covered, all spent in
  ONE multi-spend bundle; change returns to your own shielded address
  automatically. Capped at 32 notes per transaction — if the cap cannot cover
  the request, the command de-shields what those notes hold and tells you to
  run again for the remainder (value is paced, never trapped).
- **Receipt-confirmed**: the command only reports success once the transaction
  actually APPLIED on-chain; a mined-but-rejected de-shield surfaces its
  on-chain failure reason instead.

### The de-shield drain limiter

Consensus enforces a rolling circuit breaker: at most `deshieldLimitGrains` may
leave the pool per `deshieldWindowBlocks`-block window (defense in depth — even
a forged proof cannot drain the pool faster). The CLI pre-checks
`deshieldableNowGrains` from `sov_getShieldedInfo` and fails EARLY:

```
sov-wallet: only <n> XUS can be de-shielded in the current window (per-window
drain limit; window resets at height <h>) — reduce the amount or wait for the reset
```

Nothing is submitted in that case (an over-budget de-shield would be mined and
rejected, consuming your nonce for nothing). `z-balance` always shows the
current budget and the reset height.

## 4. Z-SEND — fully-private shielded → shielded transfer

Supported by consensus (an `Action::Shielded` bundle with value balance 0 —
the same path Station's "private send" uses):

```
sov-wallet <rpc> z-send <seed_hex> <to: xus1...|uxus1...> 10 --signer <account>
```

Sender, recipient, and amount all stay inside the pool; only the fee-paying
carrier transaction (moving zero transparent value) is visible on-chain.
`--signer` is the transparent account that submits and signs that carrier tx —
it must be controlled by the seed; omitted, it defaults to the seed's implicit
account id (which then must exist/afford the fee).

Expected output:

```
scanning blocks 1..=<tip> for shielded notes...
proving the private transfer — building the Halo2 prover then proving (~30s total)...
submitted (carrier signer <account>) — waiting for on-chain confirmation...
z-sent 10 XUS -> xus1... (tx <txid>)
```

Constraint: a private spend consumes ONE note, so a single unspent note must
cover the amount (change returns to you privately). If no note is large
enough, the command says so and names the largest; consolidate first
(unshield, then re-shield as one note).

## Quick reference

| Step      | Command                                                              |
|-----------|----------------------------------------------------------------------|
| shield    | `sov-wallet <rpc> transfer <seed> <from> xus1… <xus>`                 |
| check     | `sov-wallet <rpc> z-balance <seed>`                                   |
| unshield  | `sov-wallet <rpc> unshield <seed> <to_account> <xus>`                 |
| z-send    | `sov-wallet <rpc> z-send <seed> <xus1…\|uxus1…> <xus> [--signer <a>]` |

Proven end-to-end by `chain/crates/rpc/tests/shielded_wallet.rs`
(`cargo test --release -p sov-rpc --test shielded_wallet -- --ignored`), which
drives the real binary through shield → z-balance → unshield → z-send against a
live local daemon.
