# sov-stratum — the SOV RandomX Stratum bridge

A standalone TCP daemon (own crate, **not** a member of the chain workspace — the
`tools/tx-cannon` / `tools/conformance` pattern) that speaks **Monero-lineage
Stratum** to RandomX miners on one side and `sov_getBlockTemplate` /
`sov_submitBlock` JSON-RPC to a SOV node on the other. It is Phase 2 of the
pool-mining stack planned in [`.github/RELEASE-0.1.92.md`](../../.github/RELEASE-0.1.92.md).

**It is a work-distribution layer only.** It adds no consensus rule and cannot
alter a block: every accepted submission travels the node's normal validated
import path (`sov_submitBlock` → `commit_mined` → `import_block`, full
re-validation), so the bridge's word counts for nothing. Genesis
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` is untouched.

## What it does

- **Polls the node** for work: watches `sov_getHeight` and refetches a template
  via `sov_getBlockTemplate` on tip change or every `--refresh-secs` (fresh
  timestamp + mempool; the node caches templates 120 s server-side).
- **Speaks the Monero Stratum dialect** on `--bind` (line-delimited JSON-RPC):
  `login`, `getjob`, `submit`, `keepalived`, plus server-pushed `job`
  notifications. Jobs carry `{ job_id, blob, seed_hash, target, algo: "rx/0",
  height }` — the shape xmrig-class miners expect.
- **Verifies every share with the real seal.** Each `submit` is re-sealed with
  the exact `pow_seal` the importer runs (`chain/crates/pow/src/seal.rs`) on a
  single dedicated verifier thread (one light RandomX VM, ~256 MiB, process-wide;
  the seed is the genesis hash, so the VM builds once and never rotates). The
  miner's `result` field is cross-checked, never trusted.
- **Vardiff per session**: share difficulty retargets toward one share per
  `--share-secs`, clamped to ×4 per window and to `[--min-diff, --max-diff]`.
  The share rule is SOV's own (big-endian `seal <= target`, the same
  `Target::is_met_by` comparison consensus uses), so *a block is just a share
  that also cleared network difficulty* holds by construction.
- **Submits blocks**: a share meeting the network target is forwarded as
  `sov_submitBlock { templateId, nonce, timestampMs }` with the job's **frozen**
  timestamp (the timestamp is inside the hashed blob — miners never roll it).
- **Built-in SOV-native workers** (`--workers N`): optional in-process miner
  threads that grind the current template with the fast (full-dataset) RandomX
  VM — pool mining works day one with no third-party miner. Budget ~2.3 GiB RAM
  per worker in fast mode (it transparently falls back to the light VM on
  RAM-constrained hosts).

No secret material is handled anywhere: the coinbase account id is public and no
key or seed ever enters this process — so there is deliberately nothing to
zeroize.

## What it does NOT do yet

- **No decentralized sharechain, no PPLNS payouts.** Shares are verified and
  tallied per session (the `NOTE(Phase 3)` marker in `src/main.rs`), but nothing
  is paid out from them: **the entire coinbase of a found block goes to the one
  `--coinbase` account** (SOV's header pays a single `proposer`; there is no
  multi-recipient coinbase). The sharechain + payout design — including the
  single-recipient-coinbase problem and its options — is Sections 3–4 of
  [`.github/RELEASE-0.1.92.md`](../../.github/RELEASE-0.1.92.md).
- **No miner authentication or ban scoring** beyond per-session share
  verification (every share is re-sealed, so fake work earns nothing).
- **No TLS** on the Stratum port. Run it on a trusted network or behind a proxy.

## Running it

```sh
cd tools/sov-stratum
export PATH=/opt/homebrew/bin:$PATH   # cmake, for the RandomX build
cargo build --release

# Bridge a local node, mine to a specific account, with 1 built-in worker:
./target/release/sov-stratum \
  --node 127.0.0.1:8645 \
  --bind 0.0.0.0:3333 \
  --coinbase <your-account-id> \
  --workers 1
```

`--help` lists every flag (start/min/max difficulty, vardiff timing, poll and
refresh intervals).

## Running xmrig against it — the honest caveat

xmrig connects, logs in, and receives jobs normally:

```sh
xmrig -o <bridge-host>:3333 -a rx/0 -u <worker-name> -p x --keepalive
```

**But stock xmrig does not grind the right bytes.** xmrig hard-codes Monero's
block-blob layout — a 4-byte nonce at fixed offset 39 — while SOV's blob is the
Borsh `BlockHeader` preimage whose nonce is a **trailing little-endian u64** at
`nonceOffset = blob.len() − 8` (a variable-length `proposer` sits ahead of it).
No bridge-side re-framing can fix that: the blob *is* the hash preimage; its
bytes cannot be rearranged without changing the seal. Every job therefore
carries SOV extension fields — `nonce_offset`, `nonce_size: 8`, and
`target_full` (the full 256-bit big-endian share threshold, since SOV compares
the whole seal big-endian where xmrig checks the trailing 8 bytes
little-endian) — which stock miners ignore harmlessly on Monero and a
SOV-aware miner uses directly. The two supported mining paths today:

1. **The built-in worker** (`--workers N`) — provably correct, uses the same
   fast-VM `pow_seal_mining` as the in-process node miner. Start here.
2. **A patched xmrig** that honors the job's `nonce_offset`/`nonce_size` and
   `target_full` fields (a small, upstreamable change to its job/blob handling).
   We do not claim stock-xmrig support we cannot demonstrate.

Shares submitted with a nonce ground at the wrong offset simply fail the
bridge's re-seal and are rejected — wrong work can never reach the node.

## Tests

`cargo test` covers the pure rules: difficulty→target math (known pool
vectors), vardiff retargeting (raise/lower/clamp/bounds), share-vs-block
classification (equality counts as met, share ⊇ block), the blob/nonce mapping
(splice at `nonceOffset` is byte-identical to Borsh re-encoding the header —
the bridge-side twin of the node-side Phase-1 invariant), miner wire-format
nonce parsing, template parsing of the documented RPC shape (bad `nonceOffset`
and unknown algorithms are refused), and that `sov_submitBlock` params carry
the job's frozen `timestampMs`.
