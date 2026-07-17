# SOV v0.1.89 — Headers-first sync (block locator): catch-up in one round-trip

A node that fell behind on a stale tip used to find where it diverged by walking
**backward one block per round-trip** — it *did* catch up, but crawled for minutes and
looked hung the whole time. This replaces that with the design Bitcoin, Monero, and Zcash
all use: a **block locator** + **headers-first** fork-point discovery. **Genesis `cb0272ff`
unchanged** — this is P2P-wire-layer only, fully additive; no consensus, block, header, or
KAT change (the KAT reproduces byte-for-byte).

## The problem

When a node's local tip is off the canonical chain (e.g. it mined a short branch while
briefly behind), the next canonical block won't extend it, and the node has to locate the
common ancestor. The old path requested one block at a time going backward with a doubling
step — O(N) round-trips against a live peer, each subject to the 2-second stall timeout. On
mainnet, hundreds of blocks behind, that was a multi-minute crawl during which the sync
counter sat frozen at `0/N` and the app looked dead.

## The fix — Bitcoin/Monero/Zcash-style locator

1. **Block locator.** The lagging node sends its own active-chain block hashes at
   exponentially-spaced heights (tip, tip-1, tip-2, tip-4, … genesis) — dense near the tip
   (where a fork most likely is), sparse toward genesis, ≤32 entries for any chain length.
2. **Headers-first.** The peer finds the first locator hash on **its** active chain (the fork
   point) and replies with up to 2000 consecutive block **headers** from just past it —
   **one round-trip**. The lagging node validates the header linkage, learns the fork point,
   and hands off to the existing forward batched block download + reorg. Fork discovery goes
   from O(N) round-trips to **one**.
3. **Security unchanged.** Headers are only a fork-point *hint* (light linkage validation, no
   PoW re-verify). Every block is still fully validated on import via the unchanged path — a
   lying peer yields at worst a bad guess whose blocks then fail validation, and it is
   penalized. Serving `GetHeaders` is auth-gated like `GetBlocks`.

## Compatibility & rollout

Two new `NetMessage` variants (`GetHeaders`, `Headers`) are **appended** — every existing
message's Borsh encoding is byte-identical. `PROTOCOL_VERSION` 1 → 2;
`MIN_SUPPORTED_PROTOCOL` stays 0, so no peer is refused. A v2 node sends locators **only** to
peers that advertised protocol ≥ 2; with a v0.1.86–88 peer it uses the legacy single-block
backtrack. **Fully backward-compatible** — deploy to the relays first (zero mesh risk), then
upgrade miners; a v2 node gets the fast catch-up as soon as it talks to another v2 node.

## Proof (test-first)

`stale_tip_node_finds_fork_point_in_one_headers_exchange_and_catches_up` drives two real
nodes over the encrypted transport: node A on a stale tip, node B on the canonical chain 80
blocks ahead. It asserts A reaches B's exact head using **exactly one `GetHeaders` exchange,
zero legacy single-block requests**, and a handful of forward batches. Plus unit tests for
locator construction, fork-point serving, and header-linkage validation. `sov-rpc`,
`sov-network`, `sov-chain`, and `sov-verify` (KAT byte-for-byte) all green; clippy
`-D warnings` and `fmt` clean.

## Safety

Genesis + KAT byte-identical (no consensus/block/header encoding touched). Wire-additive and
backward-compatible with the v0.1.85–v0.1.88 mesh. The desktop Node log now names the phase
("asking … for the fork point (block locator)" → "fork point at height N — downloading
forward"), so catch-up is visible instead of a frozen counter.
