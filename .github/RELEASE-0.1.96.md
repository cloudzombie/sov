# SOV Station v0.1.96 — definitive cold-sync fix

## The bug: fresh nodes stuck forever at height 7168

A newly-installed node syncing from genesis climbed to exactly **height 7168**,
then dropped all peers and looped on 0 connections — deterministically, on every
machine (macOS and Windows alike), regardless of hardware speed. Already-synced
nodes were unaffected because they never re-download that region, which is why it
only ever hit fresh installs.

## Root cause (proven, not theorized)

The `GetBlocks` sync handler capped each served batch by **block count** (256)
only, never by **serialized size**. The block range starting at 7169 contains real
transaction activity — individual blocks up to ~2 MB, a 256-block batch totalling
~30 MB. That response serializes far past the transport's 8 MiB `MAX_FRAME`, so the
serving node's `write_frame` rejects the frame and tears down the connection. A
cold-syncing peer re-requests that same batch every time and can never cross it.

Reproduced end-to-end against the live seeds (stuck at 7168, "served then link
down"), then fixed and re-verified: a fresh node now cold-syncs clean through the
region to the chain tip.

## The fix

- **Serving side caps a `BlocksResponse` by cumulative serialized size**
  (`SYNC_BATCH_MAX_BYTES = 6 MiB`, generous headroom under the 8 MiB frame), in
  addition to the 256-block count cap. Through a large-block region the batch
  auto-shrinks (e.g. 83 blocks) so the frame is always sendable; at least one block
  is always served, so sync always advances — even across a block bigger than the
  whole budget.
- Pure, unit-tested `size_capped_batch_len` helper (5 regression tests) proving the
  served batch never reaches the transport frame ceiling.

**Consensus-neutral and genesis-safe** (`cb0272ff…`): only the number of blocks
packed into one response frame changes — no block, header, or state encoding is
touched. The receiver already handles a short batch, so **existing v0.1.94 clients
sync through as soon as the seeds run v0.1.96** — no client update strictly required,
though updating is recommended so every node serves correctly.
