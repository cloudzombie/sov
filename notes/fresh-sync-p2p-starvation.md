# Fresh-node sync: the recurring outage, and the structural fix (v0.2.7)

_Written 2026-07-30. Branch `fix/fresh-sync-p2p-starvation`._

## HEADLINE for existing Station users: the chain was stored in the OS temp dir

`node/src/gui.rs:local_node_dir` resolved to `std::env::temp_dir().join("sov-station-node-<net>")`.
On macOS that is `/var/folders/<…>/T/` — a per-user directory the OS purges on reboot, under
disk pressure, and on its periodic cleanup. So Station kept a MAINNET `blocks.log` somewhere
the operating system deletes.

Observed on the owner's machine on 2026-07-30: `blocks.log` = 63 MB, actively being written,
in `$TMPDIR/sov-station-node-mainnet/node-1/data/` — a directory whose **creation date is
July 28**, though the chain has run since July 4. It had already been wiped at least once.
That is the "syncing is ridiculous / endless fork points" experience: the node was not slow,
it was repeatedly starting from genesis.

Fixed: the chain store now lives under `station_dir()` — `<home>/.sov-station/node-<net>` —
the same durable directory that already holds the wallet keystore and device key (one
convention, not a new per-OS scheme). `SOV_STATION_DIR` still isolates a dev build's chain
exactly as before, because it overrides `station_dir` itself.

`migrate_node_dir_from_temp` moves an existing temp-dir store on the next start — atomic
`rename` when possible, copy-then-remove across filesystems (the usual `$TMPDIR` vs `$HOME`
case on macOS). **Nobody re-syncs.** If BOTH stores exist, neither is touched or deleted: the
durable one is used and the legacy one is reported. A failed migration is a hard error, never
a silent start on a fresh empty chain.

## The failure, four times

A fresh node fast-syncs to the highest baked assumevalid anchor, then must FULLY verify
every block above it. Verification is CPU-bound — a RandomX seal evaluation plus every
transaction's hybrid (Ed25519 + ML-DSA-65) signature — and PQ signatures made blocks big
(~10.8 KB/tx, up to 1.7 MB). Peers time out, the node drops every connection, and on
reconnect the fork-point locator exchange starts over. Forever.

The response each time was to move the anchor: 5000 → 6800 → 8300 → 12800 → (now) 14336.
That is a band-aid. It shortens the catch-up window; it does not stop catch-up from
killing the node.

## Root cause (exact)

`chain/crates/rpc/src/p2p.rs`, `P2p::start`. ONE worker thread did everything:

```
for (peer, msg) in tcp.drain() { state.handle(...) }   // <- imported up to 256 blocks INLINE
state.sync_log();
state.request_missing(...);
... announce / sweep / telemetry ...
```

`SyncState::handle` → `NetMessage::BlocksResponse` → `import_and_persist` per block →
`Node::import_block` → the seal check at `chain/crates/chain/src/blockchain.rs:2149`
(`is_linked_to_checkpoint` gate, then `sha_target.is_met_by(&self.seal(...))`).

So for the WHOLE batch that thread did not run `announce()` (the 320 ms heartbeat), did not
serve other peers' `GetBlocks`/`GetHeaders`, did not sweep, did not publish telemetry.
Remote peers applied their own `PEER_INACTIVITY_TIMEOUT` (45 s) to our silence and dropped
us. `retain_connected` then discarded every per-peer sync cursor, so the next connection
re-ran fork-point discovery from scratch — the "fork point" churn the operator sees.

Three separate mechanisms, all of which read "we are busy" as "the peer is bad":

1. no heartbeat while verifying → the REMOTE reaps us;
2. `BLOCK_REQUEST_TIMEOUT` / `STATUS_MAX_STRIKES` → we strike and deselect the peer that
   answered, because our own verification time was charged to it;
3. `retain_connected` dropping `sync_next` → every reconnect re-walks the locator.

## The fix

**Verification does not run on the network thread.** `SyncState::attach_verifier` spawns a
dedicated `sov-verify` thread; every unit of import work goes over a BOUNDED queue
(`VERIFY_QUEUE_DEPTH`) as a `VerifyJob`, and results come back as `VerifyReport`s applied on
the worker thread (the only thread that touches peers or the network). `BlockImporter` holds
the block log + the durability latch (now an `AtomicBool`) and is shared by both threads.

Supporting guards, each closing one of the three mechanisms above:

- **Node-lock priority.** The verifier takes/releases the node lock per block; std's `Mutex`
  is unfair, so a tight re-acquire loop starved the worker anyway (measured: 8 worker
  iterations across a 1.2 s batch, worst 453 ms). `begin_network_pass` /
  `await_network_pass` give the worker an explicit, bounded priority window. After:
  41 iterations, worst 30 ms.
- **No strikes for our own time.** `inflight` (the network timer) is cleared the instant a
  reply lands, BEFORE queueing; `request_missing` returns early while `verifying` is set,
  issuing nothing and charging nobody.
- **Stall credit.** Any worker iteration overrunning `LOOP_STALL_BUDGET` credits the excess
  to `PEER_INACTIVITY_TIMEOUT` and `STATUS_TTL`, decaying in real time. Whatever future code
  blocks the loop, the deadlines it blocked are extended by exactly as long.
- **No inline fallback under load.** A full queue DROPS the job (gossip re-arrives via
  sync; a catch-up batch is re-requested) rather than verifying on the worker. Without
  that, an authenticated peer spraying `NewBlock` could saturate the queue and push
  CPU-bound work straight back onto the socket loop.
- **`resume_from`.** The resolved fork point is chain state, not peer state. It is set from
  headers exchanges and successful imports and is NOT cleared by `retain_connected`, so a
  reconnect resumes forward download.

## Measured (test `a_slow_verification_batch_keeps_the_worker_live_and_the_fork_point_resolved`)

40 blocks, 25 ms simulated verification each:

| | worker blocked | worst worker iteration | loop iterations | announce reads |
|---|---|---|---|---|
| inline (old) | 1.21 s (the whole batch) | 1.21 s | 1 | 0 |
| verifier thread | 74 µs hand-off | 30 ms | 41 | 41/41 |

## The anchor now maintains itself

Three legs, so a fresh node months from now needs no source change:

1. **Runtime self-derivation** — `Blockchain::adopt_local_finalized_checkpoint` promotes a
   block from the node's OWN finalized history (`LOCAL_ANCHOR_DEPTH` = 1000, floored at
   `FINALITY_DEPTH`) to a local anchor, persisted to `assumevalid.dat` and re-loaded (after
   verifying it against the replayed chain) on the next boot. Refuses on a chain with no
   pins, and refuses unless the newest existing pin is MATCHED — so it can never launder an
   unverified branch. Adoption re-derives the linkage proof, so the seal skip stays
   **ancestry-gated**, never height-gated.
2. **Operator-supplied** — the config's `checkpoints` list (already existed; now documented
   as the escape hatch).
3. **One-command refresh** — `scripts/refresh-checkpoint.sh [--write]` proposes, cross-checks
   on two independent relays, refuses on disagreement, and writes the entry. The release gate
   now names this command instead of describing a manual procedure.

## Honest limits

- The Station data-dir migration has been verified by unit test
  (`a_temp_dir_chain_is_migrated_once_and_never_destroyed`,
  `the_chain_directory_is_never_inside_the_os_temp_directory`) but has NOT been run against
  the owner's real 63 MB store — that happens on their next Station start.

- A genuinely fresh node still verifies every block above the newest anchor it trusts. That
  is correct — it is the security property. What changed is that it now does so while
  keeping its peers, its fork point and its progress. Stale anchor = slow, not broken.
- Verification is still **single-threaded and sequential**. Parallel/batched RandomX across a
  thread pool is not implemented; it is the obvious next win and is not in this change.
- The node lock is still per-block and still serializes verification against RPC and mining.
  The O(N) from-genesis reorg replay is unchanged.
- Numbers above are from the simulated-cost regression test, not from a live mainnet resync.
  A real fresh-node resync against mainnet has NOT been run as part of this change.
