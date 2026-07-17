# SOV v0.1.87 — Fast sync + dead-peer eviction

A small, focused P2P/sync-hardening release: make a fresh node (notably on low-RAM Windows)
sync fast and stop chasing a retired seed's ghost. **Genesis `cb0272ff` unchanged** — both
changes are additive (a weak-subjectivity checkpoint + P2P behavior), no consensus, block, or
KAT change.

## 1. Extended assumevalid checkpoint → height 6800 (fast initial sync)

A fresh node re-runs RandomX seal-verification for every block **at or above the newest baked
checkpoint**. The checkpoint sat at height 5000, so a joining node ground ~1,900 light-mode
RandomX seals (5000 → tip) — minutes of pegged CPU that looked like a hang, worst on machines
with <4 GB RAM (light mode, ~10× slower). We baked a second checkpoint at **height 6800**
(hash `e91b89c6…9bdd89`), whose value was **independently confirmed identical on all three
live relays** (SFO/Frankfurt/Singapore) while it was ~108 blocks deep — far past finality.
`newest_checkpoint_height()` takes the max, so a fresh node now skips seal-verification for
everything below 6800 and finishes in seconds. Weak-subjectivity anchor, not a consensus rule
(a chain reaching 6800 with a different hash is still rejected by the pin).

## 2. Dead-address eviction — retired seeds age out of the mesh

v0.1.86 added exponential dial backoff, which quieted a dead peer's re-dials — but the dead IP
kept **circulating in the `Peers` gossip**: peers re-shared it, so a fresh node re-learned and
re-dialed it every time (the "still dialing the deleted NYC relay `64.225.10.34`" report).
Backoff can't fix that on its own.

v0.1.87: after `DIAL_DEAD_THRESHOLD` (5) consecutive dial failures, an address is **dead** —
refused when re-learned from gossip, filtered out of the gossip we *send* (connect-time
announce + `GetAddr` reply), and dropped from `peers.dat`. Once enough nodes mark a retired
seed dead they stop feeding it to each other, so it **ages out of the entire network** and no
fresh node ever learns it. A single successful connect clears the count, so a peer that merely
had an outage comes right back — this only buries the truly gone.

## Safety

Genesis + KAT byte-identical (checkpoints are additive; the eviction is pure P2P behavior).
Both changes are backward-compatible with v0.1.86 nodes. Coordinated deploy to the three
miners (SFO/Frankfurt/Singapore); the checkpoint is baked in the binary, so a node only gets
the fast-sync benefit once it's on v0.1.87 (relevant for the home rig + laptop).
