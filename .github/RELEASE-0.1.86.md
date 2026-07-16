# SOV v0.1.86 — Real Peer-to-Peer (DRAFT)

> **Status: DRAFT release notes for the weekend deployment.** This describes the intended
> scope; each item is checked off as its code lands and passes the release gate. Nothing
> below changes genesis.

The theme of v0.1.86 is **removing SOV's dependence on its operator.** v0.1.85 proved the
chain can survive a hashpower outage (the Emergency Difficulty Adjustment). v0.1.86 makes
the *network itself* trustless: nodes find each other without hard-coded seeds, announce and
check each other's software version, and any miner can join by pointing at any peer. After
this release, SOV is a self-healing P2P mesh, not a star centered on the seed droplets.

**Genesis `cb0272ff…` is unchanged. Every change here is additive** — new P2P message types
appended to the wire enum (never a reordering or a `Hello` field change), so a v0.1.86 node
and a v0.1.85 node still interoperate during the rollout. The block format, state
transition, and KAT vectors are byte-identical.

---

## 1. Real peer discovery — `getaddr` / `addr` gossip

**Today:** a node only knows the peers hard-coded in its `bootstrap_peers` / spec `seeds`
(the operator's droplets). If those go away, the network can't grow or heal. There is a
one-shot `Peers(Vec<String>)` message but no request for it and no ongoing exchange.

**v0.1.86:** turn `Peers` into a real address-gossip protocol (Bitcoin's `getaddr`/`addr`
model), built on the existing primitive:
- New appended messages: `GetAddr` (request peers) and `Addr(Vec<PeerAddr>)` (share a
  sample of known-good peers, with last-seen timestamps).
- A persistent, capped **address book** (`peers.dat`, tried/new buckets, eclipse-resistant
  by /16 grouping) so a node remembers reachable peers across restarts and doesn't depend on
  a seed after first contact.
- On connect, exchange `GetAddr`; periodically relay a small random `Addr` sample; age out
  stale entries. Self-address and non-routable addresses are never gossiped.
- Seeds become *bootstrap-only* (first contact), not a permanent dependency. Optional DNS
  seeds can be added later without protocol change.

**Result:** point a fresh node at *any* live peer and it discovers the rest of the network
on its own. The topology self-heals when any node — including a seed — drops.

## 2. Nodes broadcast and check their real version

**Today:** the `Hello` handshake authenticates chain-id + genesis + key + channel, but
carries **no software/protocol version**. A v0.1.84 node and a v0.1.85 node handshake
happily and only diverge when one rejects a block — the silent-fork risk we hand-managed
during the v0.1.85 rollout.

**v0.1.86:** nodes announce their version and negotiate compatibility — **without touching
the existing `Hello` encoding** (adding a field there changes its Borsh bytes and would
partition the net; that mistake is explicitly avoided):
- A new appended `Version { protocol_version, agent (e.g. "sov/0.1.86"), services, height }`
  message exchanged right after the encrypted channel is up. Old nodes that don't send it
  are still accepted (backward compatible); new nodes log the peer's real version.
- `sov_getPeerInfo` reports each peer's advertised version and agent string, so the operator
  can see the network's upgrade status at a glance.
- A configurable **minimum protocol version** a node will peer with (default: accept all),
  so a future mandatory upgrade can refuse laggards at the handshake instead of forking them
  silently.

**Result:** the network is version-aware. Rollouts stop being blind.

## 3. Miner-signaled activation (BIP-9 / BIP-8) wired to the header

**Today:** the `sov-governance` crate is a complete BIP-9/BIP-8 threshold state machine
(`Defined → Started → LockedIn → Active | Failed`), but it is **not wired to consensus** —
the header already carries a `version_bits` field and records it per block, yet nothing
consumes those signals. So every activation (mainnet launch, the v0.1.85 EDA) has to be a
hard-coded flag day.

**v0.1.86:** connect the machine to the chain:
- Feed the header `version_bits` stream into `sov-governance` at each retarget-style window
  boundary; evaluate `ThresholdState` from real mined blocks (hashpower, not stake — a
  whale's balance has zero weight).
- Miners signal readiness by setting a deployment bit in the blocks they mine; once the
  threshold is met over a window it **locks in**, then **activates** — no operator flag day.
- Expose deployment status over RPC (`sov_getDeployments`) so activation is observable.

**Honest boundary (chicken-and-egg):** v0.1.86 *itself* cannot be miner-signaled — the
signaling machinery has to be deployed before anything can signal through it. So v0.1.86 is
the **last coordinated upgrade**; it *installs* signaling so that **v0.1.87 and every future
consensus change activate by hashpower vote, never a flag day again.**

---

## Safety

- **Genesis `cb0272ff…` unchanged.** No block-format, state-transition, or KAT change — all
  three items are new P2P messages + a read of the existing `version_bits` field + a new
  address-book file. Release gate's genesis double-lock must pass byte-for-byte.
- **Backward compatible rollout.** New wire messages are appended to the enum (per the
  standing WIRE-COMPATIBILITY rule) and are optional — v0.1.86 nodes interoperate with
  v0.1.85 nodes, so this is **not** a hard flag day and there is no partition risk. Upgrade
  the fleet at a comfortable pace over the weekend.
- Discovery is hardened from day one: capped address book, /16 bucketing against eclipse,
  no gossip of self/non-routable addresses, rate-limited `getaddr`.

## Deployment plan (this weekend)

1. Land + gate each of the three items (peer discovery, version handshake, signaling wiring);
   extend `sov-redteam` with an eclipse/address-flood attack and a version-downgrade attack.
2. Cut `v0.1.86` through `scripts/release-gate.sh --cut` (genesis double-lock + full CI).
3. Roll the binary to relay-1, relay-2, and the Singapore miner (same pattern as v0.1.85:
   `gh run download` the linux artifact, per-box `install` + `systemctl restart`; Singapore
   via the relay-2 SSH jump).
4. Verify via `sov_getPeerInfo` that peers now advertise `sov/0.1.86`, that a node with an
   **empty** `bootstrap_peers` can still discover the network through a single live peer, and
   that `sov_getDeployments` reports the signaling state.
5. Update SOV Station (home rig + laptop) so the whole fleet is version-aware.

## Backlog (tracked, not in v0.1.86)

Efficient headers-first sync (avoid genesis replay on deep reorgs); remaining audit items
(oracle deviation bound / TWAP, HTLC preimage cap, zeroize-on-drop for in-process signing
seeds).
