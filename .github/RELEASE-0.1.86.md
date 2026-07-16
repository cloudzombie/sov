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

## 4. RPC JSON consistency — 32-byte fields accept hex (unblocks atomic swaps)

**Today:** the `htlc_lock` action's `hashlock` is a raw `[u8; 32]`, so serde renders it in
JSON as an *array of 32 numbers* — while every other 32-byte field (`Hash`, `AccountId`,
tx-ids) is a **hex string**. A client that hex-encodes the hashlock (as it does for all
other 32-byte fields) is rejected: `invalid SignedTransaction: invalid type: string "…",
expected an array of length 32`. This is the wart that broke the first live XUS↔ZEC swap
(`swap_mrmzgc3t_0`, 2026-07-16) and forced a fragile client-side wire-mutation workaround in
the swap desk. `sov_getHtlc` output is inconsistent the same way — the SDK already expects
`hashlock` back as hex.

**v0.1.86:** change `HtlcLock.hashlock` from `[u8; 32]` to the `Hash` newtype (whose serde is
hex for human-readable/JSON, raw bytes for binary). **Borsh-identical** — `Hash` derives
Borsh over `[u8; 32]`, and `Action` derives Borsh separately from serde, so signatures,
tx-ids, KAT vectors, and genesis `cb0272ff` are byte-for-byte unchanged; only the JSON
representation becomes hex, consistent on both input (`sov_submitTransaction`) and output
(`sov_getHtlc`). Removes the client workaround. (Consider the same for `HtlcClaim.preimage`,
though as a variable-length `Vec<u8>` it already round-trips as an array and works.)
**Node upgrade → ships in v0.1.86.**

## 3. Miner-signaled activation (BIP-9 / BIP-8) wired to the header

**Today:** the `sov-governance` crate is a complete BIP-9/BIP-8 threshold state machine
(`Defined → Started → LockedIn → Active | Failed`), but it is **not wired to consensus** —
the header already carries a `version_bits` field and records it per block, yet nothing
consumes those signals. So every activation (mainnet launch, the v0.1.85 EDA) has to be a
hard-coded flag day.

**Correction after code review:** the machine is in fact **already connected** — `Blockchain`
records the header `version_bits` stream into a `SignalLog`, and `resolved_pq_with()` already
drives the `pq-sunset` deployment by evaluating `sov_governance::state_at(deployment, height,
&signals)`. So BIP-9/BIP-8 miner-signaled activation → consensus is **done today** (the
governance crate's "not yet in the live header" doc comment is stale). Miners already move a
deployment `Defined→Started→LockedIn→Active` by setting its bit in the blocks they mine, with
no operator flag day.

**v0.1.86 therefore adds the missing OBSERVABILITY** (the machinery was invisible):
- `Blockchain::deployment_states()` + a `sov_getDeployments` RPC exposing each deployment's
  name, bit, live `ThresholdState`, window, and LOT flag — evaluated at the current height by
  the *same* `state_at` that gates real activation, so what it reports is what consensus will
  enforce. An operator (and the explorer) can now watch a hashpower vote progress.

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

Remaining audit items: HTLC preimage byte cap, zeroize-on-drop for in-process signing seeds,
`disconnect_to` hard-assert. These are small and land opportunistically.

---

# Major development gaps (post-v0.1.86 roadmap — the REALLY big tickets)

Beyond v0.1.86's P2P work, these are the large, strategic gaps between "a working PoW
cryptocurrency" (which SOV is) and "a complete, trust-minimized, production monetary
network." Each is a multi-day-to-multi-week effort and would be its own release track.
Ranked by leverage. **None requires a genesis change** unless explicitly noted.

1. **Light client / SPV — trust-minimized wallets.** Today every wallet needs a full node
   or must *trust* an RPC endpoint (the relays). There is no header-chain + Merkle-proof
   verification path (only the block header type exists). This is the single biggest
   adoption/decentralization gap: mobile and browser wallets currently trust our relays for
   balances. Ship a headers-only sync + `sov_getProof` (Merkle proof of a tx/account against
   a committed root) so a light wallet verifies without a full node. Pairs with #2.

2. **Efficient sync — headers-first, no genesis replay.** A joining node and any deep reorg
   replay the chain **from genesis** (`rebuild_branch`, O(chain length)); the undo ring only
   covers the last 256 blocks. As the chain grows this makes fresh sync and partition-heal
   costs balloon. Add headers-first download + checkpoint-anchored state sync so a new node is
   usable in minutes, not a full replay. (assumevalid from v0.1.83 helps seal cost, not this.)

3. **xUSD is not production-safe — no liquidation engine + weak oracle.** The CDP stablecoin
   can mint against 150%-collateralized vaults, but there is **no liquidation mechanism** —
   an undercollateralized vault (ZEC/collateral price drop) cannot be liquidated, so the peg
   and system solvency are unprotected. The oracle is a **single key** with only a crude 10×
   circuit-breaker (v0.1.85) — no TWAP, no multi-source median, no staleness bound. Build:
   a keeper-driven liquidation auction + oracle hardening (median-of-N feeds, TWAP, staleness
   rejection). Until then xUSD should be treated as experimental.

4. **Post-quantum shielded pool.** Transparent sigs + transport are hybrid PQ (Ed25519+ML-DSA,
   X25519+ML-KEM), but the shielded pool is Orchard/Halo2 over Pallas — **not** PQ (harvest-
   now-decrypt-later exposure, honestly disclosed). Closing this is a large cryptographic
   effort (a PQ-secure shielded construction) and is the one real hole in the PQ positioning.

5. **End-to-end atomic swap completion (XUS↔ZEC).** The HTLC legs exist on both chains and the
   `lightwalletd` client is written, but no swap has completed end-to-end: the ZEC **sighash
   is unproven** and the running desk isn't wired to a ZEC watcher (no lightwalletd endpoint
   in its config). Prove a ZEC claim/refund sighash against mainnet, wire the desk's ZEC
   observation, and land an acceptance self-swap. (v0.1.86 item #4 unblocks the XUS leg.)

6. **External professional security audit + formal review.** All audits to date are internal
   (adversarial reviews + the redteam gauntlet). Before promoting mainnet as production-grade,
   a reputable third-party audit of consensus, the shielded circuits, and the crypto
   composition — plus economic/emission review — is the missing trust anchor.

7. **Smart-contract platform maturity.** A wasmi VM + host ABI + token composability exist,
   but gas metering hardening, cross-node determinism guarantees under adversarial contracts,
   and a contract-developer SDK/toolchain are unproven at production scale. Decide whether
   contracts are a first-class product; if so, this is a large track of its own.

8. **Hashpower decentralization — mining pool / Stratum.** External miners can't easily join a
   shared pool (no Stratum/pool protocol); today mining is effectively our nodes plus the
   home rig. A pool/Stratum path and public mining docs would let third parties contribute
   hashpower — the real test of "trustless P2P mining."

Cross-cutting operational (not code, but load-bearing): treasury keys should be **cold +
multisig + SLIP-39** (currently hot); and the fleet still needs the home rig + laptop on
v0.1.85 before the 22:00 UTC EDA activation.
