# SOV v0.1.92 — Pool-mining stack: `sov_getBlockTemplate`/`sov_submitBlock` RPC, a RandomX Stratum bridge, and a decentralized sharechain plan

> **This release starts SOV's pool-mining stack.** Before it, SOV had **no** pool infrastructure
> of any kind — no `getblocktemplate`, no Stratum, no share accounting, no sharechain (verified at
> branch-off: `grep -rli 'stratum\|getblocktemplate' chain/crates` returned nothing; the only
> "pool" in the tree is the *shielded* note pool, an unrelated privacy construct). Every SOV block
> is mined by a node grinding its own template (`MiningCandidate::into_sealed_block`,
> `chain/crates/chain/src/blockchain.rs:206`) — solo mining only. This document is the engineering
> plan for a **work-distribution layer on top of the existing template producer and validated
> import path**. It adds **no consensus rule**. Genesis
> `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` is untouched and stays
> byte-identical; the KAT vectors reproduce byte-for-byte. Phase 1 (the template/submit RPC) is
> **implemented in v0.1.92** (see Section 1 — the contract below is the *landed* one, cited to the
> shipped code, not a sketch); Phase 2 (the RandomX Stratum bridge) is the core follow-on in this
> release line; Phases 3–4 (sharechain + the payout-consensus decision) are scoped and staged
> here, not shipped.

---

## 0) Why pool mining, why now, and which model

SOV's mainnet seal is **RandomX** (`PowAlgo::RandomX`, `chain/crates/pow/src/seal.rs:45`) —
Monero's memory-hard, CPU-friendly PoW. That single fact decides the entire design space:

- SOV is **not** Bitcoin-lineage, so **Bitcoin Stratum and Bitcoin's `getblocktemplate` job shape
  do not apply.** A SOV pool speaks the **Monero/RandomX** Stratum dialect (login/job/submit with
  a hash *blob* + *seed_hash* + *target*), which is what `xmrig` and every commodity RandomX miner
  speak.
- The RandomX lineage also means the right decentralized-pool prior art is **P2Pool (Monero)**,
  not a Bitcoin pool.

**Why now:** solo mining is a variance wall. At mainnet difficulty a small CPU miner may wait weeks
for a block; pools convert that variance into steady small payouts, which is what keeps small,
geographically-spread hashpower on the network — the decentralization SOV's RandomX choice exists
to protect. The July 16 EDA incident (hashpower left, difficulty couldn't follow — see the
v0.1.85 notes) is exactly the failure mode a healthy population of small pooled miners resists.

**Prior art, honestly attributed:**

- **DATUM / OCEAN** (`github.com/OCEAN-xyz/datum_gateway`, MIT C daemon) — *Bitcoin*. DATUM's
  contribution is pushing **template construction to the miner** (the miner builds its own block
  from its own mempool policy) while still relaying shares to a **centralized pool** that does
  accounting and payout via **TIDES** (a PPLNS-family scheme run by the operator). DATUM
  decentralizes *template choice*; it does **not** decentralize *custody or payout* — there is
  still an operator. Good censorship-resistance for block *content*, but a custodial payout desk.
- **P2Pool (Monero)** — a fully **decentralized sharechain**: a low-difficulty P2P side-chain of
  shares with **direct-in-coinbase PPLNS payouts** and **no operator, no custody**. The found
  Monero block's coinbase pays every recent sharer directly, so there is nothing to trust and
  nothing to steal.

**SOV's choice: the P2Pool model — fully decentralized, non-custodial, no operator.** This matches
the reserve-grade ethos (no trusted third party in the value path) and SOV's RandomX lineage. We
do **not** build a DATUM-style custodial pool. The one place SOV differs from Monero — and it is
the crux of this whole plan — is the **coinbase shape** (Section 3): Monero can split its coinbase
across every sharer; SOV's header pays a **single** `proposer` account
(`chain/crates/types/src/block.rs:39`). That constraint drives the payout design and is confronted
head-on, not glossed.

---

## 1) `sov_getBlockTemplate` + `sov_submitBlock` — the RPC contract (Phase 1, **implemented in v0.1.92**)

> **Status: IMPLEMENTED.** Dispatch arms at `chain/crates/rpc/src/lib.rs:1348`
> (`sov_getBlockTemplate`) and `:1401` (`sov_submitBlock`), template cache at `:168`, candidate
> accessors + external-seal methods on `MiningCandidate`
> (`chain/crates/chain/src/blockchain.rs:195-310`), node plumbing at
> `chain/crates/node/src/node.rs:158/:177`. Proven end-to-end by
> `get_block_template_and_submit_block_round_trip_advances_height` and
> `submit_block_whole_header_form_and_coinbase_override_and_unknown_template`
> (`chain/crates/rpc/tests/rpc.rs:257/:304`). Additive, genesis-safe: **new RPC methods and new
> read-only/`Clone` surface only** — no change to any block/header/tx encoding, state root,
> emission, difficulty, chain spec, or KAT.

### What it exposes

The producer already builds everything a pool needs and hands it back *unsealed*:
`Blockchain::build_candidate(transactions, timestamp_ms)` (`blockchain.rs:982`; now a thin wrapper
over `build_candidate_for(…, proposer)` at `:1007`, which lets a template credit an explicit
coinbase account) returns a `MiningCandidate { block, target, pow_algo, pow_key }`
(`blockchain.rs:187`). The only expensive step — grinding `header.nonce` until
`target.is_met_by(seal)` — is deliberately factored **off the chain lock**
(`into_sealed_block`, `blockchain.rs:206`; `try_seal_batch`, `:230`) precisely so it can run
*elsewhere*. A pool is just "elsewhere that isn't this node's CPU."

The pieces an external grinder needs, all on the candidate:

- **The header to grind** — `MiningCandidate.block().header` (`BlockHeader`, `block.rs:24`):
  `height`, `prev_hash`, `tx_root`, `receipts_root`, `state_root`, `timestamp_ms`, `proposer`,
  `version_bits`, `bits: u32`, and the mutable `nonce: u64` (`block.rs:58`).
- **The PoW seed** — `pow_key: Hash`, the RandomX key; on any chain it is the **genesis hash**
  (`pow_key: self.genesis_hash`, `blockchain.rs:1110`). This is the Monero-Stratum **`seed_hash`**.
- **The target** — `target()` (`blockchain.rs:251`), a 256-bit threshold (smaller seal = more
  work), plus the compact `header.bits` already committed into the header.
- **The seal preimage rule** — `BlockHeader::pow_preimage()` = the Borsh bytes of the header
  (`block.rs:73`), hashed by `sov_pow::pow_seal(algo, key, preimage)` (`seal.rs:113`). This exact
  byte string is the Stratum **blob** (Section 2).

### The templateId cache — submit stays tiny and the node stays authoritative

A miner never sends a block body over RPC (untrusted, large, and it must not be able to smuggle in
altered transactions). `sov_getBlockTemplate` **caches the built `MiningCandidate` server-side,
keyed by `templateId` = the unsealed header's hash** (`header.hash()`, `block.rs:64`; headers are
built with `nonce: 0`, `block.rs:126`, so the id is deterministic per template).
`sov_submitBlock` sends back only the grind result; the node reconstructs the block from its own
cached candidate, re-seals with the verify VM, and imports through the **normal validated path**
(`Node::commit_mined`, `node.rs:213` → `import_block`/`import_block_tracked`,
`blockchain.rs:1128/:1138`) — the same path the in-process miner uses. The miner can only ever
supply a nonce (and a rolled timestamp); everything else is the node's own bytes.

The cache (`TemplateCache`, `rpc/src/lib.rs:168`) is a `Mutex`-guarded map with
`TEMPLATE_TTL = 120 s` (`:153`) and `MAX_CACHED_TEMPLATES = 64` (`:158`, oldest-evicted) — sized so
a share against the just-previous job still resolves, while a stale submit fails cleanly with
"unknown or expired templateId — call sov_getBlockTemplate again".

### The landed request/response shapes (the contract the Stratum bridge consumes)

**`sov_getBlockTemplate`** — params: `{ "coinbaseAccount": "<AccountId string>" }` (optional;
`rpc/src/lib.rs:1351`). When present, the template's coinbase is credited to that account (a
pool/finder account — Section 3); otherwise the node's configured miner identity
(`set_coinbase`, `node.rs:52`) is used. The template's timestamp is pre-clamped exactly as the
in-process miner clamps it — `clamp_block_timestamp(now, parent_ts, mtp)` =
`max(now, parent+1, mtp+1)` (`daemon.rs:956`) — so a handed-out template is one import accepts.
Returns:

```json
{
  "templateId":    "<hex 32B — hash of the unsealed header (nonce=0); the cache key>",
  "height":        123456,
  "prevHash":      "<hex 32B>",
  "txRoot":        "<hex 32B>",
  "stateRoot":     "<hex 32B>",
  "receiptsRoot":  "<hex 32B>",
  "timestampMs":   1750000000000,
  "minTimestampMs": 1749999998001,
  "bits":          486604799,
  "target":        "<hex 32B, the full 256-bit target; smaller seal = more work>",
  "powAlgo":       "RandomX",
  "powKey":        "<hex 32B RandomX seed = the chain's genesis hash>",
  "proposer":      "<AccountId string — the coinbase recipient bound into this template>",
  "versionBits":   0,
  "blob":          "<hex Borsh header preimage @ nonce=0 — the exact bytes pow_seal hashes>",
  "nonceOffset":   168
}
```

`blob` + `nonceOffset` are the load-bearing fields for Stratum: the nonce is the **trailing
little-endian u64** of the fixed-tail Borsh header, so `nonceOffset = blob.len() − 8`
(`rpc/src/lib.rs:1379`) and a miner splices candidate nonces in place without ever re-encoding
Borsh in another language. **The offset is template-variable** (the `proposer` AccountId is a
variable-length string field ahead of it), which is why the node computes and returns it rather
than letting a client assume a constant — this matters for miner compatibility (Section 2).
`minTimestampMs` is the consensus floor (`max(parent+1, mtp+1)`, `:1366`) for a miner that rolls
time; rolling below it produces a block import will reject.

**`sov_submitBlock`** — two accepted forms (`rpc/src/lib.rs:1401-1436`):

```json
(a) { "templateId": "<hex>", "nonce": 123456789, "timestampMs": 1750000000000 }
(b) { "header": { …full BlockHeader JSON incl. its nonce/timestamp… } }
```

Form (a) is the normal path: `nonce` is a JSON u64 **or** a hex string with optional `0x`
(`param_u64_flexible`, `:604`); `timestampMs` is optional time-rolling. The node looks up the
cached candidate and calls `MiningCandidate::seal_with_nonce(nonce, timestamp_ms)`
(`blockchain.rs:275`), which re-seals with the verify VM and returns the block **iff** the seal
meets the target. Form (b) is the whole-header fallback for a caller that already holds a sealed
header: the candidate is located by `tx_root` match (`get_by_tx_root`, `:1410`) and sealed via
`seal_from_header` (`blockchain.rs:295`), which enforces `tx_root` equality — the body still never
crosses the wire.

Failure semantics, exactly as landed: an unknown/expired `templateId`, a `tx_root` with no cached
match, or a seal that misses the target is a **JSON-RPC error** (chain untouched — proven by the
unknown-template test at `rpc.rs:313-320`). A block that seals correctly but is **rejected by
import** returns a result object `{ "accepted": false, "hash", "height", "error": "import
rejected: <ChainError>" }`. Success returns `{ "accepted": true, "hash": "<hex>", "height": n }`
after the block has been (1) committed through full validation (`commit_mined` — a tip race files
it on a side branch under heaviest-work fork choice, exactly like any mining race), (2) **appended
+ fsynced to the durable block log fail-closed** before being advertised (`:1443-1456` — the same
SOV-H001 durability rule as the in-process miner; a persist failure means the block is *not*
gossiped), and (3) flooded to the network (`NetMessage::NewBlock`, `:1459-1462`, with the node
lock dropped before I/O, mirroring the tx-gossip path).

**Note for the bridge: there is deliberately no "share" concept in this RPC.** The node only ever
sees full network-difficulty solutions; share targets, vardiff, and share accounting are entirely
the Stratum bridge's business (Section 2). Keeping the node's surface minimal keeps its trust
story minimal.

**Genesis-safety:** both methods are new arms in the same dispatch match as
`sov_getBlockByHeight` (`:806`) and `sov_submitTransaction` (`:1104`). They drive the **existing**
producer and the **existing** validated import path — the same code `produce_once`
(`daemon.rs:1405`) runs — so block bytes, seal rule, difficulty, emission, and state root are
untouched. The additions to consensus crates are `Clone` on `MiningCandidate` plus read-only
accessors and the two externally-driven seal methods (`blockchain.rs:186-310`) — additive surface,
no behavior change to any existing path. `sov-verify` KAT + genesis-pin tests stay green.

### Phase-1 tests (landed)

- `get_block_template_and_submit_block_round_trip_advances_height` (`rpc.rs:257`) — fetch a
  template, grind the trailing-u64 nonce **over the returned `blob` at `nonceOffset`** against the
  returned `target` (the test's `grind` helper at `:362` splices `nonce.to_le_bytes()` in place —
  proving the exact splice contract a Stratum bridge will use), submit, assert `accepted`, and
  assert the chain height advanced through the validated path.
- `submit_block_whole_header_form_and_coinbase_override_and_unknown_template` (`rpc.rs:304`) — an
  unknown `templateId` errors cleanly with the chain untouched; a `coinbaseAccount` override binds
  the proposer into the template and the **imported block** credits that account; the whole-header
  form (b) round-trips (Borsh-decode the ground blob → JSON header → submit).

---

## 2) The RandomX Stratum bridge (Phase 2 — the core follow-on in this release line)

> **Status: DESIGN, next to build.** A new standalone crate/binary `tools/sov-stratum` (mirroring
> the `tools/tx-cannon` / `tools/conformance` pattern — its own crate, off the consensus
> workspace's critical path). **No consensus surface.** It is a TCP daemon that speaks
> Monero-lineage Stratum to RandomX miners on one side and `sov_getBlockTemplate` /
> `sov_submitBlock` JSON-RPC to a SOV node on the other.

### Why Monero Stratum, concretely

Bitcoin Stratum sends a coinbase-split + merkle branch and has the miner assemble a Bitcoin
header; its job shape is Bitcoin-specific and useless here. **Monero (RandomX) Stratum** sends the
miner a ready-to-hash **blob**, a **seed_hash** (the RandomX key), and a **target**, and the miner
grinds a nonce embedded at a known offset in the blob. That is exactly the shape
`sov_getBlockTemplate` already returns: `blob` = blob, `powKey` = seed_hash, `target` = target,
`nonceOffset` = where the nonce lives.

### The blob ⇄ header mapping — and the honest xmrig caveat

- **Blob** = the template's `blob` (hex Borsh of `BlockHeader` @ nonce 0) — the precise byte
  string `pow_seal` hashes (`block.rs:73` → `seal.rs:113`).
- **Nonce** = the trailing little-endian `u64` at `nonceOffset`. The miner mutates only these
  bytes (proven splice-equivalent to re-encoding by the Phase-1 round-trip test).
- **seed_hash** = `powKey` = the genesis hash. RandomX rebuilds its dataset when the seed changes;
  for SOV it is **constant** (genesis-fixed, `blockchain.rs:1110`), so miners build the dataset
  **once** — a real efficiency win over Monero's epoch rotation.
- **Target** = the per-session **share target** the bridge sets via vardiff (never harder than the
  network target from the template).

**The caveat, stated plainly (prove, don't claim):** stock `xmrig` assumes Monero's *block-blob
layout* — a 4-byte nonce at a **fixed** offset 39. SOV's blob is a Borsh header whose nonce is an
8-byte field at a **template-variable** offset (variable-length `proposer` sits ahead of it). So
**unmodified xmrig does not grind the right bytes**, and no bridge-side re-framing can fix that —
the blob *is* the hash preimage; its bytes cannot be rearranged without changing the seal. The
plan therefore ships two miner paths, in order:

1. **A built-in SOV-native worker in the bridge (day one).** The bridge links `sov-pow` and grinds
   with the **fast (full-dataset) RandomX VM** (`pow_seal_mining`, `seal.rs:124` — the same ~10×
   hot-loop VM the in-process miner uses at `blockchain.rs:236`), honoring `nonceOffset` natively.
   Pool mining works immediately with provable correctness, no third-party miner required.
2. **xmrig compatibility via a small, upstreamable patch** — teach the job object an optional
   `nonce_offset`/`nonce_size` extension (miners that ignore unknown fields keep working on
   Monero; patched miners can mine SOV). Until that lands upstream we document a patched build; we
   do **not** claim stock-xmrig support we cannot demonstrate.

**Timestamp discipline:** `timestamp_ms` is inside the blob, so it is part of the hash. The bridge
**freezes the timestamp per job** (from the template's `timestampMs`) and pushes a new job on tip
change or refresh — it does not let miners roll time independently (a rolled time changes the
blob). On submit it passes the job's `timestampMs` through to `sov_submitBlock` so the node
reconstructs the identical preimage via `seal_with_nonce` (`blockchain.rs:275`).

### Stratum method surface (Monero dialect)

- **`login`** → assign a session; send the first job `{ job_id (= templateId), blob, seed_hash,
  target, height }`.
- **`job` (push)** → new template on tip change / template refresh (the bridge polls or is nudged;
  templates naturally rebuild per tip exactly as the solo miner's do); miners abandon the old blob.
- **`submit`** `{ job_id, nonce, result }` → bridge-local share validation; if the seal also meets
  the **network** target, forward `sov_submitBlock { templateId: job_id, nonce, timestampMs }`.
- **`keepalived`** → session heartbeat.

### Vardiff + share validation

The bridge runs **vardiff** per connection, targeting ~1 share every N seconds by tuning each
session's share target (numerically ≥ the network target — i.e. easier). For each `submit`:

1. Splice `nonce` at `nonceOffset` into the job blob.
2. Seal locally — the bridge depends on `sov-pow` and calls the same `pow_seal(RandomX, seed,
   blob)` (`seal.rs:113`) the importer uses — and compare against the **share target**. Never
   trust the miner's `result` field; recompute. A valid share earns PPLNS weight (Section 4)
   without ever touching the node.
3. If the same seal also meets the **network target** (from the template's `target`), forward to
   `sov_submitBlock` — the node re-validates everything on import anyway. **A block is just a
   share that also cleared network difficulty** — the standard pool invariant.

### Files / tests (Phase 2)

- **Add** `tools/sov-stratum/` (new crate, own `Cargo.toml`; no edits to workspace version
  fields). Depends on `sov-pow` (share validation + native worker), `sov-mining` (`Target`),
  `sov-primitives`/`sov-types` (hex/header round-trips), and a small JSON-RPC client. Async TCP
  Stratum server.
- **Tests:** blob-splice round-trip (splice at `nonceOffset` == Borsh re-encode of the header with
  that nonce — the same invariant Phase 1 proves from the node side, now proven from the bridge
  side); a share meeting the share target but not the network target is credited and **not**
  forwarded; one meeting the network target is forwarded to a mock `sov_submitBlock` with the
  job's frozen `timestampMs`; vardiff raises/lowers a session target under fast/slow share
  arrival; a submit against a superseded job is rejected as stale.
- **Genesis-safety:** nothing in this crate can alter a block — it can only relay a nonce the node
  independently re-seals and fully re-validates.

---

## 3) The hard problem — payout under a single-recipient coinbase

**This is the crux.** SOV's coinbase pays **one** account: `BlockHeader.proposer: AccountId`
(`block.rs:39`) is the sole coinbase claim, and the runtime credits **100% of coinbase + fees to
that one account** (`apply_coinbase` — applied first in the build path, `blockchain.rs:1050`;
cross-referenced in the v0.1.90 notes at `execution.rs:1540` / `mining/src/lib.rs:171`). There is
**no multi-output coinbase**, no coinbase-split `Action` variant, and genesis is frozen. So
**P2Pool's "pay every sharer directly in the coinbase" is structurally impossible on SOV as-is.**
That is the honest constraint; here are the real options.

### (a) Coordinated hard fork to a multi-output coinbase — most trustless, biggest lift

Change consensus so a block carries a coinbase paying an ordered set of `(AccountId, amount)`
outputs summing to `reward + fees`, with the split **verified by the importer**. This is the true
P2Pool design: the found block *is* the payout — atomic, trustless, no follow-on transactions.

- **Cost:** it changes the block/coinbase encoding and the STF → it **forks every un-upgraded
  node** and **breaks the frozen genesis KAT**. It must ship behind a **miner-signaled
  activation** — the exact mechanism SOV already has (`PqDeploymentConfig` /
  `sov_governance::Deployment`, `blockchain.rs:317`; the same discipline as the v0.1.86 activation
  and the PQ sunset) — and to *nobody* until miners cross the threshold. Biggest engineering +
  coordination lift; highest assurance.
- **Verdict:** the **ideal long-term** endpoint, but not a v0.1.92 item. It belongs to Phase 4
  with its own spec, KAT vectors, and activation, alongside the consensus items disclosed in the
  v0.1.90 coordinated-fork bundle.

### (b) NO consensus change — payout enforced by *sharechain rule*, not by the coinbase — RECOMMENDED

Keep the single-recipient coinbase exactly as frozen. The block **finder** receives 100% into the
coinbase. Trustlessness comes not from the coinbase shape but from the **sharechain's own
consensus rule**: a solved share is only a **valid** sharechain block if the SOV block it carries
**also includes the correct PPLNS payout transactions** — ordinary `Transfer` actions from the
finder to each account in the recent-share window, in the exact PPLNS-weighted amounts every
sharechain peer computes deterministically.

- The sharechain **rejects** any solved share whose embedded SOV block omits, under-pays, or
  mis-addresses those payouts. A finder physically *can* keep the coinbase (SOV consensus lets
  them), but then their block earns **no share credit and is orphaned by every honest sharechain
  peer** — they forfeit their standing in the very pool paying them. Including the payouts is the
  economically rational move for a *continuing* participant.
- **Honest limit — this is cryptoeconomic enforcement, not atomic trustlessness.** SOV's main
  chain accepts a finder's block *regardless* of whether it embeds the payouts (the coinbase pays
  the finder 100%; the payout is separate `Transfer`s the sharechain — not consensus — polices).
  So a finder who is *exiting the pool*, or who lands a large fee-spike block where the one-time
  coinbase grab exceeds the discounted value of future share credit, **can publish-and-omit and
  keep everything**. The penalty is only forfeited future PPLNS standing. This is the same
  incentive model that secures most PPLNS pools, and it is strong for steady participants — but it
  is **not** P2Pool's atomic "the block *is* the payout" guarantee. Genuine atomic trustlessness
  requires **option (a)** (the multi-output coinbase hard fork). We ship (b) as the genesis-safe
  default and treat (a) as the long-term ideal, stated plainly rather than overclaimed.
- Payouts ride **in the same found block**, funded by that block's own coinbase. This works
  because SOV's producer **applies the coinbase before executing transactions** — verified in
  code: "The coinbase is applied to the probe first, mirroring final execution exactly (a
  transaction may spend coinbase-funded balance)" (`blockchain.rs:1039-1050`, and pass 2 at
  `:1074`, "coinbase first, exactly as import will"). Net effect: the finder nets their PPLNS
  share; everyone else in the window is paid by transfer in the block that pays the finder.
  **Trustless-by-sharechain-rule**, though *not atomic-in-coinbase* — the one honest caveat vs (a).
- **Residual trust surface (disclosed):** (1) the finder can *withhold* a solved block entirely —
  the classic block-withholding attack, which P2Pool also has; the sharechain's short share
  interval makes withholding costly and statistically detectable. (2) The mempool/producer must
  admit the finder's payout transfers into the found block itself — the pool's template flow does
  this by construction (the payouts are part of the template the finder grinds, built via
  `sov_getBlockTemplate` on a node whose mempool the pool feeds). (3) Payout transfers consume the
  finder's nonces and pay normal fees — accepted overhead, priced in the window math.
- **Cost:** **zero consensus change** — payouts are plain `Transfer` actions the STF already
  executes; enforcement lives entirely in the new, off-consensus sharechain (Section 4). Genesis +
  KAT byte-identical.
- **Verdict:** the **genesis-safe path** — decentralized, non-custodial PPLNS with no fork and no
  operator, shippable without waiting on coordination.

### (c) Smart-contract escrow/splitter via the existing WASM VM + multisig

Route the coinbase (`coinbaseAccount` override, Section 1) to a **contract/multisig account** that
accumulates rewards and splits them per an on-chain rule, using SOV's existing WASM VM and M-of-N
multisig (`SetMultisig`/`MultisigExec`; contract storage is write-priced,
`state/src/ledger.rs:335`).

- **Cost:** no new consensus action, but it reintroduces **custody-in-flight** (funds sit in the
  contract between block and split) and a **governance surface** (who controls splitter policy /
  the multisig keys) — precisely the operator-trust P2Pool exists to eliminate. It also puts value
  custody on contract execution, a higher assurance bar than plain transfers.
- **Verdict:** viable for a *permissioned/consortium* pool; **more trusted than (b)** and
  off-mission for the non-custodial design. Documented, not pursued.

### Recommendation

**Ship (b)** — sharechain-enforced PPLNS payouts under the frozen single-recipient coinbase — as
the genesis-safe route, and **stage (a)** — the multi-output coinbase — as the ideal long-term
endpoint behind a miner-signaled activation (Phase 4). (b) delivers a working P2Pool-class pool
with no consensus change and no operator; (a) later upgrades the payout from
"enforced-by-sharechain-rule" to "atomic-in-coinbase" once a fork is justified on its own merits.
(c) is recorded for completeness only.

---

## 4) The decentralized sharechain (Phase 3, scoped here — built after Phases 1–2)

The sharechain is a **low-difficulty P2P side-chain of shares** — a second, faster chain whose
"blocks" are shares. It is **entirely off SOV consensus**: it never changes a SOV block, and a SOV
node validating the main chain neither knows nor cares that it exists. It reuses SOV's existing,
battle-tested pieces rather than inventing new machinery.

### What a share commits to

A **share** is a candidate SOV block (built via `sov_getBlockTemplate`) whose seal meets a **share
target** (≫ easier than network), plus sharechain metadata:

- the SOV `templateId`/header it ground — so any peer verifies the seal with the same
  `sov_pow::pow_seal` call the importer uses (`seal.rs:113`);
- the **finder's payout account**;
- the **previous share** hash (the sharechain's own `prev_hash`) and recent **uncles**;
- the **PPLNS window** implied by its sharechain position — recomputed deterministically by every
  peer, never trusted from the finder.

When a share *also* meets the **network target**, the SOV block it carries **must embed the PPLNS
payout transfers** for the current window (Section 3(b)); the sharechain validity rule rejects it
otherwise. That is where trustless payout is enforced.

### Difficulty adjustment, uncles, orphans

- **Retarget:** reuse SOV's **LWMA-1** (`Difficulty::lwma`,
  `chain/crates/mining/src/difficulty.rs:93` — the same Monero-lineage algorithm the main chain
  runs), tuned to a short share interval (~10 s) so shares are frequent and payout variance low.
- **Uncles:** as in P2Pool, near-simultaneous shares that miss the tip are included as **uncles**
  and still earn PPLNS weight, so slower-linked miners aren't structurally penalized and the
  sharechain doesn't centralize toward the best-connected peer. Sharechain-local rule; never
  touches SOV consensus.
- **Orphans:** a share on a stale sharechain tip is reorged out by cumulative share-work — the
  heaviest-work fork choice SOV already uses on the main chain, re-applied to the sharechain's own
  work metric.

### PPLNS window

**Pay-Per-Last-N-Shares:** payout weight is each account's fraction of the last **N** shares (by
share-work) at the instant a block is found. N spans a few main-chain block-times of shares —
variance stays low and pool-hopping is unprofitable (the defining PPLNS property). The window is a
pure function of the sharechain, so a cheating finder cannot fabricate weights: any block whose
embedded payouts diverge from the deterministic computation is rejected by rule.

### Reuse of existing SOV pieces (no new crypto in the trust path)

- **P2P transport:** the `sov-network` stack (Noise/ML-KEM, domain-bound handshake —
  `network/src/message.rs:236`) carries sharechain gossip on its own logical channel — the same
  hardened transport as the main chain, not a second networking stack.
- **Sealing:** `sov-pow` `pow_seal`/`pow_seal_mining` (`seal.rs:113/:124`) — a share and a block
  are the *same* RandomX computation at different targets.
- **Retarget:** `sov-mining` LWMA-1 (`difficulty.rs:93`), as above.
- **Payouts:** plain `Transfer` actions the STF already executes — no new action, no VM
  dependency on path (b).

### Files / tests (Phase 3)

- **Add** `tools/sov-sharechain/` (or `chain/crates/sharechain/` if first-class types warrant it —
  **an additive crate either way**; consensus crates' behavior is never edited). Depends on
  `sov-network`, `sov-pow`, `sov-mining`, `sov-types`. Runs beside the Stratum bridge: the
  bridge's shares feed the sharechain; the sharechain computes the PPLNS window and dictates the
  payout transfers embedded in network-target templates.
- **Tests:** deterministic PPLNS window (same share history ⇒ identical weights on every peer); a
  network-target share embedding **wrong** payouts is rejected by the validity rule (the
  cheating-finder test); uncle inclusion earns proportional weight; sharechain LWMA holds the
  share interval under swinging hashrate; heaviest-share-work reorg drops an orphaned branch.
- **Genesis-safety:** the sharechain is a wholly separate P2P chain importing **zero** consensus
  risk. The only SOV-visible artifacts are ordinary blocks from the existing producer carrying
  ordinary `Transfer` transactions — indistinguishable to a SOV node from any other block. KAT and
  genesis untouched.

---

## 5) Payout-consensus decision (Phase 4 — disclosed, not shipped)

The only part of this plan that could ever touch SOV consensus is the **optional** upgrade from
Section 3(b) (sharechain-enforced payouts, genesis-safe) to Section 3(a) (**multi-output
coinbase**, atomic, forking). Phase 4 is that decision:

- **Default:** stay on (b) — zero consensus change, non-custodial, working. No action required.
- **If (a) is chosen** (atomic-in-coinbase payout, eliminating the finder-withholding surface): it
  is a **coordinated hard fork** — new coinbase encoding + STF verification — shipped behind a
  **miner-signaled activation** (`sov_governance::Deployment` / `PqDeploymentConfig`,
  `blockchain.rs:317`), to nobody until the signaling threshold is met, with cross-impl KAT
  vectors proving the new coinbase across the Rust node and the TS second client. It belongs with
  the other consensus items in the v0.1.90 coordinated-fork bundle — **not** in v0.1.92.

**No payout-consensus change ships in v0.1.92.** This release delivers the genesis-safe stack
(Phase 1 landed, Phase 2 next, Phase 3 scoped) and records the fork option honestly for a future
coordinated activation.

---

## Phased delivery summary

| Phase | Deliverable | Where | Consensus surface | Status |
|------|-------------|-------|-------------------|--------|
| **1** | `sov_getBlockTemplate` + `sov_submitBlock`, `TemplateCache`, external-seal methods | `chain/crates/rpc/src/lib.rs:148-207/:1343-1472`, `chain/crates/chain/src/blockchain.rs:186-310`, `chain/crates/node/src/node.rs:158-211` | **None** — new RPC onto the existing producer + validated import | **Implemented in v0.1.92** (tests `rpc.rs:257/:304`) |
| **2** | RandomX Stratum bridge (Monero dialect, vardiff, local share validation, native worker) | new `tools/sov-stratum/` | **None** — relays a nonce the node re-seals + re-validates | v0.1.92 line, next to build |
| **3** | Decentralized sharechain + PPLNS, sharechain-enforced payouts (option b) | new `tools/sov-sharechain/` (reuses `sov-network`/`sov-pow`/`sov-mining`) | **None** — separate P2P chain; SOV sees only ordinary blocks with ordinary `Transfer`s | scoped, after Phase 2 |
| **4** | Payout-consensus decision: keep (b), or fork to multi-output coinbase (a) | `chain` consensus, miner-signaled activation | **(a) only:** hard fork, KAT-affecting → activation-gated | **disclosed, not shipped** |

**Genesis discipline across all phases:** everything in Phases 1–3 is **additive** — new RPC
methods, new standalone crates, new read-only accessors/`Clone` — with **no** change to any
block/header/transaction encoding, state root, emission, difficulty, chain spec, or KAT vector.
Genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` stays byte-identical
and the `sov-verify` KAT + genesis-pin tests must be green at every phase gate. The one
consensus-affecting option (Phase 4(a)) is quarantined behind a miner-signaled activation and
ships to nobody until all miners upgrade together — the same discipline as the v0.1.86 activation,
the PQ sunset, and the v0.1.90 coordinated-fork bundle.

**Prove, don't claim:** every behavioral addition carries a named test. Phase 1's blob/nonceOffset
splice contract is already proven from the node side (`rpc.rs:257/:362`) and will be re-proven
from the bridge side in Phase 2; the sharechain's PPLNS window will be proven deterministic and
its payout rule proven to reject a cheating finder before any of it is called working. Where a
compatibility claim cannot yet be demonstrated (stock xmrig), this document says so instead of
claiming it.
