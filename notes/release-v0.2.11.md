# SOV / SOV Station v0.2.11 — release notes (DRAFT)

_Drafted 2026-08-08 against `main` @ `eb51cd6` (v0.2.10 + the 15872 anchor refresh), live mainnet
tip **19,511**. One version source: `node/Cargo.toml`. SOV and SOV Station ship as one release._

**Contents:** §1 node memory (release-blocking) · §2 P2P/relay/sync hardening · §3 Station private
balance chips · **§3A address checksums, every field, every type** · §4 minors · §5 explicit
non-goals · §6 safety bar · §7 order of work · §8 open question.

**This release changes NO consensus rule.** Genesis
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` stays frozen. No new signal
bit is defined, nothing is armed, no deployment schedule moves, and the signal mask stays
`0b1111`. Every change below is **node-local, display-only, test-only, or ops**. The state
transition function is byte-identical to v0.2.10 — that is the acceptance bar, not an aspiration
(§6).

---

## 0. Why this release exists

v0.2.10 **cannot be deployed.** The upgrade was attempted on sfo3 on 2026-08-06 and rolled back:
the binary OOM-kills ~21 s into startup, before it emits a single log line, on a 2 GB node
(details in [2026-08-06.md](2026-08-06.md) FINDING 4). Consequences, all live right now:

- Both droplets still run a **pre-0.2.6** binary (`sha256 2969de29…`).
- `tx-timestamp` (bit 3) has been **Active since h18432**. The fleet does not know the deployment
  exists, so it would reject any block carrying an `Action::Timestamped` — a latent split with
  the fleet on the losing side. Dormant only because no client can construct that envelope yet.
- The baked anchor is **15872** against tip **19,511** — lag **3,639**, far past the release
  gate's `CP_MAX_LAG` of 2000. The gate will refuse `--cut` until it is refreshed.

So v0.2.11 has exactly one job that outranks everything else: **be a release the fleet can
actually run.** Every other item is chosen to be provably safe alongside it.

---

## 1. Node memory — make the node runnable on a 2 GB host again  ★ RELEASE-BLOCKING

### 1.1 What was found (verified in the tree, 2026-08-08)

The node keeps **four unbounded, height-linear structures resident in RAM**, in
`chain/crates/chain/src/blockchain.rs`:

| field | line | what it holds | grows with |
|---|---|---|---|
| `blocks: Vec<Block>` | 41 | the entire active chain, **full block bodies**, genesis..head | chain height |
| `index: HashMap<Hash, BlockIndexEntry>` | 48 | **every block ever accepted**, including lighter side branches | height + forks |
| `active_receipts: HashMap<u64, Vec<Receipt>>` | 149 | receipts for **every** active block | chain height |
| `tx_height: HashMap<Hash, u64>` | 152 | **every transaction hash** ever seen, → height | total tx count |

This is not a v0.2.10 regression — it is the standing design. What v0.2.10 did was push a 2 GB
host over the line. Blocks are large on this chain (PQ signatures ~10.8 KB/tx; a pool-v2 bundle
is ~115 KB, measured), so at 19.5k blocks the resident set is already near the ceiling.

**Honest limit: the v0.2.5 → v0.2.10 delta is NOT yet isolated.** Established facts only:
v0.2.5 runs at **898 MB steady** on the same host at the same height; v0.2.10 dies before its
first log line, with systemd recording peaks of 483 M / 918 M / 1.4 G across restarts. The
light-mode guard is **not** implicated — it correctly demoted (1.65 GB available < the 2.6 GB
`FAST_DATASET_MIN_AVAIL_BYTES` at `chain/crates/pow/src/seal.rs:62`) and the process never
reached mining. Candidate contributors not yet separated: v0.2.7's `BlockImporter` + verifier
thread + bounded queue, v0.2.7's `assumevalid.dat` adoption (which re-verifies against the
replayed chain at boot), and v0.2.6's `Receipt::timing` field widening every stored receipt.

### 1.2 Step 1 — MEASURE before changing anything (gate on this)

No allocation is touched until we can attribute it. Deliverable, in-repo and repeatable:

- A `scripts/measure-startup-memory.sh` harness that boots a given binary against a **copy** of a
  mainnet-sized store and records peak RSS to first-log-line and to steady state.
- A table across **v0.2.5, v0.2.6, v0.2.7, v0.2.8, v0.2.9, v0.2.10** at the same height, so the
  regression is attributed to a release rather than guessed at.
- Per-structure accounting at steady state for the four fields above.

**This measurement is a release gate.** If it does not identify the delta, the memory work is
deferred and v0.2.11 ships §2–§5 only, with the fleet staying on its current binary and the bit-3
hazard managed by the standing "do not broadcast `Timestamped`" rule. Shipping a guessed fix into
the only public relay is exactly the failure mode that took the relay down on 2026-08-06.

### 1.3 Step 2 — the conservative fix

Scoped to what is provably behavior-preserving:

1. **Bound the in-memory receipt cache**, backed by on-disk lookup. `active_receipts` becomes a
   bounded LRU over recent heights; anything evicted is served from the persisted snapshot /
   block log. **Hard requirement: `sov_getReceipt`, `sov_getBlockReceipts`, and
   `sov_getReceiptProof` return byte-identical JSON for every height, before and after.** A
   receipt that is currently answerable must stay answerable — pinned by a test that queries a
   receipt from below the eviction window.
2. **Bound `tx_height`** the same way, with the same "answers do not change" requirement for
   `sov_getReceipt` by tx id.
3. **Fix whatever §1.2 attributes**, narrowly.

**Explicitly NOT in v0.2.11:** restructuring `blocks` or `index`. Moving block bodies out of RAM
touches fork choice, reorg replay and the checkpoint linkage proof at once. It is the right fix
and it is a v0.3 change with its own audit — not a passenger on the release that has to unbreak
the fleet.

### 1.4 Step 3 — a guard so it cannot silently rot again

A startup check that logs resident-set size against host RAM and **warns loudly** past a
threshold, plus a release-gate assertion that peak startup RSS on a mainnet-sized store stays
under a budget. The anchor guard (`CP_MAX_LAG`) is the model: it caught the stale anchor exactly
as designed on 2026-08-02. Memory deserves the same tripwire.

---

## 2. P2P / relay / sync hardening

### 2.1 A SECOND PUBLIC RELAY  ★ highest-value item in this release

**The network has one publicly reachable RPC — sfo3.** fra1 binds RPC to loopback; sgp1 was
destroyed 2026-07-31. This single fact is behind three separate problems already in the notes:

- `scripts/refresh-checkpoint.sh` cannot complete its **two-independent-relay** confirmation
  without a human doing the second leg over SSH, which is why the anchor silently rotted until
  the release gate caught it (`9eee9d9`).
- There is no v0.2.6+ node to query for authoritative deployment state — establishing bit 3's
  status required counting `version_bits` over 864 blocks by hand.
- A sfo3 suspension (the DO bill) takes out the public entry point **and** ~13% of hashpower at
  once.

Deliverables: stand up a second public relay; either expose fra1's RPC behind the same
allow-listed read-only surface or add a third host. Then make `refresh-checkpoint.sh` complete
its two-relay rule **unattended**, and keep its existing refusal-on-disagreement behavior.

This is ops, not code, and it is deliberately listed first: it removes a single point of failure
that no amount of node hardening addresses.

### 2.2 Re-enable the fresh-node sync regression test

`fresh_node_syncs_across_many_batch_boundaries_despite_losing_its_only_peer`
(`chain/crates/rpc/tests/p2p.rs:1120`) was marked `#[ignore]` in v0.2.8 (`4ee8add`) because
real-TCP timing could red a release on a slow CI runner. It is the **only** end-to-end guard on
the exact failure that has now bitten this project four times.

Make it deterministic rather than ignored: drive it on a simulated clock / explicit step
barriers instead of wall-clock sleeps, then return it to the default set. Same for the three
`#[ignore]`d fork-recovery tests in `chain/crates/rpc/src/p2p.rs` (lines 3490, 3664, 3839) —
including the one that pins the sgp1 incident shape. A regression test that does not run is not
a regression test.

### 2.3 Measure and bound reorg replay cost (measurement only in 0.2.11)

`Blockchain::rebuild_branch` (`blockchain.rs:2856`) walks ancestors `while cursor !=
self.genesis_hash`, clones `genesis_ledger`, and **replays every block from height 1**. It is not
O(depth) — it is **O(chain height), from genesis, for any reorg at any depth**. At 19.5k blocks a
one-block reorg replays the entire chain.

This is the amplifier behind the sync-fork-poisoning timeouts and the long-standing "O(N) reorg"
debt. **The fix is not in this release** — snapshot-anchored replay changes the code path that
decides which chain is canonical, and it needs its own design, audit and byte-identical proof.

In v0.2.11: instrument it. Log reorg depth, replayed-block count and wall-clock; add a benchmark
so the cost is a tracked number rather than folklore. Then write the design for v0.2.12
(periodic ledger snapshots so replay starts from the nearest snapshot below the fork point,
with a test asserting the resulting state root is identical to a from-genesis replay).

### 2.4 Relay observability

`sov_getPeerInfo` exists but nothing routinely reads it. Add a small `scripts/fleet-health.sh`
that, for each relay, reports height, peer count, deployment states, binary version and
`MemAvailable` in one table. Every incident this session began with hand-assembling that picture
from five separate calls. Cheap, read-only, and it makes fleet drift visible before it becomes a
split.

### 2.5 No P2P constant changes

`SYNC_BATCH` (256), `SYNC_BATCH_MAX_BYTES` (6 MiB), `BLOCK_REQUEST_TIMEOUT` (2 s),
`PEER_INACTIVITY_TIMEOUT` (45 s), `HEADERS_BATCH` (2000), `LOCATOR_CAP` (32), the penalty
weights and the stall-credit budget are **unchanged**. They were tuned against real incidents in
v0.2.7/v0.2.8 and there is no evidence in hand that any of them is wrong. Retuning them in the
release that must unbreak the fleet would confound the one variable we need to trust.

---

## 3. SOV Station — private balances back on the wallet chips

### 3.1 The defect

`balance_card` (`node/src/gui.rs:9627`) computes the private-balance chip like this:

```rust
let shielded = self
    .shielded                                  // <-- pool v1 (Orchard) ONLY
    .lock().ok()
    .map(|m| m.view_for(&account))
    .filter(|v| v.account == account && v.balance > 0)
    .map(|v| grains_to_xus_plain(u128::from(v.balance)));
```

Two independent bugs:

1. **It never reads `shielded_v2`.** The field exists (`gui.rs:3667`) and is scanned
   (`scan_shielded_v2`, `gui.rs:4929`), but the chip only consults pool v1. Pool v2 went **Active
   at h15552** and is where value actually sits — the auditor confirmed real v2 shields of 25,
   500 and 50 XUS and a 525 XUS de-shield on mainnet. **A wallet holding only pool-v2 value shows
   no private chip at all.** That is the reported "can't see private balances".
2. **`balance > 0` conflates "scanned and empty" with "never scanned."** The codebase already has
   the right accessor — `own_figures()` (`gui.rs:2607` for v1, `gui.rs:2845` for v2) returns
   `Some` only when the view was scanned **for this wallet** and `scanned_height > 0`. The chip
   bypasses it and hand-rolls a weaker check.

### 3.2 The fix

- Read **both** pools via `own_figures(&account)`, so the chip is driven by the same accessor the
  panels use.
- Show **two distinct chips** — `🛡 v1 private` and `🛡 v2 private` — never a single summed
  figure. Summing across pools would invent a number the chain does not have and would hide which
  pool the value is spendable from.
- Render three states honestly, per the convention already established in v0.2.9:
  **unscanned → `—` / "scan to view"** (never `0`), **scanned-and-empty → a real `0`**,
  **scanned-with-value → the figure**.
- Keep `ShieldedV2View::guard()`'s zeroing of foreign views and the per-account
  `ScannedPools` keying **exactly as-is** — that isolation was the v0.2.9 fix and this change
  must not weaken it. Regression test: wallet A's chip never renders wallet B's figure.

### 3.3 Related Station items

- Make the private chips **click-through** to the matching pool panel.
- Surface `scanned_height` next to the chip, so a stale scan is visible as stale rather than
  reading as current truth.

---

## 3A. Address checksums — every address field, every type  ★ OWNER-REQUESTED

### 3A.1 What is ALREADY protected (good news first)

**Every shielded address type already carries a real checksum.** `chain/crates/shielded/src/address.rs`:

| form | prefix | encoding | checksum |
|---|---|---|---|
| Shielded (Orchard, v1) | `xus1…` | bech32m | 30-bit |
| Unified | `uxus1…` | bech32m | 30-bit |
| **Pool-v2 PQ** | `xusq1…` | bech32m (`Bech32mLong`) | **30-bit** |

The giant PQ address is **not** the weak link. A pool-v2 address is 1,216 bytes of ML-KEM key
material (~1,950 characters), which exceeds the 1023-character bound the `bech32` crate enforces —
so `Bech32mLong` raises `CODE_LENGTH` while **reusing the crate's Bech32m checksum engine
verbatim**: same generator polynomial, same target residue, nothing hand-rolled. This is the same
choice Zcash makes for unified addresses (ZIP-316).

What that buys, stated precisely: a corrupted `xusq1…` address is accepted with probability
**~2⁻³⁰** (about 1 in a billion), and the existing tests exercise **every single-character
substitution position on a full-length v2 address and assert every one is rejected**. Case
handling and HRP separation are unchanged.

What is honestly given up: beyond the BCH code length the checksum no longer *guarantees*
detection of up to 4 errors. It is a probabilistic 30-bit guarantee, not a combinatorial one.
That is inherent to the size of a lattice KEM address, not a design shortcut — no encoding of
1,216 bytes can meet the bound.

**So: a `xusq1…` that decodes is essentially certainly the address that was typed.** The UI's job
is to *say so*, which it currently does not (§3A.3).

### 3A.2 The real gap — transparent accounts have NO checksum at all

`AccountId::validate` (`chain/crates/primitives/src/account.rs:79`) checks only:

- length within `3..=64`;
- characters are ASCII lowercase, digits, or `- _ .`;
- no leading/trailing separator, no adjacent separators.

**There is no checksum, and none is possible to add on-chain without a hard fork.** An implicit
account id is 64 raw lowercase hex characters. Mistype one character and the result is *still*
64 characters, *still* lowercase hex, *still* a perfectly valid `AccountId` — pointing at an
account nobody holds a key for. Value sent there is permanently unspendable, with no error at any
layer.

This is not hypothetical: the 2026-08-06 sweep moved **3,262 XUS** to
`a35755d3…4c1e24`, pasted as raw hex, with zero checksum protection anywhere in the path. It
worked because the string was copied, not typed. That is luck, not engineering.

### 3A.3 The design — a checksummed *presentation* layer, zero consensus surface

`AccountId` is consensus. Its format is genesis-frozen and **will not change in this release or
any patch release.** The fix is the same one Bitcoin and Ethereum arrived at: leave the on-chain
identifier alone and put a checksummed encoding in front of it, at the wallet boundary.

1. **New transparent address form `xust1…`** — the 32-byte account id encoded with the **same
   audited bech32m engine** already used for `xus1`/`uxus1`/`xusq1`, under a new HRP. Decoding
   yields the identical raw hex `AccountId` that goes on the wire, so **the chain sees byte-identical
   transactions** and no node needs to understand the new form. Round-trip property to test:
   `decode(encode(id)) == id` for every account id, and `encode` is canonical lowercase.
2. **Raw 64-hex stays accepted forever.** Every existing address, script, key file, runbook and
   third-party tool keeps working unchanged. This is a strictly additive input format.
3. **But raw hex is visibly marked as UNVERIFIED.** When a field holds raw hex, the UI says so —
   *"no checksum: this address cannot be verified, check it character by character"* — and offers
   the `xust1…` equivalent to copy instead. The warning is the point: the operator should feel the
   difference between a checked and an unchecked address.
4. **An EIP-55-style mixed-case hex form is explicitly rejected as the primary answer.**
   `validate` requires lowercase, so mixed-case hex can never be an `AccountId`; it could only be
   a display convention, and carrying two competing checksum schemes for one identifier is worse
   than one good one. Note it as considered-and-declined so it is not re-proposed.

### 3A.4 Uniform address-field behavior — every field, every type

One shared widget, used by **every** address input in Station (transparent send, private send,
shield/de-shield recipient, HTLC counterparty, name/NFT targets, multisig members, oracle and
vault fields), with identical semantics everywhere:

- **Live per-keystroke state** — one of: `EMPTY`, `INCOMPLETE`, `✔ VALID <kind>`,
  `✖ INVALID: <exact reason>`. Never a bare "invalid".
- **Name the kind on success**, so the operator sees *what* they pasted: `✔ VALID · pool-v2 PQ
  (checksum OK)`, `✔ VALID · shielded v1`, `✔ VALID · unified`, `✔ VALID · transparent
  (checksummed)`, `⚠ VALID FORM · transparent raw hex — UNCHECKED`.
- **Surface the real decode error.** `AddressError` already distinguishes `Encoding` (checksum
  failure), `WrongKind` (with expected vs. got prefix), `Payload`, `NoKnownReceiver`,
  `DuplicateReceiver` and `V2Chunking` — every one is diagnosable. Render them; do not collapse
  them.
- **Wrong-kind is a first-class message**, not a validation failure: pasting a `xusq1…` into a
  transparent field should say *"this is a pool-v2 PQ address — use the private send tab"*, not
  "invalid address".
- **Truncation guard.** A `xusq1…` is ~1,950 characters and is the address most likely to be
  clipped by a chat client, terminal wrap or spreadsheet cell. Detect a short-but-well-formed
  prefix and say **"this address looks TRUNCATED"** rather than reporting a checksum failure —
  the operator's next action differs completely.
- **Elide, never silently reshape.** Long addresses display head…tail (the v0.2.9 outbox fix);
  the full value must remain copyable, and eliding must never reach the value that gets signed.

### 3A.5 Confirmation proportional to risk

- A **re-paste/confirm step** on the recipient for sends above an operator-set threshold: the
  address must match a second entry before the send arms.
- **Show the decoded kind and the head…tail one last time in the confirm step**, so the final
  thing seen before signing is what the chain will receive.
- **Address book**: label and save a verified recipient, so repeat sends select a known entry
  instead of re-pasting. Most real-world loss is repeat-paste, not first-paste.

### 3A.6 Test bar (mirrors what pool-v2 already does)

- Every single-character substitution, at every position, rejected — for `xust1…` exactly as the
  existing suite already does for `xusq1…`.
- Single-character deletion and insertion rejected; transposition of adjacent characters rejected.
- Truncation at every length classified as `TRUNCATED`, not as a generic checksum failure.
- `decode(encode(id)) == id` over a large corpus of account ids, and canonical-lowercase output.
- **A test asserting the on-wire transaction is byte-identical** whether the recipient was entered
  as raw hex or as `xust1…`. This is the one that proves §3A.3's "zero consensus surface" claim.

### 3A.7 Scope note

§3A.1–§3A.2 are findings; §3A.3–§3A.6 are the work. The transparent `xust1…` form and the shared
field widget are the substance — the shielded types already have the cryptography and mostly need
the UI to *report* it. None of it touches consensus, and all of it is testable without a node.

---

## 4. Minor / developer-facing

- **`sov_getReceipt` parameter is `txId`, not `txid`.** A wrong-case key returns
  `missing string param 'txId'`, which is easy to misread as "the method doesn't exist" (it
  caught me on 2026-08-06). Document the exact casing in the RPC docs; consider accepting both.
  Verified working: tx `c3295294…` → `{"status":{"status":"success"},"height":18749,
  "gas_used":165176}`.
- **Fee is `gas_used × 10` grains** on a plain transfer (165,176 gas → 1,651,760 grains =
  0.0165176 XUS, measured on mainnet). Document it; it is currently folklore.
- **`sov-wallet transfer` takes whole XUS only** (`u128`) and the RPC address must be
  `host:port` — a `http://` prefix fails with a DNS error. Both cost real time during the
  2026-08-06 sweep. Fix the usage string, accept a URL prefix, and consider a `sweep` subcommand
  that computes `balance − fee` itself.
- **Delete the stale `redteam-gui/` directory.** It exists at the repo root with **0 git-tracked
  files** (leftover `target/` build residue from the v0.2.8 extraction). Harmless, but it
  contradicts "this monorepo carries zero red-team code" for anyone reading the tree.
- **Refresh the assumevalid anchor** (required — the gate blocks the cut otherwise). Run
  `scripts/refresh-checkpoint.sh --write` **at cut time**, not from this draft: the tip moves.
  It must land past finality depth and inside `CP_MAX_LAG`, cross-checked identical on two
  relays (§2.1 makes that unattended).

---

## 5. Explicitly NOT in v0.2.11

Listed so the omissions are decisions rather than oversights:

- **No consensus change, no new signal bit, no arming, no schedule change.**
- **No `blocks`/`index` storage restructuring** (§1.3) — v0.3, with its own audit.
- **No snapshot-anchored reorg replay** (§2.3) — v0.2.12, after the measurement lands.
- **No P2P constant retuning** (§2.5).
- **No parallel/batched RandomX verification.** Still single-threaded and sequential; it remains
  the obvious next sync win and is not in this release.
- **No multisig rework** (owner-flagged as poor, back-burnered).
- **`MAX_BLOCK_WEIGHT` block-path enforcement (C5/PQV2-07)** — real and still open: weight is
  enforced at mempool admission but block production does not accumulate it and import does not
  recompute it. It is a consensus-surface change and does not belong in this release.

---

## 6. Safety bar — how "never break anything" is proven, not asserted

Every item below is a gate, not a checklist item:

1. **Genesis double-lock** + the full `sov-verify` KAT re-proved byte-for-byte
   (`scripts/release-gate.sh`).
2. **STF byte-identical to v0.2.10.** The memory work (§1.3) touches caches and indices only;
   no execution path changes. Proven by replaying mainnet history on both binaries and asserting
   identical state roots at every height.
3. **RPC answers unchanged.** A differential harness runs every read method against a v0.2.10 and
   a v0.2.11 node on the same store and diffs the JSON. Receipt queries from below the eviction
   window are the specific case to prove.
4. **The ignored sync tests run** (§2.2). A release cannot claim sync hardening while its sync
   regression tests are disabled.
5. **Startup-memory budget asserted** on a mainnet-sized store (§1.4).
6. **Rehearse on the E2E rig before the fleet.** `tools/e2e-vm` boots a real isolated multi-node
   testnet; it is the standing pre-tag hard gate and this release must pass it.
7. **Deploy discipline, learned on 2026-08-06:** back up the binary first, check `MemAvailable`
   first, **one node at a time**, verify tip advances and `sov_getDeployments` shows four
   deployments before touching the second host. Rollback is `cp` the `.bak` back — that is what
   saved the only public relay. Upgrade **fra1 first** this time, not sfo3: fra1 has 4 GB and no
   public RPC role, so a failure there costs hashpower rather than the network's entry point.

---

## 7. Suggested order of work

1. §1.2 measurement harness → attribute the regression. **Everything else waits on nothing; this
   gates only §1.3.**
2. §2.1 second public relay (ops, parallel, unblocks the anchor rule).
3. §3A.3 the `xust1…` transparent encoding + §3A.4 the shared address-field widget. Pure
   library + UI, no node risk, and it closes the only place in the system where a typo silently
   destroys value.
4. §3 Station private chips (self-contained, display-only).
5. §1.3 the narrow memory fix, once §1.2 says what to fix.
6. §2.2 deterministic sync tests; §2.3 reorg instrumentation; §4 minors.
7. Anchor refresh at cut time → release gate → E2E rehearsal → tag → **fra1, then sfo3**.

## 8. Open question for the owner

**Does v0.2.11 wait for the memory fix, or ship without it?** If §1.2 cannot attribute the
regression quickly, there is a real choice: ship §2–§5 as a Station-and-tooling release that the
fleet still cannot run, or hold the tag until the fleet can actually upgrade. The recommendation
is to hold — a release the only public relay cannot run does not reduce any of the three live
risks — but that is a call about pace, and it is yours.
