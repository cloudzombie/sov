# SOV v0.1.90 — Security-hardening release (Codex audit response) + wallet/mempool fixes

> **This release is primarily the ship-now, genesis-safe security remediation from the Codex
> external audit** (see "Security-audit response" below), plus the shielded-wallet accounting fix
> and mempool nonce-gap resilience. Genesis `cb0272ff` is untouched and proven byte-identical.

## Surface cleanup: de-emphasize SNS

> **Status: still planned, NOT implemented in this release.** Captured from a 2026-07-17 product
> decision; deferred — it is a separate UI/product change (explorer + Station) from the security
> work that makes up v0.1.90, and is tracked here so it isn't lost.

## Remove the Sovereign Name Service (SNS) from user-facing surfaces

**Rationale:** SOV is post-quantum *privacy* cash. Foregrounding human-readable `*.sov`
named accounts is off-brand and privacy-hostile — named accounts are the opposite of what
private money should promote. So SNS comes **off the surface**.

**Scope — surface only, NOT consensus.** The SNS consensus feature (`RegisterName`,
`TransferName`, and the NFT machinery it's built on) is **genesis-frozen** (`cb0272ff`) and
cannot be removed without a chain reset — so it stays in the protocol, honestly. v0.1.90
only removes/hides it from the UIs so it is neither promoted nor a first-class navigation
target. Existing names keep working on-chain; they just aren't advertised.

### Surfaces to remove/hide (scouted 2026-07-17)

**Block explorer (`sov-explorer` repo — deploys independently, do first):**
- `web/index.html:59` — the top-nav `<a href="#/sns">SNS</a>` link → remove.
- `web/app.js` — the whole SNS view (`snsView` at `#/sns`, `snsCard`, the resolve form),
  the account-page `SNS: <names>` block (~L889) and the "resolved from SNS name" crumb
  (~L885), the route label `sns: 'Names'` (~L1224), and the `register SNS name` action
  label (~L275). Decide: fully drop the `#/sns` route, or keep it reachable by direct URL
  but unlinked. Recommend: drop the nav link + the account-page name display; leave the
  raw action decode intact (it's just indexing).
- `web/tools.js:9` — `explainAction` `register_name` / `transfer_name` descriptions: keep
  (they explain a raw on-chain action honestly) or soften; low priority.

**SOV Station app (`node/src/gui.rs` — ships in a node release):**
- The Wallet → **Sovereign Name Service** panel (register/transfer names UI) → hide the tab
  / entry point. This is what the explorer's empty-state currently points users to
  ("Register one in SOV Station → Wallet → Sovereign Name Service"), so remove that hint too.

**Gotomarket site (`gotomarket` repo):** confirm no SNS mention (initial grep: none in the
lean rewrite — verify before shipping).

**Do NOT touch:** the consensus actions, the SNS RPCs (`sov_getName`, `sov_resolveName`,
`sov_listNames`, `sov_namesOf`) — they can stay for anyone who wants them; they're just not
surfaced. Genesis + KAT unchanged (this is all UI).

---

## Mempool nonce-gap resilience — a rejected/missing tx must not wedge an account

> **Status: IMPLEMENTED in v0.1.90.** Raised 2026-07-17 while load-testing with the TX cannon.
> Shipped both mitigation (1) gap-free admission with a typed `MempoolError::NonceGap { expected, got }`
> and full resolution (2) TTL-eviction of entries stranded behind a gap. Node-local, genesis-safe;
> 21 mempool tests green (`cargo test -p sov-mempool`).

**The problem.** SOV uses an account-nonce model: a sender's txs must mine in strict,
contiguous nonce order. Today the mempool (`chain/crates/mempool/src/lib.rs`) *admits*
future-nonce txs and holds them, but block-building "skips any sender whose next expected
nonce is missing — never proposing a transaction that would be rejected for a nonce gap."
So if nonce `N` never lands (it was rejected at admission — per-sender pending limit,
mempool full, a momentary affordability race — or simply never submitted), every later tx
`N+1, N+2, …` the account already pushed is **stranded behind the gap and stalls**. The
code itself notes this ("later stall, wedging the nonce"). A high submission rate (Target
TX/s / Firehose, or any buggy client that advances its local nonce on a *rejected* submit)
makes it easy to open such a gap.

**Goal for v0.1.90: mitigate or fully resolve so a gap can never permanently wedge an
account.** Node-side, consensus-neutral, genesis `cb0272ff` untouched (mempool is
node-local policy, not consensus; no block/STF/KAT change).

**Options (decide during implementation):**

1. **Mitigation — gap-free admission.** Reject at admission any tx whose nonce is not
   contiguous with the account's current on-chain nonce + its already-pending set (i.e. only
   admit `next..=next+pending_len`). A gap then simply *cannot form in the pool*; the client
   learns immediately (a clear `NonceGap { expected, got }` error) and resubmits the missing
   nonce instead of silently stranding a queue. Simplest and fully robust; the only cost is
   that a client must submit roughly in order (which correct clients already do).

2. **Full resolution — queued→pending promotion + eviction (Ethereum-style).** Keep a
   bounded per-sender *queued* set for future-nonce txs, promote to *pending* the moment the
   gap fills, and **time-evict** txs stranded behind a gap after a TTL so a permanent gap
   self-clears instead of occupying the pool forever. Pairs with a richer `sov_getNonce`
   that reports both the on-chain nonce and the next *mineable* (contiguous) nonce, so a
   client can always recover.

**Recommended:** ship **(1)** as the guaranteed mitigation (a gap can't wedge anything),
and layer **(2)**'s TTL-eviction on stranded entries so any pre-existing stuck txs drain.
Add a regression test: open a gap, confirm later txs are neither stranded forever nor
block-building poison, and that the account recovers once the missing nonce is (re)submitted.

**Client-side (already handled in the TX cannon):** continuous modes advance the local nonce
only on *accept* (commit-on-accept), holding + retrying the same nonce on a capacity
rejection — so the tool never opens a gap in the first place. The node-side fix above is the
defense-in-depth so that *no* client (not just ours) can wedge an account.

---

## Shielded-pool wallet accounting — "1 unspent note, 0 shielded XUS" (+ a more serious latent bug)

> **Status: IMPLEMENTED in v0.1.90.** Root cause found + verified in code 2026-07-17. All fixes
> are **wallet/library-side, genesis `cb0272ff` untouched** (no consensus/encoding/KAT change).
> Shipped: change-output gated on `change > 0` (transfer.rs), zero-value owned notes skipped at
> ingest while the commitment is still appended for tree alignment (store.rs), a versioned
> `Persisted` store that forces a one-time clean rebuild of any contaminated cache, the
> in-order-ingest `debug_assert!` promoted to a hard error, and the GUI scan now **receipt-filtered**
> (ingests only `success` bundles via `sov_getBlockReceipts`) with a **"Rescan from scratch"**
> recovery button. 27 shielded tests green + a new `receipt_succeeded_only_on_success` GUI test.

**The reported symptom (cosmetic — funds are safe).** SOV Station showed the main account
with **1 unspent note but 0 shielded XUS**. `balance()` and `unspent_count()` iterate the
*same* filtered note set (`chain/crates/shielded/src/store.rs:246-262`), so this is provably
**one zero-value note**. Its origin: `shielded_transfer_with_change`
(`chain/crates/shielded/src/transfer.rs:100-108`) adds a change output **unconditionally**,
even when change == 0 — unlike the de-shield builders, which gate it (`if change > 0`,
`transfer.rs:199` and `:269`). A private send of an amount exactly equal to the selected
note's value therefore mints a real, on-chain, **zero-value** note encrypted to the sender;
the wallet stores + counts it forever (spend selection requires `value >= amount > 0`, so it
can never be spent → its nullifier never publishes). Balance stays correct (adds 0); the
count is off by one. **Display-level only; no XUS is misreported as spendable.**

**The more serious bug the investigation surfaced (real accounting risk).** The wallet scan
(`node/src/gui.rs:8190-8199`) ingests **every** `Action::Shielded` bundle in a block with
**no receipt/execution-status check**. But the runtime *includes* shielded txs in blocks and
can mark them `Failed` without mutating shielded state (`chain/crates/runtime/src/execution.rs`:
malformed bundle, invalid proof, unknown anchor, **de-shield drain-limit**, unaffordable,
double-spend). This chain has already had one mined-but-rejected de-shield. Ingesting a
failed bundle makes the wallet: mark its nullifiers spent (drops notes consensus still holds
→ **under-report**), append its commitments to the local witness tree (**desyncs the tree** →
later spends fail "unknown anchor"), and store any decryptable output as a **phantom note**.
This can misreport spendable value in both directions and brick future shielded spends.

### Fix plan (all verified against current code; genesis-safe)

1. **Gate the change output** — `shielded_transfer_with_change` (`transfer.rs:100-108`): wrap
   the change `add_output` in `if change > 0 { … }`, mirroring `:199`/`:269`. (Orchard pads
   with dummy actions, so bundle shape stays valid.) Stops minting new zero-value notes.
2. **Receipt-filter the scan** — `scan_store` (`gui.rs:8190-8199`): fetch `sov_getBlockReceipts`
   per block and ingest only bundles whose tx receipt status is `success` (receipts are in tx
   order → zip with `block.transactions`). Fixes the failed-tx-ingestion class.
3. **Skip zero-value owned notes at ingest** — `store.rs` `ingest_block` (`157-167`): still
   `append` the commitment (tree alignment MUST be preserved), but don't `own`/`mark` a
   value-0 note. Heals the existing phantom on rescan.
4. **Versioned note store → one-time clean rebuild** — add a `version`/magic to `Persisted`
   (`store.rs:66-75`); an old/unversioned blob deserializes to `None`, which already falls
   back to a fresh rescan (`gui.rs:8152-8156`). Purges every existing store's phantom notes
   and any failed-tx contamination. (While there, promote the in-order-ingest `debug_assert!`
   at `store.rs:131-134` to a hard error.)
5. **Enforce the invariant** — after each scan, verify the wallet's tree root is a
   consensus-known anchor (extend `sov_getShieldedInfo` to return the current anchor; on
   mismatch, rebuild from birthday + warn). **Invariant:** *every owned-unspent note has
   value > 0, its commitment is in the consensus tree, its nullifier is absent from the
   consensus nullifier set, the wallet tree root is a consensus anchor, and balance + count
   derive from one store.*
6. **Regression tests** (`shielded` crate, matching `store.rs:340-495` style):
   exact-value transfer ⇒ sender ends `unspent_count()==0` AND `balance()==0` (fails today);
   a block carrying a consensus-**rejected** bundle must not alter the store via the
   receipt-filtered path (balance/count/tree-root match a consensus scan); versioned-store
   migration forces a clean rescan.

**Immediate confirmation the user can run now:** quit SOV Station, delete
`~/.sov-station/notes/<implicit-id>.store` (an explicitly rebuildable cache), relaunch +
rescan. If "1 note, 0 XUS" returns, the note is real on-chain data (root cause #1, cosmetic);
if it vanishes, the store was merely stale. Either way **funds are safe** — this is wallet
bookkeeping, not consensus.

---
---

# Security-audit response (Codex external review, 2026-07-18)

> **Status: the ship-now list below is IMPLEMENTED in v0.1.90** (see "What actually ships"); the
> coordinated hard-fork bundle + separate-repo work remain staged. Every claim was re-checked
> against the actual source before disposition; the six Priority-0 consensus verdicts were
> additionally run through an adversarial refutation pass (each survived). File:line evidence is
> recorded per item. Genesis `cb0272ff` is **untouched by everything shipping in v0.1.90** —
> proven byte-identical after all changes (`sov-verify` KAT + `sov-rpc` genesis-pin tests green) —
> the only changes that would alter consensus are explicitly quarantined into the "coordinated
> hard-fork" bundle and ship to *nobody* until all miners upgrade together.
>
> **Landed in v0.1.90 (all green locally — fmt/clippy/tests):** producer timestamp clamp
> (future-tip miner-stall); peer-block persistence fail-closed; peer `Status` expiry + strike-out
> of unsubstantiated mining-gate claims; interim implicit-account handshake guard; shielded
> receipt-filtered scan + change-output gating + versioned store + "Rescan from scratch";
> mempool nonce-gap resilience; Station RPC loopback-by-default + explicit LAN opt-in; HTLC swap
> client hardening (OS-RNG masked/entropy-gated/zeroized secret, tip-relative timeout floor,
> receipt-confirmed completion); conformance mainnet deny-gate + spend/fee ceilings + seed
> zeroize; TX-Cannon honest fee copy; Windows mainnet docs; dashboard regen guard; and the CI +
> release-provenance jobs (SDK/tools/PowerShell CI gates, SHA256SUMS + keyless cosign + SBOM +
> build-provenance attestation, SHA-pinned actions).

This external audit substantially **overlaps the Luna audit** (`Luna - Audit/AUDIT.md`,
SOV-LUNA-2026-07-09). Where a finding was already triaged there it is cross-referenced — the
two reviews independently reached the same conclusions, which is corroboration, not new news.
Four Codex claims are **factually incorrect about this codebase** and are marked *refuted* with
evidence; we will not "fix" a non-problem, but we record why so the disposition is auditable.

## What actually ships in v0.1.90 (node-local / GUI / tooling / CI / docs — NO fork, genesis-safe)

Everything in this list is wallet-, tool-, CI-, docs-, or node-policy-side. None of it changes
a block, header, transaction encoding, state root, or the KAT. It is safe to ship unilaterally.

1. **Stop future-dated tips from trapping the stock miner** *(Codex P0 — the one P0 item that
   needs no fork)*. A peer can publish a tip dated up to ~2 h ahead (accepted under
   `MAX_FUTURE_DRIFT_MS`). The honest producer then builds its template with the bare local
   clock — `build_candidate(now_ms())` at `rpc/src/daemon.rs:1555`, no clamp against the parent
   timestamp — so its sealed block has `timestamp_ms < parent.timestamp_ms` and is rejected at
   commit as `NonMonotonicTimestamp` (`chain/src/blockchain.rs:1198`). The node then spins,
   never committing, until its wall clock passes the future tip — a real liveness/griefing
   stall (self-clearing after ≤2 h). **Fix:** clamp the template timestamp to
   `max(now_ms(), parent.timestamp_ms + 1, median_time_past + 1)` in the daemon miner and the
   `node.produce` path. Purely producer-side timestamp *selection*; importers already accept any
   monotonic, above-MTP timestamp, so **no consensus rule changes** and no coordinated
   activation is required. Regression test: a future-dated parent must not stall successor
   production.

2. **Make peer block persistence fail closed** *(Codex P1; Luna H001 partial)*. The Luna H001
   fix (commit `3e222cf`, v0.1.80) made the **mined** path fail-closed — an append/fsync failure
   after `commit_mined` halts mining and the block is never gossiped (`daemon.rs:1706-1724`).
   The **peer-import** path was deliberately left fail-*open* in the same commit: if
   `append_unsynced` (`p2p.rs:660-676`) or the per-drain fsync (`p2p.rs:605-620`) fails, a
   `⚠ DURABILITY` line is logged but the in-memory chain keeps advancing and the block is
   re-broadcast — so on persistent storage failure a restart replays a *shorter durable prefix*
   than the node advertised. Peer-import is the dominant path for every non-mining node. **Fix:**
   on peer-path append/fsync failure, stop further imports/gossip (mirror the mined-path FATAL).
   Node-local; no wire or consensus impact.

3. **Restore Station RPC to loopback by default + explicit public-node mode** *(Codex P1; Luna
   H003)*. SOV Station force-rewrites the persisted node-config `rpc_addr` to `0.0.0.0:8645` on
   **every** start (`node/src/gui.rs:9086-9090` migrates even existing loopback configs), so the
   desktop wallet's RPC is LAN-reachable by default with **no auth token** and no
   loopback/public toggle. This was intentional in v0.1.49 (the RPC surface is key-free: reads +
   submit of already-signed txs, never signs or holds keys) and a per-IP token-bucket rate
   limiter landed v0.1.85 (`rpc/src/lib.rs:92-137`) — but LAN-open-by-default is the wrong
   default. **Fix:** default the embedded node's RPC back to `127.0.0.1:8645`, remove the forced
   `0.0.0.0` migration, and add an explicit "Expose RPC on LAN" opt-in for conformance/explorer
   use. GUI/config only.

4. **Shielded wallet: process only successful receipts + a clean rescan path** *(Codex P1 —
   already the planned v0.1.90 work above)*. The audit independently rediscovered the exact bug
   this release already plans to fix (see "Shielded-pool wallet accounting" above): `scan_store`
   (`gui.rs:8190-8199`) ingests **every** `Action::Shielded` bundle with no receipt-status
   check, so a mined-but-`Failed` shielded tx corrupts the spent-set and witness tree. The RPC
   prerequisite already exists — `sov_getBlockReceipts` (`rpc/src/lib.rs:728-742`, added
   `18ff1b7`). **Fix:** implement plan items 1–6, and add a **"Rescan from scratch"** GUI button
   that deletes the rebuildable note-store cache and re-runs the scan (today the only recovery is
   quitting and hand-deleting the store file). Wallet/library-side, genesis untouched.

5. **P2P: stop trusting unverified peer `Status` to pause mining / pick the sync peer, and
   expire the observations** *(Codex P1; Luna M001)*. A peer's *claimed* height/head/chain-work
   is stored as-claimed with no header/PoW verification (`p2p.rs:836-861`); `should_gate_mining`
   is driven by the max claimed height (`sync_status.rs:103-105`), and the best sync peer is the
   max *claimed* chain-work (`p2p.rs:1309-1330`). Any peer that completes the signed Hello — i.e.
   anyone with a keypair — can therefore keep the local node in `Syncing` forever (never mining)
   by announcing an enormous height, and answering with empty/`None` block responses carries no
   penalty (only a block that *fails full validation* is penalized). `PeerStatus` also has **no
   timestamp/TTL**, so a stale claim from a still-connected peer persists indefinitely (bounds
   *are* adequate: one status per socket, purged on disconnect — only *expiry* is missing).
   **Fix (node-local, no wire change):** add a received-at instant + TTL to `PeerStatus`; bound
   how long an unsubstantiated claim can hold `should_gate_mining` true; penalize/expire claims
   that repeatedly fail to materialize into importable headers/blocks. *(The deeper "require a
   headers/PoW proof before changing sync state" is the coordinated item — see the fork bundle.)*

6. **HTLC swap client hardening (Station Swaps tab)** *(Codex P1, several items)*. The Swaps tab
   is **HTLC-only** — Station exposes no intent UI at all, so the audit's IntentCreate/Settle
   framing doesn't apply to Station. What is real and fixable client-side now:
   - **OS-generated, masked, zeroized secrets.** The HTLC preimage is user-typed free text
     (`gui.rs:5348-5353`), unmasked, with the only check being non-empty (`:5440`) — a 1-char
     secret is accepted and is trivially brute-forceable by the counterparty before timeout.
     **Fix:** a "Generate" button producing 32 `OsRng` bytes, `.password(true)` masking, a
     minimum-entropy gate that rejects weak manual secrets, and zeroize-after-submit.
   - **Timeouts from current height with a floor.** The timeout is a raw absolute height
     (`gui.rs:5354,5437`) with no reference to the tip and no margin — entering `0`/a past height
     creates an instantly-refundable, never-claimable lock. **Fix:** fetch the tip, take a
     relative offset with an enforced floor (e.g. ≥20 blocks), show the absolute height.
   - **Don't say "complete" on mempool admission.** "✓ HTLC opened/claimed/refunded"
     (`gui.rs:5464,5539,5563`) prints on submit, but execution can still `Failed` on-chain
     (bad preimage, timed-out, insufficient balance — `execution.rs:566-607`) with the nonce
     consumed. **Fix:** wire the *already-written* `await_receipt` poller (`gui.rs:8219-8241`,
     currently only called by shielded flows) into the HTLC lock/claim/refund paths.
   - **Zeroize the preimage + its copies** (`gui.rs:1464,5433,5521`) — a bearer secret worth the
     locked funds, currently in a plain egui `String` that survives after use. *(The
     consensus-side "reject zero-value / already-expired HTLC" is in the fork bundle.)*

7. **CI: add SDK, conformance, TX-Cannon, and PowerShell checks** *(Codex P1)*. `ci.yml` today
   runs `lint / test(3-OS) / station / verify / contracts / reproducible / supply-chain / fuzz /
   hygiene / sanitizers / hardening` — but **never** runs the TypeScript SDK's own `vitest`
   suite (the SDK is our consensus *second client*; a TS-side KAT drift is only caught by the
   Rust drift-guard today), never compiles `tools/conformance` or `tools/tx-cannon` (both have
   regressed recently — commits `306f048`, `2e916fc`), and runs no PowerShell analysis on
   `windows/`. **Fix:** additive jobs — Node 20 + `npm ci` + `vitest` for `sdk/`; `cargo
   build/test` for the two tools; `PSScriptAnalyzer` for `windows/scripts/*.ps1`. Zero consensus
   surface. *(Naming caution: CI's existing "conformance" is `sov-verify`'s STF conformance — a
   different thing from `tools/conformance`.)*

8. **Release provenance: signed checksums, SBOM, attestation, SHA-pinned actions** *(Codex P1)*.
   `release.yml` publishes the Windows zip / macOS dmg / Linux tarball with **no** checksum, **no**
   signature (macOS `codesign --sign -` is ad-hoc Gatekeeper-only), **no** SBOM, **no** build
   provenance, and every action pinned by moving **tag** (`actions/checkout@v4`,
   `softprops/action-gh-release@v2`, `crate-ci/typos@master`) not SHA. We already prove
   *reproducibility* (`scripts/reproducible-build.sh` in both CI and the gate) but publish no
   attestation, so a downloader can't verify what they got matches what CI built. **Fix:** emit a
   `SHA256SUMS` + `minisign`/`cosign` signature, generate a CycloneDX SBOM (`cargo-cyclonedx`),
   add `actions/attest-build-provenance` (`id-token: write` + `attestations: write`), and SHA-pin
   all actions. **Priority within this:** `crate-ci/typos@master` — a compromised master branch of
   that action runs arbitrary code in CI on every push; pin it first.

9. **Tooling safety** *(Codex P4)*.
   - **Conformance runner mainnet guard.** `tools/conformance` can be pointed at any two RPC
     endpoints today with **zero** mainnet guard — its preflight only checks the two nodes agree
     with each other (`src/main.rs:360-420`), never that the chain isn't mainnet. Each sweep moves
     **real value**: ~20 signed txs, helper funding, a 5-XUS HTLC lock, and **2 permanent SNS
     registrations at 1 XUS each** — the SNS fees and all gas go irrevocably to whichever miner
     wins (a stranger, on mainnet). Its README's "safe to re-run" is misleading. **Fix:** refuse
     to run against genesis `cb0272ff` unless a typed danger-acknowledgement flag is passed; add
     max-spend / max-fee ceilings; scope the "safe to re-run" wording to testnet.
   - **Conformance seed zeroization.** The tool takes a full seed/recovery-phrase and holds it as
     plain `[u8;32]` across three structs + the raw HTTP body of the web path
     (`main.rs:110-212`), none zeroized — while the sibling `tx-cannon` already uses `Zeroizing`.
     **Fix:** wrap the seed/phrase/request buffers in `Zeroizing`.
   - **TX-Cannon closed-loop copy is wrong.** The "closed loop — no XUS can leave" label
     (`tools/tx-cannon/src/main.rs:1471`, and `:373/:506-509/:1474`) is false: recycle mode does
     confine principal to the user's own wallets, but every tx pays a real ~0.00021-XUS fee that
     consensus routes to **whoever mines the block** (a third party on mainnet). **Fix (copy
     only):** "principal recycles among your wallets; each tx still pays its miner fee to whoever
     mines the block" — drop the absolute claim.
   - **Windows package docs are stale + testnet-framed.** `windows/README.md` titles the package
     "testnet-1", claims a **93 % / 5 % / 2 %** miner/founder/dev coinbase split, and never
     mentions live mainnet or genesis `cb0272ff`. Current consensus pays **100 % of coinbase +
     fees to the miner** (`execution.rs:1540`, `mining/src/lib.rs:171`); the 93/5/2 split never
     existed (the tax was 90/9/1 in v0.1.50 and is now removed). A user following these docs joins
     **testnet**, not mainnet. **Fix:** rewrite for mainnet reality (genesis `cb0272ff`, 12.5
     XUS/block, 840 k halving, 100 % to miner, no premine), or stamp the package TESTNET-ONLY.
   - **Dashboard regen guard + stale architecture.** `dashboard/serve.mjs:109` routes
     `POST /api/regenerate` with no Origin/Host/CSRF check into an unconditional `cargo test
     --workspace` spawn with no single-flight lock — a local drive-by CSRF / DNS-rebind target
     that can exhaust the machine and race `status.js` writes. Its hand-written "Technological
     Architecture" section is the **pre-Nakamoto** concept doc (contradicts the shipped chain on
     sharding/finality/supply — the most misleading stale copy in the repo, on a "prove don't
     claim" project). **Fix:** single-flight guard + Origin/Host validation on the endpoint;
     replace/delete the stale architecture section (or retire `dashboard/` for `dash2/`).

## Coordinated hard-fork bundle — consensus-affecting, ships to NOBODY until all miners upgrade together

These change transaction/settlement/validity rules or the state root. On a **live** chain any of
them forks un-upgraded nodes, so they are staged behind a **miner-signaled activation** (the same
mechanism as the v0.1.86 activation and the PQ sunset) — never hot-patched. v0.1.90 **discloses**
them honestly; it does not silently ship them.

- **Domain-separate the transaction signing preimage** *(Codex P0 — the crown-jewel gap)*.
  `Transaction::signing_bytes` is the **bare Borsh** of `{signer, public_key, nonce, action}`
  (`types/src/transaction.rs:423-425`) — **no chain-id, no genesis hash, no domain tag, no
  version byte**. (The codebase already knows the pattern: multisig/rotation sub-messages prepend
  `"sov:multisig:v1"`/`"sov:rotate:v1"` — the top-level tx preimage just omits it.) So the same
  signed Transfer verifies byte-for-byte on **every** SOV-family network. The adversarial pass
  made this *worse*, not better: because implicit account ids are `hash(pubkey)` and are
  self-certifying at execution (`execution.rs:136-141`), the target account **need not
  pre-exist** — any testnet/fork tx from an implicit account at its mainnet nonce (0 for a fresh
  account) executes on mainnet if balance suffices. The network-layer handshake *is* domain-bound
  (`network/src/message.rs:236`), but that protects peering, not tx authorization. **Fix:**
  prepend a `"sov:tx:v1"` domain tag + chain-id/genesis binding to the preimage. This changes
  `tx_id` and invalidates every existing signature + the frozen genesis KAT → activation-height
  fork. **Bundle with the intent fix below and ship the replay-rejection KAT vectors with it.**

- **Domain-separate signed SWAP intents** *(Codex P0)*. Identical shape:
  `Intent::signing_bytes` is plain Borsh with no chain/genesis/domain binding
  (`intents/src/lib.rs:97-100`); settlement (`execution.rs:817-851`) adds no wrapper. A signed
  intent is equally valid on any SOV-family chain where the owner's key matches (which, for
  implicit ids, is automatic). **Fix:** `"sov:intent:v1"` tag + chain/genesis binding in the same
  activation as the tx fix.

- **Cross-network replay-rejection KAT vectors + migration tests** *(Codex P0)*. `sdk/vectors/*`
  and the Rust vector trees contain **no** vector asserting a tx/intent signed for one network is
  rejected on another (there's no network field to assert on today). The vectors themselves are
  test-only (no fork), but they are only *meaningful* once the two domain-binding fixes land —
  so they ship **with** the activation, proving the new binding across the Rust node and the TS
  second client.

- **Reject zero-value and already-expired HTLCs at creation** *(Codex P1)*. The `HtlcLock` arm
  (`execution.rs:558-589`) validates only balance and duplicate/overflow — no `amount == 0`
  rejection (contrast `TokenIssue` at `:652`) and no `timeout_height <= height` rejection. A
  zero-value HTLC is a dust/fake-fund vector; a past-dated one is a griefing primitive. Rejecting
  them makes previously-valid txs `Failed` → consensus-tightening → coordinated activation (same
  class as the `033ad79` rollout). The **client-side floors in item 6 mitigate for Station users
  now.**

- **Bind the peer `account` field into the signed handshake transcript** *(Codex P1; Luna H002)*.
  `handshake_bytes` signs chain-id + genesis + channel-binding but **not** `account`, and
  `account` is never cross-checked against `public_key` (`network/src/message.rs:236-241`,
  `:203-229`) — so any keypair can authenticate and *claim any account id*, which drives peer
  dedup/identity. It's a **wire-protocol** change (P2P v3, no consensus/state impact) → all peers
  upgrade together. **Interim node-local guard that ships in v0.1.90:** require a peer's *implicit*
  account id to derive from its `public_key`, closing the spoof for implicit ids without a wire
  change.

- **Require a headers/PoW proof before `Status` changes sync/mining state** *(Codex P1; Luna
  M001)*. The v0.1.90 node-local mitigation (item 5) bounds and expires unverified claims; the
  *full* fix — treat `Status` chain-work/height as a hint and demand a header proof before
  gating mining or selecting a sync peer — touches the sync protocol and is coordinated.

- **xUSD liquidation / redemption / bad-debt accounting** *(Codex P3)*. The CDP machinery is
  **live and ungated on mainnet since v0.1.77** (`b3b0a49`): `VaultDeposit/Mint/Burn/Withdraw` +
  `OracleUpdate` with a 150 % ratio (`state/src/vault.rs`, `execution.rs:1248-1443`). The `Action`
  enum **ends at `OracleUpdate`** — there is **no** `Liquidate`, `Redeem`, or bad-debt variant.
  If the oracle price ever put a vault below 150 %, nothing forces closure; only the owner's
  `VaultBurn` can unwind it. Adding liquidation/redemption/auction/bad-debt is **new consensus
  actions** requiring both an economic spec (owner-approved — we will not invent collateral/
  auction/governance parameters) and a coordinated activation. **v0.1.90 discloses honestly** that
  xUSD has no liquidation mechanism and the oracle is still at the $1.00 seed. Surface-side, we add
  experimental-warning copy (see below); the consensus rules cannot be "hidden" on-chain.

- **Meaningful de-shield rate limit** *(Codex P5; Luna M003)*. `mainnet.json` overrides the
  native 21,000-SOV/576-block circuit breaker to **21,000,000** SOV/576 blocks — the whole supply
  — so the limiter is a deliberate no-op (v0.1.71, `82a4ea2`). Genesis-safe but consensus-
  affecting (nodes with different limits fork on an over-limit de-shield), so re-tightening is a
  coordinated rollout. **This is an intentional, disclosed choice, not a bug** — noted so the
  turnstile isn't mistaken for a live guardrail.

- **Per-block execution/resource limit** *(Codex P5)*. The only block-level bound is the elastic
  **byte** cap (1–4 MiB, v0.1.67); there is no per-block gas/weight ceiling
  (`blockchain.rs:938-985`). Every op *is* individually fee-priced (SHIELDED_VERIFY 500 k,
  ML-DSA 60 k) and the byte cap indirectly bounds op-count, but a 4 MiB block of Halo2/ML-DSA
  verifications has no explicit execution-time ceiling. A block-gas cap is a new validity rule →
  coordinated.

- **State rent / expiration / pruning** *(Codex P5)*. No rent/expiry exists: consumed-intent ids
  are a monotone never-pruned set, names are permanent, contract storage is write-priced but never
  expires (`state/src/ledger.rs:335`). (One audit nuance corrected: **settled** HTLCs *are* pruned
  on claim/refund — only expired-but-never-refunded ones linger.) All growth is fee-priced at
  write; reclaiming it changes the STF/state root → coordinated design.

- **Strict protocol-version negotiation** *(Codex P5)*. The machinery exists and is enforced —
  peers advertise `(protocol_version, agent)` and sub-`MIN_SUPPORTED_PROTOCOL` peers are
  disconnected — but `MIN` is deliberately `0` during rollout, so every version is currently
  accepted. Raising `MIN` is a one-constant, node-local change that *shuns* old peers network-
  wide, so it's scheduled with the first mandatory upgrade, not shipped silently in v0.1.90.

## Already fixed — cite, don't re-do

- **IntentSettle multisig-authorization bypass** *(Codex P1)* — **FIXED v0.1.85, commit
  `033ad79`.** A compromised pre-multisig key could drain a multisig account via `IntentSettle`
  (the M-of-N threshold was never consulted for the intent *owner*). Multisig-owned accounts can
  no longer be settled by single-key intents (`execution.rs:833-846`); regression test
  `a_multisig_owner_intent_cannot_be_single_key_settled`. Genesis + KAT byte-identical.
- **Oracle deviation bound** *(Codex P3)* — **FIXED v0.1.85, commit `4e50ac3`.** A
  `MAX_ORACLE_MOVE=10` circuit breaker rejects any single `OracleUpdate` >10× or <1/10 the
  current price (`execution.rs:1424-1437`), bounding a compromised feed key's per-block blast
  radius. (Multi-source median/TWAP + staleness rejection remain open — see below.)
- **GUI wallet secret zeroization** *(Codex P5)* — **FIXED 2026-06-28, commit `fc54125`** for the
  wallet surface (seeds, mnemonics, passphrases, on-drop scrub). Remaining gaps (HTLC preimage;
  the chain-side `sov-crypto`/`sov-wallet` key stack relying on plain drop) are covered by item 6
  and a library-only zeroize pass in this release.

## Refuted — Codex claims that don't hold against this codebase (recorded with evidence)

We checked each and the premise is incorrect; **no change is warranted**, but the reasoning is
logged so the disposition is auditable rather than dismissive.

- **"Disable/gate legacy transaction formats after activation"** *(Codex P0)* — **refuted.** There
  is exactly **one** transaction encoding (a single Borsh `Transaction`, no version discriminant);
  no alternate/legacy tx formats are accepted, so there is nothing of that kind to gate. The
  nearest analogue — legacy Ed25519 (V1) vs hybrid-PQ (V2) signatures — already **has** a
  miner-signaled sunset that forces high-value V1 accounts to rotate then rejects V1 past
  `sunset_height` (`execution.rs:189-222`); it exists in consensus and awaits signaling.
- **"SDK consensus integers lose precision (use bigint/decimal strings)"** *(Codex P1)* —
  **refuted.** The SDK already does exactly that: every amount is a canonical decimal
  `GrainString` at the wire/type layer and `bigint` in all arithmetic + borsh
  (`sdk/src/types.ts`, `units.ts`). And the precision math doesn't even threaten XUS — 1 XUS =
  10⁸ grains, so the entire 21 M supply is 2.1 × 10¹⁵ grains, **below** `Number.MAX_SAFE_INTEGER`
  (9.0 × 10¹⁵). No floating-point ever carries an amount.
- **"Gas pricing doesn't reflect hybrid-signature / crypto-op cost"** *(Codex P5)* — **refuted.**
  Gas is not flat: `envelope_gas` surcharges the hybrid envelope's ~5.3 KB of extra key+sig bytes
  per byte **plus** a dedicated 60,000-gas ML-DSA verification charge; zk-SNARK verification
  carries 500,000 gas (`runtime/src/gas.rs:41-156`). Whether the *absolute constants* match
  measured CPU perfectly is tunable opinion (and frozen — re-tuning is itself a hard fork), but
  "does not reflect crypto cost" is false.
- **"Stale default relays" (explorer)** *(Codex P4)* — **refuted.** The explorer's defaults at
  HEAD are exactly the current live seeds (NY `64.225.10.34`, SF `137.184.83.91`, testnet
  `159.203.109.204`); set in `d71dfe3`, verified 2026-07-18.

## Partially bounded by design — disclose, don't over-fix

- **Candidate-controlled emergency difficulty** *(Codex P0)* — **partially addressed / bounded.**
  The factual description is correct (the EDA easing is driven by the candidate's own
  miner-supplied timestamp, up to 8 halvings = 256× easier). But the design already bounds it: the
  8-halving cap is *sized to* the 2 h future-drift acceptance window (2 h ÷ (6 × 2.5 min) = 8), the
  lower bound is pinned by monotonic + BIP-113 MTP, and — decisively — the eased target feeds
  chain-work (`blockchain.rs:1245`), so a cheap future-dated block carries proportionally **less**
  work and **cannot out-compete** honest blocks under heaviest-work fork choice. Tightening it
  (e.g. deriving the stall gap from MTP instead of the raw parent timestamp) is a consensus change.
  **Disposition: accepted, bounded risk — disclosed, scheduled with the next fork, not an
  emergency.**
- **Mempool nonce-gap + replacement** *(Codex P5)* — the nonce-gap wedge is the **already-planned
  v0.1.90 node-local work** (see "Mempool nonce-gap resilience" above). On replacement: there is
  **no** fee-bump/RBF by design — a second tx at the same `(signer, nonce)` returns
  `NonceTaken`, a deliberate consequence of SOV's fixed gas price (no fee auction to outbid).
- **xUSD surface exposure** *(Codex P3)* — the Station Mint/Burn xUSD **GUI page never shipped**
  (there is nothing to hide in the GUI). The real exposure is consensus-level (see the fork
  bundle): minting is live and any hand-crafted `VaultDeposit`+`VaultMint` mints at the $1.00 seed
  today. v0.1.90 adds **experimental-warning copy** to the RPC docs + release notes and keeps the
  GUI page unshipped; oracle **staleness/timestamp rejection** and **multi-source median/TWAP**
  remain open and are consensus changes (fork bundle).
- **Hardware-wallet / secure-signing integration** *(Codex P5)* — confirmed absent (no
  ledger/trezor/hid dependency; the `TREZOR` hits are the standard BIP-39 test mnemonic). This is
  acknowledged roadmap wallet work alongside OS-keychain, not a v0.1.90 item.

## Separate repo — block explorer (`cloudzombie/sov-explorer`, ships independently of v0.1.90)

Tracked and dispositioned there; recorded here for completeness. **Open:** the indexer never
recomputes tx IDs / block hash / tx+receipt Merkle roots — it stores relay-provided digests
verbatim (`src/indexer.js:20-55`), so one compromised relay could serve tampered tx bodies under
an honest digest (the TS SDK's KAT-proven codec is the natural local verifier); `/healthz` runs
O(N)-over-blocks SQLite aggregates **twice per network per request** (`src/server.js:350-373`) —
cache with a short TTL. **Partially addressed:** cross-relay **hash** agreement at a common height
is enforced fail-closed (`d71dfe3`/`c060d04`) but full-**payload** agreement is not (each body
comes from one relay); heavyweight listings use keyset **cursors** since `469460d` (only the
paid-gated catalog/names endpoints keep bounded offset); TLS-relay enforcement machinery exists
and the production systemd unit sets `REQUIRE_TLS_RELAYS=1` (the plain-`http` IP *defaults* are
opt-out) — but the reverse-proxy `X-Forwarded-For` parsing takes the **leftmost** (spoofable) hop
and should take the last untrusted hop. **Refuted:** stale default relays (above).

## Full SWAP-product build-out *(Codex P2 — larger project, not a v0.1.90 line item)*

The audit's Priority-2 "complete SWAP product" (paired-chain state machine, counter-leg
verification, safe timelock ordering, reorg/confirmation policy, pre-signed refunds, secret-reveal
state, restart recovery, solver/MEV protections) is a **surrounding protocol-client** project on
top of the existing, sound on-chain HTLC engine — the engine does **not** need replacement. The
v0.1.90 client-side HTLC hardening (item 6) is the safe first slice; the full paired-chain client
is scoped separately and is **not** claimed as done in this release.
