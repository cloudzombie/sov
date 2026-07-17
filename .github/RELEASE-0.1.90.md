# SOV v0.1.90 — Surface cleanup: de-emphasize SNS (DRAFT / planned)

> **Status: planned, not yet implemented.** Captured from a 2026-07-17 product decision.

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

> **Status: planned for v0.1.90.** Raised 2026-07-17 while load-testing with the TX cannon.

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

> **Status: planned for v0.1.90.** Root cause found + verified in code 2026-07-17. All fixes
> are **wallet/library-side, genesis `cb0272ff` untouched** (no consensus/encoding/KAT change).

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
