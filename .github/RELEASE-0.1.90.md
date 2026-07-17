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
