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
