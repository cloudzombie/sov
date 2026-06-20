# SOV dashboard

The live build dashboard for the SOV project. A single static page that
reads the **real** repo state — workspace crates, Rust LOC,
`cargo test --workspace` output, and a hand-curated phase list — and
renders it as the project's blueprint + kanban view.

It is deliberately a static site: open
[`dashboard/index.html`](index.html) in a browser (`file://` works) and
you have the dashboard. No build step, no framework. Viewing needs nothing
but a browser; for **one-click refresh**, a tiny optional server
([`serve.mjs`](serve.mjs)) backs the in-page **Regenerate** button — see
[Regenerating from the page](#regenerating-from-the-page-one-click).

## Files

| File | Role |
|---|---|
| [`index.html`](index.html) | The dashboard page. Loads `status.js` and (when present) `chain-status.js` as sibling `<script>` tags. |
| [`phases.json`](phases.json) | **Single source of truth** for the roadmap. Hand-edited; must reflect real repo state. |
| [`gen-status.mjs`](gen-status.mjs) | Generator. Reads the repo, runs `cargo test --workspace`, parses `phases.json`, emits `status.js`. |
| [`serve.mjs`](serve.mjs) | Optional local server (Node std `http`, **no deps**). Serves the dashboard and exposes `POST /api/regenerate`, which runs `gen-status.mjs` so the in-page **Regenerate** button works. Loopback-only (`127.0.0.1`). |
| `status.js` | **Auto-generated.** Assigns `window.SOV_STATUS = { ... }`. Never hand-edit. |
| `chain-status.js` | Optional. Written **only** by `cargo run --release -p sov-node --bin sov-miner` to report the operator's own real mining session. Absent until you mine — the Live Mining panel honestly says "You are not mining" in that case. |

## Opening the dashboard

```sh
open dashboard/index.html        # macOS
xdg-open dashboard/index.html    # Linux
start dashboard\index.html       # Windows
```

The page loads `status.js` as a sibling `<script src="status.js">` (not via
`fetch()`), which is exactly why `gen-status.mjs` emits a
`window.SOV_STATUS = ...` assignment rather than a JSON file: a plain
`<script>` works under `file://`, where `fetch()` is blocked.

## Regenerating from the page (one-click)

The **Regenerate** button at the top of the Live Build Dashboard re-runs the
real generator and reloads the page — no terminal needed. Because a `file://`
page cannot spawn `cargo`/`node`, the button is backed by a tiny local server:

```sh
# from the repo root (or anywhere — paths resolve from the script)
node dashboard/serve.mjs        # -> http://localhost:8787
PORT=9000 node dashboard/serve.mjs
```

Then open the printed URL and click **Regenerate**. The button POSTs to
`/api/regenerate`, which runs exactly `node dashboard/gen-status.mjs` (a real
`cargo test --workspace`), then reloads so the freshly written `status.js`
renders. It reports the generator's real exit code and output — nothing is
faked. Opened from `file://` instead, the button honestly says it needs the
server and prints the command rather than pretending to refresh.

## Editing the roadmap

The kanban is **read-only and source-driven**. To reflect progress:

1. Edit [`phases.json`](phases.json). Flip an item's `"done"` flag only when
   the change is genuinely verified in the repo (the SOV hard rule applies:
   no fabricated completion).
2. Regenerate `status.js`:

   ```sh
   # run from the repo root, NOT from dashboard/
   node dashboard/gen-status.mjs
   ```
3. Reload `index.html`.

At time of writing `phases.json` has **11 phases** (0–9 plus the recently
added Phase 10 — the JavaScript / TypeScript SDK at
[`../sdk/`](../sdk/README.md)) covering **60 items** in total.

`status` and `done` are decoupled on purpose:

- `done: true` is the only way an item lands in the **Done** lane. The
  generator never silently upgrades anything.
- `status: "in_progress"` (or `"doing"`) puts an item in the **In Progress**
  lane *only if* `done` is still `false`. An item flagged `status: "done"`
  but `done: false` is demoted to in-progress — completion is never
  fabricated.

By convention, dashboard updates in this repo are delegated to a dedicated
subagent: **edit `phases.json` → run the generator → confirm the kanban
matches the repo**. Keep that delegated; don't paraphrase numbers inline.

## What `gen-status.mjs` actually does

The generator is the contract that keeps the dashboard honest. From a
single pass over the repo it produces:

- `chain.crateCount`, `chain.crates[]` — directory scan of
  `../chain/crates/`. Each entry records its `Cargo.toml` `name`, Rust file
  count, Rust LOC, whether it appears in the workspace `members = [...]`,
  whether it has a `src/lib.rs` or `src/main.rs`, and an honest `state`
  (`active` / `not_in_workspace` / `incomplete`) — distinguishing a wired
  crate from incomplete scaffolding.
- `chain.rustFiles`, `chain.rustLoc` — recursive count of `.rs` files and
  lines under `../chain/crates/`, excluding `target/`, `node_modules/`,
  and `.git/`.
- `chain.tests` — the result of really running
  `cargo test --workspace --manifest-path ../chain/Cargo.toml`. The
  generator parses every `test result: ok./FAILED. N passed; M failed`
  line and sums them; if the build itself fails, it reports `status:
  "error"` with the first `error` line — never a fabricated count.
- `explorer` — directory scan of `../explorer/`. Honest categories:
  `not_started` (no `package.json`, no source files), `scaffolding`
  (`package.json` only), or `in_progress` (source files present).
- `progress` and `phases` — derived from `phases.json`, with the
  status / done sanity check described above.

The generator requires **Node ≥ 25** and a working `cargo` binary on
`PATH`. It must be run **from the repo root** so its relative `../chain`
and `../explorer` paths resolve.

## Honest snapshot

This README intentionally does **not** quote headline numbers (crate count,
test count, LOC, percent-complete). Those values live exactly once, in
`status.js`, and refresh whenever the generator runs. To see the current
numbers, read [`status.js`](status.js) — its `chain.crateCount`,
`chain.rustLoc`, `chain.tests`, and `progress` fields are the source of
truth — or just open the dashboard.

## Hard rule

No fabricated, sample, or placeholder data anywhere on the page. Every
metric is computed by the generator from real files or real command
output, and the dashboard renders only what is actually present:

- Live Mining shows "You are not mining" when `chain-status.js` is absent.
- The In Progress / Todo lanes reflect `phases.json` exactly, with the
  status / done guard above.
- Test counts come from a real `cargo test --workspace` run.
- Crate state distinguishes wired-and-tested crates from scaffolding that
  is not yet part of the build.

If a value would have to be invented to display it, the dashboard shows
its honest empty state instead. That's the rule.
