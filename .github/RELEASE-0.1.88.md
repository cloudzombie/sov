# SOV v0.1.88 — Windows startup-hang fix (never wedge before indexing)

A small, Windows-focused desktop-app fix: SOV Station could hang on **"Starting…"** and
never reach chain indexing/sync on Windows, while macOS started fine. This removes the one
unbounded blocking call on the startup path and makes the whole pre-indexing sequence
self-diagnosing. **Genesis `cb0272ff` unchanged** — this is a GUI/startup change only, no
consensus, block, KAT, or P2P-wire change.

## The bug

On node start, SOV Station's first action is a **single-instance guard** that terminates any
stale copy of the app still holding the P2P/RPC ports. On Windows that guard shelled out to
`taskkill … /F` and **waited on it with no timeout**. If a *prior* `sov-station.exe` was
wedged in an uninterruptible kernel wait — e.g. stuck mid ~2 GiB RandomX dataset allocation,
or blocked in a socket syscall — `taskkill` could hang indefinitely, and because this runs
*before* chain replay, the app sat on "Starting…" forever and **"indexing…" never printed**.
macOS was immune: it reaps via `pgrep` / `kill -9`, which never blocks this way.

This was **not** the RandomX-checkpoint slowdown addressed in v0.1.87 (that fix is correct and
stays); the checkpoint is applied on the desktop node too, so historical blocks below height
6800 skip seal-verification. The remaining Windows hang was purely this startup shell-out.

## The fix

1. **Bounded process-kill (`run_bounded`).** Every external process-termination on the startup
   path — the Windows single-instance `taskkill` and the tracked-node `kill_pid` — now spawns
   the tool and waits **at most 4 s**, force-killing and abandoning it on overrun. A stuck
   target can no longer wedge startup. Best-effort by design: if a genuine port-holder
   survives, the later bind fails with a **clear "address already in use" error**, never a
   silent hang.

2. **Pre-indexing breadcrumbs.** The startup path between "start requested" and "indexing…"
   previously logged nothing, so a hang there was a black box. It now streams a line before
   each heavy/blocking step — clearing a stale instance, sealing the miner keystore, unlocking
   the keystore + verifying genesis — so the Node-tab log pinpoints the exact wedging call if
   anything else ever stalls.

## Safety

Genesis + KAT byte-identical (no chain code touched). No P2P-wire or protocol-version change,
so v0.1.88 interoperates with the v0.1.85–v0.1.87 mesh unchanged. Windows-only behavior in
practice; macOS/Linux keep their existing (already-safe) reap path, now also bounded. The
Windows artifact is built by the release workflow — the home rig + laptop pick up the fix by
installing the v0.1.88 `SOV-Station-*-windows-x64.zip`.
