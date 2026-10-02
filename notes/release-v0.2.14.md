# SOV Station v0.2.14 — wallet UI and operation preservation

Prepared 2026-10-01 for a **main-only** release under
[release-version-contract.md](release-version-contract.md). The owner explicitly
requested GitHub binaries. A release is not published until the normal strict
gate, five-node E2E and platform artifact checks succeed.

## Changes

- Brighter text, shared dark/light design helpers, workspace navigation,
  consistent layout and a bounded status footer.
- Six wallet tasks: Overview, Send, Receive, Privacy, Identity and Backup.
  Assets, Swaps, Vaults, Activity, Node, Mining and Blocks remain available.
- Public balance and owned **v1/v2 shielded amounts** remain separate; unknown
  or unscanned balances are not represented as zero. Live pool v2 includes its
  scan, receive/export, private send, shield and de-shield controls.
- Send retains existing address routing, Max, shortcut/Undo, priority tip,
  live auction details, pending/replacement and offline signing workflows.
  The current form drives the payment cost display.
- Reviews retain wallet/account, network/RPC, route, amount and approved bid.
  Changing terms expires the review. Replacements reuse the original nonce,
  recipient and amount. Pending history works across nodes on the same chain
  while remaining isolated from other networks.
- Pool reviews separate the note amount from network fees paid by the public
  account. V2 does not label a v1 fee estimate as the exact STARK transaction fee.
- Recovery acknowledgement, phrase hiding, watch-only restrictions, encrypted
  backups and existing operation dispatch are preserved.

The [operation map](station-ui-feature-map.md) contains 100 searchable
operation/capability entries. No existing operation handlers were removed in
the preservation audit. README descriptions now distinguish actual GUI
operations from CLI-only and roadmap capabilities.

## Validation recorded before the release gate

Station regression suite: **160 passed, 0 failed, 1 ignored**. Station formatting,
Clippy with warnings denied and the native production build pass. Native
inspection used a separate disabled-signing preview with synthetic balances;
it does not claim real-fund transaction testing. See [2026-10-01.md](2026-10-01.md).

The normal release workflow independently requires frozen-genesis checks,
workspace/KAT verification, dependency audits, reproducible builds, a zero-skip
five-node E2E run and each platform artifact's version self-report.

## Packaging and upgrade

The existing release workflow produces Windows x64 Station ZIP, Apple Silicon
macOS Station DMG and Linux x64 headless-node TAR.GZ. These are production
binaries, distinct from the local disposable design preview. Desktop packages
embed the node in-process; closing Station stops that node.

The UI work changes no consensus, genesis, chain identity or key derivation.
Existing wallet/chain storage paths remain in use. No genesis restart or new
wallet is required. The running local v0.2.13 app has not been replaced by this
release preparation.
