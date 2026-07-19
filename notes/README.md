# SOV project notes

The durable, in-repo memory for this project. Read this first every session; it is
how we do not lose our place.

## The system (concrete, follow it every session)

1. **`STATUS.md`** — the master anchor. Current version, what is LIVE, and every open
   track with its **exact next action**. Update it at the end of every working session.
   If you read one file, read this one.
2. **`YYYY-MM-DD.md`** — one **daily log** per working day. Append-only. What was done,
   decided, shipped, and what is next. Create a new one each day (`notes/2026-07-19.md`).
3. **`activation-*.md`** — deep **runbooks** for each big activation track (the
   pool-mining / stratum rollout, the tx-domain hard fork). These hold the step-by-step
   detail that STATUS only summarizes.

## Rules

- **Concrete over vague.** Cite files/commits/heights, not "we did some work."
- **Convert relative dates to absolute** (e.g. "today" → `2026-07-19`).
- **Genesis discipline is sacred.** Genesis
  `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` is FROZEN.
  Nothing that ships changes it; every phase gate re-proves the KAT byte-for-byte.
- **Dormant-first.** Consensus-affecting work ships inactive behind a miner-signaled
  activation and is turned on only by a separate, coordinated, explicitly-approved step.
- These notes are committed to the repo, so they survive sessions and are visible to
  everyone. The assistant's private `~/.claude/.../memory/` index points here.

## Index

- [STATUS.md](STATUS.md) — master state + next actions **(read first)**
- [activation-tx-domain.md](activation-tx-domain.md) — cross-network replay hard fork runbook
- [activation-pool-mining.md](activation-pool-mining.md) — stratum + `getBlockTemplate` pool rollout runbook
- Daily logs: `2026-07-19.md`, …
