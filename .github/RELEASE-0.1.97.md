# SOV Station v0.1.97 — accurate live hashrate display

## What changed

The network hashrate shown by `sov_getDifficulty` (and therefore the explorer and
the main site) was a **120-block trailing average**. That's Bitcoin's default, but at
SOV's 150s block time 120 blocks span ~5 hours — far too long for a small,
fast-growing network. A recent jump in hashpower (e.g. miners coming back online
after the v0.1.96 cold-sync fix) showed up only half-smoothed for hours, making the
figure read materially **low** relative to the real, current rate.

Measured from live chain data at release time:

| window | span | hashrate |
|---|---|---|
| 120 blocks (old) | ~5 h | ~640 H/s |
| 30 blocks (new) | ~1.2 h | ~950 H/s |
| 15 blocks | ~0.6 h | ~1390 H/s |

## The fix

`estimate_hashrate` now uses a **30-block window** (~1.2h) — responsive enough to
track a rising network closely, still long enough to average out per-block
solve-time variance. Chosen over 15 (accurate but swings on a single slow block)
and 120 (the laggy default).

**Display-only. Consensus-neutral, genesis-safe (`cb0272ff…`).** `estimate_hashrate`
has exactly one caller — the `sov_getDifficulty` RPC's `hashrate` field — and is not
referenced in block validation, import, difficulty retargeting, genesis, or any KAT.
The mining/difficulty machinery is untouched; only the number reported to explorers
changes. No client update required; the value corrects as soon as nodes/explorer run
v0.1.97.
