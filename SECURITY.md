# Security Policy

SOV is a sovereign reserve-asset L1: its correctness guarantees are not
negotiable. This document covers responsible disclosure, the (planned) bug
bounty, and the scope of external audits. It is the engineering-readiness half of
Phase 7 item **p7-i9** — the public invariant dashboard is the other half (see
`dashboard/index.html`, the *Verification & Validity* panel).

> **Honest status:** No third-party security audit has been performed yet, and no
> bug-bounty payouts are live. This policy defines the program and scope so an
> audit/bounty can begin; it does **not** claim either has happened. Mainnet is
> gated on a completed external audit (see the roadmap).

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for anything exploitable.

- Email: `security@sov.example` *(placeholder — replace with the project's real
  disclosure address before any public testnet)*.
- Include: affected component/crate, version/commit, impact, and a minimal
  reproduction.
- We aim to acknowledge within 72 hours and to coordinate a fix and disclosure
  timeline with you.

Please act in good faith: no data destruction, no privacy violations, no
disruption of others, and give us reasonable time to remediate before public
disclosure.

## What invariants must always hold (highest-severity surface)

A break in any of these is critical. They are specified in
[`chain/docs/state-transition.md`](chain/docs/state-transition.md) and
continuously checked by the [`sov-verify`](chain/crates/verify) suite:

- **Supply cap** — total supply never exceeds 21,000,000 SOV; mining and staking
  emission never exceed their budgets.
- **Value conservation / no unauthorized mint** — every block satisfies
  `Δsupply == Δmined + Δstaked`.
- **No double-spend** — nonce-enforced; replay is impossible.
- **Consensus safety** — no two conflicting blocks finalize under `< 1/3`
  byzantine stake; equivocation is provable and slashed.
- **Determinism** — identical blocks reproduce identical state roots on every
  node.

## Audit scope

In scope: the Rust workspace under `chain/` — Nakamoto proof-of-work consensus,
runtime, state, crypto composition, coinbase emission, the shielded pool, VM, and
the verification suite. The crypto primitives themselves are audited upstream
crates (ed25519-dalek, blake3, sha2, randomx-rs (RandomX reference), fips204
(ML-DSA), fips203 (ML-KEM), chacha20poly1305, wasmi); SOV's job is correct
composition, which is what an audit should target.

Out of scope (until built): live P2P/daemon (Phase 8) and the block explorer
(Phase 9).

## Bug bounty (planned)

A bounty program will open alongside the public "Sovereign Testnet". Severity will
follow the invariant list above (consensus-safety / supply / unauthorized-mint =
critical). Reward tiers and the funding pool are operational decisions to be set
before launch; this section reserves the policy, not specific payouts.
