# Security Policy

SOV is a sovereign reserve-asset L1: its correctness guarantees are not
negotiable. This document covers responsible disclosure, the (planned) bug
bounty, and the scope of external audits. It is the engineering-readiness half of
Phase 7 item **p7-i9** — the public invariant dashboard is the other half (see
`dashboard/index.html`, the *Verification & Validity* panel).

> **Honest status:** Mainnet is **live** (fair-launched 2026-07-04) and has **not**
> had a third-party security audit; no bug-bounty payouts are live. The current
> assessment of record is the internal `Luna` audit (2026-07-09). This policy defines
> the program and scope so an external audit/bounty can begin; it does **not** claim
> either has happened. Run a node and hold value at your own risk until an external
> audit is completed (see the roadmap).

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

- **Supply cap** — total supply never exceeds 21,000,000 SOV; the mining coinbase
  never exceeds its scheduled budget.
- **Value conservation / no unauthorized mint** — every block satisfies
  `Δsupply == Δmined` (the coinbase is the only issuance; there is no staking).
- **No double-spend** — nonce-enforced; replay is impossible.
- **Consensus safety** — pure proof-of-work under heaviest-cumulative-work fork
  choice, with probabilistic finality at a confirmation depth (Nakamoto). There is
  **no stake, no slashing, and no BFT committee** — hashpower is the only vote.
- **Determinism** — identical blocks reproduce identical state roots on every
  node.

## Audit scope

In scope: the Rust workspace under `chain/` — Nakamoto proof-of-work consensus,
runtime, state, crypto composition, coinbase emission, the shielded pool, VM, and
the verification suite. The crypto primitives themselves are audited upstream
crates (ed25519-dalek, blake3, sha2, randomx-rs (RandomX reference), fips204
(ML-DSA), fips203 (ML-KEM), chacha20poly1305, wasmi); SOV's job is correct
composition, which is what an audit should target.

Now **live and in scope** (fair-launched mainnet, 2026-07-04): the P2P transport +
daemon (`chain/crates/network`, `chain/crates/rpc`) and SOV Station (`node/`). These
have **not** had a third-party audit; the internal `Luna` audit (2026-07-09) is the
current assessment of record. The block explorer is a separate application in the
`cloudzombie/sov-explorer` repository and must be audited there.

## Bug bounty (planned)

A bounty program will open alongside the public "Sovereign Testnet". Severity will
follow the invariant list above (consensus-safety / supply / unauthorized-mint =
critical). Reward tiers and the funding pool are operational decisions to be set
before launch; this section reserves the policy, not specific payouts.
