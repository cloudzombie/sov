# Grant Application — `swapd`: Trustless, Non-Custodial BTC/ZEC ⇄ SOV Atomic Swaps

**Program:** Zcash Community Grants (ZCG)
**Category:** Interoperability — Atomic Swaps
**Requested amount:** **$48,000 USD** (payable in ZEC), milestone-based, four tranches
**Applicant status:** Independent, pseudonymous-capable, solo builder
**License:** MIT/Apache-2.0 dual (all deliverables open source)

> **Fill-in before submitting** (marked `[TODO]` throughout): forum handle, GitHub handle, ZEC payout address, personal/pseudonymous bio, and the URL of the pre-submission forum feedback thread. ZCG requires you to (1) post the idea to the Community Forum → (2) file the GitHub application (`grant_application.yaml`) → (3) link it back on the forum. This document is the body you paste into both.

---

## 1. One-line summary

Fund an open-source daemon, **`swapd`**, that performs **trustless, non-custodial HTLC atomic swaps** between **ZEC (and BTC)** and **XUS** — no bridge, no custodian, no wrapped assets — giving ZEC holders a private, self-sovereign on/off-ramp to a post-quantum privacy chain, and contributing reusable atomic-swap tooling and documentation back to the Zcash ecosystem.

## 2. Problem

Moving value in and out of the Zcash ecosystem today overwhelmingly relies on **custodial exchanges or bridges** — the exact trust assumptions Zcash exists to remove. Every custodial hop is a point of surveillance, seizure, and counterparty risk, and it re-links funds that a user shielded precisely to unlink them. Trustless cross-chain movement (HTLC / adapter-signature atomic swaps) is the principled alternative, but working, maintained, open-source ZEC swap tooling remains thin: several past efforts stalled, and community reviewers have repeatedly (and correctly) pushed back on "non-custodial" services that still require an operator to hold or sign over funds mid-swap.

The gap is not the cryptography — HTLCs are well understood — it is **shipped, audited, documented, genuinely operator-free software** that a ZEC holder can actually run.

## 3. Why this matters to Zcash

- **It is directly in ZCG's Interoperability mandate.** ZCG explicitly lists *atomic swaps* under Interoperability as fundable work for the public good of the Zcash ecosystem.
- **It gives ZEC a trustless exit and entry.** A ZEC holder can swap to/from XUS with no custodian in the loop and no wrapped-asset risk — the counterparty cannot take the funds; the worst case is a timeout and refund.
- **The tooling is reusable.** The HTLC construction, the timelock/refund safety logic, the BTC and ZEC leg watchers, the test vectors, and the integration guide are written to be **chain-agnostic on the Zcash side** and are published so other Zcash projects can lift them. The ZEC-leg work (transparent-address HTLC, shielded-flow documentation) is contributed back regardless of the counter-chain.
- **It aligns with Zcash's values, not just its ecosystem.** SOV/XUS is a privacy-first, ASIC-resistant, fair-launch PoW chain that already ships a **Zcash-grade Orchard/Halo2 shielded pool** (via the `orchard 0.14` crate, i.e. carrying the corrected 2026 Orchard circuit). This is a project built *with* Zcash technology that wants to be a good citizen of, and connective tissue for, the Zcash ecosystem.

## 4. What already exists (why this is fundable, not speculative)

This grant funds a well-scoped extension of **working, live software** — not a from-scratch idea. As of this application, SOV is a running mainnet Layer-1:

- **Live mainnet.** Fair-launch genesis on **2026-07-04** (genesis hash `cb0272ff…`), 21,000,000 hard cap, **zero pre-mine, no founder allocation, no token sale** — every coin is mined. RandomX PoW (ASIC-resistant), ~2.5-minute blocks, LWMA difficulty.
- **On-chain HTLC primitives already implemented.** `HtlcLock` / `HtlcClaim` / `HtlcRefund` actions exist in consensus today — the on-chain half of an atomic swap is done. `swapd` is the off-chain daemon that pairs these with Bitcoin/Zcash HTLCs to complete the swap.
- **Post-quantum security, real and fail-closed.** Hybrid **Ed25519 + ML-DSA-65 (FIPS-204)** signatures (a signature is valid only if *both* verify) and **X25519 + ML-KEM-768 (FIPS-203)** encrypted transport. Tested and fail-closed.
- **Zcash-grade shielded pool.** Orchard/Halo2 zk-SNARKs, no trusted setup, on `orchard 0.14`.
- **Correctness discipline.** An independent **TypeScript second client** re-derives block hashes and re-executes the state-transition function; **cross-implementation KAT vectors** pin consensus byte-for-byte; supply conservation is checked every block.
- **Public and verifiable.** Source: `github.com/cloudzombie/sov` · Explorer: `https://sovxus.org` · Site: `https://sovxus.com`

**Honest disclosure (see §9):** SOV is brand-new, **unaudited**, largely solo-built, has had **no external security review**, and has **no live market or liquidity**. That is precisely the work this grant is meant to fund — and why a portion of the budget is earmarked for an external security review of the swap-critical code and a public bug bounty.

## 5. Scope & deliverables

Build, harden, document, and independently review **`swapd`**: a standalone open-source daemon that executes trustless atomic swaps between XUS and (a) Bitcoin and (b) Zcash.

**In scope**
- HTLC swap protocol implementation binding a XUS `HtlcLock` to a counter-chain HTLC with matching hashlock and safe, asymmetric timelocks (claimant reveals the preimage first; refunds are guaranteed on timeout).
- **BTC ⇄ XUS** swap leg (Bitcoin P2WSH HTLC).
- **ZEC ⇄ XUS** swap leg using transparent-address ZEC HTLCs, plus a documented, tested flow for shielding/de-shielding around the transparent swap boundary so a user ends in the shielded pool.
- A refund/timeout safety layer (a "watch" loop) that guarantees no path where a correctly-behaving user can lose funds; the operator/daemon never custodies counterparty funds.
- CLI + local JSON-RPC/HTTP API, a maker/taker quote flow, and an integration guide.
- Cross-implementation **KAT test vectors** for the swap preimage/hashlock/timelock encodings, in the same style as SOV's existing consensus KATs.
- **External security review** of the swap-critical code paths and a **public bug bounty**.

**Explicitly out of scope (honest boundaries)**
- No order book, market-making, or liquidity provision — `swapd` is settlement infrastructure, not an exchange.
- The Zcash **shielded** leg is bridged via a documented shield/de-shield around a transparent HTLC (matching what current ZEC HTLC support allows); a fully shielded-to-shielded scriptless-script swap is noted as future work, not promised here.
- No claim that the Orchard shielded pool is post-quantum — it is not, same as Zcash (a known harvest-now-decrypt-later limitation, honestly disclosed).

## 6. Milestones, deliverables, KPIs & tranches

Each milestone ends with a tagged open-source release, a demo, a monthly forum status update, and a public write-up. Payment is released per milestone on delivery.

| # | Milestone | Key deliverables | KPI / acceptance | Tranche |
|---|-----------|------------------|------------------|---------|
| **M1** | Protocol + BTC⇄XUS on testnet | HTLC swap protocol spec; `swapd` core; **BTC ⇄ XUS** swap working end-to-end on testnet; KAT vectors for hashlock/timelock encodings | A third party can execute a full BTC⇄XUS testnet swap from the docs; refund path demonstrated on a deliberately-abandoned swap | **$12,000** |
| **M2** | ZEC⇄XUS leg | Transparent-ZEC HTLC leg; documented + tested shield/de-shield flow so the user finishes shielded; end-to-end **ZEC ⇄ XUS** testnet swap | A third party can execute a full ZEC⇄XUS testnet swap and end in the shielded pool; both timeout/refund paths demonstrated | **$12,000** |
| **M3** | Hardening + interfaces + docs | Refund/timeout safety layer; maker/taker quote flow; CLI + JSON-RPC/HTTP API; full integration guide; reproducible builds | No code path in which a correctly-behaving party loses funds (documented adversarial test matrix, all green); one-command reproducible build | **$11,000** |
| **M4** | Security review + bounty + release | External security review of swap-critical paths; findings triaged + fixed; **public bug bounty** launched; **v1.0 mainnet-ready** tagged release + signed binaries | Review report published; all critical/high findings resolved or documented; bounty live with published scope/rules | **$13,000** |
| | | | **Total** | **$48,000** |

*Intentionally set just under ZCG's $50,000 KYC threshold. I am willing to complete KYC (while remaining publicly pseudonymous) if the committee prefers.*

## 7. Itemized budget

| Item | Amount | Notes |
|------|--------|-------|
| Engineering — `swapd` core, BTC + ZEC legs, safety layer, CLI/API, docs (~5 months, solo) | $38,500 | The bulk of the work; solo builder rate well below market for this scope |
| External security review of HTLC + swap-critical code paths | $6,000 | Independent reviewer focused narrowly on the swap-critical surface |
| Public bug-bounty seed pool (swap scope) | $2,500 | Seeds a standing bounty; scoped to `swapd` + on-chain HTLC actions |
| Infrastructure — relay/watch VPS + BTC/ZEC/XUS testnet nodes (~$30/mo × ~6 mo + buffer) | $500 | Infra cost is genuinely tiny for this project |
| Contingency | $500 | |
| **Total** | **$48,000** | Paid in ZEC, milestone-tranched |

## 8. Timeline

Approximately **6 months** from funding, solo, part-to-full-time:

- **Month 1–1.5:** M1 (protocol + BTC⇄XUS testnet)
- **Month 2.5–3:** M2 (ZEC⇄XUS leg)
- **Month 4:** M3 (hardening, interfaces, docs)
- **Month 5–6:** M4 (external review, bounty launch, v1.0 release)

Monthly status updates posted to the grant's forum thread, as ZCG requires, with each milestone's payout contingent on the update + deliverable.

## 9. Honest risks & disclosures

- **Unaudited, no prior external review, largely solo-built.** True today. The grant's M4 explicitly funds an independent review + a standing bug bounty to begin closing this gap. I will not represent `swapd` as production-safe before that review lands.
- **No live market/liquidity for XUS.** `swapd` is settlement plumbing; it does not create demand. This grant does not ask ZCG to fund liquidity or listings, and I make no promise of trading volume. The public good delivered is the *tooling and documentation*, which stand on their own for the Zcash ecosystem.
- **Shielded-to-shielded swaps are future work.** The ZEC leg uses a transparent HTLC with a documented shield/de-shield boundary. I am not promising a fully shielded scriptless-script swap under this grant.
- **The shielded pool is not post-quantum.** Orchard/Halo2, same as Zcash — a known harvest-now-decrypt-later limitation, disclosed, not hidden.
- **Solo-builder / bus-factor risk.** Mitigation: everything is open source under permissive licenses, spec + KAT vectors + docs are milestone deliverables, and builds are reproducible — so the work is continuable by others if I step away.
- **Counter-chain / dependency risk.** Bitcoin and Zcash HTLC/script behavior and node interfaces can change; the protocol spec pins exact assumptions and the test matrix is run against pinned node versions.

## 10. Why me

Solo builder who has already shipped a **live, fair-launch, post-quantum PoW Layer-1** — RandomX consensus, hybrid PQ signatures and transport, a Zcash-grade Orchard/Halo2 shielded pool, on-chain HTLC actions, an independent second client, and cross-implementation KAT vectors — all public and verifiable at `github.com/cloudzombie/sov`, with a live explorer at `https://sovxus.org`. The on-chain half of atomic swaps already exists in this codebase; this grant funds the off-chain daemon, the ZEC integration, the review, and the documentation that turn it into a public good for Zcash.

`[TODO: 2–4 sentence personal or pseudonymous bio — relevant background, prior open-source work, and how reviewers can reach you.]`

## 11. Deliverables recap (public goods)

- `swapd` — open-source (MIT/Apache-2.0) trustless BTC/ZEC ⇄ XUS atomic-swap daemon
- HTLC swap protocol spec + cross-implementation KAT vectors
- Tested transparent-ZEC HTLC leg + documented shield/de-shield flow (reusable by other Zcash projects)
- Integration guide, CLI, and JSON-RPC/HTTP API
- Published external security review of the swap-critical code + a live public bug bounty

## 12. Links

- Source: https://github.com/cloudzombie/sov
- Explorer: https://sovxus.org
- Site: https://sovxus.com
- Pre-submission forum feedback thread: `[TODO: paste URL]`
- GitHub application issue: `[TODO: paste URL]`

## 13. Administrative (to complete on submission)

- **ZEC payout address:** `[TODO]`
- **Forum handle:** `[TODO]`
- **GitHub handle:** `[TODO]`
- **KYC:** Willing to complete if requested; publicly pseudonymous. (Kept the ask just under the $50k mandatory-KYC threshold to reduce friction, but happy to comply.)
