# Runbook — v0.1.98 ACTIVATION PLAN (tx-domain fork + fee-auction mempool)

> ★★★ CONSOLIDATED TARGET. v0.1.95 was SKIPPED as a release; its entire plan (the
> tx-domain hard-fork activation) folds into **v0.1.98**, bundled with the new
> **fee-priority mempool + v2 transaction envelope (tip/bid)**. Both touch the
> transaction envelope + signing and both need the identical dormant → miner-signaled
> activation machinery, so they activate as ONE coordinated event — strictly less risk
> than two separate flag days on a live reserve chain.

_Last updated 2026-07-21. Supersedes the v0.1.95 target in
[activation-tx-domain.md](activation-tx-domain.md) (kept for design reference)._

## Golden rules (unchanged, do not break)
- Genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` NEVER changes.
- Consensus changes ship **dormant**; arming is a separate, coordinated, explicitly-approved step.
- Every phase gate re-proves the `sov-verify` KAT byte-for-byte + genesis pins before shipping.
- Reserve-grade: conservative pace, prove-don't-claim, external-audit-before-production.

---

## PART A — tx-domain hard fork (carried over from the skipped v0.1.95)

**State:** shipped DORMANT in v0.1.93 (`25b3b5d`). Full machinery present + tested;
`tx_domain_deployment` defaults `None` → signing bytes byte-identical to pre-v0.1.93.
Nothing armed. Closes "ghost chain" cross-network signature replay by binding each
tx/intent signature to `{chain_id, genesis}`.

**Why hard fork + generous horizon:** post-activation a node enforces the bound
preimage — a legacy-signed tx is rejected, and an un-upgraded node rejects a
correctly-bound tx (forks off). So every node AND every signer must be upgraded BEFORE
the flag day. A ~250-block (~10h) countdown is NOT acceptable (decision 2026-07-19);
generous horizon (days) only, after prerequisites provably met + explicit go.

**Safe activation order (do NOT reorder):**
1. **Phase-2 client signing** (additive/DORMANT) — every signer becomes domain-aware via
   the read-only `sov_getSigningDomain` RPC (returns `chainId`+genesis, or null while
   dormant). Each client queries it and calls `sign_in(Some(domain))` when non-null, else
   `sign()`. **Status of the 5 signers (VERIFY each before arming):**
   - [x] `sov_getSigningDomain` RPC — landed + tested (`get_signing_domain_reports_dormant_by_default`)
   - [~] SOV Station (`node/src/gui.rs`) — references present; MUST re-verify it queries + signs bound
   - [ ] TS SDK (`sdk/`) — the KAT second client — NOT DONE
   - [ ] Rust wallet (`chain/crates/wallet`) — NOT DONE
   - [ ] `tools/conformance` — NOT DONE
   - [ ] `tools/tx-cannon` — NOT DONE
2. **Grace-window gate** (DORMANT) — for `[H_a, H_a+G)` accept EITHER legacy OR bound;
   `≥ H_a+G` bound-only. Removes the boundary cliff for in-flight legacy txs.
3. **Confirm the fleet** — every node + wallet + tool on the v0.1.98 binary (roll-call +
   `sov_getDeployments`).
4. **Fable adversarial audit** of `25b3b5d` + grace-window + Part B.
5. **Schedule** a concrete height on a generous horizon (days) with explicit owner go.
6. **Activate.**

Preimage: `tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh` — tag `sov:tx:v1` /
`sov:intent:v1`. `SigningDomain::frame` in `primitives/src/signing_domain.rs`. tx id is
UNCHANGED (hash of bare borsh) → KAT byte-for-byte; only the signature binds.

---

## PART B — Fee-priority mempool + v2 transaction envelope (the "auction")

### B.0 Problem statement (verified against current code, 2026-07-21)
- `Transaction { signer, public_key, nonce, action }` — **NO fee/tip field exists.**
- Fee is protocol-fixed: `gas_used × gas_price`, `gas_price = 10 grains` (mainnet), a
  CONSENSUS-CRITICAL constant in `mining/src/lib.rs`. Every transfer pays an identical fee.
- Mempool orders strictly by `(signer, nonce)` — `Mempool::select` walks each signer's
  contiguous nonce run. The code documents "there is no fee auction to bid for priority."
- Fee destination TODAY: `distribute_fee(ledger, ctx, fee) → credit(ctx.miner, fee)` —
  **already 100% to the miner.** (So a tip-to-miner is an extension of existing behavior,
  not new plumbing.)

**Conclusion:** a priority queue alone does nothing — there is no bid dimension to sort on.
The auction requires a **tip field**, which requires a **versioned tx envelope**.

### B.1 The two layers
**Layer 1 — Fee-priority mempool + template builder (POLICY, zero consensus surface).**
Like Bitcoin: block validity does NOT depend on tx ordering/selection, so this is
node-local and genesis-safe — shippable in ANY release, no fork. Changes:
- Admission/eviction ordered by **effective feerate** (tip per byte); when full, evict the
  lowest-feerate package.
- `select()` becomes greedy-by-feerate across signers, still nonce-contiguous per signer.
- Replace-by-fee: same `(signer, nonce)` with a higher tip replaces the pooled tx, subject
  to a minimum bump % (anti-spam).

**Layer 2 — v2 envelope carrying an optional `tip` (CONSENSUS-adjacent, genesis-safe).**
Users need a bid dimension. Add a versioned tx variant with a `tip: Balance` field.
- **Fixed fee stays as the FLOOR** (unchanged, consensus-critical); the tip is a bid ON
  TOP. Predictable minimum + auction only under congestion. (Bitcoin min-relay + bidding.)
- **Tip → the miner** via the existing `distribute_fee` path (default; see open question on
  ★TAX routing).
- Per-signer nonce contiguity means a high-tip tx behind a low-tip earlier nonce prices as
  a **package** (Ethereum effective-feerate), so a later high bid cannot jump its own
  earlier nonce.

### B.1a KEYSTONE ENCODING DECISION — tip = additive `Action::Tipped` variant
**The tip must NOT be a new field on `Transaction`.** In Borsh, ANY added struct field
changes the bytes — even `Option<Balance>` (1-byte `None` tag) or a `Vec` (4-byte empty
length) — which would move genesis `cb0272ff` and break every existing KAT. Enum
variants, by contrast, are self-describing (a discriminant byte), so appending one is
byte-identical for all existing variants. This is exactly why multisig / SNS were
additive.

**Decision:** carry the tip as a NEW appended `Action` variant that wraps the real action:
```
Action::Tipped { tip: Balance, inner: Box<Action> }   // new discriminant, appended last
```
- `Transaction` / `SignedTransaction` / `Block` structs are **UNCHANGED** ⇒ genesis +
  every existing KAT vector are provably byte-identical (verified by the release-gate
  genesis rebuild + `sov-verify` KAT). New KAT vectors added for `Tipped`.
- The tip is committed inside `signing_bytes` automatically (it's in the action), so the
  signature binds it; tx id machinery untouched.
- **Gating (dormant):** admission (`Mempool::insert`) + import (`validate_candidate`) +
  execution reject `Action::Tipped` UNLESS the `fee-auction` `governance::Deployment` is
  `Active` at that height — reusing the SAME BIP-9 engine as tx-domain. Pre-activation:
  no `Tipped` tx is accepted anywhere ⇒ byte-identical behavior.
- **Runtime:** on `Tipped { tip, inner }` — reject if `inner` is itself `Tipped` (no
  nesting); charge the normal intrinsic fee on `inner`; additionally debit `tip` from the
  signer and credit the miner via the existing `distribute_fee`/`credit(ctx.miner, …)`
  path (tip routing default = 100% miner); then execute `inner`. `gas_for(Tipped) =
  gas_for(inner) + BOOKKEEPING_GAS`.
- **Mempool feerate:** effective bid = `tip` (0 for v1/untipped). Ordering reads the tip
  off the action; untipped txs keep today's fair `(signer, nonce)` behavior at bid 0.
- **RBF:** replace a pooled `(signer, nonce)` iff `new_tip ≥ old_tip + MIN_RBF_BUMP`.

### B.2 Why genesis-safe (the precise argument)
1. **Genesis has 0 transactions** (verified live: block 0 tx count = 0) → its hash cannot
   depend on any tx-format addition.
2. **Additive enum variant** — the proven pattern (multisig, SNS, tx-domain all did it):
   v1 txs stay byte-identical forever; existing KAT vectors untouched; NEW KATs added for
   v2. No reset.
3. **Dormant → miner-signaled activation** (reuses `governance::Deployment` / `state_at`,
   the SAME BIP-9 engine as tx-domain): v2 txs rejected until activation → pre-activation
   byte-identical.

### B.2b Nonce-queue + replace-by-fee (the "tx stuck while one is pending" bug)
**Observed 2026-07-21 (SOV Station v0.1.97):** a private send failed with
`mempool rejected: a transaction with signer a35755d3… and nonce N is already pooled`
(`MempoolError::NonceTaken`) while one tx was already pending ("1 pending").

**Root cause (code-confirmed):** the wallet client builds every tx with `sov_getNonce`
= the **on-chain** nonce, ignoring what it already has pending. Two sends ⇒ both use
nonce N ⇒ collision. **The mempool ALREADY accepts contiguous next nonces** — admission
computes `expected = on_chain_nonce + sender_count(signer)` and accepts `nonce ≤ expected`
(`mempool/src/lib.rs` ~L264). So a second send built at **N+1** would have been accepted
and mined right after the first. This is a **client bug, not a consensus limit.**

**Fix 1 — Queue (wallet-side, NO consensus change, genesis-safe, may ship early):**
- Add `sov_getNextNonce{account}` → `on_chain_nonce + pooled_count(signer)` (a thin RPC
  over the mempool's existing `sender_count`).
- Station / SDK / Rust wallet / tx-cannon build at that nonce instead of `sov_getNonce`.
- Result: fire N, N+1, N+2 back-to-back; they mine in order. Directly fixes the screenshot.
- Verification: I9 — after admitting a tx at nonce N, a distinct tx at N+1 from the same
  signer is admitted (not `NonceTaken`), and both select in ascending nonce order.

**Fix 2 — Replace-by-fee / cancel (rides on the B.1 tip field):**
- Re-send the SAME `(signer, nonce)` with a higher tip to REPLACE the pooled tx; today
  `NonceTaken` refuses in-place replacement (would orphan the entry). With the tip field,
  allow replacement iff `new_tip ≥ old_tip + MIN_RBF_BUMP` (evict old, insert new).
- A "cancel" is an RBF replacement with a no-op/self-transfer at the stuck nonce.
- Verification: I6 already covers RBF ≥ min-bump; add I10 — an RBF below min-bump is
  refused; an RBF at/above it atomically replaces (no orphaned id, capacity preserved).

### B.3 Interaction with Part A (why they belong together)
Both change the transaction envelope + the signed preimage. Doing them as ONE v2 envelope
+ ONE activation event means: one KAT-vector regeneration, one grace window, one fleet
roll-call, one flag day. The v2 tx is BOTH domain-bound AND tip-carrying. Splitting them =
two forks = double the coordination risk on reserve mainnet.

---

## Combined verification plan (backtest + formal)

### Invariants to prove (each = a test + a stated theorem-style property)
- **I1 — Genesis immutability.** Rebuild genesis byte-for-byte to `cb0272ff` with the v2
  envelope compiled in but DORMANT. (Backed by release-gate step [3].)
- **I2 — Pre-activation byte-identity.** With deployment `None`: every v1 signing preimage,
  tx id, block encoding, and the full `sov-verify` KAT set reproduce byte-for-byte vs
  v0.1.97. (release-gate KAT step.)
- **I3 — Fee floor is inviolable.** For any v2 tx, admission + execution require
  `balance ≥ intrinsic_fee + tip + outflow`; a tx paying `< intrinsic_fee` is rejected
  exactly as today (extends `CannotAffordFee`).
- **I4 — Conservation with tips.** `Σ debits = Σ credits` still holds: `tip` moves signer →
  miner, nothing minted/burned. The existing supply-conservation import check
  (`check_transition`) must pass unchanged. THE critical reserve invariant.
- **I5 — No nonce jumping.** Package feerate ⇒ a later-nonce high tip cannot be mined before
  the same signer's earlier lower-tip nonce. Property test over random tip/nonce sequences.
- **I6 — Monotone auction.** Under a full mempool, raising a tx's tip never lowers its
  inclusion priority; RBF requires ≥ min-bump. Property test.
- **I7 — Grace-window soundness (Part A).** In `[H_a, H_a+G)` both legacy and bound verify;
  `≥ H_a+G` legacy is rejected; `< H_a` bound is rejected. Boundary tests at
  `H_a-1, H_a, H_a+G-1, H_a+G`.
- **I8 — Deployment inertness.** With the deployment scheduled but not `Active`, mainnet
  behavior is identical to v0.1.97 (mempool policy may reorder — that's non-consensus — but
  no v2 tx is accepted and no signing changes).

### Backtest method (replay against real history — no mainnet risk)
1. Pull the real `blocks.log` from a seed (platform-independent), replay it through the
   v0.1.98 binary with the deployment DORMANT → must produce the identical tip hash +
   supply the live chain reports. (Proves I2/I8 on 9,000+ real blocks.)
2. Fork a throwaway local 2-node net from that history; schedule activation at a near
   height; drive v1-legacy + v2-tip + bound txs across `[H_a-…, H_a+G+…]`; assert
   I3–I7 hold at every boundary and the two nodes agree on tip hash + supply each block.
3. Cross-node KAT: the TS SDK (second client) must reproduce the v2 signing preimage +
   tx id byte-for-byte from the Rust `sov-katgen` vectors (add v2 vectors).

### Formal-verification method (as far as this codebase supports)
- **Property tests** (proptest-style) for I3–I6: random `(nonce, tip, balance, action)`
  sequences ⇒ assert conservation, floor, package-ordering, monotonicity.
- **Exhaustive boundary tests** for I7 at the four grace-window edges.
- **`sov-verify` KAT** as the byte-for-byte cross-impl consensus pin (Rust source vs TS
  second client) for I2.
- **`check_transition`/`check_ledger` import invariants** (already reject supply-breaking
  blocks) exercised with tip-bearing blocks for I4.
- **redteam harness** (`sov-redteam`): add attacks — forge a tip larger than balance;
  replay a v2 tx cross-net (must fail post-activation); RBF below min-bump; nonce-jump via
  tip. All must be defended (nonzero exit on any vuln).
- NOTE: this is test-based + KAT-based assurance ("prove-don't-claim"), NOT machine-checked
  proofs in a proof assistant. Do not overstate it as the latter. Reserve-grade still
  requires the external audit (Part A step 4 + a crypto/econ review of Part B) before
  "production."

## Sequencing
1. **Part B Layer 1** (fee-priority mempool policy) — ship EARLY, own release or folded in;
   zero consensus surface, reversible, gives the template builder the ordering it needs.
2. **Complete Part A Phase-2 signers** (SDK, wallet, conformance, tx-cannon) — the current
   blocker; without it a tx-domain flag day rejects every legacy tx.
3. **Part B Layer 2** (v2 envelope + tip) as an additive DORMANT variant, same release.
4. **Grace window + fleet roll-call + Fable audit + external econ/crypto review.**
5. **Schedule one generous-horizon activation** (explicit owner go) → activate BOTH.

## Open questions (owner decisions, not engineering)
1. **Tip routing:** 100% to miner (Bitcoin-style, simplest, DEFAULT) vs through the ★TAX
   split (90% miner / 9% US Treasury / 1% dev) like coinbase? Economics call.
2. **Fee floor under congestion:** keep the flat fixed floor, or add a dynamic base-fee
   (EIP-1559 with a static-ish base) once real demand exists? Today blocks are ~574 B and
   mostly empty — no congestion to price yet, so START with flat floor + tip.
3. **Min RBF bump %** and **max tip** sanity bound.
4. Whether to also give the mempool a small **min-relay tip** to deter free spam once tips
   exist.

## BUILD PROGRESS (branch `feat/v0.1.98-mempool-auction`)

- **Slice 1 — nonce-queue (`sov_getNextNonce`)** — ✅ DONE. Fixes the live NonceTaken bug
  (queue sends instead of colliding; self-heals reorg holes via first-free-slot walk +
  `evict_stranded` on both prune ticks). Fable-audited ×2, all findings closed. Genesis-safe,
  consensus-neutral. mempool 27 / node 10 green. Commits `8ab41c9`, `6d4821c` (+ base).
- **Slice 2a — `Action::Tipped` envelope, DORMANT** — ✅ DONE. Additive variant (appended
  last), gas defined, hard-rejected (`ExecutionError::FeatureInactive`) until activation ⇒
  any block carrying it is invalid. **PROVEN genesis-safe: genesis rebuilds to cb0272ff (6/6),
  KAT byte-identical (6/6), runtime 70/70.** Commit `8a0daac`. `NestedTip` error pre-added.
- **Slice 2b — activation gate + tip charging + inner-dispatch** — ⏭️ NEXT (value-moving /
  conservation-critical; built with the I4 conservation test + KAT vectors + Fable audit, NOT
  rushed). Add `BlockContext.fee_auction_active` (thread from a `fee_auction_deployment` on
  Blockchain, dormant `None`), unwrap `Tipped` at the `effective_action` step (mirror the
  MultisigExec unwrap): gate on active, reject nesting (`NestedTip`), check affordability of
  `intrinsic_fee + tip + outflow`, debit `tip` → credit `ctx.miner` via `credit()`, execute
  `inner`. New KAT vectors for a tipped tx.
- **Slice 3** — mempool feerate ordering + RBF (bid = tip; replace ≥ MIN_RBF_BUMP) + template.
- **Slice 4** — confirm conservation (I4) end-to-end with tips in real blocks.
- **Slice 5** — Part A Phase-2 signers (SDK, wallet, Station, conformance, tx-cannon).
- **Slice 6** — grace window + full release gate + end-to-end Fable audit + external review.

Everything above is on a BRANCH, dormant/additive, nothing armed, genesis frozen — safe for
morning review. No mainnet touch until the fleet + audits + explicit go.

## Immediate next action
Slice 2b (above) — the activation logic — with the conservation invariant test first.
