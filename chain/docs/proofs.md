# SOV Chain — Formal Mathematical Proofs

**Status: normative supplement.**
**Author: Fable 5 (`claude-fable-5`), 2026-06-09 — every code pointer, line
number, and test name below was re-verified against the working tree on that
date. Parts VII (native assets), VIII (contract execution, VM ABI v2), IX
(issuer-sovereign compliance), X (atomic intent settlement), XI
(cryptographic agility and key rotation), XII (hybrid post-quantum
signatures), XIII (hybrid post-quantum transport), XIV (the Q-day
runbook as consensus policy), and XV (shielded drain bound and the privacy
horizon) added 2026-06-10/11 alongside the code they prove, re-verified the
same way.**
**Revised 2026-06-12 (Opus 4.8) for the Nakamoto consensus migration: SOV is
now pure proof-of-work, exactly as Bitcoin and Zcash. Proof-of-stake is gone
(no `staked` balance, no staking emission budget, no stake-weighted
committee); BFT finality is gone (no validator votes, no equivocation slashing,
no proposer schedule). Issuance is the block coinbase on Bitcoin's emission
schedule with NO pre-mine, fork choice is heaviest accumulated work, finality
is confirmation depth, and the difficulty a header may claim is fixed by the
retarget rule and committed in Bitcoin's compact `nBits`. Part III was rewritten
to the Nakamoto model; Part I/0 dropped the staking terms; the former Part XVI
(an off-chain compute marketplace) was deleted with its code.**

This document proves the SOV chain's core safety properties. The discipline
throughout:

1. Every theorem is stated over the **actual data structures and predicates in
   the code** — not a re-modelled abstraction that could drift from the
   implementation.
2. Every theorem closes with a **Code** pointer to the exact function proved
   about, and a **Machine-checked-by** pointer to a passing test in the
   workspace suite that exercises the same property against the real
   implementation. The proofs are therefore re-verified on every CI run.
3. All quantities are integer **grains** (`u128`); `1 XUS = 10^8 grains` and
   the cap is `MAX_SUPPLY_GRAINS = 21 000 000 · 10^8 = 2.1 × 10^15`
   ([`amount.rs:27`](../crates/primitives/src/amount.rs)). No proof uses
   real-number arithmetic; every step is exact over `ℤ`.

## Standing assumptions

The proofs are unconditional **except** where they explicitly invoke one of:

- **A1 (hash security).** Blake3 — the chain's only general-purpose hash
  ([`hash.rs:30`](../crates/primitives/src/hash.rs)) — is collision- and
  second-preimage-resistant, and behaves as a random oracle where stated.
- **A2 (signature security).** Per-scheme, since keys are versioned
  (Part XI): **A2a** — Ed25519 is EUF-CMA secure (`ed25519-dalek`, strict
  verification); **A2b** — ML-DSA-65 (FIPS 204, `fips204` crate) is EUF-CMA
  secure. A `V1` signature relies on A2a; a `V2` **hybrid** signature is
  unforgeable if **either** A2a *or* A2b holds (Theorem 30) — in particular,
  hybrid accounts stay secure if a quantum computer falsifies A2a. *Honest
  note:* the `fips204` implementation is NIST-ACVP-vector-tested but does not
  yet have `ed25519-dalek`'s audit depth — which is exactly why the protocol
  only ever uses ML-DSA in conjunction with Ed25519, never alone.
- **A3 (circuit soundness).** The Orchard/Halo2 zk-SNARK system is sound.
  Theorem 7 deliberately shows the *supply* argument does **not** depend on A3.
- **A4 (key-exchange security).** Per-component, for the p2p transport
  (Part XIII): **A4a** — X25519 CDH is hard (the Noise channel); **A4b** —
  ML-KEM-768 (FIPS 203, `fips203` crate) is IND-CCA secure. Transport
  confidentiality holds if **either** A4a *or* A4b holds.
- **P1 (distribution).** There is **no protocol tax**: the entire coinbase and every
  fee are paid to the block's miner (`distribute_fee` / `apply_coinbase` in
  [`runtime/src/execution.rs`](../crates/runtime/src/execution.rs)). Distribution is a
  single credit to one recipient, so it trivially pays out exactly what was collected
  (no rounding, no remainder). Lemma 2 states where this is used.

---

## Part 0 — The model

### Definition 1 (ledger state)

A ledger state `L` ([`ledger.rs`](../crates/state/src/ledger.rs)) consists of:

- a finite account map `A`, each account `a` carrying
  `balance(a), locked(a) ∈ ℤ≥0`, a `nonce(a) ∈ ℕ`, an optional
  controlling key `key(a)`, and optional contract `code(a)`. (There is no
  `staked` field: SOV has no proof-of-stake.)
- one scalar counter `mined(L) ∈ ℤ≥0` — cumulative proof-of-work issuance.
  (There is no fee-burn counter — SOV is not deflationary — and no `staked_e`
  staking-emission counter.)
- the shielded-pool value `shield(L) ∈ ℤ≥0` and the HTLC escrow total
  `htlc(L) ∈ ℤ≥0`;
- the shielded consensus state `Σ(L) = (T, 𝒜, 𝒩)`: an append-only note-
  commitment tree `T`, the set `𝒜` of every anchor (tree root) the chain has
  held, and the spent-nullifier set `𝒩`
  ([`shielded/state.rs:36`](../crates/shielded/src/state.rs)).

### Definition 2 (total supply)

$$
S(L) \;=\; \sum_{a \in A} \big(\mathrm{balance}(a)+\mathrm{locked}(a)\big)
\;+\; \mathrm{shield}(L)\;+\;\mathrm{htlc}(L).
$$

This is exactly `Ledger::total_supply`
([`ledger.rs:395`](../crates/state/src/ledger.rs)): the account sum is
`Account::total()` (`balance + locked`, [`account.rs:72`](../crates/state/src/account.rs))
plus `shielded_value` plus `htlc_locked`. Write `C = MAX_SUPPLY_GRAINS`.

### Definition 3 (transition)

A transition `L → L'` is the application of one block: first the **coinbase**
(`apply_coinbase` [`execution.rs:1284`](../crates/runtime/src/execution.rs))
mints the scheduled proof-of-work subsidy to the block's miner, then the
block's finite sequence of signed transactions via `apply_transactions`, each
through `apply_transaction`
([`execution.rs:105`](../crates/runtime/src/execution.rs)). A transaction is
either **rejected** (`Err`: bad signature, wrong key, bad nonce, oversized
data, or unaffordable intrinsic fee — it is never included in a block), or
**admitted**, in which case it yields a receipt whose status is `Success` or
`Failed`. The coinbase is **not** a transaction (it carries no signature and
appears in no receipt); it is a block-level mint, exactly as in Bitcoin.

### Lemma 0 (no silent wraparound)

Every monetary operation in the state-transition function uses
`Balance::checked_add` / `checked_sub`
([`amount.rs:61,66`](../crates/primitives/src/amount.rs)); a result outside
`[0, 2^128)` yields `None`/`Err` and the transaction aborts. Hence every
arithmetic step written as an equation below holds **exactly over `ℤ`**, or
the transaction did not commit.
**Machine-checked-by:** `amount::tests::checked_arithmetic`.

### Lemma 1 (rejection atomicity)

If `apply_transaction` returns `Err`, the ledger is unchanged.

**Proof.** Inspect the function in order
([`execution.rs:105–195`](../crates/runtime/src/execution.rs)). The rejection
gates — signature (`:110`), authorization (`:121`), nonce (`:138`), BIP-110
size (`:147`), fee affordability (`:174`) — all return before any call to
`set_account` or any ledger counter/pool mutation: the signer is mutated only
on a **local copy**, written back at `:609` after the action arm completes.
Within the arms, each `Err`-returning `checked_*` either precedes the first
ledger mutation of that arm, or is made unreachable by an explicit pre-check
performed before mutating (the shielded arm pre-checks affordability at
`:428–434` before `apply_shielded_bundle`; the transfer arm computes the
recipient's `checked_add` before writing either account). ∎

---

## Part I — Monetary theorems

### Lemma 2 (coinbase/fee distribution exactness)

For any amount `f ≥ 0` grains — a transaction fee in `distribute_fee` or a block
subsidy in `apply_coinbase`
([`execution.rs`](../crates/runtime/src/execution.rs)) — the protocol credits the
**entire** amount to the block's miner:

$$
\mathrm{miner} = f
$$

There is no tax and no burn term. Trivially:

1. `miner = f` — **every grain is paid out; nothing is created, lost, or burned**;
2. `0 ≤ miner ≤ f`.

**Proof.** Distribution is a single `credit(miner, f)`, so the amount paid out equals
`f` exactly, with no rounding, remainder, or burn. ∎

**Code:** `distribute_fee`, `apply_coinbase`, `credit`
([`execution.rs`](../crates/runtime/src/execution.rs)).
**Machine-checked-by:**
`execution::tests::deploy_then_call_contract_charges_gas_fee_to_caller` (asserts the
miner receives the entire fee — no tax, no burn); the SDK `stf.test.ts` coinbase test
reproduces the identical full-to-miner credit byte-for-byte.

### Theorem 1 (value conservation)

For every committed transition `L → L'`,

$$
S(L') \;=\; S(L) \;+\; \Delta\mathrm{mined},
$$

where `Δx = x(L') − x(L)` and `Δmined ≥ 0`. There is **no `−Δburned` term**: SOV
has no burn, so supply is non-decreasing.

**Proof.** A block is the coinbase followed by the left-to-right composition of
its transactions, and the claimed equation telescopes under composition, so it
suffices to prove it for the coinbase and for one admitted transaction. By
Lemma 0 each equation is exact, and by Lemma 1 rejected transactions
contribute `Δ = 0`.

**Coinbase** (`apply_coinbase` [`execution.rs`](../crates/runtime/src/execution.rs)):
it credits `primary + secondary + miner_cut` and sets `mined += r`, where
`r = reward_at(height, mined(L))` (Lemma 3) and the three shares sum to exactly
`r` (Lemma 2). So `ΔS = r = Δmined` **independent of how the tax splits it** — the
whole subsidy enters supply, only its recipients differ. (When `r = 0` — issuance
off or budget spent — nothing moves.) This is the **only** source of `Δmined`: no
transaction can mint.

Then the per-arm case analysis over `apply_transaction`
([`execution.rs`](../crates/runtime/src/execution.rs)):

1. **Transfer**: `balance(signer) −= v`, `balance(to) += v`; net
   `ΔS = 0`. Self-transfer and the `Failed` path move nothing.
2. **ClaimVesting**: `locked −= v`, `balance += v`; `ΔS = 0`.
3. **Deploy / Call**: touch `code` and contract storage only — never a
   balance, lock, pool, or counter; `ΔS = 0` apart from the fee (case 6).
4. **Shielded**, value balance `vb`: if `vb < 0`,
   `balance(signer) −= |vb|` and `shield += |vb|`; if `vb > 0`, `shield −= vb`
   and `balance(signer) += vb`; if `vb = 0`, neither moves. All three give
   `ΔS = 0`.
5. **HtlcLock / HtlcClaim / HtlcRefund**: lock moves `balance → htlc`;
   claim and refund move `htlc → balance`. `ΔS = 0`.
6. **Fee:** the fee `f` was debited from `balance(signer)` before the arm ran
   (plus any VM gas), removing `f` from `S`. `distribute_fee` then credits
   `primary + secondary + miner = f` back to balances (Lemma 2) — **nothing is
   burned**. Net fee effect: `ΔS = −f + f = 0`.

(There are no `Mine`, `Stake`, `Unstake`, or `MineShielded` arms: issuance is
the block coinbase above, and proof-of-stake is gone entirely.)

Summing: the only nonzero contribution to `ΔS` is `+Δmined` (the coinbase); every
transaction, fee included, is supply-neutral. Monotonicity: `mined` is written
only by `add_mined_emitted` ([`ledger.rs`](../crates/state/src/ledger.rs)) — there
is no decrement anywhere in the workspace, and no burn counter at all — via
`checked_add` (Lemma 0). ∎

**Code:** `apply_coinbase`, `apply_transaction`, `distribute_fee`; the
**independent re-checker** `check_transition`
([`invariants.rs`](../crates/verify/src/invariants.rs)) enforces this exact
equation, plus monotonicity of the `mined` counter, on every imported block —
written against the ledger interface, not the execution code, so a bug in
execution cannot also hide the violation.
**Machine-checked-by:** `invariants::tests::{transfer_conserves_value,
mint_is_accounted_by_the_mined_counter, destroyed_value_is_caught,
regressed_emission_is_caught, combined_transfer_and_coinbase_balances}`;
`execution::tests::htlc_atomic_swap_locks_then_claims_with_the_preimage`.

### Theorem 2 (no unauthorized mint)

If `S(L') > S(L)` then `Δmined > 0`: supply can rise **only** through the
proof-of-work emission counter (the coinbase).

**Proof.** Rearrange Theorem 1: `Δmined = S(L') − S(L) > 0`. Contrapositive: a
block with `Δmined = 0` (no coinbase, e.g. once the budget is spent) has
`S(L') = S(L)` — supply is held exactly, never raised (and, with no burn, never
lowered either). ∎

**Machine-checked-by:** `invariants::tests::unauthorized_mint_is_caught`
(constructs supply-up-with-no-counter-move and asserts `ValueNotConserved`);
`invariants::tests::shielded_pool_cannot_manufacture_supply`.

### Lemma 3 (the reward schedule is non-increasing and room-bounded)

`MiningPolicy::reward_at` ([`mining/lib.rs:158`](../crates/mining/src/lib.rs))
is **Bitcoin's emission rule verbatim** — the subsidy is keyed to block
*height* `n` (not to cumulative supply), halving every `I` blocks, then clamped
to the budget room:

$$
r(n, m) \;=\;
\begin{cases}
0 & n = 0 \text{ (genesis: no pre-mine)}\\[2pt]
0 & m \ge B_m\\[2pt]
\min\!\big(\,b \,»\, h(n),\; B_m - m\,\big) & n \ge 1,\ m < B_m,
\end{cases}
\qquad h(n) = \big\lfloor (n-1) / I \big\rfloor
$$

(with `b » h = 0` for `h ≥ 127`), base reward `b`, halving interval `I ≥ 1`,
mining budget `B_m`, and `m` the cumulative mined supply. Then:
(i) `r(n,m) ≤ B_m − m` for all `m < B_m`, and `r(n,m) = 0` for `m ≥ B_m` or
`n = 0`;
(ii) for fixed height `n`, `r(n, ·)` is non-increasing in `m`;
(iii) the per-height scheduled subsidy `b » h(n)` is non-increasing in `n` and
halves exactly every `I` blocks.

**Proof.** (i) is the `min` clamp and the explicit `n = 0` and `m ≥ B_m`
guards (`:159,163`). (ii): `m ↦ b » h(n)` is constant in `m` and
`m ↦ B_m − m` is strictly decreasing; the pointwise `min` is non-increasing.
(iii): `h(n) = ⌊(n−1)/I⌋` is non-decreasing in `n` and increases by exactly 1
each time `n` crosses a multiple-of-`I` boundary, so `b » h(n)` halves there;
the `h ≥ 127` guard caps the shift at `0` instead of shifting out of range. ∎

**Machine-checked-by:** `mining::tests::{subsidy_halves_on_bitcoins_height_schedule,
reward_clamps_to_budget}` (including `r(n, B_m − 1) = 1`, `r(n, B_m) = 0`,
`r(0, ·) = 0`).

### Theorem 3 (the 21M supply cap holds for all time)

For every reachable state `L`: `S(L) ≤ C` and `mined(L) ≤ B_m`.

**Proof.** Induction on block height, with the budget bound carried as part of
the induction invariant.

*Base.* `GenesisConfig::build` ([`genesis.rs:88`](../crates/chain/src/genesis.rs))
computes `total = Σ balance + Σ vesting + B_m` with `checked_add` throughout
and returns `SupplyCapExceeded` unless `total ≤ C` (`:106`). The constructed
ledger satisfies `S(L₀) = total − B_m ≤ C` and `mined(L₀) = 0`.

*Step.* Assume `S(Lₙ) + (B_m − mined(Lₙ)) ≤ C` — this strengthened invariant
holds at genesis by the base case. By Theorem 1 **every** transition (coinbase or
transaction) satisfies `ΔS = Δmined`, so the left side changes by
`ΔS − Δmined = 0` — the invariant is preserved exactly by every block (with no
burn there is not even a `−Δburned ≤ 0` slack term). The budget bound is preserved:
the only writer of `mined` is the coinbase, which adds
`r(n, mined(Lₙ)) ≤ B_m − mined(Lₙ)` (Lemma 3.i), so `mined(Lₙ₊₁) ≤ B_m`.
Finally `S(Lₙ₊₁) ≤ S(Lₙ₊₁) + (B_m − mined) ≤ C`. ∎

**Code:** `GenesisConfig::build`, `MiningPolicy::reward_at`; the independent
re-checker `check_ledger`
([`invariants.rs:134`](../crates/verify/src/invariants.rs)) re-asserts both
bounds on every state.
**Machine-checked-by:** `genesis::tests::rejects_supply_over_cap`;
`invariants::tests::{supply_over_cap_is_caught, mined_over_budget_is_caught,
within_cap_and_budgets_passes}`.

### Corollary 3.1 (no pre-mine: every coin is mined)

Under the production policy `MiningPolicy::mainnet_like`, the mining budget is
the **entire** cap, `B_m = C` ([`mining/lib.rs`](../crates/mining/src/lib.rs)).
Then any genesis allocation is rejected, and the genesis supply is exactly
zero: `S(L₀) = 0`.

**Proof.** With `B_m = C`, the genesis check `Σ balance + Σ vesting + B_m ≤ C`
becomes `Σ balance + Σ vesting ≤ 0`, which (all terms `≥ 0`) holds **iff** every
genesis balance and every vesting grant is zero — any funded allocation makes
`total > C` and is rejected with `SupplyCapExceeded`. Hence a valid mainnet
genesis has `S(L₀) = 0`, and by Theorem 1 every later grain of supply is a
coinbase mint: there is **no pre-mine**, founder allocation, or premined
treasury, and genesis supply is zero. ∎

*Scope.* This is a **Bitcoin-style fair launch**: no pre-mine and no protocol tax.
Every coin is mined, and the **entire** coinbase (and every fee) reaches the block's
miner — 100% (Lemma 2).

**Machine-checked-by:**
`genesis::tests::mainnet_policy_forbids_any_premine` (a 1-grain balance or
vesting grant fails; a clean mainnet genesis has total supply zero);
`mining::tests::mainnet_emission_is_bitcoins_and_forbids_any_premine`.

### Theorem 4 (emission terminates; fixed terminal supply)

(a) Cumulative mining emission is non-decreasing, bounded by `B_m`, and the
per-block reward is exactly `0` at the budget with **no integer-overflow
resumption** (the BIP-42 class of bug is excluded).
(b) Once `mined = B_m`, every block has `ΔS = 0`: the total supply is **fixed
forever** — there is no mint (budget spent) and no burn.

**Proof.** (a) is Lemma 3: the explicit `m ≥ B_m → 0` guard and the
`h ≥ 127 → 0` shift guard leave no wraparound path, and the clamp gives the
bound; when `r(n,m) = 0` the coinbase mints nothing
([`execution.rs`](../crates/runtime/src/execution.rs)).
(b) With the budget exhausted, `Δmined = 0` (Lemma 3.i gives zero room), so by
Theorem 1 `S(L') = S(L)` exactly. Fees no longer reduce supply — they are paid
out in full to the tax recipients and the miner (Lemma 2) — so the terminal
supply is a hard, constant `≤ 21M`: a fixed-supply reserve asset (like Bitcoin's
terminal state, with no deflation in either chain). ∎

**Machine-checked-by:**
`invariants::tests::long_tail_is_fixed_supply_once_emission_is_exhausted`
(asserts `r(B_m) = 0`, a mid-emission mint raises supply, and a post-emission
fee is supply-neutral).

---

## Part II — The shielded pool

### Theorem 5 (turnstile: the pool cannot manufacture supply, even if A3 fails)

No shielded action increases `S`. Even an **unsound** zero-knowledge proof
cannot mint SOV: the worst an accepted-but-invalid bundle can do is move value
*within* the pool, bounded by `shield(L) ≥ 0`.

**Proof.** By Theorem 1 case 7, `ΔS = 0` for every `Shielded` action — this is
a structural property of the execution arm (the only supply-relevant writes
are the equal-and-opposite pair on `(balance(signer), shield)`,
[`execution.rs:446–465`](../crates/runtime/src/execution.rs)), independent of
what the proof attests. Non-negativity of the pool: a de-shield (`vb > 0`) is
pre-checked `shield(L) ≥ vb` (`:431`) before any mutation, and
`sub_shielded_value` is itself checked
([`ledger.rs:301`](../crates/state/src/ledger.rs)) — so cumulative
extractions can never exceed cumulative insertions. Finally, the failure mode
"credit the pool from thin air" is independently caught: it raises `S` with
no counter move, which `check_transition` rejects as `ValueNotConserved`
(Theorem 2). Hence a circuit-soundness break (¬A3) is confined to intra-pool
theft; the 21M cap and the transparent ledger are unaffected. ∎

**Machine-checked-by:**
`invariants::tests::{shield_into_the_pool_is_supply_neutral,
shielded_pool_cannot_manufacture_supply}`;
`execution::tests::shielded_action_shields_value_verifies_proof_and_rejects_replay`.

### Theorem 6 (nullifier uniqueness — no double spend; bundle atomicity)

(a) In every reachable state, the spent-nullifier set `𝒩` contains each
nullifier at most once (it is a set), and **no accepted bundle ever spends a
nullifier already in `𝒩`, nor the same nullifier twice within itself**.
(b) Bundle application is atomic: a bundle that violates (a) is rejected with
`Σ(L)` (tree, anchors, nullifiers) completely unchanged.
(c) Consequently, under A3 (each note's spend is bound to a unique
nullifier), every shielded note is spendable at most once in the chain's
entire history.

**Proof.** `ShieldedState::apply_bundle`
([`shielded/state.rs:157`](../crates/shielded/src/state.rs)) runs two phases.
*Phase 1 (validate, no mutation):* it iterates all of the bundle's nullifiers,
checking each against the chain set `𝒩` **and** against a scratch set
`within` that detects intra-bundle repeats; any hit returns
`Err(DoubleSpend)` before any insertion — establishing (b), since phase 1
writes only to the scratch. *Phase 2 (apply):* only after every nullifier
passes does it insert them into `𝒩` and append the output commitments to the
tree. So an accepted bundle's nullifiers were all fresh, giving (a) by
induction over accepted bundles (genesis starts with `𝒩 = ∅`). For (c): A3
gives that a valid spend proof for a note `n` reveals `nf(n)`, a deterministic
injective function of the note and its spending key; by (a), `nf(n)` enters
`𝒩` at most once, and any second spend of `n` must present the same `nf(n)`
and is rejected in phase 1. The execution layer additionally treats the
rejection as a failed action with no ledger mutation
([`execution.rs:442–445`](../crates/runtime/src/execution.rs)). ∎

**Code:** `apply_bundle`, `add_nullifier`
([`shielded/state.rs:141,157`](../crates/shielded/src/state.rs));
`Ledger::apply_shielded_bundle` ([`ledger.rs:285`](../crates/state/src/ledger.rs)).
**Machine-checked-by:**
`shielded::state` tests `nullifier_double_spend_is_rejected`,
`applying_a_real_minted_bundle_absorbs_its_note_commitment`;
`execution::tests::shielded_action_shields_value_verifies_proof_and_rejects_replay`
(replay of a real bundle is rejected end-to-end).

### Theorem 7 (anchor soundness: spends are rooted in the chain's own history)

A bundle is accepted only if its anchor is a member of `𝒜`, and `𝒜` contains
**exactly** the roots the chain's commitment tree has actually held (the empty
root, plus the root after each accepted commitment append). Hence, under A1
and A3, every accepted spend proves membership of its spent note in the
chain's real note-commitment tree at some past block — never in a tree the
prover invented.

**Proof.** Membership gate: both shielded execution arms refuse any bundle
with `¬anchor_is_known(anchor)`
([`execution.rs:415, 497`](../crates/runtime/src/execution.rs)). Exact
characterization of `𝒜`: at construction, `𝒜 = {root(∅)}`
([`shielded/state.rs:59–66`](../crates/shielded/src/state.rs)); the **only**
other writer is `add_commitment` (`:101`), which appends one commitment to
the append-only tree and inserts the resulting `self.anchor()`. No deletion
exists. By induction, `𝒜` is precisely the set of historical roots. A3 then
gives that a verifying spend proof against anchor `α ∈ 𝒜` certifies the spent
note was a leaf of the tree whose root was `α`; A1 (collision resistance of
the tree hash) gives that `α` determines that tree's contents. ∎

**Machine-checked-by:** `shielded::state` tests
`empty_state_anchor_is_the_empty_tree_anchor`,
`appending_commitments_advances_anchor_and_keeps_history`;
`execution` rejection of unknown anchors is exercised by the bundle tests
(any bundle built against a foreign tree fails the `anchor_is_known` gate).

### Remark 7.1 (shielding a coinbase — honest scope)

There is **one** issuance path: the block coinbase mints the schedule to the
miner's transparent account (Theorem 1, coinbase case). A miner who wants its
reward in the shielded pool shields it afterward with an ordinary `Shielded`
action — which by Theorem 1 (case 4) is supply-neutral, moving value from the
transparent balance into the pool without minting. So there is no second,
direct-to-pool issuance path to reason about: shielded coinbase reduces to
"coinbase, then shield", and both steps are already covered. (The former
`MineShielded` action — a direct-to-pool mint — was removed with the Nakamoto
migration; collapsing issuance to a single transparent coinbase is strictly
simpler to audit.)

---

## Part III — Consensus (Nakamoto proof-of-work)

SOV's consensus is **Bitcoin's, verbatim**: blocks are sealed by proof of work,
the chain with the most accumulated work wins, and finality is the depth a block
is buried at. There are **no validators, no committee, no stake, and no voting**
of any kind — only hashpower.

**Setup.** Each block header carries a difficulty `bits` (Bitcoin's compact
`nBits`) decoding to a 256-bit `Target`, and a `nonce`. The header's **seal** is
`pow_seal(algo, key, header)` ([`pow/seal.rs`](../crates/pow/src/seal.rs)),
where `algo` is the chain's genesis-fixed [`PowAlgo`] — **RandomX** on mainnet
(Monero's memory-hard, ASIC-resistant CPU proof of work, keyed by the genesis
hash) or SHA-256d on dev/test chains. The block is validly mined iff
`seal ≤ Target`. RandomX is computed via the audited `randomx-rs` reference
bindings; the difficulty/work machinery below is hash-agnostic — it treats the
seal as an opaque 256-bit value, so everything holds for either algorithm. The
**work** of one block at
`target` is Bitcoin's `GetBlockProof`,
`W(t) = ⌊2²⁵⁶ / (t + 1)⌋ = ⌊~t / (t+1)⌋ + 1`
([`mining/work.rs`](../crates/mining/src/work.rs)), and a chain's **cumulative
work** is the sum of `W` over its blocks. The required target at each height is
fixed by the retarget rule (Theorem 18), snapped to the compact grid, so it is a
pure function of the branch — not a quantity a miner may choose.

### Theorem 8 (heaviest-work fork choice; reorg correctness)

The node's active chain is always a **valid** chain of **maximum cumulative
work** among all valid blocks it holds. A competing branch replaces the active
chain **iff** its cumulative work is strictly greater, and only after the whole
branch re-validates and re-executes from the genesis ledger.

**Proof.** `import_block`
([`blockchain.rs`](../crates/chain/src/blockchain.rs)) first runs
`validate_candidate` (parent known; height/link; checkpoint; BIP-113 timestamp;
**difficulty bits equal the required value**; `pow_hash ≤ target`; tx-root;
signatures) and computes `new_work = parent.chain_work + W(target)`. Then
exactly one branch is taken: (i) if the block extends the active head it is
executed against the live ledger and committed; (ii) else if
`new_work > head_work` it triggers a **reorg** — `rebuild_branch` replays the
competing branch from the snapshotted genesis ledger, and the result is adopted
**only if every block in it re-validates and its committed roots match**, so an
invalid heavier branch can never displace a valid lighter one; (iii) else the
block is stored as a side branch and the active chain is untouched. Each stored
block carries its `chain_work`, so the comparison is exact integer `U256`
arithmetic (no overflow: a chain cannot accumulate more work than the hash
space). Strictness of `>` means equal-work ties keep the incumbent — no
gratuitous reorgs. ∎

**Code:** `import_block`, `validate_candidate`, `rebuild_branch`,
`Work::of_target`.
**Machine-checked-by:** `blockchain::tests::heavier_branch_triggers_reorg`;
`mining::work::tests::{harder_target_is_more_work, work_accumulates_and_orders,
easiest_target_is_one_unit}`; the multi-replica convergence test
`chaos.rs` (independent nodes fed blocks in different orders agree on the
heaviest chain).

### Theorem 9 (difficulty is not forgeable)

A block cannot claim an easier difficulty than its branch requires. For a block
extending parent `p`, let `bits*` be the compact encoding of the retarget-
required target `T*(p)` (Theorem 18). The block is accepted only if
`header.bits == bits*` **and** `pow_hash ≤ from_compact(bits*)`.

**Proof.** `validate_candidate` computes `T*(p)` from the parent branch,
canonicalized to the compact grid (so `from_compact(to_compact(T*)) = T*`),
sets `required = to_compact(T*)`, and rejects the block with
`BadDifficultyBits` unless `header.bits == required`. Because `header.bits` is
part of the Borsh-encoded header, it is committed in the seal; and because the
target is canonical, the subsequent check `seal ≤ T*` is against exactly the
committed, required difficulty. Hence a miner can neither (a) declare a smaller
difficulty to make the PoW cheaper — that is rejected before the PoW check — nor
(b) declare one difficulty and be graded against another. Under A1, finding
`nonce` with `pow_seal(header) ≤ T*` costs the expected `W(T*)` evaluations of
the seal (RandomX on mainnet); there is no shortcut. ∎

**Code:** `Target::{to_compact, from_compact}`
([`pow/target.rs`](../crates/pow/src/target.rs)); the `bits` rule in
`validate_candidate`.
**Machine-checked-by:**
`blockchain::tests::{header_commits_the_required_difficulty_bits,
block_claiming_easier_difficulty_is_rejected}`;
`pow::target::tests::{compact_matches_bitcoin_max_target,
compact_round_trips_for_canonical_values, compact_rejects_negative_and_overflow}`.

### Theorem 10 (confirmation-depth finality; probabilistic, never premature)

A block at depth `d` in the active chain has `d` confirmations, reported final
once `d ≥ FINALITY_DEPTH = 6` ([`blockchain.rs`](../crates/chain/src/blockchain.rs)).
Confirmations are monotone non-decreasing as the active chain grows on top, and
`is_final` is a pure function of chain state (it survives restart). Finality is
**probabilistic**: reversing a `d`-confirmed block requires privately
out-mining the honest network across `d` consecutive blocks.

**Proof.** `confirmations(h) = height(head) − height(block h) + 1` for a block
on the active chain, `None` otherwise; `is_final(h) ⟺ confirmations(h) ≥ 6`.
Both read only committed chain state, so any node replaying the same blocks
computes the same answer — there is no separate finalized-set to persist or to
disagree about (contrast a BFT gadget). Monotonicity: extending the active head
increases `height(head)` by one and leaves ancestors' heights fixed, so each
ancestor's confirmation count only grows; a reorg only occurs to a **strictly
heavier** chain (Theorem 8), which an adversary can produce for the last `d`
blocks only by exceeding the honest network's cumulative work over that span —
the standard Nakamoto cost, exponentially small in `d` for a minority miner
(A1). ∎

**Code:** `confirmations`, `is_final`, `FINALITY_DEPTH`.
**Machine-checked-by:**
`blockchain::tests::finality_is_confirmation_depth_in_the_active_chain`;
the chaos test's invariant that a tracked block's confirmation depth only ever
grows across replicas; `fault_injection.rs` (two valid candidate blocks at one
height each have no confirmations and are not final until one branch out-works
the other).

### Proposition 11 (coinbase authorization — work names the payee)

The coinbase of a block credits the schedule to the header's `proposer`
account, and **whoever finds the proof of work chooses that account**. There is
no proposer schedule and no permission to mine: any account may mine to itself.

**Proof.** `apply_coinbase` mints `reward_at(height, mined)` to
`ctx.miner = header.proposer` (Theorem 1, coinbase case). The `proposer` field
is part of the Borsh-encoded header and therefore committed in `pow_hash`, so it
is fixed before the nonce is ground and cannot be altered without redoing the
work — the coinbase claim is bound to the work that authorizes the block. No
other check gates *who* may produce a block: validity is the proof of work
(Theorem 9) alone. A node selects its own payee via `set_coinbase`, defaulting
to the genesis coinbase account. ∎

**Code:** `apply_coinbase`, `BlockHeader::proposer`, `Blockchain::set_coinbase`.
**Machine-checked-by:**
`blockchain::tests::{coinbase_mints_the_scheduled_reward_to_the_miner_every_block,
set_coinbase_routes_the_reward_to_the_operator_account}`.

---

## Part IV — Authenticated data structures

### Theorem 12 (state proof soundness)

The world state is committed by a depth-256 Sparse Merkle Tree over Blake3
with domain separation — leaves `H(0x00 ‖ value)`, internal nodes
`H(0x01 ‖ left ‖ right)` ([`smt.rs:33,41`](../crates/state/src/smt.rs)).
Under A1, a `MerkleProof` verifying against root `R` for key `k` with
`value = Some(v)` certifies the committed map sends `k ↦ v` (**inclusion**),
and with `value = None` certifies `k` is absent (**exclusion**); producing a
verifying proof for a false claim implies a Blake3 collision.

**Proof.** `verify` ([`smt.rs:87`](../crates/state/src/smt.rs)) requires
exactly `TREE_HEIGHT` siblings (no truncated-path forgeries), pins the leaf to
`H(0x00‖v)` or `Hash::ZERO`, then folds the 256 siblings upward, ordering
left/right by bit `k_i`, accepting iff the result equals `R`. Suppose a proof
verifies for `(k, v')` while the honest tree at root `R` holds `v ≠ v'` at
`k` (absence is the case `leaf = ZERO`). The honest tree and the forged
recomputation both evaluate to `R` along the same 256-step path for `k`, but
start from different level-0 values (`H(0x00‖v) ≠ H(0x00‖v')` unless that is
already a collision). Let `j` be the first level (moving up) where the two
computations agree; their inputs at level `j` differ in the child position on
`k`'s path, so the agreement at `j` is a collision on the `0x01`-prefixed
node encoding. The `0x00`/`0x01` prefixes exclude the remaining degenerate
case of a leaf encoding colliding with a node encoding (the strings differ in
their first byte, so equality of digests is again a collision). Either way a
Blake3 collision is exhibited, contradicting A1. ∎

**Machine-checked-by:** `smt::tests::{inclusion_proof_verifies,
exclusion_proof_verifies, proof_against_wrong_root_fails,
root_is_independent_of_insertion_order}`;
`ledger::tests::proofs_track_state_root`.

### Corollary 12.1 (transaction Merkle root)

The block transaction root uses the same leaf/node domain separation, and a
lone node at any level is **promoted unchanged** rather than duplicated
([`merkle.rs:54`](../crates/crypto/src/merkle.rs)) — excluding the classic
CVE-2012-2459 duplicate-leaf malleability, where two different transaction
lists hash to one root. `import_block` rejects any body whose root mismatches
its header (`tx_root_matches`,
[`blockchain.rs:344`](../crates/chain/src/blockchain.rs)).
**Machine-checked-by:** `merkle::tests::{leaf_and_node_domains_differ,
order_sensitive}`.

---

## Part V — Execution integrity

### Theorem 13 (authorization and replay protection)

(a) Value never leaves an account without a valid Ed25519 signature under that
account's registered controlling key. (b) Each `(account, nonce)` pair is
consumed at most once; no admitted transaction can be replayed.

**Proof.** (a) `apply_transaction` rejects unless `stx.verify_signature()`
over the canonical signing bytes ([`execution.rs:110`](../crates/runtime/src/execution.rs)),
then requires `tx.public_key == key(signer)` for any keyed account.
The sole exception — a **keyless** account (e.g. one that has only ever received
a coinbase or a transfer and never set a key) — *adopts* `tx.public_key` via a
`RotateKey` whose possession proof is a signature under that very key; the
signature already proves possession, and a keyless account holds no spendable
authority until it is claimed this way. Under A2 a third party cannot produce
the required signature. By Lemma 1, every rejection leaves the ledger untouched.
(b) Admission requires `tx.nonce == nonce(signer)` (`:138`). The nonce is
incremented (`checked_add`) immediately upon admission (`:182–185`) and the
incremented account is written back at `:609` **even when the action fails**
— so after processing nonce `n` the account demands `n+1`, and resubmission of
the same signed transaction fails the equality. Nonces strictly increase,
totally ordering each account's admitted transactions. ∎

**Machine-checked-by:** `execution::tests::{wrong_key_is_unauthorized,
bad_nonce_is_rejected, tampered_signature_is_rejected,
insufficient_balance_fails_but_consumes_nonce,
successful_transfer_moves_funds_and_bumps_nonce}`; block-level re-validation
`Block::all_signatures_valid` enforced at import
([`blockchain.rs:347`](../crates/chain/src/blockchain.rs)).

### Theorem 14 (HTLC exclusivity and conservation)

For every HTLC `h` with escrow `v`, hashlock `H_v`, timeout `t`:
(i) the escrow `v` is debited from the locker exactly once at lock time and
re-credited exactly once in total — to the recipient **or** the locker, never
both; (ii) only the recipient can claim, only with a preimage `p` with
`sha256(p) = H_v`, and only at heights `< t`; only the locker can refund, and
only at heights `≥ t`; (iii) `S` is conserved throughout (Theorem 1 case 9).

**Proof.** Lock ([`execution.rs:526`](../crates/runtime/src/execution.rs))
debits the signer and inserts `h` keyed by the transaction id;
`Ledger::lock_htlc` ([`ledger.rs:320`](../crates/state/src/ledger.rs))
refuses a duplicate id, so one escrow per id. Claim (`:558`) requires, in
order: the HTLC exists, `signer = recipient`, `height < t`, and
`sha256(preimage) = H_v`; refund (`:585`) requires existence,
`signer = locker`, `height ≥ t`. The guards `height < t` and `height ≥ t`
partition all heights, so at any single height at most one of the two paths
is open, and **both** paths call `settle_htlc`
([`ledger.rs:334`](../crates/state/src/ledger.rs)), which removes the entry —
so the first success makes every later claim *and* refund fail with
`"no such HTLC"`. Exactly one credit of `v` ever occurs. ∎

**Machine-checked-by:**
`execution::tests::{htlc_atomic_swap_locks_then_claims_with_the_preimage,
htlc_refunds_to_the_locker_only_after_timeout}`.

### Theorem 15 (import determinism — no trusted production path)

A block commits iff re-executing its transactions against the importer's own
ledger reproduces the header's `state_root` and `receipts_root` exactly.
Hence all honest importers of a block reach byte-identical state, and a
proposer cannot install state it did not legitimately compute.

**Proof.** `import_block` ([`blockchain.rs`](../crates/chain/src/blockchain.rs))
validates linkage (`height`, `prev_hash`), the weak-subjectivity checkpoints,
the time gates (Theorem 16), the proof of work and committed difficulty
(Theorems 8–9), the transaction root (Corollary 12.1) and all signatures — then
clones the ledger, applies the coinbase, runs `apply_transactions`, and requires
`scratch.state_root() == header.state_root` and
`receipts_root(receipts) == header.receipts_root` (`:371–376`), committing
atomically only on success (`:394`). The STF is deterministic: it consults no
clock or randomness, account iteration is over a `BTreeMap`, and the SMT root
is insertion-order-independent (Theorem 12's test
`root_is_independent_of_insertion_order`). `produce_block` (`:225`) computes
the header roots with the *same* functions over the same inputs, so honest
production imports and tampered production cannot: forging a header that
passes requires either the actual computation or a state-root collision (A1). ∎

**Machine-checked-by:** `blockchain::tests::{produce_and_import_advances_state,
tampered_state_root_is_rejected, wrong_prev_hash_is_rejected,
multi_block_sequence_keeps_roots_consistent, checkpoint_mismatch_is_rejected,
matching_checkpoint_is_accepted}`; cross-implementation replay agreement in
[`verify/tests/replay.rs`](../crates/verify/tests/replay.rs).

### Theorem 16 (time discipline — BIP-113)

In any committed chain: (i) timestamps are non-decreasing; (ii) every block's
timestamp strictly exceeds the median timestamp of the (up to) 11 blocks
preceding it; (iii) the interval a single block contributes to difficulty
retargeting is capped at 16× the target block time.

**Proof.** (i) and (ii) are import gates executed before any state change:
`timestamp_ms ≥ parent` (`blockchain.rs:316`) and `timestamp_ms > MTP`
(`:322–328`), where `median_time_past` (`:183`) is the sorted median of the
last ≤ 11 committed timestamps. Consequence of (ii): to stall the chain's
time, a proposer needs control of a majority of an 11-block window, not just
one block — a single proposer cannot pin time at the parent's value. (iii)
the retarget input is `min(timestamp − parent_timestamp, 16 · target_ms)`
(`:384–393`), so a far-future timestamp lowers difficulty by at most one
clamped step (and Theorem 18's `[¼, 4]` clamp binds first). ∎

**Machine-checked-by:**
`blockchain::tests::{a_block_must_postdate_the_median_time_past,
difficulty_retarget_ignores_inflated_future_timestamps}`.

### Proposition 17 (BIP-110 data bound)

If `max_code_bytes ≠ 0`, every admitted transaction carries at most
`max_code_bytes` of arbitrary data (its `Deploy` code) — the gate at
[`execution.rs:147–155`](../crates/runtime/src/execution.rs) rejects larger
payloads *before* the nonce is consumed (Lemma 1). With block transaction
count bounded, per-block data is bounded; block space is reserved for
monetary use. ∎

---

## Part VI — Proof of work

### Lemma 4 (the proof of work is bound to the block — no rented or stolen work)

Under Nakamoto consensus the proof-of-work preimage is the **entire block
header** (`header.pow_preimage() = borsh(header)`,
[`types/block.rs`](../crates/types/src/block.rs)), which commits to `prev_hash`,
all three roots, the timestamp, the coinbase recipient (`proposer`), the
difficulty `bits`, and the `nonce`. Borsh is an injective encoding, so each
header maps to a unique preimage; hence under A1 a solution (a `nonce` making
`seal(header) ≤ target`) is valid for **exactly that header** and nothing else:

- it is bound to `prev_hash`, so it only extends that parent (next-block
  freshness — a solution cannot be replayed onto a different branch or height);
- it is bound to `proposer`, so the coinbase **cannot be stolen** — re-pointing
  the reward changes the preimage and invalidates the work; and
- it is bound to `bits`, so it cannot be re-graded against an easier target
  (Theorem 9).

Changing any field forces the work to be redone. ∎
**Machine-checked-by:**
`blockchain::tests::block_claiming_easier_difficulty_is_rejected` (re-pointing
the header's difficulty invalidates the seal) and
`blockchain::tests::tampered_state_root_is_rejected` (any header change is
caught); `pow::seal::tests::randomx_seal_is_deterministic_and_input_sensitive`
(distinct preimages give distinct seals).

### Theorem 18 (difficulty–target correspondence, bounded retarget, compact fidelity)

(a) `D ↦ target(D) = ⌊(2^256 − 1)/D⌋` is non-increasing, so higher difficulty
admits a (weakly) smaller fraction of the hash space; under the random-oracle
model the acceptance probability of one hash is `(target+1)/2^256 ≈ 1/D`.
(b) The chain retargets **once per epoch** (`RETARGET_INTERVAL = 2016` blocks,
Bitcoin's value) from the epoch's actual vs expected timespan, and one retarget
step multiplies `D` by a factor within `[¼, 4]`, with `D ≥ 1` always.
(c) The consensus target is **canonical** under Bitcoin's compact `nBits`:
`from_compact(to_compact(t)) = t` for every consensus target `t`, and the
encoding is a faithful round-trip on the compact grid.

**Proof.** (a) `Difficulty::to_target` computes `U256::MAX / D` exactly in
256-bit integers ([`difficulty.rs:26`](../crates/mining/src/difficulty.rs));
integer division is non-increasing in the divisor, and acceptance is
`hash ≤ target` (`Target::is_met_by`), a set of size `target + 1` out of `2^256`
equiprobable values. (b) `expected_targets`
([`blockchain.rs`](../crates/chain/src/blockchain.rs)) holds the target constant
within an epoch and, at each `RETARGET_INTERVAL` boundary, applies `retarget`
(`difficulty.rs:51`): `D' = clamp(⌊D · target/actual⌋, max(D/4, 1), 4D)` with
saturating multiplication and floored inputs `≥ 1` — the clamp bounds are
explicit and the final `.max(1)` keeps `D ≥ 1`. The actual timespan is measured
across the epoch's first-to-last block (2015 intervals against 2016·target —
Bitcoin's exact off-by-one), bounded by Theorem 16(iii). (c) `to_compact`
follows Bitcoin's `GetCompact` (size byte + 3-byte mantissa, high-bit
normalization) and `from_compact` its `SetCompact` (with the negative/overflow
guards); the consensus target is snapped to this grid before use
(`canonical_target`), so the value a miner seals against, the value an importer
checks, and `from_compact(header.bits)` are bit-identical (Theorem 9). ∎

**Machine-checked-by:** `difficulty::tests::{higher_difficulty_is_a_smaller_target,
retarget_raises_when_blocks_are_fast, retarget_is_clamped_to_4x,
target_difficulty_roundtrip_is_close, min_difficulty_is_easiest_target}`;
`blockchain::tests::difficulty_is_stable_within_an_epoch`;
`pow::target::tests::{compact_round_trips_for_canonical_values,
compact_handles_high_bit_mantissa_shift, compact_small_size_low_bytes}`.

---

## Part VII — Native assets

The chain admits issuer-bound **native assets** (tokens): first-class ledger
entries, not contract storage. An asset is a triple
`(issuer, symbol, (issued, burned))` with balances
`b_a : AccountId → ℕ`, all committed to the state root
([`ledger.rs:441`](../crates/state/src/ledger.rs), `:459`). Token units are
their **own denomination**: they never appear in `S` (Definition 2), so no
token operation can interact with the 21M cap — but each asset carries the
same counter-accounted conservation discipline as SOV itself.

### Lemma 5 (asset-id injectivity)

`asset_id(issuer, symbol) = Blake3("sov:asset:v1" ‖ issuer ‖ 0x00 ‖ symbol)`
([`ledger.rs:47`](../crates/state/src/ledger.rs)) has an **injective
preimage** over `(issuer, symbol)`: the domain tag is fixed, and the `0x00`
separator cannot occur inside an `AccountId` (charset `a-z 0-9 - _ .`), so
the issuer segment of any preimage is uniquely delimited. Distinct pairs hash
distinct strings; under A1, distinct pairs yield distinct ids except with
collision probability. ∎

**Machine-checked-by:**
`ledger::tests::token_asset_id_is_injective_over_issuer_and_symbol`
(including the splice case: `("a.sovx", "YZ") ≠ ("a.sov", "xYZ")`).

### Theorem 19 (issuance authorization by hash binding)

Only the account recorded as an asset's issuer can ever increase its
`issued` counter. There is no registry, no admin key, and no transaction
that transfers issuance rights.

**Proof.** The only code path that raises `issued` is the
`Action::TokenIssue` arm
([`execution.rs:607`](../crates/runtime/src/execution.rs)), which computes
the target id as `asset_id(signer, symbol)` — from the **signer**, not from
a user-supplied id. By Theorem 13 the signer is authenticated (A2) and by
Lemma 5 the derivation is injective: for a mint to land on asset `a` created
by issuer `I`, the signer must satisfy `asset_id(signer, symbol) = a =
asset_id(I, symbol_a)`, which under A1 forces `signer = I`. A defensive
in-band check (`info.issuer == tx.signer`, `:625`) additionally fails the
action if a collision were ever found. `TokenTransfer` and `TokenBurn` never
touch `issued`. ∎

**Machine-checked-by:**
`execution::tests::token_asset_id_binds_issuance_to_the_issuer` (two accounts
issuing the same symbol create disjoint assets; the victim's counter and
balances are untouched).

### Theorem 20 (per-asset conservation)

For every asset `a`, after every block:
(i) `Σ_id b_a(id) = issued_a − burned_a` with `burned_a ≤ issued_a`;
(ii) `issued_a` and `burned_a` are monotonic, and `issued_a` rises only via
`TokenIssue` (Theorem 19), `burned_a` only via a holder burning its **own**
balance; (iii) the asset's `(issuer, symbol)` is immutable and the asset is
never deleted.

**Proof.** *(i)* is re-checked from scratch after every block by
`check_token_conservation`
([`invariants.rs:173`](../crates/verify/src/invariants.rs)): it sums every
asset's balances in checked `u128`, requires `burned ≤ issued` and
`Σ balances = issued − burned`, and rejects any balance whose asset has no
issuance record (units with no origin). *(ii)–(iii)* are transition
invariants (`invariants.rs:293`): for each asset present before, the asset
must persist with identical `issuer`/`symbol` and non-decreasing counters.
Inductively, as for Theorem 1: the execution arms preserve (i) exactly —
issue adds `amount` to one balance and to `issued`
([`execution.rs:607`](../crates/runtime/src/execution.rs)); transfer moves
`amount` between two balances with checked arithmetic and validate-then-apply
atomicity (`:655`); burn subtracts `amount` from the signer's own balance and
adds it to `burned` (`:689`); every failure path mutates nothing (Lemma 1).
Burn-overflow is unreachable on a conserved state, since
`burned' = burned + amount ≤ burned + Σb = issued`. ∎

**Machine-checked-by:**
`execution::tests::{token_issue_transfer_burn_lifecycle_conserves_the_asset,
token_transfer_and_burn_enforce_balances_and_fail_gracefully}`;
`invariants::tests::{conserved_token_state_passes, forged_token_balance_is_caught,
token_balance_without_issuance_record_is_caught,
token_burn_exceeding_issuance_is_caught, token_issue_and_burn_transitions_conserve,
token_counter_regression_is_caught, token_identity_mutation_or_vanishing_is_caught}`.

### Corollary 20.1 (non-interference with the SOV monetary base)

No token operation changes `S`, `mined`, or the supply cap
arithmetic of Theorems 1–4, except by paying its transaction fee in native
SOV exactly as any other action (Lemma 2): token balances are excluded from
`total_supply` by construction
([`ledger.rs`](../crates/state/src/ledger.rs) `total_supply` sums accounts,
the shielded pool, and HTLC escrow only). Moreover, unlike SOV — whose cap
makes `u128` overflow unreachable (Lemma 0) — a token's cumulative issuance
*can* reach `2^128 − 1`; the execution arm therefore treats issuance overflow
as a **failed action** (nonce consumed, fee paid, nothing mutated), never an
admission error, so no token can be used to invalidate an otherwise-valid
block. ∎

**Machine-checked-by:**
`invariants::tests::token_units_never_enter_native_supply` (10¹² token units,
native supply exactly zero);
`execution::tests::{token_issuance_overflow_fails_the_action_without_invalidating_the_block,
token_actions_pay_their_fee_in_native_sov}`.

---

## Part VIII — Contract execution (VM ABI v2)

Contracts run in a deterministic wasmi interpreter with an explicit host ABI:
storage, block height, calldata, the authenticated caller, the contract's own
address, bounded return data and events, and a token bridge
(`token_balance`/`token_transfer`) restricted to the contract's **own**
balances. The VM never sees the `Ledger`
([`vm/lib.rs`](../crates/vm/src/lib.rs)): the runtime materializes inputs and
re-validates all outputs.

### Theorem 21 (containment: a contract call cannot violate any ledger theorem)

No contract execution, however adversarial, can change any quantity governed
by Theorems 1–4 (native supply) or 19–20 (token conservation), except by
(a) paying the caller's gas fee in native SOV, and (b) moving token units
**out of the contract's own balance** through commands that re-satisfy
Theorem 20.

**Proof.** The VM's only effects channel is its returned outcome: the host ABI
([`vm/lib.rs:198`](../crates/vm/src/lib.rs)) exposes no function that touches
native balances, emission counters, or other accounts' token balances —
there is no ambient authority to leak. The runtime arm
([`execution.rs:358`](../crates/runtime/src/execution.rs)) commits three
things: (i) the gas fee, debited from the *signer* with checked arithmetic
and routed through Lemma 2's split; (ii) storage writes, which carry no
value; (iii) token-transfer commands, applied by
`settle_contract_token_transfers` ([`execution.rs:796`](../crates/runtime/src/execution.rs)),
which debits **only the contract account**, requires the asset to exist,
validates every recipient as a well-formed `AccountId`, and uses checked
`u128` arithmetic over a scratch view (fresh ledger reads overlaid with
in-batch updates, so sequences and self-transfers settle exactly) — written
back **only if the entire batch is sound**, all-or-nothing. Each committed
command is balance-to-balance within one asset: `issued` and `burned` are
untouched, so `Σ balances = issued − burned` is preserved (Theorem 20), and
no native quantity moves (Corollary 20.1). A command batch that fails
validation fails the whole action, committing neither storage nor transfers.
Defense in depth: the in-VM working copy
([`vm/lib.rs:378`](../crates/vm/src/lib.rs)) already debits each queued
transfer, so an overspending batch cannot even be produced by a correct VM —
but the proof does not rely on this; runtime re-validation alone suffices. ∎

**Machine-checked-by:**
`execution::tests::{contract_token_transfer_moves_only_the_contracts_own_balance_and_conserves,
contract_token_transfer_to_invalid_account_fails_without_committing}` (the
second includes the storage-rollback case);
`vm::tests::token_balance_reads_the_materialized_balance_and_overspend_is_minus_one`.

### Lemma 6 (bounded execution and bounded output)

Every contract call terminates within its gas limit, and its committed
footprint is bounded by constants: wasmi fuel metering traps unbounded
computation (`VmError::OutOfGas`); per-call storage writes ≤ 1 MiB with
per-entry caps; return data ≤ 64 KiB; events ≤ 64 per call with topic ≤ 64 B
and payload ≤ 1 KiB; token commands ≤ 128 per call; every host read is
length-validated before allocation (≤ 1 MiB)
([`vm/lib.rs:129–137`](../crates/vm/src/lib.rs)). Calldata is bounded
upstream by the BIP-110 gate (Proposition 17, extended to `Call`) and priced
per byte. So a block of `n` transactions has an `O(n)` state and receipt
footprint with explicit constants — no contract can blow up a node's
memory or the chain's committed state. ∎

**Machine-checked-by:** `vm::tests::{out_of_gas_traps_and_does_not_commit,
event_count_is_capped, rejects_oversized_host_read,
oversized_storage_key_is_rejected}`;
`execution::tests::oversized_calldata_is_rejected_by_bip110`.

### Proposition 22 (authenticated observability)

A contract observes the **authenticated** caller — the runtime sets
`ExecContext::caller` to the transaction signer only after the signature,
key-authorization, and nonce gates of Theorem 13 — so in-contract access
control built on `caller` inherits Ed25519 security (A2); a caller identity
cannot be spoofed without a forgery. Return data and events are recorded in
the transaction's [`Receipt`](../crates/types/src/receipt.rs) and therefore
committed under `receipts_root`: by Theorem 15, every importer re-executes
and re-derives them, so contract outputs are consensus state, not node-local
logs, and are exactly as deterministic as the STF itself. ∎

**Machine-checked-by:**
`execution::tests::abi_v2_exposes_calldata_and_caller_and_records_return_data_and_events`;
receipt commitment via `receipt::tests::hash_is_content_sensitive` and the
import-determinism suite of Theorem 15; cross-implementation receipt parity
(Rust ↔ TypeScript SDK) via the regenerated KAT vectors in
[`verify/tests/vectors/transactions.json`](../crates/verify/tests/vectors/transactions.json).

---

## Part IX — Issuer-sovereign compliance (regulated assets)

An asset's issuer may install a [`CompliancePolicy`](../crates/compliance/src/controls.rs)
— pause/freeze, an allow- or deny-list of accounts, and a per-holder rolling
spend-velocity limit — committed to the state root
([`ledger.rs:513`](../crates/state/src/ledger.rs)), so enforcement is
consensus, not node policy. The decision function is the pure, independently
tested `check_transfer` ([`controls.rs:120`](../crates/compliance/src/controls.rs)).

### Theorem 23 (regulation authorization)

Only an asset's issuer can install or replace its compliance policy.

**Proof.** The only path that writes a policy is the `Action::TokenSetPolicy`
arm ([`execution.rs:817`](../crates/runtime/src/execution.rs)), which
requires the asset to exist and `info.issuer == tx.signer`, where the signer
is authenticated by Theorem 13 (A2) and the issuer field is immutable by
Theorem 20(iii). With Theorem 19, the full regulated-issuance authority of an
asset — minting *and* regulation — reduces to control of the issuer account's
key, with no registry, admin role, or protocol override anywhere. The policy
is bounded state: at most 1024 list entries, priced per entry in gas. ∎

**Machine-checked-by:**
`execution::tests::{only_the_issuer_may_set_an_assets_policy,
oversized_policy_is_rejected_and_replacement_resets_windows}`.

### Theorem 24 (enforcement completeness)

If asset `a` has a policy `P`, then **every** path that moves units of `a`
enforces `P`: (i) `TokenTransfer` — sender permitted, then
`check_transfer` (freeze, recipient control, velocity); (ii) `TokenBurn` —
same gate with the sender as counterparty; (iii) `TokenIssue` — pause and
recipient control; (iv) every contract-bridge command — the identical gate
with the contract as sender and its velocity window threaded across the
batch. There is no fifth path.

**Proof.** By Theorem 20's case analysis the only code that writes token
balances or counters is the four arms above plus
`settle_contract_token_transfers`. Arms (i)–(ii) call `check_token_outgoing`
([`execution.rs:1004`](../crates/runtime/src/execution.rs)) *before* any
balance read, and persist the updated velocity window only together with the
movement it accounts for — a gated-then-failed movement (e.g. insufficient
funds) updates nothing (Lemma 1 discipline). Arm (iii) checks pause and
recipient permission in-arm. The bridge applies the same checks per command
with the batch-threaded window, so a batch cannot exceed a limit its
commands individually respect; any blocked command fails the whole action and
nothing commits (Theorem 21's all-or-nothing). The velocity arithmetic itself
is the pure `check_transfer` function, separately unit-tested in
`sov-compliance` — the runtime adds no arithmetic of its own. A self-transfer
moves nothing and is exempt by construction (it is not a movement). ∎

**Machine-checked-by:**
`execution::tests::{paused_asset_blocks_issue_transfer_and_burn_until_unpaused,
deny_listed_account_is_blocked_in_both_directions,
spend_velocity_limit_caps_a_holder_per_window_and_rolls_over,
contract_token_transfers_obey_the_assets_compliance_policy}`.

### Corollary 24.1 (the monetary base is never regulable)

No compliance policy can affect native SOV: the gates exist only inside the
token arms and the token bridge, and native transfers, the coinbase, vesting,
HTLCs, and the shielded pool contain no policy consult — regulation
is strictly per-asset and issuer-opt-in. An issuer can freeze *its own
asset*; nobody can freeze SOV. Moreover compliance state cannot dangle: the
verifier rejects a policy without its asset or a velocity window without a
policy ([`invariants.rs:232`](../crates/verify/src/invariants.rs)), and
replacing a policy clears the asset's windows
([`ledger.rs:513`](../crates/state/src/ledger.rs)), so stale accounting
never persists in the committed root. ∎

**Machine-checked-by:**
`execution::tests::compliance_never_touches_native_sov`;
`invariants::tests::orphaned_compliance_state_is_caught`;
`ledger::tests::token_policy_and_windows_commit_persist_and_reset_on_replacement`.

---

## Part X — Atomic intent settlement (liquidity rails)

The on-chain liquidity rail: an owner signs a declarative
[`Intent`](../crates/intents/src/lib.rs) off-chain — *give exactly `X` of
asset `A`, receive at least `Y` of asset `B`, until height `H`* — and a
solver fills it on-chain via `Action::IntentSettle`. Legs are native SOV or
on-chain assets; `External` (bridge-pool) legs are **refused with an explicit
error** directing to the proven HTLC path (Theorem 14), because no live
counterparty-chain infrastructure exists to make them real.

### Theorem 25 (double authorization)

A settlement executes only if **both** parties cryptographically authorized
it: the solver by signing the transaction (Theorem 13), and the owner by an
Ed25519 signature over the intent's canonical Borsh bytes that verifies
against the owner account's **registered on-chain key**.

**Proof.** The arm ([`execution.rs:817`](../crates/runtime/src/execution.rs))
requires, in order: `settlement.solver = tx.signer` (so the solver is the
authenticated transaction signer); `ledger.account(owner).key =
Some(intent.public_key)` — the committed key inside the signed bytes must be
the owner's registered key, so an intent naming an owner but signed by any
other key is rejected *regardless of its valid signature*; and
`SignedIntent::verify` over `Intent::signing_bytes` (deterministic Borsh, so
any field tampering — amounts, assets, expiry, nonce — changes the message
and falsifies the signature, A2). The owner's terms are then enforced
literally: `deliver_amount ≥ min_receive` and `height ≤ expiry_height` are
arm gates, so a solver can over-deliver to win but never under-deliver or
settle late. ∎

**Machine-checked-by:**
`execution::tests::{forged_or_tampered_intents_are_rejected,
intent_cannot_be_replayed_or_filled_below_minimum_or_after_expiry}`.

### Theorem 26 (single use)

Each intent settles **at most once**, ever — across all heights, forks aside
— and a cancelled intent never settles.

**Proof.** The intent id is `Blake3(signing_bytes)`
([`intents/lib.rs:89`](../crates/intents/src/lib.rs)) — by A1, unique per
exact terms (owner, nonce, assets, amounts, expiry). The arm rejects any id
present in the committed consumed-intent set and inserts the id on success
([`ledger.rs:576`](../crates/state/src/ledger.rs)); the set is monotone
(never pruned), committed to the state root, and persisted, so the exclusion
is consensus state — the exact nullifier discipline of Theorem 6, applied to
swaps. `IntentCancel` (`execution.rs:868`), permitted only to the owner,
inserts the same id, making cancellation indistinguishable from consumption
to any later fill. A new fill requires new signed terms (a fresh owner
nonce ⇒ a fresh id). ∎

**Machine-checked-by:**
`execution::tests::{intent_cannot_be_replayed_or_filled_below_minimum_or_after_expiry,
cancel_consumes_the_intent_and_only_the_owner_may_cancel}`;
`ledger::tests::consumed_intents_commit_to_the_root_and_persist`.

### Theorem 27 (settlement atomicity and conservation)

A settlement moves both legs or neither; every committed settlement
preserves Theorem 1 (native supply unchanged — the legs are
balance-to-balance), Theorem 20 (per-asset conservation — token counters
untouched), and Theorem 24 (both token legs pass their assets' compliance
gates, including spend-velocity accounting, before anything moves).

**Proof.** `settle_intent_legs`
([`execution.rs:1099`](../crates/runtime/src/execution.rs)) is strictly
validate-then-apply: leg classification (`settle_leg`, `:1068`, where
`External` legs return the honest refusal), both compliance gates, and all
four debit/credit post-states are computed with checked arithmetic **before
the first write**; any failure returns with the ledger untouched. The write
set is collision-free by the arm's gates — give and want assets are distinct
(degenerate-swap gate) and owner ≠ solver (self-fill gate) — so the writes
commute and the composite is exactly the two intended transfers. The
solver's native funds are read and written through the in-flight signer
account, never a stale ledger read, so the settlement cannot double-spend
the solver's own gas fee. No path touches `issued`/`burned`, emission
counters, or mints — supply on every asset, native included, is conserved
identically to a pair of plain transfers. ∎

**Machine-checked-by:**
`execution::tests::{intent_settlement_swaps_token_for_sov_atomically_and_conserves,
token_for_token_settlement_conserves_both_assets,
underfunded_settlement_moves_nothing_on_either_side,
settlement_respects_the_assets_compliance_policy,
external_pool_legs_are_refused_not_mocked}` — each conservation case is
re-checked by the independent `check_transition`/`check_ledger` verifiers
inside the tests themselves.

---

## Part XI — Cryptographic agility and key rotation

[`PublicKey`](../crates/crypto/src/keys.rs) and
[`Signature`](../crates/crypto/src/signature.rs) are **versioned enums**: the
Borsh discriminant is the on-chain scheme byte (`0x00` = Ed25519). One scheme
exists today; the enum's shape is the deliverable — a post-quantum hybrid
lands as a new variant plus a key rotation, not a re-architecture. A2
correspondingly becomes per-scheme: A2(V1) = Ed25519 EUF-CMA.

### Theorem 28 (scheme commitment — no cross-scheme confusion)

(i) A signature of one scheme never verifies under a key of another;
(ii) the scheme of a transaction's key is committed **under its own
signature**, so a signed transaction cannot be reinterpreted under a
different scheme; (iii) an unknown scheme byte cannot enter the state.

**Proof.** (i) `PublicKey::verify`
([`keys.rs:68`](../crates/crypto/src/keys.rs)) matches on the
*(key, signature)* scheme pair; only same-scheme pairs have a verification
path. (ii) `Transaction::signing_bytes` is the Borsh encoding of the whole
transaction, which contains `public_key` — discriminant byte included — so
by A2 any change to the scheme byte falsifies the signature exactly as a
changed amount would (Theorem 13's argument applies verbatim). (iii) Borsh
deserialization of an undefined discriminant fails, so no block, vote,
account, or handshake message carrying an unknown scheme can decode, let
alone validate. Consensus votes, the network handshake, intent signatures,
and rotation proofs all use these same two types, so the property is
protocol-wide by construction. ∎

**Machine-checked-by:**
`keys::tests::borsh_encoding_carries_the_scheme_byte` (scheme byte position,
round-trip, and unknown-scheme rejection); byte-for-byte cross-implementation
parity (Rust ↔ TypeScript SDK) over the regenerated KAT vectors, whose
signing bytes now contain the scheme byte.

### Theorem 29 (rotation: exclusivity, possession, and single-use)

`Action::RotateKey` replaces an account's controlling key such that:
(i) only the current key can initiate a rotation; (ii) the new key must be
**provably possessed**; (iii) a possession proof works for exactly one
(account, nonce) pair; (iv) the old key is dead from the next transaction on;
(v) no funds move.

**Proof.** (i) A rotation is a transaction, so Theorem 13's gates apply: the
current registered key must sign it. (ii) The arm
([`execution.rs:884`](../crates/runtime/src/execution.rs)) requires
`new_key.verify(msg, proof)` where `msg = rotation_signing_bytes(signer,
nonce, new_key)` ([`transaction.rs:233`](../crates/types/src/transaction.rs))
— a signature *by the new key*, so installing a key nobody holds requires a
forgery (A2). (iii) `msg` embeds the domain tag, the signer (NUL-separated —
injective, as the id charset excludes `0x00`), and the nonce; by Theorem
13(b) each (account, nonce) executes at most once, and a proof replayed for
another account or nonce signs a different message. (iv) Authorization reads
`account.key` fresh per transaction (`execution.rs:121`), which the rotation
overwrote; the old key now fails the equality gate. (v) The arm touches only
`signer.key` — no balance field — and conservation (Theorem 1) is re-checked
after the block regardless. This is the migration vehicle for Phase 18: a
future hybrid scheme deploys as new enum variants (Theorem 28 keeps them
unconfusable), and every account moves with one rotation each. ∎

**Machine-checked-by:**
`execution::tests::{rotate_key_replaces_the_controlling_key_and_kills_the_old_one,
rotation_requires_a_possession_proof_from_the_new_key,
rotation_proofs_are_bound_to_account_and_nonce}`.

---

## Part XII — Hybrid post-quantum signatures

Scheme `0x01` (`V2HybridMlDsa65`) pairs Ed25519 with ML-DSA-65 (FIPS 204,
NIST's standardized lattice signature): key = both verifying keys
(32 + 1952 bytes), signature = both component signatures (64 + 3309 bytes),
and verification is the **conjunction** — both components over the same
message ([`keys.rs`](../crates/crypto/src/keys.rs) `verify`). Hybrid keygen
and signing are fully deterministic (component keys derived under distinct
Blake3 domain tags from one master seed; ML-DSA in FIPS 204 deterministic
mode), so hybrid keys are HD-wallet derivable and reproducible.

### Theorem 30 (hybrid unforgeability under either assumption)

A forgery against a `V2` hybrid key requires a forgery against **both**
component schemes on the same message. Hence the hybrid is EUF-CMA secure if
A2a **or** A2b holds — at least as strong as the stronger component, and in
particular still secure against an adversary with a cryptographically
relevant quantum computer (who falsifies A2a but not, per current knowledge,
A2b).

**Proof.** `PublicKey::verify` for the `(V2, V2)` pair returns true only if
the strict Ed25519 check passes *and* the ML-DSA-65 check passes over the
identical message bytes; any other (key, signature) scheme pairing returns
false (Theorem 28(i) extended — verified by the no-downgrade test: a valid
Ed25519 signature by the hybrid's own component key is rejected by the hybrid
key, so an attacker cannot strip the PQ half). A forger must therefore output
`(m, σ_ed, σ_ml)` with both components valid: that output is simultaneously
an Ed25519 forgery (contradicting A2a) and an ML-DSA forgery (contradicting
A2b); it exists only if **both** assumptions fail. Both forgery directions
are exercised: a valid-Ed25519/corrupt-ML-DSA pair and a corrupt-Ed25519/
valid-ML-DSA pair are each rejected. ∎

**Machine-checked-by:**
`keys::tests::{hybrid_verification_is_a_conjunction_half_forgeries_fail,
cross_scheme_verification_always_fails,
hybrid_sign_and_verify_roundtrip_and_determinism,
hybrid_borsh_and_json_roundtrip_with_scheme_tags}`.

### Corollary 30.1 (live migration and full-stack participation)

Any account migrates to post-quantum protection with **one transaction**: a
`RotateKey` whose new key is hybrid (Theorem 29 applies verbatim — the
possession proof is simply a hybrid signature). After rotation, spending from
the account requires both component signatures, and Theorem 13's
authorization gate enforces it on every transaction. Mining participates
identically: a miner's coinbase account may be hybrid-keyed with no consensus
change, since the proof of work (Theorems 8–9) is what authorizes a block —
issuance and security are scheme-agnostic by construction. Block space is priced
honestly: a hybrid envelope pays a per-byte surcharge over the V1 baseline plus
an ML-DSA verification fee
([`gas.rs`](../crates/runtime/src/gas.rs) `envelope_gas`); V1 fee behavior is
byte-for-byte unchanged. ∎

**Machine-checked-by:**
`execution::tests::{account_migrates_to_a_hybrid_pq_key_and_transacts_under_it,
hybrid_envelopes_pay_the_per_byte_surcharge_v1_fees_unchanged}`.

---

## Part XIII — Hybrid post-quantum transport

Every p2p connection ([`tcp.rs`](../crates/network/src/tcp.rs)) layers two
key exchanges: the Noise XX handshake (X25519, `snow`), then an ML-KEM-768
encapsulation carried **inside** the Noise channel
([`pq.rs`](../crates/network/src/pq.rs)). Application frames are sealed
twice — an inner ChaCha20-Poly1305 layer keyed by
`Blake3("sov:pq-channel:<dir>:v1" ‖ handshake_hash ‖ kem_secret)` per
direction, inside the outer Noise encryption.

### Theorem 31 (no harvest-now-decrypt-later)

A passive adversary who records a connection's entire wire traffic can
recover an application frame only by recovering **both** the Noise channel
keys (breaking A4a) **and** the ML-KEM shared secret (breaking A4b).

**Proof.** Every application frame on the wire is
`Noise_Enc(PQ_Enc(plaintext))`. The outer layer requires the X25519-derived
Noise transport keys (A4a). The inner key is
`Blake3(domain ‖ handshake_hash ‖ kem_secret)`: under A1, recovering it
requires both inputs — the handshake hash is itself a function of the Noise
handshake (A4a-protected), and `kem_secret` is the ML-KEM-768 decapsulation
secret whose only wire exposure is the encapsulation ciphertext (A4b), itself
transmitted *inside* the Noise channel. So with A4a broken (e.g. by a future
quantum computer) the adversary obtains the outer plaintext = inner
ciphertext and the KEM ciphertext, but the inner key still requires the
ML-KEM secret (A4b); with A4b broken, the outer Noise layer stands (A4a). Per-direction keys are domain-separated; nonces are monotone
counters per direction, so nonce reuse is impossible by construction, and
the AEAD tag rejects tampered, truncated, reordered, or replayed inner
frames. **Fail closed**: a connection that cannot complete the KEM exchange
never becomes a peer — there is no classical-only fallback to downgrade to. ∎

**Machine-checked-by:**
`pq::tests::{seals_and_opens_in_both_directions, tampered_frames_are_rejected,
replayed_and_reordered_frames_are_rejected,
different_secrets_or_bindings_cannot_interoperate}`;
`tcp::tests::{delivers_a_broadcast_over_real_tcp,
a_peer_that_fails_the_kem_exchange_never_becomes_a_connection,
rejects_an_unencrypted_peer}` — the broadcast test runs the full hybrid
stack over a real socket.

### Remark 31.1 (authentication scope — honest)

This hybridizes transport **confidentiality**. Channel *authentication* is
the application-level signed `Hello` bound to the Noise handshake hash, whose
signature scheme is the node's identity key: post-quantum exactly when the
operator uses a hybrid (`V2`) identity key — available since Part XII with no
further protocol change. An active quantum MITM at connection time is
therefore defeated only for hybrid-keyed peers; recorded-traffic privacy
(Theorem 31) holds for everyone. ∎

---

## Part XIV — The Q-day runbook as consensus policy

Blocks carry BIP-9/8 **version bits** in their hash-committed headers; the
`pq-sunset` deployment (`sov-governance` state machine) activates from that
signal history, and the chain derives a [`PqSchedule`]
([`blockchain.rs:205`](../crates/chain/src/blockchain.rs) `resolved_pq`)
enforced inside the STF ([`execution.rs:172`](../crates/runtime/src/execution.rs)).

### Theorem 32 (activation: deterministic, monotone, and guaranteed)

For any signal history: (i) every node derives the identical activation
height (and hence the identical schedule); (ii) once `Active`, the deployment
is `Active` at every later height; (iii) with BIP-8 `lockinontimeout = true`,
activation occurs for **every possible** signal history by the timeout — a
flag day that miners can accelerate but not veto.

**Proof.** (i) The version bits live in the header, which is hash-committed
(Theorem 15 makes headers identical across honest nodes), and `state_at` is a
pure function of (deployment, height, signal history) — the state at a
window depends only on signaling in *prior* windows, so a block's schedule
never depends on its own bits. (ii) `Active` is terminal in the transition
relation. (iii) With LOT, the `Started → Failed` edge is unreachable;
`Started` exits to `LockedIn` by threshold or timeout, and `LockedIn → Active`
at the next eligible boundary. All three properties are checked
**exhaustively** over all 256 eight-block signal histories. ∎

**Machine-checked-by:**
`blockchain::tests::pq_activation_is_deterministic_and_monotone_over_all_signal_histories`
(exhaustive); header-bit commitment via the regenerated block KATs (Rust ↔
TypeScript header parity).

### Theorem 33 (sunset safety: bounded quantum exposure)

Under the active schedule with rotation window `[R, S)`: (a) in the window,
an account holding ≥ the threshold under a legacy (`V1`) key can execute
exactly one kind of transaction — a `RotateKey` to a non-legacy key (a
`V1 → V1` rotation is rejected, so the window cannot be ridden out);
(b) at heights ≥ `S`, **no** legacy-signed transaction is admissible — by
any account, for any action, rotation included; (c) hybrid-keyed accounts
are unaffected at every phase; (d) the gates are *rejections* (consensus
admission), enforced identically by producers and importers — a block
smuggling a gated transaction is invalid.

**Consequence.** After `S`, a quantum adversary who fully breaks Ed25519
(falsifying A2a) gains **nothing actionable on-chain**: every account that
rotated is protected by Theorem 30 (forgery also requires breaking ML-DSA),
and every account that did not is frozen — its legacy key can authorize
nothing, so forging it authorizes nothing. The honest trade-off is stated
plainly: un-rotated funds are locked at the sunset, because a `V1` signature
no longer constitutes proof of ownership; freezing is the protective choice,
and any future recovery path is a governance decision outside this code.

**Proof.** The gate sits in `apply_transaction` after authorization and
before nonce consumption: (b) is the first check (`height ≥ S` ∧ legacy ⇒
reject), so it dominates; (a) matches the action against
`RotateKey { new_key }` with `new_key` non-legacy — every other action, and
every rotation to a `V1` key, rejects; (c) the gate is conditioned on the
transaction key being `V1Ed25519`, so `V2` transactions never enter it;
(d) rejection makes any containing block fail `apply_transactions` on
import (Theorem 15's re-execution), proven by the smuggled-block test. ∎

**Machine-checked-by:**
`execution::tests::{pq_window_forces_rich_legacy_accounts_to_rotate_and_only_to_hybrid,
pq_window_spares_small_legacy_accounts_until_the_sunset,
pq_sunset_never_touches_hybrid_accounts}` (boundary heights exact);
`blockchain::tests::miner_signaled_pq_sunset_activates_and_enforces_end_to_end`
(the full lifecycle over real produced/imported blocks: signaling →
lock-in → activation → producer exclusion → smuggled-block rejection →
rotation → hybrid flow → freeze).

### Remark 33.1 (launch posture: PQ-native genesis)

The chain has never been live, so no existing account needs this migration:
`sov-testnet gen` and `sov-wallet keygen` now derive **hybrid keys by
default** — every genesis account (the miner identity included) is born
post-quantum (machine-checked by
`daemon::tests::pq_native_genesis_boots_finalizes_and_transacts_on_hybrid_keys`:
a hybrid-keyed chain boots, mines blocks, and accepts hybrid-signed transfers
over real RPC). The sunset machinery of
Theorems 32–33 therefore targets only accounts created later with legacy
keys on an open network — and it is the general scheme-retirement tool for
the day the *hybrid* scheme itself must be superseded. ∎

---

## Part XV — Shielded-pool drain bound and the privacy horizon

The shielded pool's last layer of defense in depth: a consensus **drain
limiter** ([`execution.rs`](../crates/runtime/src/execution.rs), the
`Action::Shielded` de-shield path) over a rolling window committed to the
state root ([`ledger.rs`](../crates/state/src/ledger.rs)
`deshield_window`). Policy: at most `deshield_limit_grains` may leave the
pool per `deshield_window_blocks` (mainnet-like preset: 21,000 XUS per
~day; `0` disables).

### Theorem 34 (bounded drain, even if A3 fails)

Suppose the Halo2 proof system is fully broken (¬A3: an adversary can forge
a verifying proof for any statement). Then the adversary still cannot
inflate SOV supply (Theorem 5), and the total value it can extract from the
shielded pool is bounded by `deshield_limit_grains` per window — linear in
elapsed windows, never a flash drain.

**Proof.** A forged proof gives the adversary one capability at the
execution layer: submitting `Shielded` bundles that pass verification with
an arbitrary value balance. For `vb < 0` (shield) the signer pays
transparently — no gain. For `vb = 0` nothing crosses the boundary (worst
case is intra-pool theft from other shielded holders — real, acknowledged,
and not preventable at this layer). For `vb > 0` (de-shield), **before any
mutation** the runtime checks, in order: the window cap — the rolling
window (start, spent) is read from committed state, rolled if
`height − start ≥ window`, and the de-shield fails if
`spent + |vb| > deshield_limit_grains` — and the pool-balance turnstile
(`|vb| ≤ shielded_value`). The window is persisted only together with the
movement it meters, and it is consensus state: every importer re-derives
it (Theorem 15), so a producer cannot under-count it. Summing over windows:
extraction ≤ `limit × ⌈blocks/window⌉`. The bound holds *unconditionally* —
it does not assume the proof system, only A1/A2 and the STF discipline of
Lemma 1. ∎

**Machine-checked-by:**
`execution::tests::deshield_rate_limit_caps_pool_outflow_per_window` — a
**real Halo2** shield + a **real** de-shield bundle (the new
`sov_shielded::unshield` builder, spend with no output) blocked over the
cap and settled under it, with conservation re-verified by
`check_transition`/`check_ledger`;
`ledger::tests::deshield_window_commits_persists_and_default_is_canonical`.

### Remark 34.1 (the privacy horizon — the one thing code cannot fix)

The pool's note encryption and circuit rest on elliptic-curve assumptions a
quantum computer breaks, and every shielded transaction is **public
ciphertext recorded forever**. A future quantum adversary can therefore
decrypt *past* shielded amounts, recipients, and linkages — no upgrade can
retroactively re-encrypt published data. The protocol's stance, disclosed in
[`quantum-posture.md`](quantum-posture.md): funds are safe regardless
(Theorems 5 and 34 hold without A3), shielded *privacy* is time-limited
against a quantum-capable adversary, and the long-term fix is a hash-based
(STARK-class) shielded pool — a research track, with nothing
production-audited shipping today and no imitation of one shipped here. ∎

---

## The trust chain, summarized

| # | Property | Depends on | Independent re-checker | Machine check |
|---|---|---|---|---|
| L2 | Fee split exact, no lost grains | P1 | `check_transition` | fee tests |
| 1 | Value conserved every block | — | `check_transition`, every import | invariants tests |
| 2 | No unauthorized mint | — | `check_transition` | `unauthorized_mint_is_caught` |
| 3 | Supply ≤ 21M forever | — | `check_ledger` | cap/budget tests |
| 3.1 | No pre-mine (mainnet genesis supply = 0) | — | genesis cap = full budget | `mainnet_policy_forbids_any_premine` |
| 4 | Emission terminates; fixed terminal supply | — | reward clamp | `long_tail_is_fixed_supply…` |
| 5 | Shielded turnstile (holds even if ¬A3) | — | `check_transition` + pool floor | `shielded_pool_cannot_manufacture_supply` |
| 6 | No nullifier double-spend; atomic bundles | A3 for (c) only | two-phase `apply_bundle` | `nullifier_double_spend_is_rejected` |
| 7 | Anchors = real chain history | A1, A3 | `anchor_is_known` gate | anchor tests |
| 8 | Heaviest-work fork choice; reorg correctness | A1 | `chain_work` compare + replay-from-genesis | reorg + work tests |
| 9 | Difficulty not forgeable (committed `nBits`) | A1 | required-bits gate + canonical compact | bits + compact tests |
| 10 | Confirmation-depth finality (probabilistic) | A1 | pure-function depth, ≥ 6 | finality + chaos tests |
| 11 | Coinbase authorized by the work (no schedule) | A1 | `proposer` committed in `pow_hash` | coinbase tests |
| 12 | State/tx proof soundness | A1 | domain separation | SMT + merkle tests |
| 13 | Authorization & replay protection | A2 | nonce + Ed25519 gates | admission tests |
| 14 | HTLC exclusivity | A1 (sha256) | height partition + settle | HTLC tests |
| 15 | Import determinism | A1 | root re-execution gate | tamper tests |
| 16 | Time discipline (BIP-113) | — | MTP gate | timestamp tests |
| 17 | Data bound (BIP-110) | — | pre-admission gate | size tests |
| 18 | PoW difficulty correspondence | A1 (RO) | 256-bit division | difficulty tests |
| 19 | Token issuance bound to issuer by hash | A1, A2 | derived asset id | forged-issuer test |
| 20 | Per-asset conservation (`Σb = issued − burned`) | — | `check_ledger` + `check_transition` | token invariant tests |
| 20.1 | Tokens cannot touch the 21M XUS base | — | `total_supply` exclusion | `token_units_never_enter_native_supply` |
| 21 | Contract containment (no ledger theorem violable from a Call) | A2 | runtime re-validation of all VM outputs | treasury/rollback tests |
| L6 | Bounded execution & output (gas, storage, events, return) | — | explicit constant caps | VM bound tests |
| 22 | Authenticated caller; receipts commit contract outputs | A1, A2 | `receipts_root` re-execution | echo-contract test + KAT parity |
| 23 | Only the issuer can regulate its asset | A1, A2 | issuer-equality gate | policy-hijack test |
| 24 | Compliance enforced on every token-moving path | — | single gate fn + bridge | pause/deny/velocity tests |
| 24.1 | Native SOV is never regulable | — | no policy consult outside token arms | `compliance_never_touches_native_sov` |
| 25 | Settlement requires both parties' signatures | A1, A2 | on-chain key binding + Borsh canonical bytes | forgery/tamper tests |
| 26 | An intent settles at most once | A1 | committed consumed-id set (nullifier discipline) | replay/cancel tests |
| 27 | Settlement atomic; conserves every asset | — | validate-then-apply + `check_transition` | swap conservation tests |
| 28 | Scheme committed under the signature; no cross-scheme confusion | A2 | versioned enums + Borsh discriminant | scheme-byte + KAT parity tests |
| 29 | Key rotation: exclusive, possession-proven, single-use | A2 | domain-tagged proof bound to (account, nonce) | rotation adversarial tests |
| 30 | Hybrid PQ: forgery needs Ed25519 AND ML-DSA broken | A2a or A2b | conjunction verify + no-downgrade | half-forgery tests |
| 30.1 | One-tx PQ migration; hybrid miner identity | A2a or A2b | RotateKey + scheme-agnostic PoW | migration test |
| 31 | Transport: no harvest-now-decrypt-later | A4a or A4b | double seal, fail-closed KEM | PQ channel + real-socket tests |
| 32 | PQ activation deterministic/monotone/guaranteed | A1 | header-committed bits + pure state walk | **exhaustive** 256-history check |
| 33 | Sunset bounds quantum exposure (rotate or freeze) | — | STF admission gate, import-enforced | window/sunset/smuggle tests |
| 34 | Pool drain bounded even if the zk system breaks | — | committed rolling window, validate-then-apply | real-proof unshield tests |

### What is, and is not, proven

Proven here: ledger-level safety (conservation, cap, **no pre-mine**, issuance,
turnstile, double-spend exclusion), **Nakamoto consensus** (heaviest-work fork
choice and reorg correctness, unforgeable committed difficulty, confirmation-
depth finality, work-authorized coinbase), authenticated-state soundness, and
execution integrity — each tied to a test that re-runs against the same code on
every CI pass.

**Not** provable from code, and stated plainly: finality is **probabilistic**,
not absolute — a sufficiently large share of global hashpower can reorg recent
blocks (Theorem 10 bounds the cost, it does not make reversal impossible). The
mainnet seal is **RandomX** (memory-hard, ASIC-resistant) precisely so commodity
CPUs — Apple M-series included — can mine and the early network is not captured
by rentable SHA-256 ASIC hashpower; but no proof-of-work chain is immune to a
party that out-hashes the honest network, and bootstrapping a new chain's
hashrate is an operational reality, not a code property. Network-level liveness
under partition or
message loss; the internal soundness of the Orchard/Halo2 circuit (A3 —
mitigated by Theorem 5: even its failure cannot inflate supply); the security of
the underlying primitives (A1, A2 — standard, widely audited assumptions); and
operational concerns (key custody, third-party audit, sustained multi-miner
testnet), which remain on the production-readiness list in
[`security-review.md`](security-review.md).
