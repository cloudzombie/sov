# SOV State Transition Specification

**Status: normative.** This is the authoritative specification of SOV's state
transition function (STF) — the rules by which a `(state, transaction)` pair
produces a new state. It is written to be unambiguous and is **machine-checked**:
every rule below carries a `Verified-by` pointer to a passing test that exercises
it against the real implementation. Mechanized model-checking of consensus
safety/liveness (TLA+ / Stateright) is tracked separately under roadmap item
**p7-i1**; this document specifies the *execution* STF (p7-i0).

All quantities are integer **grains** (`u128`), `1 SOV = 10^8 grains`. No rule
uses floating point. The reference implementation is
[`crates/runtime/src/execution.rs`](../crates/runtime/src/execution.rs)
(`apply_transaction` / `apply_transactions`); the committed state is the
[`Ledger`](../crates/state/src/ledger.rs) and its `state_root`.

## Notation

A transaction `tx = (signer, public_key, nonce, action)` carries a signature. The
state is the ledger `L`; `L[a]` is account `a` with fields `balance`, `staked`,
`locked`, `nonce`, `key`, `code`, plus the global committed counters
`mined_emitted` and `staked_emitted`. `total_supply(L) = Σ (balance + staked +
locked)` over all accounts.

---

## Admission rules (checked for every transaction, in order)

### STF-AUTH — authentication
**Pre:** the signature verifies (Ed25519) against `tx.public_key` over the
transaction's canonical Borsh signing bytes.
**On failure:** the transaction is rejected; **state is unchanged**.
**Code:** `apply_transaction` step 1. **Verified-by:** `sov-crypto` sign/verify
tests; `sov-chain::blockchain` block import re-checks all signatures
(`all_signatures_valid`).

### STF-AUTHZ — authorization
**Pre:** `tx.public_key` equals the controlling `key` registered on `L[signer]`.
A first `Mine` from a keyless account registers `tx.public_key` as its key.
**On failure:** rejected; state unchanged.
**Code:** `apply_transaction` step 2. **Verified-by:**
`sov-verify::conformance` (`stf_*`), runtime auth tests.

### STF-NONCE — ordering & replay protection
**Pre:** `tx.nonce == L[signer].nonce`.
**Effect on admission:** `L[signer].nonce += 1` — **even if the action then
fails** (STF-NONCE-CONSUME), so a rejected payment can never be replayed.
**On nonce mismatch:** the transaction takes no effect.
**Code:** `apply_transaction` step 3. **Verified-by:**
`sov-verify::conformance::stf_stale_nonce_cannot_replay`,
`sov-verify::conformance::stf_failed_action_still_consumes_nonce`.

---

## Action rules (applied only after admission)

### STF-TRANSFER — `Action::Transfer { to, amount }`
**Pre:** `L[signer].balance ≥ amount`.
**Effect:** `L[signer].balance -= amount`; `L[to].balance += amount`.
**Post:** `total_supply` unchanged (value conserved).
**On insufficient funds:** action fails; balances unchanged (nonce still
consumed). **Verified-by:**
`sov-verify::conformance::stf_transfer_is_exact_and_conserves`,
`sov-runtime` `total_supply_is_conserved_by_transfer`.

### STF-MINE — `Action::Mine { solution }`
**Pre:** `solution` satisfies the per-algorithm `Target` for
`challenge(prev_hash, signer, nonce)`; `mined_emitted < mining_budget_grains`.
**Effect:** `reward = MiningPolicy::reward(mined_emitted)` (halved on **mined**
supply, clamped to the mining budget); `L[signer].balance += reward`;
`mined_emitted += reward`.
**Post:** `Δtotal_supply == reward == Δmined_emitted`; `mined_emitted ≤
mining_budget_grains`.
**On invalid solution or exhausted budget:** action fails; no mint.
**Code:** `Action::Mine` arm. **Verified-by:** `sov-mining` reward tests,
`sov-verify` replay (real PoW mint) + invariants.

### STF-STAKE — `Action::Stake { amount, lock_blocks }`
**Pre:** `amount > 0`; `min_lock_blocks ≤ lock_blocks ≤ max_lock_blocks`;
`L[signer].balance ≥ amount`; a re-stake may not shorten an existing lock.
**Effect:** `reward = clamp(StakingPolicy::reward(amount, lock_blocks),
staking_budget_grains − staked_emitted)`; move `amount` from `balance` to
`staked`, add `reward` to `staked`; `staked_emitted += reward`;
`unstake_height = max(unstake_height, height + lock_blocks)`.
**Post:** `Δtotal_supply == reward == Δstaked_emitted`; `staked_emitted ≤
staking_budget_grains`. **Verified-by:** `sov-staking` reward tests,
`sov-chain` `staking_round_trip_through_blocks`, `sov-verify` invariants.

### STF-UNSTAKE — `Action::Unstake { amount }`
**Pre:** `height ≥ L[signer].unstake_height`; `L[signer].staked ≥ amount`.
**Effect:** move `amount` from `staked` to `balance`.
**Post:** `total_supply` unchanged. **Verified-by:** `sov-chain`
`staking_round_trip_through_blocks`.

### STF-VESTING — `Action::ClaimVesting`
**Pre:** `height ≥ L[signer].unlock_height` and `L[signer].locked > 0`.
**Effect:** move all `locked` to `balance`.
**Post:** `total_supply` unchanged. **Verified-by:** `sov-chain` vesting tests.

### STF-CONTRACT — `Action::Deploy { code }` / `Action::Call { contract, gas_limit }`
**Deploy:** sets `L[signer].code = code` (rejects empty code).
**Call:** runs `code` on the deterministic `sov-vm` (wasmi), gas-metered;
per-contract storage is committed to `state_root`; the caller is charged
`vm_gas_used × gas_price`, paid to the block proposer.
**Post:** no SOV is minted; `total_supply` unchanged. **Verified-by:** `sov-vm`
integration test, `sov-chain` deploy/call tests.

---

## Global invariants (must hold after every block)

### STF-CONSERVE — value conservation & no unauthorized mint
For any block taking `L → L'`:
`total_supply(L') == total_supply(L) + Δmined_emitted + Δstaked_emitted`, with
both counters monotonic non-decreasing. Equivalently, the **only** ways supply
rises are STF-MINE and STF-STAKE; every other action conserves it.
**Verified-by:** `sov-verify::invariants::check_transition` + its unit tests +
`sov-verify` property test `invariants_hold_under_random_tx_sequences` +
the real-chain replay test.

### STF-CAP — supply cap & emission budgets
`total_supply ≤ MAX_SUPPLY_GRAINS (2.1e15)`; `mined_emitted ≤
mining_budget_grains`; `staked_emitted ≤ staking_budget_grains`. Genesis enforces
`genesis_alloc + mining_budget + staking_budget ≤ MAX_SUPPLY_GRAINS`, so the cap
holds inductively. **Verified-by:** `sov-verify::invariants::check_ledger` +
tests; `sov-chain::genesis` cap test.

### STF-DETERMINISM — reproducibility & cross-node agreement
Importing the same blocks from the same genesis yields a **byte-identical**
`state_root` at every height, on any node. Ordered state (`BTreeMap`), integer
math, no wall-clock and no randomness in execution. **Verified-by:**
`sov-verify` replay/cross-node integration test
(`invariants_hold_over_real_blocks_and_replay_agrees_cross_node`).

---

## Honest boundary

This document plus its `Verified-by` tests make the STF a *machine-checked
normative specification*: every rule has an executable check. It is **not** a
mechanized formal proof — exhaustive model-checking of the consensus protocol's
safety and liveness (TLA+ / Stateright) is roadmap item **p7-i1**, and is not
claimed here.
