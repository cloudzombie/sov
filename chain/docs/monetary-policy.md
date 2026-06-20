# SOV Monetary Policy

SOV is a **fixed-cap, non-deflationary** reserve asset: a hard 21M ceiling, every
coin mined (no pre-mine), and — once emission ends — a permanently fixed supply.
This document states the policy and points to the consensus code and the
conformance proof that enforce it; nothing here is aspirational.

## 1. Hard cap, one budget, no pre-mine

Total issuance can never exceed **21,000,000 XUS** (`MAX_SUPPLY_GRAINS`,
1 XUS = 10^8 grains). There is a single emission source — proof-of-work mining —
and its budget is the **entire cap**: `MiningPolicy.mining_budget_grains =
MAX_SUPPLY_GRAINS`. There is no staking budget and no genesis headroom.

Genesis validates `Σ(genesis balances + vesting) + mining_budget ≤
MAX_SUPPLY_GRAINS` (`crates/chain/src/genesis.rs`). Because the mining budget is
the whole cap, this check rejects **any** funded genesis balance — a mainnet
genesis has supply exactly zero. The ledger tracks `mined_emitted` as a committed,
monotonic counter folded into the state root, so issuance is auditable and can
never be double-counted or recovered once spent.

## 2. Emission schedule (and why it terminates)

The coinbase follows **Bitcoin's height-keyed halving rule at Zcash's cadence**:

- base reward **12.5 XUS**, halving every **840,000 blocks**
  (`reward(h) = 12.5 ≫ ⌊(h−1)/840000⌋`);
- at **2.5-minute blocks**, a halving falls roughly every **4 years**;
- the geometric series sums to **20,999,999.9076 XUS** — just under the 21M cap.

Two guards make termination exact: the shift is bounded (`halvings ≥ 127 ⇒ 0`),
so there is **no integer-overflow resumption** (the [BIP-42] class of bug), and
every reward is clamped to the room left in the budget, so issuance approaches
the cap and then is **exactly zero**.

## 3. The tax: how the coinbase and fees are distributed (no burn)

`fee = gas_used × gas_price`. **Every coinbase and every fee** is split the same
three ways (`distribute_fee` / `apply_coinbase` in
`crates/runtime/src/execution.rs`):

- **5% to the founder** (`tax_primary_bps = 500`, `tax_primary_recipient`);
- **2% to a dev fund** (`tax_secondary_bps = 200`, `tax_secondary_recipient`);
- the remaining **93% to the block's miner**.

**Nothing is burned** — every grain of every fee and every subsidy is paid out.
The tax is a perpetual protocol allocation, so SOV is **no-pre-mine but not a
Bitcoin-style fair launch**. Genesis validates
`tax_primary_bps + tax_secondary_bps ≤ 100%`. The native-SOV `burned` counter has
been removed; the per-asset `TokenBurn` redemption of *issued tokens* is a
separate, unrelated feature and does not touch SOV supply.

## 4. Conservation and a fixed terminal supply

Total supply obeys the conservation law enforced every block by
`sov-verify::check_transition`:

```
supply_after == supply_before + Δmined
```

- **During emission** (`Δmined > 0`): supply grows, but the rate falls with every
  halving — *disinflation*.
- **After emission** (budget exhausted ⇒ `Δmined = 0`): every block has `ΔS = 0`.
  A fee only *moves* value (sender → founder/dev/miner); it never changes total
  supply. The terminal supply is therefore **fixed forever** — a hard-capped
  reserve asset, not a deflationary one.

This is proven, not asserted:
`long_tail_is_fixed_supply_once_emission_is_exhausted` in
`crates/verify/src/invariants.rs` exercises all phases against the real ledger and
invariant.

## 5. Long-term security budget (the deliberate choice)

After the subsidy decays, miner revenue comes entirely from the **93% miner share
of transaction fees** — the fee-funded long tail Bitcoin chose, on purpose. The
founder/dev tax (5% + 2%) continues to apply to those fees in perpetuity. A tail
*emission* would fund miners forever but make SOV inflationary, contradicting the
reserve-asset thesis; SOV funds long-run security from fees instead.

[BIP-42]: https://github.com/bitcoin/bips/blob/master/bip-0042.mediawiki
