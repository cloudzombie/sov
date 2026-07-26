# Pool v2 spend circuit — soundness argument

**What this document is.** A written, per-constraint justification that the
pool-v2 AIR proves what we claim it proves. It exists because the dangerous
failure of a STARK circuit is not a code defect but a constraint nobody wrote:
an under-constrained AIR compiles, passes every test, and lets a prover produce
a valid proof of a false statement.

**Status.** Internal. This is the artifact an external audit should attack, not
a substitute for one. Where an argument rests on an assumption, the assumption
is named. Where something is unproven, it says so.

**Scope.** `chain/crates/shielded-pq/src/air.rs` (the AIR), with the premises it
depends on in `prover.rs` (`verify_spend`) and `note.rs` (value bounds).

---

## 0. What the proof is supposed to establish

Given public inputs — per-slot anchors, nullifiers, output commitments, the
dummy flags, and the transparent legs `t_in` / `t_out` / `fee` — a valid proof
must establish that the prover knows, for each of 4 input slots and 4 output
slots, witnesses such that:

1. **Membership** — every real input note's commitment sits in a Merkle tree
   whose root is the published anchor.
2. **Ownership** — the prover knows the spending key of every real input note;
   knowing a note's *contents* (as its sender does) is not sufficient.
3. **Nullifier correctness** — each published nullifier is the unique value
   determined by that note.
4. **Output binding** — each published output commitment is the commitment to a
   note the prover chose, at a value the circuit constrained.
5. **Conservation** — inputs plus `t_in` equal outputs plus `t_out` plus `fee`,
   **over the integers**, with no field wraparound.

Privacy (which values and which notes) is not this document's subject.

---

## 1. Trace shape

31 columns × 1024 rows. Columns: 12 Rescue-Prime sponge state, 4 `rho`, 4 `nsk`,
1 Merkle path bit, 8 value registers (4 in, 4 out), 2 range-check (bit,
accumulator).

Each input occupies 24 hash cycles of 8 rows: owner tag, commitment stage 1,
commitment stage 2, 20 Merkle levels, and the nullifier. Each output occupies 2
cycles. Range-check segments follow. All constraint activity ends before the
padding region.

---

## 2. The hash is a hash

Constraints 0–11 enforce one Rescue-Prime round per row, written in the
algebraically balanced form

```
MDS · s^7 + ARK1[r]  ==  ( INV_MDS · (s' − ARK2[r]) )^7
```

so both sides are degree 7 rather than requiring an inverse-power in-circuit.
The round mask `hmask` is zero on the final row of each 8-row cycle, which is
the injection row — so a cycle is exactly 7 rounds plus one absorption row.

**This is where we depend on someone else's work.** We do not prove
Rescue-Prime collision resistance; we rely on the published analysis of
`Rp64_256` as implemented in winterfell. What we *do* argue is that the circuit
computes that permutation faithfully and absorbs the right values at the right
rows — which is what the rest of this document is about.

Every sponge injection additionally pins the capacity to `[8, DOMAIN, 0, 0]`,
where `DOMAIN` differs per use (owner tag, commit stage 1, commit stage 2,
Merkle node, nullifier, dummy nullifier). Domain separation is therefore
enforced *by constraint*, not by convention: a prover cannot reuse a digest
computed under one domain in a position expecting another, because the capacity
element carrying the domain is fixed at the injection row.

---

## 3. Ownership — why a note's sender cannot spend it

The commitment is built as

```
owner_tag = H_TAG(nsk, 0)
cm_1      = H_C1(value, owner_tag)
cm        = H_C2(cm_1, rho)
```

Constraints 28–31 force the owner-tag sponge to absorb the **`nsk` registers**
in its left rate half on row 0, and constraints 36–39 do the same at each
subsequent input's segment seed. Constraints 51–54 chain the resulting tag
digest into commitment stage 1, and 55–58 force the value absorbed alongside it
to be that input's **private value register**.

So the commitment binds `nsk`, and the only path to a commitment that opens is
through the `nsk` registers. A sender knows `value` and `rho` and can compute
the commitment, but cannot produce a trace that reaches it without `nsk`.

This closes a hole found during development: a bare PRF nullifier over `rho`
alone would have let a note's sender spend it. The owner tag is the fix, and it
is load-bearing, not decorative.

---

## 4. Membership — the Merkle chain

Constraints 71–82 inject each level: the running digest occupies the left rate
half when the path bit is 0 and the right half when it is 1, with the sibling as
a free witness. Constraint 83 is `b·(1−b) = 0` — the path bit is boolean, so a
prover cannot use a fractional bit to place the digest in both halves and forge
a path.

The chain runs `TREE_DEPTH = 20` levels, and the digest at `root_row(i)` is a
**boundary assertion** against `anchors[i]`. The prover therefore cannot choose
the root; it is fixed by public input.

**Dependency, stated explicitly:** the circuit proves membership in a tree with
the claimed root. That the root is a *recent, real* anchor is a consensus check,
not a circuit property — it lives in the anchor-ring membership test. The
circuit is sound about "this note is in *that* tree"; consensus must be sound
about "that tree is ours."

---

## 5. Nullifier — unique, and domain-separated by dummy status

Constraints 84–94 seed the nullifier sponge with `nsk` in the left rate half and
`rho` in the right. Both are register columns, held constant across the input's
segment by constraints 12–19 (`m_const_keys`), so the values absorbed here are
the same ones that produced the commitment in §3.

The nullifier is thus a deterministic function of `(nsk, rho)` — the same pair
that determines the commitment. Two distinct nullifiers for one note would
require two distinct `(nsk, rho)` pairs producing the same commitment, i.e. a
Rescue-Prime collision. The digest at `nf_row(i)` is asserted against
`nullifiers[i]`, so the published value is the computed one.

Constraint 95–98 selects the capacity domain by the **public** `input_dummy[i]`
flag: real and dummy nullifiers live in separate domains, so a dummy can never
collide with a real nullifier.

---

## 6. Conservation — the argument that matters most

Constraint 128 enforces, at a single row:

```
t_in − t_out − fee + Σ v_in[i] − Σ v_out[j]  ==  0   (mod p)
```

This is field equality. Field equality only implies **integer** equality if
neither side can wrap the modulus. That is the entire soundness question for
inflation, and it depends on two premises:

**Premise A — every private value is 61 bits.** Constraints 118–119 implement an
MSB-first double-and-add: `acc' = 2·acc + bit'`, with `bit ∈ {0,1}` enforced by
`bit·(bit−1) = 0`. Per segment the accumulator is asserted `0` at its base row,
runs exactly `VALUE_BITS = 61` steps, and constraint 120–127 asserts the landing
accumulator equals that value register. The masks are built over
`base..base+61` (accumulation), `base+1..=base+61` (bit booleanity), and
`base+61` (landing), so **every** claimed bit is boolean-constrained and the
register equals exactly the 61-bit sum. The segment allocates 64 rows; the 3
slack rows fall *after* the landing row and cannot influence it, and the value
registers are held constant across the whole active region by constraints 20–27.

Therefore each of the 8 private values is an integer in `[0, 2^61)`.

**Premise B — the public legs are bounded, before verification.** This is
enforced *outside* the circuit, in `verify_spend` (`prover.rs:503–507`):
`transparent_in`, `transparent_out`, and `fee_grains` are each rejected if they
exceed `MAX_NOTE_VALUE = 2^61 − 1`, **before** the proof is checked.

Given A and B, with the Goldilocks modulus `p = 2^64 − 2^32 + 1`:

- LHS ≤ 4·(2^61−1) + (2^61−1) = 5·(2^61−1) ≈ 1.153 × 10^19 < p
- RHS ≤ 4·(2^61−1) + 2·(2^61−1) = 6·(2^61−1) ≈ 1.384 × 10^19 < p

Both sides are integers below `p`, so equality mod `p` is equality over the
integers. **No wrap is reachable, and no value can be minted.** This is checked
numerically by `note.rs::no_wrap_bound_argument_holds`.

Why 61 and not 64: the original design assumed a `< 2^66` headroom that
Goldilocks does not have — `p` is below `2^64`, so four 64-bit values can wrap.
61 bits is the largest width for which the bound above holds with 4-in/4-out.
The cost is nil in practice: SOV's entire supply is ≈ 2^51 grains, about 2^10
below the cap.

**Premise B was the single most fragile link, and is now structural.** It lives
in the verifier rather than the AIR, so a future call site that verified without
it would silently reintroduce field wraparound and unbounded inflation — with
every existing test still passing. That is no longer possible to forget:
`Bounded` (in `prover.rs`) has a private field and exactly one constructor,
`Bounded::check`, which performs the bound and dummy-slot checks; and
`verify_bounded` accepts nothing else. Verifying without having bounded the
publics does not compile. `verify_spend` remains the convenience entry point and
simply does `Bounded::check` then `verify_bounded`.

---

## 7. Dummy slots

Dummy inputs and outputs are declared by **public** flags. For a dummy slot the
value register is asserted `0` at row 0, so it contributes nothing to
conservation; its Merkle/nullifier rows are left as unconstrained junk that is
never surfaced. That is sound only because `verify_spend` (`prover.rs:510–517`)
rejects any dummy slot carrying nonzero published anchors, nullifiers, or
commitments. Circuit and verifier share this obligation, and the verifier half
is the one to keep an eye on.

---

## 8. What this argument does NOT establish

Stated plainly, because a soundness argument that overclaims is worse than none:

1. ~~**Concrete security level** — underived.~~ **DERIVED, see §10.** The
   answer is materially worse than the headline number, and it changes the
   recommended parameters.
2. **Rescue-Prime and winterfell.** We rely on their published analysis and on
   the correctness of the winterfell implementation, including its FRI verifier.
3. **Completeness.** That an honest prover always succeeds is evidenced by
   tests, not argued here.
4. **Privacy.** Which notes and values are hidden — separate property, separate
   argument. Note that dummy *flags* are public, so slot occupancy is not
   hidden.
5. **The consensus layer.** Anchor recency, cross-block and cross-reorg
   nullifier uniqueness, the value turnstile, and verification-cost DoS are all
   outside the circuit and outside this document.
6. **Under-constraint in general.** This document argues that the constraints
   present are sufficient for the five claims in §0. It cannot prove that no
   *additional* freedom exists — that is precisely what an external audit with
   under-constraint tooling is for.

---

## 9. Where an auditor should push hardest

In our own order of concern:

1. **Premise B's placement** (§6) — a verifier-side bound holding up an
   in-circuit soundness claim.
2. **Dummy-slot junk rows** (§7) — unconstrained trace regions are exactly where
   under-constraint hides; is the verifier-side rejection genuinely total?
3. **The derived bit-security number** (§8.1).
4. **Sponge injection masks** — every argument in §§3–5 assumes each mask
   activates on exactly the intended rows. The masks are constructed
   programmatically; an off-by-one would silently drop a constraint while every
   test still passed.


---

## 10. Concrete security level — measured, not conjectured

Winterfell computes both figures from a real proof. `tests/security_level.rs`
does exactly that, on a realistic 2-in/2-out bundle at the shipped parameters
(42 FRI queries, blowup 8, 16 bits grinding, quadratic extension):

| measure | bits |
|---|---|
| conjectured (capacity) | **127** |
| proven — Johnson / list-decoding radius | **75** |
| proven — unique decoding radius | **50** |

The 127 we have been quoting is the *conjectured* figure. Unconditionally, the
protocol is at **75 bits**, and **50** under the most conservative bound.

That matters more than usual right now: the capacity-soundness conjectures on
which deployed STARKs set parameters had their strongest up-to-capacity forms
**disproved over large fields in late 2025**. Quoting a conjectured number is
therefore not a conservative posture for an asset that intends to hold reserves.

### Adding queries does not fix it

A sweep over queries x blowup (same test) shows proven security **saturates**
under a quadratic extension:

| extension | blowup | queries | proven | proof size |
|---|---|---|---|---|
| quadratic | 8 | 42 | 75 | 53.8 KB |
| quadratic | 8 | 64 | 86 | 74.1 KB |
| quadratic | 8 | 200 | **86** | 182.4 KB |
| quadratic | 16 | 200 | **82** | 209.7 KB |
| quadratic | 32 | 200 | **79** | 236.6 KB |

Past ~64 queries the number stops moving: 86 bits is a **structural ceiling**,
not a query-budget problem. Spending 3.4x the proof size buys nothing.

### The cubic extension breaks the ceiling

The binding constraint is the extension field. Goldilocks is a 64-bit base
field; a quadratic extension gives 128 bits of extension, and the proven bound
saturates below it. Moving to a **cubic** extension changes the picture
completely:

| extension | blowup | queries | proven | proof size |
|---|---|---|---|---|
| cubic | 8 | 64 | 111 | 85.3 KB |
| cubic | 8 | 96 | **128** | 115.9 KB |
| cubic | 16 | 42 | 99 | 67.4 KB |
| cubic | 16 | 64 | **128** | **94.3 KB** |
| cubic | 32 | 42 | 120 | 71.9 KB |
| cubic | 32 | 64 | **128** | 103.4 KB |

**ADOPTED (this is now `proof_options()`): cubic extension, blowup 16, 64
queries.** Measured after the change, on the same realistic bundle:

| | previous (42q / 8 / quadratic) | **adopted (64q / 16 / cubic)** |
|---|---|---|
| conjectured | 127 | 128 |
| **proven (Johnson/ldr)** | **75** | **128** |
| proven (unique decoding) | 50 | **74** |
| proof bytes | 55,054 | **96,586** |
| verify (median) | 621 us | **970 us** |

Verification cost rose 621 -> 970 us, which remains far below the block
interval even for a saturated block, so the liveness budget is unaffected.

The honest trade: **1.75x proof size to go from 75 proven bits to 128.** For a
pool that is not yet armed, and for a chain whose stated bar is reserve grade,
that is the right side of the trade. The cost is paid in bandwidth and block
weight, both of which are already being sized for ~144 KB bundles.

If 128 proven is judged too expensive, `cubic / blowup 32 / 42 queries` gives
**120 proven bits at 71.9 KB** — still a large improvement over today at a
smaller size than the 128-bit option.

**This change is cheap to make now and expensive later:** the parameters are
baked into `proof_options()`, and `verify_spend` accepts only proofs generated
with them. Changing them after the pool is armed is a consensus change requiring
its own deployment; changing them while the pool is dormant costs nothing but a
re-benchmark.
