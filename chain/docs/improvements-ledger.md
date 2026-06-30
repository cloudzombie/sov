# SOV Improvements Ledger — "All of Bitcoin, all of Zcash, and more"

**Mandate (user, 2026-06-11):** SOV must incorporate *every* worthwhile
improvement Bitcoin and Zcash have made, plus our own. This is the honest
running scorecard: what we already have, what's worth adding, and what is
deliberately out of scope. ✅ = in code + tested. 🔶 = partial / different
form. ⬜ = planned. ❌ = deliberately not (with reason).

## Bitcoin lineage

| Improvement | Status | Notes |
|---|---|---|
| 21M hard cap, halving schedule | ✅ | **Bitcoin's halving rule at Zcash's cadence:** 12.5-XUS subsidy halving every 840,000 blocks (height-keyed, `base >> ((h−1)/840000)`; ~4-year halvings at 2.5-minute blocks), geometric total 20,999,999.9076 XUS under `MAX_SUPPLY_GRAINS`; machine-checked |
| **No pre-mine** | ✅ | The mainnet mining budget IS the full 21M cap, so genesis arithmetically rejects ANY funded balance or vesting grant (`mainnet_policy_forbids_any_premine` test); genesis supply is exactly ZERO — every coin is mined. NOT a Bitcoin-style fair launch (see the tax row below), but nothing is pre-allocated |
| **100% miner coinbase + fees, no tax, no burn** | ✅ | The ENTIRE coinbase AND every fee go to the block's miner — no protocol tax, nothing burned (pure Nakamoto). The deflationary fee-burn is REMOVED entirely. Supply invariant is `supply == genesis + mined` (no `− burned`) — hard-capped, not deflationary. A Bitcoin-style fair launch: no pre-mine, no founder/dev allocation |
| Proof-of-work consensus (Nakamoto) | ✅ | **Pure Nakamoto, complete:** blocks sealed by proof of work; heaviest-work fork choice + reorg; coinbase issuance (halving, budget-capped) to the header's miner; continuous mining; **BFT fully removed** — no finality gadget, no validator votes, no proposer schedule, no committee; finality = confirmation depth (6, Bitcoin's convention); committed difficulty in Bitcoin's compact `nBits` (i5). Seal algorithm is a genesis-fixed `PowAlgo` (see RandomX below) |
| **ASIC resistance — RandomX** | ✅ | **The mainnet seal is Monero's RandomX** (memory-hard, CPU-optimized) via the audited `randomx-rs` reference bindings, keyed by the genesis hash — commodity machines (Apple M-series included) mine fairly and the chain resists ASIC capture at bootstrap. SHA-256d remains a selectable `PowAlgo` for fast dev/test chains; the difficulty/work/fork-choice stack is hash-agnostic. Build dep: cmake + a C++ toolchain (as Monero requires). `randomx_chain_mines_and_verifies_a_real_block` mines + verifies a real RandomX block |
| Probabilistic finality (confirmations) | ✅ | `confirmations()` / `is_final()` = depth in the heaviest-work chain; survives restart by construction (pure function of chain state) |
| **No proof-of-stake of any kind** | ✅ | Stake/Unstake actions, staking emission, stake-weighted committees, and the `sov-staking` crate are DELETED (2026-06-12, user mandate: "Bitcoin and Zcash do not do PoS"). PoW coinbase is the only emission source; the bridge operator committee is one-member-one-vote, not stake-weighted |
| Difficulty retargeting | ✅ | Epoch-based (Bitcoin model), 4× clamp; per-block target now derived from the block's own branch (`expected_targets`) so work is computable on any fork |
| Median-time-past (BIP-113) | ✅ | Enforced on import |
| Non-malleable transaction ids | ✅ | tx id is Blake3 of the signing bytes, signature-independent (the SegWit malleability fix, by construction) |
| Timelocks (CLTV/CSV, BIP-65/68/112) | 🔶 | HTLC height timeouts exist; general per-output relative/absolute locks ⬜ |
| Encrypted P2P (BIP-324) | ✅ | **Exceeds it** — Noise XX + ML-KEM-768 hybrid (post-quantum), not just ChaCha |
| Schnorr / key aggregation (BIP-340) | ⬜ | Evaluate MuSig-style aggregation for multisig compaction |
| Taproot / MAST (BIP-341) | 🔶 | We have a WASM VM (more general than Script); MAST-style spend privacy ⬜ |
| RBF / fee bumping | ⬜ | Replace-by-fee + CPFP for mempool fee markets |
| Compact block relay (BIP-152) | ⬜ | Bandwidth-efficient propagation for the gossip layer |
| Headers-first / assumevalid sync | 🔶 | Have block-by-height catch-up; headers-first + checkpointed assumevalid ⬜ |
| Compact block filters (BIP-157/158) | ⬜ | Light-client privacy-preserving sync |
| Full-RBF mempool policy, package relay | ⬜ | Modern mempool policy |
| Weak-subjectivity checkpoints | ✅ | `checkpoints` gate in import |
| Reproducible / deterministic builds | ✅ | Dockerfile + script, bit-for-bit verified |

## Zcash lineage

| Improvement | Status | Notes |
|---|---|---|
| Shielded pool, zero-knowledge | ✅ | Orchard / Halo2 |
| **No trusted setup** (Halo2/NU5) | ✅ | We start where Zcash *ended up* — no Sprout/Sapling ceremony baggage |
| Unified addresses | ✅ | `usov1…` (privacy-first routing) |
| Shielded coinbase (Heartwood) | 🔶 | **Honest regression (Nakamoto i3):** `MineShielded` is retired (it was a second issuance path against the block coinbase). Today a miner shields its transparent coinbase with a normal `Shielded` action; direct-to-pool coinbase returns as a block-level coinbase *destination* in a later increment |
| Note encryption / diversified addresses | ✅ | Orchard receivers, `sov1…` |
| Viewing / incoming-viewing keys | ⬜ | Audit/compliance disclosure without spend authority |
| ZIP-317-style proportional fees | 🔶 | Per-byte + per-action gas; revisit a shielded-action fee floor |
| Pool turnstile (supply firewall) | ✅ | **Exceeds it** — turnstile *proven* (Thm 5) + de-shield rate limiter (Thm 34) bounding loss even if the circuit breaks; Zcash had a counterfeiting bug this design contains |
| ASIC/rent resistance | ✅ | Achieved with **Monero's RandomX** (memory-hard CPU PoW) rather than Zcash's Equihash — a real, solvable, M-series-friendly seal. Equihash was removed entirely (no solver, GPU-oriented). See the Bitcoin-lineage "ASIC resistance — RandomX" row |

## SOV-native (beyond both)

| Improvement | Status | Notes |
|---|---|---|
| Post-quantum native from genesis | ✅ | Hybrid Ed25519+ML-DSA-65 keys, ML-KEM transport, Q-day sunset governance — neither Bitcoin nor Zcash has this |
| Machine-checked proofs as a product | ✅ | `proofs.md`, 76 sections tied to tests |
| Native assets + per-asset conservation | ✅ | Issuer-bound, USDC-path compliance |
| Composability (VM ABI v2) | ✅ | calldata, events, token bridge |
| Atomic intent settlement | ✅ | On-chain liquidity rails |
| ~~Apple-Silicon compute marketplace~~ | ❌ | **DELETED (2026-06-12, user mandate: superfluous to sovereign money).** With it went the orphaned `sov-confidential` (TEE-executor intents), `sov-sharding` (NEAR Nightshade — contrary to Bitcoin consensus), `sov-accounts` (NEAR access-key abstraction, never wired), and `sov-captable` (never wired). The chain is the money layer, nothing else |
| Named accounts (vs hash addresses) | ✅ | Human-readable transparent tier |

## Open strategic decisions (force these into the open at the testnet-1 freeze)

1. **Mainnet PoW algorithm & 51%-resistance — DECIDED: RandomX.** The mainnet
   seal is **Monero's RandomX** (memory-hard, CPU/M-series-friendly) so a new
   chain isn't trivially captured by rentable SHA-256 ASIC hashpower and
   commodity machines can bootstrap it fairly. The seal is a genesis-fixed
   `PowAlgo` (SHA-256d stays available for fast dev/test chains). Residual open
   item: early-network hashrate is still small — merge-mining with Bitcoin
   remains a *possible* future overlay, but is no longer the primary answer.
2. **Probabilistic vs fast finality.** Pure Nakamoto = confirmations. A later
   optional finality overlay could be reconsidered, but not at the cost of the
   "PoW is the security" story.

## Explicitly out of scope (honest)

- ❌ Trusted-setup ceremonies — Halo2 makes them unnecessary.
- ❌ Hand-rolled crypto of any kind — audited crates only (standing rule).
- ❌ Faked/mocked data anywhere — standing rule.
