# SOV Internal Security Review & Threat Model

**Purpose.** This is the project's *internal* security review and the
audit-readiness package handed to an external auditor (Phase 7 · p7-i9). It is
**not** an external audit — no third party has reviewed SOV yet; engaging an
audit firm is a procurement step, and mainnet is gated on its completion (see
[`/SECURITY.md`](../../SECURITY.md)). This document is one of the *tools* that
makes that audit efficient: it states the assets, threat actors, attack surface,
defenses, and trust assumptions, each cross-referenced to code and tests.

## Assets to protect

1. **The 21M supply cap** and the mining/staking emission budgets.
2. **Finality** — a finalized block is irreversible.
3. **Account funds** — only the controlling key may move balance/stake.
4. **Pooled cross-chain value & custody** (`sov-bridge`, `sov-mpc`).
5. **Deterministic state** — all nodes agree on the same `state_root`.

## Threat actors & defenses

| Actor | Capability | Defense | Evidence |
|---|---|---|---|
| Malicious **user** | submit arbitrary signed txs | auth (Ed25519) → authz (registered key) → nonce → checked execution; failed actions still consume the nonce | `runtime::execution`, `sov-verify` conformance + properties |
| Malicious **miner** | forge PoW / over-mint | solution verified vs. per-miner challenge + target; reward clamped to the mining budget, keyed on mined supply only | `sov-pow`, `sov-mining`, invariant `check_transition` |
| Hostile **miner / 51%** | reorg recent blocks by out-hashing the network | finality is confirmation depth (probabilistic); RandomX makes hashpower commodity-CPU-bound, resisting cheap ASIC capture; deeper confirmations cost exponentially more | `chain::import_block` (heaviest-work fork choice), `chaos` |
| Malicious **peer** | send forged/tampered blocks | every block re-validated (roots re-computed, PoW + difficulty re-checked, signatures re-checked) on import — no trusted path | `chain::import_block`, `fault_injection` |
| **Supply-chain** | tampered binary | reproducible builds + pinned toolchain/container; audited crypto crates only | `scripts/reproducible-build.sh`, `Dockerfile` |

## Trust assumptions (explicit)

- **Honest-majority hashpower** (Nakamoto): an adversary out-hashing the honest
  network can reorg recent blocks; finality is confirmation depth, probabilistic.
  The mainnet seal is RandomX (memory-hard) so commodity CPUs compete and the
  chain resists ASIC capture. There is no stake, committee, or BFT quorum.
- Cryptographic primitives are correct as provided by their **audited upstream
  crates** (ed25519-dalek, blake3, sha2, randomx-rs (RandomX reference), fips204
  (ML-DSA), fips203 (ML-KEM), chacha20poly1305, wasmi); SOV composes, never
  re-implements, them.

## Known limitations (honest, in-scope for audit)

- Several subsystems (`sov-sharding`, `sov-accounts`, `sov-compliance`,
  `sov-mpc` custody, `sov-compute`, `sov-governance`) are complete, tested
  units **not yet wired into the live single-ledger runtime** — that integration
  is Phase 8.
- Live P2P/daemon hardening (DoS, eclipse, sync) is **Phase 8**; today's network
  is in-memory + loopback.
- No hardware-rooted remote attestation (no SGX/TDX on the target hardware).

## Audit-readiness checklist

- [x] Normative state-transition specification — [`state-transition.md`](state-transition.md)
- [x] Protocol invariants, machine-checked — `sov-verify::invariants`
- [x] Consensus safety/liveness model check — `sov-verify` `consensus_model`
- [x] Deterministic replay & cross-node agreement — `sov-verify` `replay`
- [x] Known-answer test vectors (crypto/serialization) — `sov-verify` `kat`
- [x] Property-based tests + fuzz targets — `sov-verify` `properties`, `chain/fuzz/`
- [x] Adversarial/fault-injection suite — `sov-verify` `fault_injection`
- [x] Reproducible builds + pinned environment — `scripts/reproducible-build.sh`, `Dockerfile`
- [x] Disclosure policy + bug-bounty program — [`/SECURITY.md`](../../SECURITY.md)
- [ ] **External third-party audit** — *pending engagement (not faked)*
- [ ] **Live bug bounty** — *opens with the public testnet*
