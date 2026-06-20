# SOV Quantum Posture — What Is Protected, What Is Not

**Status: normative disclosure. Last verified against the working tree
2026-06-16 — post-Nakamoto (consensus is pure proof-of-work: no validators, no
BFT votes) and post-rebrand (ticker XUS).** This document states the chain's security
posture against a cryptographically relevant quantum computer (CRQC) in
plain language, including the one exposure that **no future code change can
fix**. Every claim below maps to a theorem in [`proofs.md`](proofs.md) and a
passing test.

## Protected today

| Surface | Mechanism | Proof |
|---|---|---|
| **Money / account ownership** | Hybrid Ed25519+ML-DSA-65 keys (FIPS 204); forging requires breaking BOTH schemes. Genesis is PQ-native by default — every key `sov-testnet gen` mints is hybrid. | Theorems 30, 30.1; Remark 33.1 |
| **Consensus / mining** | Pure Nakamoto proof-of-work: a block is authorized by hashpower, not signatures, so consensus is scheme-agnostic — a miner's coinbase account is hybrid-keyed with no consensus change. (The PoW hash itself is hash-secure; see the hashing row.) | Corollary 30.1; A1 |
| **Legacy stragglers** | The miner-signaled `pq-sunset` (BIP-8, miners cannot veto): threshold accounts forced to rotate, then all legacy keys frozen — a forged Ed25519 signature authorizes nothing after the sunset. | Theorems 32–33 |
| **P2P transport privacy** | Hybrid X25519 + ML-KEM-768 (FIPS 203) channel; recorded traffic requires breaking both. No harvest-now-decrypt-later for the wire. | Theorem 31 |
| **All hashing** (state roots, tx ids, PoW, HTLC locks) | Blake3/SHA-256 — Grover only halves security margins; no break. | Standing assumption A1 |
| **Supply, even if the zk proof system fails** | The turnstile: a forged shielded proof cannot mint SOV (conservation catches it), and the drain limiter caps pool outflow at `deshield_limit_grains` per `deshield_window_blocks` (mainnet-like preset: 21,000 XUS per ~day) — slow enough for governance to respond. | Theorems 5, 34 |

## NOT protected — stated plainly

**Shielded-pool privacy is harvest-now-decrypt-later exposed.** The Orchard
shielded pool's note encryption and its Halo2 proof system rest on
elliptic-curve assumptions (Pallas) that a CRQC breaks. Consequences:

1. **Recorded chain data is forever.** Every shielded transaction ever
   committed to the chain is public ciphertext. An adversary who archives the
   chain today and obtains a CRQC later can decrypt **amounts, recipients,
   and linkages of past shielded activity**. No future upgrade, migration, or
   code change can retroactively re-encrypt data that is already public.
   If your threat model includes a future quantum adversary, treat shielded
   privacy as **time-limited**, with a horizon equal to the arrival of a
   CRQC.
2. **What this does NOT threaten:** funds. The supply turnstile (Theorem 5)
   and the drain limiter (Theorem 34) hold regardless of the proof system's
   soundness — a quantum adversary could deanonymize past activity and at
   worst steal *within* the pool at a bounded rate, but can never inflate
   SOV or touch transparent balances.

**The long-term fix is a hash-based (STARK-class) shielded pool** — both
post-quantum sound and post-quantum private. This is a research track:
no production-audited construction with Orchard's maturity exists today, and
this project does not ship imitations of one. Until it exists, the honest
guidance for users is above.

## Implementation caveats (also honest)

- The PQ implementations (`fips203`, `fips204`) are pure-Rust and NIST
  ACVP-vector-tested, but do **not** yet have the audit depth of
  `ed25519-dalek`. This is exactly why every PQ use is a **hybrid
  conjunction** — the classical, audited scheme must also pass. The chain
  never trusts lattice cryptography alone.
- Transport *authentication* (as opposed to privacy) is post-quantum only
  for peers whose identity keys are hybrid — the generated default, but an
  operator who hand-configures a legacy key keeps classical-only
  authentication (Remark 31.1).
- An external third-party audit of the whole stack, including the PQ
  integration, remains open (tracked as the standing audit item) and is a
  launch prerequisite. Nothing in this document substitutes for it.
