# sov-redteam

A **standalone adversarial harness** for the SOV chain. It builds a real in-process
chain — the actual consensus code (`produce_block` / `import_block`), the same path a
node runs — and throws a battery of theoretical attacks at it, then reports which
**defenses held**. This is *not* the unit-test suite; it's a red team you run on demand.

```
cargo run -p sov-redteam
```

Each attack is judged **DEFENDED** (the chain rejected it or resolved it correctly) or
**VULNERABLE** (the attack succeeded — a real finding). The process exits non-zero if
anything is vulnerable, so CI or a release gate can consume it.

## What it attacks

| Category | Attack | Defense under test |
|---|---|---|
| **time** | timewarp: backdate to median-time-past | BIP-113 MTP rule vs. difficulty gaming |
| **time** | pre-genesis timestamp | lower timestamp bound |
| **tamper** | state_root / tx_root / timestamp / nonce / bits / prev_hash | the PoW seal binds every header field |
| **supply** | coinbase redirect (steal the reward) | seal covers `proposer` |
| **forgery** | corrupted transaction signature | signatures fail closed |
| **post-quantum** | valid Ed25519 half + broken ML-DSA half | **hybrid conjunction** — a future Ed25519 break alone can't forge |
| **replay** | import the same block twice | no double-advance / double-credit |
| **consensus** | equal-work fork, both arrival orders | deterministic tie-break (no permanent fork with thin hashpower) |

## Honest scope

We cannot run Shor's or Grover's algorithm, and we cannot forge a BLAKE3 collision —
no one can. What this proves is that the chain **fails closed**: every forgery a
classical attacker can produce is rejected, the seal binds the whole header, and the
hybrid signature needs **both** halves — so even a future break of Ed25519 alone leaves
ML-DSA-65 (FIPS-204) stopping the forgery.

New attacks are one function returning an `Outcome`; add it to the `outcomes` vec in
`main.rs`.
