# Rust SOV Station: Post-Quantum Migration Requirements

**Assessment: 2026-10-08.** Goal: preserve ownership, authenticated transport,
and chain validity if conventional elliptic-curve cryptography fails, with
explicit quantum hash-search margins. This specifies upgrade work; it is not
an activation schedule or security proof. See [current posture](quantum-posture.md) and the working
[fresh-chain rehearsal](pq-rehearsal.md).

## Immediate client hardening

- Preserve Station hybrid generation/restoration and full-key account binding.
  Test that a valid classical signature alone cannot satisfy hybrid ownership.
- Bind Hello to the complete Noise + ML-KEM public transcript; reject either
  substituted KEM message. Never retry with the old Noise-only binding.
  Coordinate seed/miner/client rollout because old peers cannot authenticate
  with corrected peers.
- Under the resolved sunset schedule, retire secondary authorization:
  intent makers, off-chain and cached multisig approvals, replacement keys,
  and replacement policies. Use protected-account holdings for rotation rules.
- Distinguish hybrid account protection, v1 exposure, and v2's pending proof
  analysis in Station. Activation or a badge cannot stand in for an audit.

## Legacy-key retirement

The baked mainnet preset has no `pq-sunset`. Publish a consensus proposal with
a fresh signal bit, future start/timeout/minimum-activation heights,
period/threshold, lock-in rule, rotation delay, and native-balance threshold.
Do not derive heights from guessed chain progress or alter prior schedules.

Inventory single-key accounts, multisig vaults, cached proposals, outstanding
intents, contract/token administrator authority, and peer identities. Provide
Station migration workflows proving the new key and replacing vault policies.
Define lost/inactive-account treatment. Migration must precede compromise:
after classical signature forgery is practical, an old signature cannot
identify the legitimate owner.

Station now respects each keystore's signing `scheme`. Missing or explicit
`ed25519` seeded entries restore their original legacy identity with encrypted
seed/phrase retained. Unsupported entries are retained for encrypted re-export.
The migration review saves the hybrid wallet before sending an old-key-signed
`RotateKey` with proof from the new hybrid key. It verifies the selected network
and frozen genesis, original ownership, and pre-sunset migration availability.
Rotation preserves the original account ID and funds; the replacement wallet
can attach to that watched account when its hybrid key is confirmed on chain.

Verify mining, mempool admission, import, log replay, and reorgs across exact
rotation/sunset boundaries. Cover hybrid relayers with classical secondary
signatures, cached proposals, downgrade attempts, and valid hybrid activity.
All supported Rust platforms must reproduce identical roots. Existing
`Account::total()` thresholds include native liquid and vesting funds, not
token valuation; changing that requires a separately specified policy.

## Shielded authorization and retirement

Complete Orchard authorization and recipient-bound migration builders are
implemented. The new non-circular digest includes the Orchard effects
commitment, chain identity, receiving account, and carrier nonce. The runtime
requires it at R, closes v1 deposits at R, and freezes v1 at S, recursively
through carriers. Historical proof-only behavior is explicit before R.
Regression tests cover real notes/proofs, signature/value-balance mutations,
recipient/nonce/domain changes, failed receipt semantics, and historical replay.
Independent integration review is still required before mainnet activation.

The unmasked Winterfell v2 suite is quarantined: Station creates/broadcasts no
v2 proofs, RPC and gossip admit no new v2 carriers, and the new PQ fork freezes
it at R. Preserve already activated pre-fork block verification. A replacement
must use a new proof-version/suite and a coordinated activation; see
[pq-proof-remediation.md](pq-proof-remediation.md).

Complete the [external circuit audit and QROM analysis](../../notes/audit-scope-pq-pool.md#9-post-quantum-qrom-soundness-of-the-proof--pqv2-05).
Reconcile Rescue-Prime/STARK hash margins, Fiat-Shamir security, FRI parameters,
grinding, multi-target effects, and note-encryption composition into a written
quantum security level. Version parameter changes if the target is unmet.
Regression tests cannot supply this proof.

## Versioned hashing and mining

Specify preimage, second-preimage, collision, and mining targets separately.
For at least 128 bits against ideal generic quantum collision search, evaluate
a reviewed construction with at least 384-bit output, such as SHA3-384/512.
Longer BLAKE3 XOF output does not strengthen its internals.

Specify a consensus-committed suite identifier, fixed encodings,
domain-separated preimages, and activation. Retain old-suite historical
verification and existing references. Cover IDs, roots, account bindings,
contract/asset IDs, genesis references, nullifiers, snapshots, proofs, RPC and
offline-wallet formats. Address migration needs an ownership mapping; a new
hash cannot invalidate recoverable funds or silently redirect them.

Keep existing SHA-256 HTLCs redeemable. New lock suites must be tagged and
external-chain compatible; local cryptography does not upgrade Bitcoin/Zcash
counterparty ownership. A 128-bit ideal quantum preimage target needs at least
256 bits of secret entropy.

Assess coherent RandomX implementation costs and effective-work concentration
before claiming mining resilience. Replacement PoW needs miner/validator
agreement, target/work accounting, coordinated activation, and fork-choice
tests across the boundary. A longer digest does not remove quantum search.

## Algorithm agility and evidence

ML-DSA and ML-KEM remain public-key algorithms with their own assumptions. If
lattice failure is also in scope, evaluate an independent PQ signature such as
hash-based [SLH-DSA (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final) in a
conjunction scheme with explicit tags. Assess signature size, bandwidth,
verification cost, and gas before proposing it. No finite suite guarantees
survival if all constituent assumptions are broken.

Release evidence must include independent standard vectors, cross-client
encoding parity, signature-half/downgrade rejection, transcript substitution,
old/new peer compatibility, activation boundaries, old-history replay,
end-to-end Station flows, and independent PQ/proof audits. Publish passed
and pending gates; use the network's coordinated release process.
