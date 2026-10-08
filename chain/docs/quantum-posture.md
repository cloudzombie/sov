# SOV Quantum Posture — Current Protection and Remaining Gaps

**Working-tree assessment: 2026-10-08.** SOV Station is the native Rust client
in `node/`; it runs the Rust node and transport in process. This assessment
describes code, not a remote node's current height or activation state. Mainnet
is live; an independent audit of the integrated stack remains outstanding.
Tests verify implementation behavior, not resistance to unknown attacks.

Post-quantum cryptography runs on ordinary computers. It does not put hashes,
a wallet, or a blockchain into a physical quantum state. The threat here is a
quantum computer that breaks conventional elliptic-curve cryptography,
including ECDSA, Ed25519, X25519, and Orchard's curve assumptions. If every
public-key primitive, including ML-DSA and ML-KEM, is broken, these mechanisms
cannot guarantee survival either.

## Current Rust protection

| Surface | Implementation | Qualification |
|---|---|---|
| Station account keys | New generation, normal mnemonic/seed restoration, and signing use hybrid Ed25519 + ML-DSA-65. Account IDs commit to the full hybrid key. | Both signatures must verify. If Ed25519 is forgeable, ownership still depends on ML-DSA and hash/seed assumptions. Scheme-aware legacy seeded imports preserve the original account and encrypted recovery material. Ordinary signing/mining stays disabled; the explicit migration flow authorizes only rotation to a hybrid key before sunset. |
| Peer traffic | Noise/X25519 plus an inner ML-KEM-768/ChaCha20-Poly1305 layer; no classical-only fallback. | Passive recordings remain protected while either encryption layer holds. Authentication needs the combined transcript binding and a hybrid identity. |
| Peer authentication | Protocol-v3 signed Hello binds chain, genesis, claimed account, Noise transcript, and exact ML-KEM encapsulation key/ciphertext. | Corrected locally in this change. Old binaries sign only the Noise binding and cannot authenticate with corrected peers. A coordinated rollout is required. Mainnet and the PQ rehearsal namespace now refuse classical-only peer identities; legacy development networks retain compatibility. |
| Legacy-key retirement | The runtime can retire legacy transaction, intent-owner, and multisig authority under a resolved `PqSchedule`. | **Not scheduled in the baked mainnet preset.** Default hybrid generation does not protect legacy balances. |
| Supply | Transparent/shielded turnstiles and conservation constrain net issuance; drain limits constrain withdrawals. | Accounting defenses do not prove ownership, privacy, or proof soundness, and do not prevent theft within a pool. |

NIST standardizes ML-DSA in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
and ML-KEM in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). These are
public-key algorithms with assumptions different from elliptic-curve discrete
logarithms. Standardization is not an audit of SOV's composition or libraries.

### Legacy migration is still required

The chain starts with `pq_deployment: None`; the daemon's mainnet preset arms
transaction domains, fee auctions, shielded v2, and transaction timestamps,
but does not call `set_pq_deployment`. Legacy Ed25519 authorization remains
admissible under that schedule. Arming the sunset needs a coordinated,
history-preserving upgrade and a published rotation window and recovery policy.

After sunset, no legacy signature may authorize an action, including one
nested in a hybrid transaction. During rotation, the protected account's
native holdings govern the restriction; a relayer's balance cannot bypass it.
Multisig vaults must replace their policy before old approvals cease to count.
A signature-only rotation after classical key recovery becomes practical
cannot distinguish the owner from an attacker: migration must happen earlier.
The current threshold measures native liquid plus vesting balances; it does
not value tokens or other collateral.

## Hashing and mining

Canonical identifiers and Merkle/state commitments use **BLAKE3-256**. HTLCs
use **SHA-256** for external-chain interoperability. Mainnet proof-of-work is
**RandomX**, using BLAKE2b internally and a 256-bit final digest; development
chains can use SHA-256d.

For an ideal 256-bit digest, generic quantum preimage search takes approximately
`2^128` oracle queries. Ideal quantum collision search can take approximately
`2^(256/3)` (about `2^85`), subject to substantial memory and implementation
requirements. These are asymptotic query estimates, not a practical break or a
measured level for every construction. A 256-bit hash therefore does not
justify blanket claims of 128-bit quantum security for every use. See the
original [quantum search](https://arxiv.org/abs/quant-ph/9605034) and
[quantum collision](https://arxiv.org/abs/quant-ph/9705002) papers.

A conservative 128-bit generic quantum **collision** target needs a reviewed
construction with at least 384-bit output, such as SHA3-384/512, and analysis
of its composition. Longer BLAKE3 XOF output does not strengthen its internals
([BLAKE3 security notes](https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md#security-notes)).
Changing current hashes changes roots, IDs, and address bindings: it requires
a versioned consensus migration, not a constant swap.

Quantum amplitude amplification can accelerate PoW target search in principle.
RandomX memory hardness does not prove immunity. Coherent implementation costs
and effects on mining economics remain unquantified. Difficulty adjustment
alone does not prevent disproportionate effective work. Nakamoto consensus
still requires an honest majority of effective mining capacity.

## Shielded pools

**Pool v1 (Orchard/Halo2) uses elliptic curves.** A sufficiently capable quantum
adversary threatens its privacy, proof, and authorization assumptions. Recorded
ciphertext cannot be retroactively protected. Drain limits bound withdrawals;
they cannot make the remaining notes safe.

The corrected v1 verifier checks the Halo2 proof, every RedPallas spend
authorization, and the binding signature. The migration-window digest binds
chain ID, genesis, transparent receiving account, transaction nonce, and
Orchard's effects commitment. Modified recipients, nonces, domains, signatures,
and public value balances are rejected. After R the runtime requires this
bound authorization and prohibits new v1 deposits; at S it freezes every v1
carrier. Explicit proof-only legacy APIs reproduce pre-R history. These
consensus rules are armed on the fresh PQ rehearsal chain, **not mainnet**.
Station blocks new v1 deposits and private transfers, and permits withdrawal
only when the connected node reports an active bound recovery window.

**Pool v2 uses PQ-oriented primitives:** ML-KEM-768 note encryption, ML-DSA-65
spend authorization, and STARK/FRI over Rescue-Prime and BLAKE3. Its deployment
is **armed in the baked mainnet preset as of 0.2.5**; actual activation depends
on committed miner signals. Universally describing it as dormant is stale.
Activation is not audit evidence. New v2 carriers are now refused by RPC and
peer gossip; Station refuses all v2 proof creation and broadcast. The PQ
migration fork also freezes the current v2 suite from R onward. Existing
pre-fork block verification remains available for replay.

The current prover uses an unmasked default Winterfell trace. Constant secret
columns plus deterministic padding do not establish zero knowledge; published
trace evaluations can reveal private inputs. This is an implementation
confidentiality defect, independently of quantum attacks. Winterfell itself
[documents the absence of perfect zero knowledge](https://github.com/facebook/winterfell#planned-features).
The operational gates contain this defect; they do **not** repair the prover
or restore privacy to previously published proofs. See
[pq-proof-remediation.md](pq-proof-remediation.md).

Its proof parameters have classical soundness analysis, not a quantified
quantum-random-oracle-model (QROM) soundness level. The external circuit audit
and QROM analysis remain pending, as disclosed in the daemon's arming preset
and [audit scope](../../notes/audit-scope-pq-pool.md#9-post-quantum-qrom-soundness-of-the-proof--pqv2-05).
“Uses post-quantum primitives” is justified; “proven 128-bit post-quantum
shielded security” is not. The implementation stays quarantined until a reviewed replacement proves
both confidentiality and the intended quantum soundness target.

## Completing the migration

[quantum-migration.md](quantum-migration.md) records the remaining upgrade work
and verification gates. Existing history, genesis, hashes, and activation
schedules must stay reproducible. The [rehearsal](pq-rehearsal.md) exercises a working rotation/sunset and
cold replay. Client fixes do not arm a mainnet sunset or complete the pending
proof audit.
