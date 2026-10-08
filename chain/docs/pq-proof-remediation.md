# Current v2 proof confidentiality and quantum soundness

The current pool-v2 proof suite must not create new private notes or spending
proofs. Its prover uses Winterfell's default unmasked trace LDE. Private values
and key limbs occupy constant trace segments; padding is deterministic.
Publishing polynomial evaluations of such columns does not establish zero
knowledge. This is a concrete confidentiality gap separate from quantum
soundness. Winterfell's [official planned-features documentation](https://github.com/facebook/winterfell#planned-features)
also states that the library does not provide perfect zero knowledge.

Containment is implemented in the Rust client: all v2 proof creation and
broadcast is refused, RPC/gossip reject new v2 carriers recursively, and the
PQ migration consensus rule freezes this proof suite at R. Historical v2
verification remains available for pre-fork replay. These restrictions do not
repair existing proofs or restore already exposed information.

A working replacement needs a versioned proof suite and reviewed randomized
masking or a backend with established zero knowledge. The analysis must cover
trace commitments, queried openings, out-of-domain evaluations, auxiliary
traces, boundary assertions, degree bounds, and composition/FRI checks.
Randomizing padding alone is insufficient without proving that all public
evaluations hide the witness and that the new constraints remain sound.

Quantum-random-oracle results for FRI and related Fiat-Shamir constructions
[exist](https://eprint.iacr.org/2023/1071). They must be mapped to this exact
Winterfell transcript, DEEP/batching construction, random coin, grinding, field,
hash suite, and query parameters. The current classical estimate is not a
quantified quantum estimate. Increasing queries or a hash's XOF output alone
cannot establish the missing guarantee; the 256-bit Rescue-Prime commitments
and cubic Goldilocks extension impose additional margins.

For a conservative 128-bit generic quantum collision target, the replacement
also needs a reviewed construction with at least 384-bit commitments and
appropriately sized fields and transcript challenges. Larger output changes
proofs, note/nullifier/anchor encodings, and consensus roots, so it belongs in
the new suite rather than an unversioned replacement of the current verifier.

Before production activation: publish the confidentiality and quantum
soundness analysis, independent circuit/backend review, standard vectors,
cross-platform encodings, old-history replay, downgrade refusal, and migration
tests. Ordinary build and regression success cannot replace this evidence.
