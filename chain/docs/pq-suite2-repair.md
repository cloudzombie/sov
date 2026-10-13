# Pool-v2 hiding-proof and wallet repair (0.2.16)

Existing mainnet note commitments, Merkle positions, nullifiers, addresses,
ledger values and historical proof verification remain unchanged. No reset,
replacement genesis, supply adjustment or reclassification of old balances is
part of this upgrade.

## Replacement proof

The default Rust Station/RPC `zk-suite2` feature pins Plonky3 0.8.0's hiding
uni-STARK path. It masks trace and quotient polynomials, uses salted hiding
Merkle commitments and enforces opening budgets. Profile 2 uses Keccak-384
commitments/transcript, degree-five Goldilocks extension, 96 FRI queries,
blowup 16 and no grinding security credit. The proof has 802 trace columns.

The statement binds the actual chain ID, genesis hash, signer/payout account,
nonce and bundle ML-DSA authorization key. It also proves the original 32-byte
BLAKE3 spending-seed preimage of each input's historical NSK. Possessing the NSK
exposed by an old unmasked spend is therefore insufficient for a new spend.
Owners retain their original seed, old commitments and spend witnesses.
Independent receiving-key derivation provides fresh change/receive addresses;
the wallet scans both old and fresh keys against the same authenticated tip.

Wire version 2 has its own exact parameter ID, bounded canonical decoder and
verifier. It never falls back to version 1. The proof cap is 2 MiB, the action
cap is 2 MiB plus 16 KiB, and the transaction weight cap is 2,304 KiB.
Verification work is separately charged. The activated branch's minimum block
byte budget is 2,560 KiB; the existing 4 MiB block ceiling is unchanged.
Admission keeps the ready and queued mempool under a combined 64 MiB weight
budget, with queued entries limited to 16 MiB, including replacements.

## Mainnet rollout

Bit 2 already activated the existing pool. Version 0.2.16 additionally schedules
`shielded-v2-suite2` on bit 5, using 288-block windows and a 90% readiness
threshold. Signaling starts at **27,648**; earliest lock-in is **27,936** and
earliest activation is **28,224**. Timeout is **28,512**, without forced lock-in.
The canonical Oracle head was independently checked at 27,393 before choosing
this future schedule. Operators must upgrade miners and relays to the same
release before its readiness window. Until activation, Station preserves and
scans existing funds while refusing unsafe old proof creation. After activation,
new deposits, private sends and withdrawals use profile 2; old proof creation
and new version-1 spends remain refused. Historical blocks still replay under
the rules that applied at their own heights.

The Oracle peer endpoint is **158.101.18.90:9645**. Protocol 3 authenticates the
full Noise/ML-KEM transcript and the peer's claimed label. Node identity is
key-derived, so a claimed named account cannot impersonate another relay.
Protocol-2 clients (including 0.2.14) require a coordinated upgrade; there is no
unauthenticated downgrade. The upgraded release embeds the Oracle seed.

## Wallet and verification

The Rust wallet combines old and fresh notes in one four-input proof, derives
MAX from the four largest available inputs, and refuses stale or mismatched
scan tips. Gross withdrawal pays its actual network fee from the same verified
payout, so recovery to a fresh hybrid account requires no transparent prefund.
All fees remain accounted for, with pool debit, recipient net credit and miner
fee checked through real execution and cold replay.

Original encrypted wallets and miner keys are retained. Mainnet reset is
unavailable; sandbox reset archives prior data. Selecting a future mining payout
preserves history and backs up the prior encrypted miner key. Existing specs and
configured peers survive startup. Unknown submission delivery is tracked by
its locally computed transaction ID, including a durable public-identifier
journal written before network submission; private amounts, recipients and
secrets are not journaled.

Verification includes real mixed-key proofs, adversarial seed-witness proofs,
carrier/redirection rejection, restore/scan/send/withdraw over real loopback RPC,
fee and supply conservation, replay/nullifier rejection, and a panic-abort
hostile-frame verifier corpus. Native mining and Node tabs display measured
activity. Native `diagnostics` and daemon `--verify-history` commands provide
bounded, read-only machine-readable evidence without loading wallet keys.

```sh
cargo test --release --locked --manifest-path chain/Cargo.toml -p sov-shielded-pq --features zk-suite2
cargo test --release --locked --manifest-path chain/Cargo.toml -p sov-rpc --test suite2_recovery --test suite2_fee_funding
cargo test --release --locked --manifest-path node/Cargo.toml
cargo run --release --locked --manifest-path chain/Cargo.toml -p sov-shielded-pq --features zk-suite2 --example verify_hostile_frames
sov-rpcd --verify-history chain-spec.json blocks.log
sov-station diagnostics 127.0.0.1:8645
```

## Security limits

Tests and code review do not establish an independent cryptographic audit or an
exact-profile QROM security bound. Wider proof hashes do not upgrade the existing
256-bit note/tree hashes or canonical chain hashes; changing those encodings
requires another versioned migration. Seed-preimage recovery assumes original
seeds stayed secret. It cannot restore value already spent by an attacker.
The separate legacy-authorization/pool-v1 retirement deployment (bit 4) remains
unarmed on mainnet. This release does not claim that every historical key/hash
assumption has been migrated or that any blockchain is immune to every attack.
