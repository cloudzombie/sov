# Rust post-quantum activation rehearsal

The reserved `sov-pq-rehearsal-` namespace selects a separate fresh genesis and
the production governance/runtime code. Canonical mainnet and testnet genesis
and earlier deployment schedules remain unchanged.

| Rule | Rehearsal configuration |
|---|---|
| Transaction domains, bit 0 | Start 8, timeout 16, period 8, threshold 9/10, LOT on, minimum activation 24, no grace |
| PQ sunset, bit 4 | Start 32, timeout 40, period 8, threshold 9/10, LOT on, minimum activation R=48 |
| Legacy threshold | Zero native grains, so every legacy account must migrate |
| Final sunset | S=R+16=64 |
| Pool v1 | No deposits at R; bound withdrawals/private actions during R..S; completely frozen at S |
| Pool v2 | Unarmed; current unmasked proof suite also frozen by the PQ rule at R |
| Peer identities | Hybrid Ed25519 + ML-DSA-65 required |

Generate isolated node configuration from the `chain` directory:

```sh
cargo run --offline --locked -p sov-rpc --bin sov-testnet -- gen --pq-rehearsal yes --out ../.tmp/pq-rehearsal --miners 2 --policy test --block-time-ms 1000
```

The generator refuses a canonical chain ID or a rehearsal ID containing
`mainnet`; using the reserved namespace requires the explicit flag. Generated
keystores contain test secrets and belong only in this disposable directory.
The generator does not start miners or change an existing network.

`sov_getQuantumStatus` and the `quantumPolicy` field of `sov_getDeployments`
report the rules for the **next includable block**, including actual R/S once
activation resolves. Missing policy is unavailable, never evidence of safety.
The proof-security/privacy flags remain false in this build.

The daemon regression `pq_rehearsal_executes_rotation_sunset_and_cold_replay`
produces/imports 66 real blocks, accepts an ordinary legacy transfer before R,
rejects it at R, rotates the original account, accepts hybrid activity at S,
and cold-replays to the same head, state root, and status. Governance tests
also cover all-signaling and no-signaling histories. Runtime tests cover
unrotated authority, intent and vault secondary signatures, pool retirement,
and recipient-bound recovery.

Mainnet retirement still needs a published future schedule and an operator
rollout. The rehearsal cannot protect unrotated mainnet balances by itself.
