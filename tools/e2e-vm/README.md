# sov-e2e-vm — Live multi-node release harness

One command stands up a **real, isolated, multi-node SOV blockchain** — real
release `sov-rpcd` binaries, real P2P over TCP, real proof-of-work, real fees
and emission (`mainnet_like` policy, sha256d seal) — drives it through the W8
lifecycle matrix, asserts every step, tears everything down deterministically,
and emits a machine-readable JSON report plus a human summary.

**Release gate: exit 0 only if no step failed or skipped.** The release workflow
passes `--require-complete`; an aborted dependency is a reported skip and fails
the gate. The current matrix contains live checks for every step.

```
cargo run --release --manifest-path tools/e2e-vm/Cargo.toml -- run \
    [--backend local|ssh|container] [--ssh-config hosts.json] [--require-complete] \
    [--bins DIR] [--run-dir DIR] [--report FILE] \
    [--base-rpc 18645] [--base-p2p 19645] [--keep]
```

If `chain/target/release/sov-rpcd` / `sov-wallet` are missing, the harness
builds them (`cargo build --release -p sov-rpc`). It never uses `cargo run` for
nodes — the deployed bits are the tested bits.

## Isolation (hard guarantees, all asserted)

* Fresh chain id `sov-e2e-v020-s8a` with its **own genesis hash**, pinned in
  `src/net.rs` (`EXPECTED_GENESIS_HASH`) and re-verified by the node itself via
  the spec's `expected_genesis_hash`. The matrix **asserts** it differs from the
  frozen mainnet (`cb0272ff…`) and testnet-1 hashes — SOV peers handshake on
  `chain_id` + genesis hash, so no mainnet node would ever talk to this network
  even if it could reach it.
* Local backend binds **loopback only** (RPC and P2P), no baked seeds in the
  spec, no mainnet endpoint anywhere in this tool.
* All parameters and signing seeds are **pinned**, so runs are reproducible;
  the seeds are throwaway constants that never control real value.
* Do not run two harnesses concurrently on one machine with the same ports;
  same-chain LAN discovery could bridge them (they are the *same* pinned chain).

## Topology and matrix

5 nodes: `node-1..3` mine (`val01..val03.e2e.sov`), `node-4` is the observer
(all wallet traffic and the restart victim), `node-5` is the late joiner.

| # | step | status today |
|---|------|--------------|
| 1 | genesis determinism across nodes, differs from mainnet/testnet pins, matches harness pin | live |
| 2 | P2P authenticated mesh, convergence, late-join synchronization | live |
| 3 | mining: 10 more blocks, at least 3 coinbase producers, tip agreement | live |
| 4 | pool-v2 quarantine while bit 2 is inactive: direct, tipped, timestamped, multisig-exec, deferred proposal and nested proposal RPC probes; exact privacy-policy rejection and unchanged accounts/pools/proposals/ready-and-queued mempool | live |
| 5 | shielded-v1 recovery across tx-domain activation: real pre-fork note, real BIP-9 activation, snapshot-deleted cold boot, post-fork withdrawal | live |
| 6 | independently recount raw miner signaling and verify 9/10 BIP-9 threshold/activation boundary | live |
| 7 | real CLI pool-v1 lifecycle: shield 5, scan, withdraw 2, private send 1, with grain-exact pool/balance/fee deltas | live |
| 8 | restart/replay survival: delete snapshot, reproduce pinned head/hash/state root from blocks.log, reconverge | live |
| 9 | cross-node block/hash/state-root and aligned supply conformance | live |
| 10 | pool-v1 note created before bit-2 activation remains spendable after activation; pool-v2 value stays zero | live |
| 11 | direct v2 RPC quarantine with bit 2 active, no state changes | live |
| 12 | tipped/timestamped/multisig-exec v2 quarantine with bit 2 active, no state changes | live |
| 13 | direct/nested deferred v2 proposal quarantine with bit 2 active, no nonce/fee/proposal/state changes | live |
| 14 | every node rejects every v2 carrier and reports privacy/security/creation flags false; real pool/anchor/nullifier/read-wallet agreement | live |
| 15 | snapshot-deleted cold replay reproduces pinned block/state root and quarantine state, then refuses every v2 carrier again | live |

v0.2.15 quarantines the current unmasked pool-v2 prover because it exposes
private inputs. Bit-2 activation remains a real BIP-9 rehearsal, while new
transaction admission stays closed. The probes deliberately use structurally
valid JSON transactions with a zero signature and empty bundle: they require
the **specific privacy-policy error before signature/proof verification**, so
an invalid-signature, malformed-input, dormancy, or transport failure cannot
make the release gate pass. No probe generates an unsafe private-input proof.
The test reads exact account, pool, proposal and ready/queued mempool snapshots
before and after every rejection; height and miner emission may advance during
these read calls and are not treated as rejected-transaction mutations.

Historical nonempty-v2 verifier, ledger disconnect/reorg and replay fixtures
remain tested in `sov-shielded-pq`, `sov-state`, `sov-runtime` and `sov-chain`.
The live harness cannot claim a new safe v2 send or migration until a reviewed
replacement suite is implemented. Pool-v1 flows here use the existing
unarmed-PQ-retirement rehearsal chain; they do not claim that Station permits
new pool-v1 deposits on mainnet. Mainnet PQ retirement remains unarmed.

### The activation the harness drives

`baked_deployments()` in `chain/crates/rpc/src/daemon.rs` now has a second arm
next to the frozen mainnet preset: a chain id in the **reserved `sov-e2e-`
namespace** (this harness's own) gets a rehearsal preset: `tx-domain` on bit 0,
period 32, start 384, threshold 9/10, LOT off, grace `G = 0`; `shielded-v2` on
bit 2 starts at 512. The miner signal mask is `0b101`. With full signaling,
`tx-domain` locks in at 416 and activates at 448; bit 2 locks in at 544 and
activates at 576. The state machine and threshold arithmetic are shared with
mainnet. The PQ sunset deployment is absent in this namespace; its dedicated
66-block rehearsal and replay tests exercise migration/retirement separately.

The mainnet arm is evaluated **first and unconditionally**, so the frozen mainnet
preset can never be displaced; `sov-mainnet`, `sov-testnet-1`, `sov-test` and
`sov-dev` are all unaffected (asserted by
`e2e_rehearsal_namespace_arms_a_real_bit0_deployment_and_never_shadows_mainnet`
in `daemon.rs`). Being a *baked* preset keyed on the chain id, it is identical on
every node by construction — no per-node divergence is expressible.

`G = 0` is deliberate: from the activation height, transactions are `Bound`-only
(chain-bound signatures, legacy rejected). The pre-activation note is therefore
spent under the strictest possible post-fork regime, which is exactly the claim
law F8 makes.

A hard FAIL aborts the dependent steps that follow (recorded as skips naming
the failed dependency) and the run exits non-zero after full teardown.

## Backends

The matrix only ever talks to node RPC endpoints; **where** nodes run is a
swappable backend:

* **`local`** (default, zero-dependency): each node is a separate `sov-rpcd`
  **process** on loopback with its own data dir and ports. This is the backend
  the in-repo proof runs use.
* **`ssh`**: same interface against real VMs. `--ssh-config hosts.json` lists
  hosts (see `ssh-hosts.example.json`); `node-K` is placed on the K-th host,
  the binary is `scp`'d once per host, nodes run under `nohup` with a pidfile.
  Node configs written for this backend must carry host-valid addresses —
  treat the first ssh run as bring-up (it cannot be exercised on a machine
  without VMs, which is why the proof runs use `local`).
* **`container`**: documented stub (`container_backend_stub` in
  `src/backend.rs` states the exact `docker run`/`rm -f`/`exec` mapping). This
  development machine has no docker/podman/multipass/qemu, so an honest
  implementation cannot be built or tested here.

## Teardown (deterministic, success or failure)

Every started process is stopped and reaped; the harness then **verifies**
every RPC endpoint refuses connections (an accepting socket means an orphan —
the run fails), and removes the run directory unless `--keep`. A `Drop`
backstop kills children even on a panic path.

## Report

JSON on stdout (and `--report FILE`): per-step `name`, `status`
(`pass|fail|skip`), `detail`, and `evidence` (the heights, hashes, tx ids, gas,
and grain-exact deltas each assertion used), plus node roster, chain id,
genesis hash, and pass/fail/skip counts.
