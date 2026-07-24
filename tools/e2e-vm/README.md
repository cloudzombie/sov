# sov-e2e-vm — Live multi-node end-to-end harness (v0.2.0 program, W8 / S8a)

One command stands up a **real, isolated, multi-node SOV blockchain** — real
release `sov-rpcd` binaries, real P2P over TCP, real proof-of-work, real fees
and emission (`mainnet_like` policy, sha256d seal) — drives it through the W8
lifecycle matrix, asserts every step, tears everything down deterministically,
and emits a machine-readable JSON report plus a human summary.

**Exit 0 only if no step failed.** Skips are allowed but each carries the exact
reason and the program slice it waits on.

```
cargo run --release --manifest-path tools/e2e-vm/Cargo.toml -- run \
    [--backend local|ssh|container] [--ssh-config hosts.json] \
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
| 1 | genesis determinism across nodes, ≠ mainnet/testnet pins, == harness pin | live |
| 2 | P2P mesh (authed peers) + convergence + late-join sync to tip | live |
| 3 | mining: +10 blocks, ≥3 distinct coinbase producers, tip agreement | live |
| 4 | shielded v1 lifecycle via the real `sov-wallet` CLI: shield 5 → z-balance → unshield 2 → z-send 1; pool/balance deltas EXACT (fees computed from on-chain receipts) | live |
| 5 | restart/replay survival: SIGKILL node-4, delete `chainstate.snapshot`, cold boot must reproduce head hash + state root from `blocks.log`, then reconverge | live |
| 6 | cross-node conformance: identical block hash + state root at sampled heights; identical supply at an aligned tip; total == mined; shielded == pool | live |
| 7 | BIP-9 activation rehearsal | **SKIP** — needs a config-driven (non-mainnet) deployment install; `baked_deployments()` (daemon.rs) is mainnet-gated and neither ChainSpec nor NodeConfig can arm a test deployment. Waits on W2 + a test-deployment config hook. |
| 8–10 | shield-v2 / z-send-v2 / unshield-v2 / v1→v2 migration / reorg-with-v2 | **SKIP** — waits on W2 (`Action::ShieldedV2` consensus wiring); no v2 action exists in current binaries. |

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
