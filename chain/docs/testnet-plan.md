# SOV testnet go-live plan

This is the plan for taking SOV live on a real, operator-run testnet — starting
with a personal two-machine deployment (a Mac and a Windows box, neither running
24/7) and generalizing to any N-validator, permissionless network. It records what
is built, the design decisions behind it, and the go-live checklist.

## Why this exists

The chain, node daemon, RPC, P2P, and persistence were all built and tested, but
there was **no operational tooling** to stand up and run a network — only a manual
runbook and hand-written sample configs with throwaway demo seeds. Standing the
network up by hand also surfaced two real consensus gaps (below). This plan closes
both and adds a single cross-platform tool, `sov-testnet`, to operate the network.

## Design decisions

- **N-validator, permissionless — not hardcoded to two nodes.** Finality is >2/3 of
  stake over whatever validator set the genesis lists; any peer with the right
  chain-id + genesis hash handshakes in. The two-machine network is one *deployment*
  of the general protocol (`sov-testnet gen --miners N` takes any N).
- **True 2-of-2 BFT for the personal testnet.** The two validators hold equal stake,
  so a block finalizes only when *both* are online — a genuine decentralization test,
  not a single-validator shortcut.
- **Build from source on each machine; no binary release pipeline.** `cargo build
  --release -p sov-rpc --bins` on each box (the Windows MSVC build is CI-verified).
- **No keys in the repo.** Keys are minted locally by `gen` from the OS CSPRNG.

## What was built

### 1. Consensus completeness — validators approve peer blocks
A follower-validator previously imported a peer's block but **cast no approval**, so
any network where no single validator held >2/3 stake could never finalize.
`Node::import_and_approve` now casts approvals from every held validator key on
import, and the P2P `NewBlock`/catch-up paths persist and gossip them. Finality
emerges from the whole set crossing the threshold — identical for 2, 4, or 100
validators. (`crates/node/src/node.rs`, `crates/rpc/src/p2p.rs`.)

### 2. Finality-evidence sync — a rejoining node converges on finality
Approvals are separate messages, so a node that was offline when a block finalized
synced the *block* but not the *votes*, and could not see it as final. The
`FinalityGadget` now retains the signed approvals as transferable evidence
(`approvals_for`), and the P2P layer adds `GetApprovals`/`ApprovalsResponse`: a
caught-up node whose head is unfinalized pulls the missing votes and re-verifies
them. (`crates/consensus/src/finality.rs`, `crates/chain/src/blockchain.rs`,
`crates/network/src/message.rs`, `crates/rpc/src/p2p.rs`.)

### 3. `sov-testnet` operator tool (`crates/rpc/src/bin/sov-testnet.rs`)
One cross-platform binary:
- `gen --miners N` — mint real keys (OS CSPRNG), write `chain-spec.json`,
  per-node `node-K/{node-config,keystore}.json`, and a `testnet.json` manifest.
- `up [--node node-K]` / `down` — launch / stop `sov-rpcd` processes (PID-tracked).
- `status` — height, head finality, mempool, and balances across all nodes.
- `faucet <account> <sov>` — sign + submit a transfer from the faucet account.
- `reset` — wipe block/approval logs, keeping keys + genesis.

## Go-live checklist

- [x] Consensus: peer-block approval + N-validator finality (regression tested).
- [x] Finality-evidence sync across downtime (regression tested).
- [x] `sov-testnet` tool, cross-platform, no fabricated data.
- [x] Gate green: full workspace tests, `clippy -D warnings`, `fmt --check`.
- [x] Loopback proof: `gen` → `up` → `faucet` finalizes on both nodes; one node
      offline → head `pending`; node rejoins → both `final`.
- [ ] **Two-machine LAN bring-up** (operator, per `testnet/RUNBOOK.md` §B): build on
      the Windows box, copy `./tn` byte-for-byte, set the peer's bootstrap to the Mac
      LAN IP, open the P2P firewall port, NTP on both. Confirm handshake, height
      agreement, quorum finality, and catch-up after one machine sleeps.
- [ ] Soak: leave it running across sleep/wake cycles; confirm restart safety and
      that pending blocks finalize when both machines are up.

## Tests (regression coverage)

`crates/rpc/tests/p2p.rs`, over real loopback TCP:
- `two_of_two_finalizes_only_when_both_validators_approve`
- `pending_block_finalizes_after_offline_validator_rejoins`
- `offline_validator_converges_on_finality_via_evidence_sync`
plus the prior gossip / catch-up / wrong-genesis tests.

## Out of scope (honest gaps)

Transport encryption (use a private overlay for remote peers), external security
audit, and a public, permissionless testnet with third-party operators. These are
deliberately not faked — build the tools, run the network, disclose what is not yet
done.
