# sov-conformance — live two-node conformance sweep

Point it at **two running, peered SOV nodes** (your two machines). For every
transaction type it builds a **real signed transaction**, submits it to node A,
waits for it to be mined (reads the on-chain receipt), checks the action's specific
effect, and then runs the **validity checksum**:

1. **Cross-node agreement** — node A and node B must report the *identical block
   hash* at the height the tx landed. A block hash commits to its transactions,
   receipts, and state root, so a matching hash is a cryptographic proof both nodes
   independently computed the same state.
2. **Supply conservation** — `total − mined` must stay equal to the genesis pre-mine
   on both nodes (no transaction may create or destroy XUS; only coinbase grows it).

It fabricates nothing: real keys, real signatures, every height/receipt/balance read
live from a node. It funds its own throwaway helper accounts from your seed and is
safe to re-run (one-shot ids are tagged per run).

This is a **standalone crate**, intentionally *not* part of the `chain/` workspace —
it never affects chain builds/tests/CI. It depends on the real chain crates by path
(same crypto, ids, and RPC client the node uses).

## Web dashboard (recommended)

```
cargo run --release -- serve            # → http://127.0.0.1:8700
cargo run --release -- serve --addr 0.0.0.0:8700
```

Open the page, fill in:

- **Node A** — the RPC address transactions are submitted to, e.g. `192.168.0.244:8645`
- **Node B** — a second node's RPC address (the cross-check), e.g. `192.168.0.7:8645`
- **Wallet seed** — 64 hex chars of a **funded** wallet (holds XUS)
- **Account** — optional; only for a *named* genesis/miner account (leave blank for a
  normal sov-station wallet, whose address is derived from the seed)

Click **Run sweep** and watch each transaction type go green/red live, with the agreed
block hash and final supply-conservation verdict. The seed never leaves this machine.

## CLI (headless / CI)

```
cargo run --release -- \
  --node-a 192.168.0.244:8645 --node-b 192.168.0.7:8645 \
  --seed-hex <64-hex funded seed> [--account faucet.reserve.sov]
```

Exit code is the number of failed cases (0 = all pass).

## Coverage

transfer · token issue/transfer/burn · NFT mint/transfer/set-meta · SNS
register/transfer · HTLC lock/claim/refund · rotate-key · multisig set+exec ·
contract deploy+call (bundled `assets/counter.wasm`).

**Delegated** (heavier fixtures, run separately): the Orchard shielded round-trip is
covered by `sov-testnet shielded`; `TokenSetPolicy` needs a `CompliancePolicy` fixture.

## Getting a funded seed

A sov-station wallet seed that holds XUS works directly. For a fresh local test net,
`sov-testnet gen` writes a per-node `keystore.json` (miner seed) and prints a
pre-funded faucet seed; pass that with `--account faucet.reserve.sov`.
