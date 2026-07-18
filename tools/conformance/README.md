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
live from a node. It funds its own throwaway helper accounts from your seed, and its
one-shot ids are tagged per run so it can be **re-run against a test net** without
colliding with state a prior run created.

> **This sweep moves REAL value — run it on a test net.** Every case broadcasts a real,
> signed, mined transaction: ~20 of them, plus helper funding, a 5-XUS HTLC lock, and
> **two permanent 1-XUS SNS registrations**. Principal sent to throwaway helper accounts
> is recoverable only if you still hold their (seed-derived) keys; **transaction fees are
> irrecoverable**, and the SNS names are burned to the registry. "Re-runnable" means the
> tool won't collide with itself — it does **not** mean free. On a fee-free test net the
> fees are zero; on mainnet they are real.
>
> **Mainnet is denied by default.** If a target node reports the frozen mainnet genesis,
> the sweep refuses to run unless you explicitly acknowledge the danger — pass
> `--i-understand-this-spends-real-xus` on the CLI, or type `i-understand-this-spends-real-xus`
> into the dashboard's acknowledgement field. Two ceilings back-stop a runaway either way:
> `--max-spend` (cumulative XUS moved, default 100) and `--max-fee` (per-transaction fee,
> default 5); the sweep aborts the moment a projected spend or a realized fee exceeds them.

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
  --seed-hex <64-hex funded seed> [--account faucet.reserve.sov] \
  [--max-spend 100] [--max-fee 5] [--i-understand-this-spends-real-xus]
```

Exit code is the number of failed cases (0 = all pass). `--max-spend` / `--max-fee` are
whole-XUS ceilings (defaults 100 / 5). `--i-understand-this-spends-real-xus` is **required
only when the target is live mainnet** — without it a mainnet target is refused.

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
