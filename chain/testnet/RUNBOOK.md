# SOV testnet runbook

A real, multi-node SOV network you operate with the **`sov-testnet`** tool. It
mints real keys, writes the genesis + per-node configs, and launches, monitors,
funds, and stops nodes — cross-platform (macOS, Windows, Linux) from one binary.

The protocol is N-validator and permissionless: a block finalizes only once **more
than two-thirds of stake** approves it, and any peer that presents the right
chain-id + genesis hash handshakes in and is discovered gossip-style. The default
two equal-stake validators are *true 2-of-2 BFT* — both must be online to finalize.

> **No keys are shipped in this repo.** You generate them locally with `gen`; the
> output directory (keys, configs, block logs) is yours and secret. Regenerate any
> time — nothing here is pre-baked.

## Build

```sh
# from chain/ — produces sov-testnet, sov-rpcd, sov-wallet, sov-rpc-miner
cargo build --release -p sov-rpc --bins
export PATH="$PWD/target/release:$PATH"   # so `sov-testnet` is on PATH (Windows: add to Path)
```

The CI matrix builds + tests on Linux, macOS, and Windows, so the Windows binary is
the same code. On Windows use the MSVC toolchain (`rustup default stable-msvc`).

## A. Local loopback testnet (one machine — e.g. this laptop)

Both validators on `127.0.0.1`, ideal for intermittent testing on a single box:

```sh
sov-testnet gen --validators 2 --out ./tn   # mint real keys + genesis + configs
sov-testnet up   --out ./tn                  # launch node-1 (seed) and node-2 (peer)
sov-testnet status --out ./tn                # height / finality / mempool / balances

# Fund and watch it finalize on BOTH nodes:
sov-testnet faucet val01.node.sov 100 --out ./tn
sov-testnet status --out ./tn                # head shows `final` on node-1 AND node-2

sov-testnet down --out ./tn                  # stop both nodes
```

`gen` writes to `--out`: `chain-spec.json` (identical on every node; its hash gates
the handshake), `node-K/node-config.json` + `node-K/keystore.json` per validator,
and `testnet.json` (the operator manifest). It prints each validator's seed once —
record them; they control real signing keys.

## B. Real two-machine LAN testnet (Mac seed + Windows peer)

1. **Generate once, on the seed machine:** `sov-testnet gen --validators 2 --out ./tn`.
2. **Copy `./tn` to the second machine** (byte-for-byte — a mismatched genesis hash
   is rejected at the handshake, by design).
3. **Point the peer at the seed.** On the Windows box, edit
   `tn/node-2/node-config.json` → `"bootstrap_peers": ["<MAC_LAN_IP>:9645"]`
   (find the Mac IP with `ipconfig getifaddr en0`). Leave node-1 (`bootstrap_peers: []`)
   as the seed.
4. **Firewall:** allow inbound TCP on the P2P port (9645 on the seed, 9646 on the
   peer if both run locally; on the LAN each machine runs one node, so 9645). Keep
   `rpc_addr` on `127.0.0.1` so JSON-RPC stays local; only the P2P port crosses the LAN.
5. **Clocks:** enable automatic time (NTP) on both. SOV enforces a median-time-past
   lower bound and a 2-hour future-drift upper bound on block timestamps, so a badly
   skewed clock will have its blocks rejected.
6. **Do not expose the P2P port to the open internet.** The handshake is authenticated
   (same-chain + key proof) but the transport is not yet encrypted; for remote peers
   use a private overlay (Tailscale/WireGuard), not port-forwarding.

Start the seed (Mac): `sov-testnet up --out ./tn --node node-1`. Start the peer
(Windows): `sov-testnet up --out ./tn --node node-2`. The peer dials the seed,
handshakes, and syncs; from then on blocks and approvals gossip both ways.

## Intermittent operation (machines not on 24/7)

This network is built to be turned off and on:

- **Finality needs a quorum.** With 2-of-2, a block produced while one machine is
  offline is **`pending`** until the other comes back, approves it, and the
  finality evidence propagates — then both report `final`. (`status` shows this.)
- **Restart safety.** Each node replays its persisted block + approval logs on
  start, so ledger state *and* finality survive a restart.
- **Catch-up + evidence sync.** A node that was offline pulls the blocks it missed
  *and* the approvals that finalized them, so its view converges on finality — it
  does not merely re-derive balances.
- **Sleep/wake.** Blocks are timestamped at production with the real wall clock and
  there are no empty blocks, so long idle gaps are fine as long as clocks stay on NTP.
- **Start clean:** `sov-testnet reset --out ./tn` wipes block/approval logs (keeping
  keys + genesis) to restart from height 0.

## Verify

- **Handshake / propagation:** `sov-testnet faucet …` on either node; `status` shows
  both nodes' height and balances track within a block interval.
- **Quorum finality:** stop one node, `faucet` again → `status` shows the new head
  `pending`; restart the node → it becomes `final` on both.
- **Restart safety:** `down` then `up` → height and finality are unchanged.

## Exercise the real protocol

- Transfer / balance / nonce: `sov-wallet <rpc> …` (and `sov-wallet keygen <seed>`).
- Mine (PoW): `sov-rpc-miner` against a node's RPC; `--shielded` mints into the
  shielded pool.
- HTLC atomic-swap claim/refund — the same actions the chain validates in consensus.
- Point the explorer at a node's `rpc_addr` for live monitoring.

See `chain/docs/testnet-plan.md` for the go-live checklist and phase plan.
