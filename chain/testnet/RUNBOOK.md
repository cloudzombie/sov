# SOV node runbook

A real, multi-node SOV network you operate with the **`sov-testnet`** tool and the
headless **`sov-rpcd`** daemon. `sov-testnet` mints real keys, writes the genesis +
per-node configs, and can launch/monitor/fund/stop nodes; `sov-rpcd` is the single
long-running node process you put under `systemd` on a server. Both are the SAME
node the desktop app (`sov-station`) embeds — identical consensus, mining, sync,
and difficulty.

The protocol is **pure Nakamoto proof-of-work** and permissionless:

- Fork choice is **heaviest cumulative work**; ties break deterministically (smaller
  block hash), so independent miners converge on one chain.
- There is **no stake, no committee, no approvals, no quorum**. Finality is
  probabilistic: a block is reported **final at 6-confirmation depth** (`FINALITY_DEPTH`).
- Any peer presenting the right **chain-id + genesis hash** authenticates into the
  network (transport is **Noise + X25519 + ML-KEM-768**, ChaCha20-Poly1305 — encrypted
  and post-quantum hybrid), then discovers the rest gossip-style.
- A joining node **downloads to the network tip before it mines** (sync-gated), so it
  never mines its own fork. Mining is a continuous grind on the live tip; rewards are
  proportional to hashpower. Per-block **LWMA-1** difficulty tracks the live hashrate
  and converges to the target block time without oscillation.

> **No keys are shipped in this repo.** You generate them locally with `gen`/`join`;
> the output directory (keys, configs, block logs) is yours and secret. Regenerate any
> time — nothing here is pre-baked.

## Build

```sh
# from chain/ — produces sov-testnet, sov-rpcd, sov-wallet, sov-rpc-miner, sov-katgen
cargo build --release -p sov-rpc --bins
export PATH="$PWD/target/release:$PATH"   # so the tools are on PATH (Windows: add to Path)
```

The CI matrix builds + tests on Linux, macOS, and Windows, so the Windows binary is the
same code. On Windows use the MSVC toolchain (`rustup default stable-msvc`).

## A. Local network on one machine

Both nodes on `127.0.0.1`, ideal for development on a single box:

```sh
sov-testnet gen    --miners 2 --out ./tn   # mint real keys + genesis + per-node configs
sov-testnet up     --out ./tn              # launch node-1 (seed) and node-2 (peer), real sov-rpcd
sov-testnet status --out ./tn              # height / head / final-depth / mempool / balances
sov-testnet down   --out ./tn              # stop both nodes
```

`gen` writes to `--out`: `chain-spec.json` (identical on every node; its hash gates the
handshake), `node-K/node-config.json` + `node-K/keystore.json` per miner, and
`testnet.json` (the operator manifest). It prints each miner's seed once — record them;
they control real signing keys.

Useful `gen` flags:

- `--miners N` — number of local miner nodes (default 2).
- `--policy mainnet-like` (default) — **no pre-mine**: the whole 21M cap is mined via the
  coinbase (12.5 XUS/block, 5%/2% founder/dev tax). `--policy test` is the plumbing-only
  shortcut whose preset has no emission, so it pre-funds a faucet for spendable coins.
- `--block-time-ms 60000` (default) — consensus target + daemon cadence. Use `150000`
  for the exact mainnet cadence (~2.5-min blocks).
- `--pow sha256d` (default; single-box friendly) or `--pow randomx` (the mainnet-fidelity,
  ASIC-resistant seal — a full dress rehearsal).

## B. Public seed node on a VPS (headless, systemd)

This is the reliable way to "become a network": a always-on node with a **public IP and
an open P2P port** is the bootstrap anchor every other node (home machines behind NAT or
host firewalls, other VPSes) dials into. The P2P transport is authenticated + encrypted,
so the port is safe to expose.

**1. Generate the network once (anywhere) and copy it to the VPS.**

```sh
sov-testnet gen --miners 1 --policy mainnet-like --out ./net
# copy ./net to the VPS, e.g.:
scp -r ./net  user@SEED_PUBLIC_IP:/opt/sov/net
scp target/release/sov-rpcd  user@SEED_PUBLIC_IP:/usr/local/bin/sov-rpcd
```

**2. On the VPS, bind P2P to all interfaces and keep RPC local.** Edit
`/opt/sov/net/node-1/node-config.json`:

```json
{
  "rpc_addr":  "127.0.0.1:8645",
  "p2p_addr":  "0.0.0.0:9645",
  "data_dir":  "/opt/sov/net/node-1/data",
  "block_time_ms": 60000,
  "bootstrap_peers": []
}
```

Use an **absolute** `data_dir` so the unit doesn't depend on the working directory. Leave
`bootstrap_peers` empty on the seed. The JSON-RPC API is **unauthenticated** — keep
`rpc_addr` on `127.0.0.1` (reach it over an SSH tunnel) or firewall it; only the P2P port
faces the internet.

**3. Open the P2P port** (cloud security group + host firewall), e.g.:

```sh
sudo ufw allow 9645/tcp           # P2P only; do NOT open 8645 (RPC)
```

**4. Install the systemd unit** (`chain/testnet/sov-rpcd.service` in this repo). Edit the
paths/`User`, then:

```sh
sudo cp chain/testnet/sov-rpcd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sov-rpcd
journalctl -u sov-rpcd -f          # the SAME live log the desktop app shows
```

You'll see the node resume from `blocks.log`, the P2P + RPC listeners bind, and the mining
loop: `⏳ connecting to peers…` → `▶ mining…` / `⏸ mining PAUSED — downloading…` →
`⛏ mined block N`.

**Restart safety:** every block is `fsync`'d to `data_dir/blocks.log` before it's
acknowledged, so a SIGTERM (systemd stop/restart) or crash loses nothing committed — the
node replays the log on boot. `Restart=always` is therefore safe.

**Encrypted keystore (recommended on a server):**

```sh
sov-testnet encrypt-keystore --out /opt/sov/net   # seals keystore.json at rest
# then set SOV_KEYSTORE_PASSPHRASE in the unit's environment (see the .service file)
```

## C. Join an existing network (another VPS, or your laptop)

On any new machine, point it at the seed's **public** P2P address. `join` copies the frozen
spec byte-for-byte and mints this machine's own post-quantum miner key:

```sh
sov-testnet join \
  --spec  ./net/chain-spec.json \
  --seed-peer SEED_PUBLIC_IP:9645 \
  --name  miner.node.sov \
  --rpc   127.0.0.1:8645 \
  --p2p   0.0.0.0:9645 \
  --out   ./join
# then run it the same way (systemd on a server, or `sov-testnet up --out ./join`)
```

The node dials the seed, authenticates, **syncs to the tip, and only then mines** — so it
joins the one chain and earns blocks in proportion to its hashpower. Add as many as you
like; one good link to a seed is enough to join (discovery spreads the rest).

> **Home machine behind a firewall/NAT:** outbound dials to the seed work even when inbound
> is blocked, so a laptop/desktop can fully participate by dialing a VPS seed — it just
> won't accept inbound peers itself. This is why a public seed node is the anchor.

## Operating notes

- **Restart safety.** `down`/stop then `up`/start (or a reboot) resumes height + ledger from
  the fsync'd `blocks.log`. No state is re-derived from scratch beyond replay.
- **Sleep/wake & idle.** Blocks carry the real wall clock; long idle gaps are fine as long as
  clocks stay on NTP. Consensus enforces a median-time-past lower bound and a 2-hour
  future-drift upper bound — a badly skewed clock has its blocks rejected. Enable NTP.
- **Difficulty.** Per-block LWMA converges to the target block time; the first
  `DIFFICULTY_WINDOW` (60) blocks mine at the genesis difficulty (warmup), then it tracks the
  live hashrate. No epoch boundaries, no oscillation.
- **Start clean:** `sov-testnet reset --out ./net` wipes the block log (keeping keys +
  genesis) to restart from height 0. On a server, `systemctl stop sov-rpcd`, delete
  `data_dir`, `systemctl start sov-rpcd`.

## Verify

- **Mining + RPC:** `curl` the node (over an SSH tunnel for a server):
  ```sh
  curl -s -X POST http://127.0.0.1:8645 -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"sov_health","params":[]}'
  # {"result":{"chainId":"sov-...","height":N,"mempool":0,"ok":true}}
  ```
  Useful methods: `sov_getHeight`, `sov_getDifficulty`, `sov_getSupply`, `sov_getMiners`,
  `sov_getHead`, `sov_isFinal`.
- **Propagation:** `sov-testnet status --out ./net` shows every node's height tracking within
  a block interval; a head buried 6 deep reports `final`.
- **No pre-mine:** `sov_getSupply` returns `mined == circulating == total` and grows only by
  the block reward — genesis supply is zero on `mainnet-like`.

## Exercise the protocol

- Transfer / balance / nonce: `sov-wallet <rpc> …` (and `sov-wallet keygen <seed>`).
- Mine against a node's RPC with `sov-rpc-miner`; `--shielded` mints into the shielded pool.
- HTLC atomic-swap claim/refund — the same actions the chain validates in consensus.
- Point the explorer at a node's `rpc_addr` for live monitoring.

See `chain/docs/testnet-plan.md` for the go-live checklist and phase plan.
