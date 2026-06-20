# SOV — Windows miner node package (testnet-1)

Run a **real, revenue-earning SOV miner on Windows** that joins **testnet-1**
alongside the Mac seed node. Consensus is **pure Bitcoin-style proof-of-work** —
each node mines continuously, the heaviest-work chain wins, and a block settles
by confirmation depth (6). There are no validators, no committee, no voting:
only hashpower.

> **Completely separate from chain code.** This folder ships only Windows scripts
> + this runbook. It contains **no chain source** — `build.ps1` compiles the
> *real* binaries from the repo's `chain/` workspace. testnet-1's identity is the
> committed, frozen spec `chain/specs/testnet-1.json`; both machines load it
> byte-for-byte, so **nothing secret is copied between them** — each node mints
> its own miner key locally.

```
windows/
  README.md                          <- this runbook
  config/node-config.template.json   <- reference shape (join writes the real one)
  scripts/
    build.ps1                        <- build sov-rpcd/-testnet/-wallet (MSVC)
    join.ps1                         <- wrap a local node around the frozen testnet-1 spec
    open-firewall.ps1                <- allow inbound TCP 9646 (P2P)
    run-miner.ps1                    <- start the node (syncs + mines + gossips)
    set-seed.ps1                     <- (optional) re-point an existing bundle at a new seed IP
    status.ps1                       <- balances on this node (revenue check)
  bundle/                            <- (git-ignored) this node's local config + keystore
```

## How you earn here

All real protocol mechanics (`chain/crates/runtime/src/execution.rs`). **Just
running the node mines** — the daemon grinds each block header's proof-of-work on
the block-time heartbeat and credits the coinbase to this node's keystore
account (no separate miner process). Under Nakamoto consensus the node that mines
a block collects the **miner share** of both the subsidy and that block's fees:

| Stream | What this node earns | Split |
|---|---|---|
| **PoW coinbase** | 12.5 XUS subsidy per block it mines | 93% miner / 5% founder / 2% dev — **no burn** |
| **Fee share** | the 93% miner share of every tx fee in blocks it mines | same 93/5/2 tax applies to fees |

Emission halves every 840,000 blocks (mainnet schedule). The coinbase mints
regardless of traffic; to see fees flow, drive transfers from the Mac.

---

## Prerequisites (Windows box)

1. **Rust (MSVC)** — <https://rustup.rs>, then `rustup default stable-msvc`
   (installs the MSVC build tools / Windows SDK when prompted).
2. **CMake** — required to build the RandomX dependency (the mainnet PoW; linked
   even when testnet-1 mines sha256d):
   ```powershell
   winget install Kitware.CMake
   ```
   Restart the shell so `cmake` is on `PATH`.
3. **Git** — clone the **full** sov repo so `chain/` (and
   `chain/specs/testnet-1.json`) sits beside `windows/`.
4. **Accurate clock** — SOV enforces a median-time-past lower bound and a 2-hour
   future-drift cap on block timestamps: `w32tm /resync`.

If PowerShell blocks the scripts: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

---

## One-time, on the Mac (seed side)

```sh
cd chain
cargo build --release            # cmake on PATH for the RandomX dep
./target/release/sov-testnet join --spec specs/testnet-1.json --out testnet1 --name mac.node.sov
./target/release/sov-testnet up   --out testnet1
ipconfig getifaddr en0           # -> e.g. 192.168.204.228 (share this; can change)
```

`mac.node.sov` is the seed (no bootstrap peer). Allow inbound TCP **9645** through
the Mac firewall. No bundle to copy — testnet-1's spec already ships in the repo.

---

## Bring up the Windows miner

From `windows\scripts\` in PowerShell:

```powershell
# 1. Build the real binaries from chain/ (first run only)
.\build.ps1

# 2. Join testnet-1: wrap a LOCAL node (fresh key) around the frozen spec and
#    point it at the Mac seed's LAN IP.
.\join.ps1 -SeedIp 192.168.204.228 -Name win.node.sov

# 3. Allow the P2P port inbound (run elevated / as Administrator)
.\open-firewall.ps1

# 4. Start the node: handshake on matching genesis hash, sync, then mine + gossip
.\run-miner.ps1

# 5. Watch your balance grow (coinbase + fee share)
.\status.ps1
```

The handshake **only** succeeds if this node computed the same genesis hash
(`b315c403…`) as the seed — the cross-machine byte-for-byte guarantee in action
(see `chain/specs/README.md`).

### Drive traffic from the Mac

```sh
cd chain
./target/release/sov-testnet faucet alice.test.sov 100 --out testnet1   # dispenses mined coins
./target/release/sov-testnet status --out testnet1                      # head height grows
```

---

## Verify it's the real thing

- **Same chain, byte-for-byte:** `status.ps1` and the Mac's `status` show the same
  head height and hash; `sov_getBlockDigest` at any buried height returns the same
  hash on both machines.
- **Cross-machine consensus:** stop the Mac seed → Windows keeps mining its own
  branch; restart the seed → the two reconcile to the heaviest-work chain (a reorg
  if they diverged). Real Nakamoto consensus across two machines.
- **Restart safety:** stop `run-miner.ps1`, start it again → the node replays its
  persisted block log and resumes at the same height.

## Security notes

- **Never expose the P2P port to the open internet.** The transport is
  Noise-encrypted + ML-KEM channel-bound and the handshake is authenticated, but
  for off-LAN peers use a private overlay (Tailscale/WireGuard), not
  port-forwarding.
- This node's miner seed lives in `bundle/node-1/keystore.json` (git-ignored,
  testnet plaintext). Keep it secret; regenerate for anything you care about.
- Keep RPC on `127.0.0.1`. Only the P2P port (9646) crosses the LAN.
