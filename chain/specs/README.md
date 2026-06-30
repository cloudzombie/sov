# SOV frozen chain specs

A **frozen chain-spec** is the single, immutable source of truth that every node
on a network loads. Its bytes determine the **genesis hash**, and peers complete
the P2P handshake only when their `chain_id` **and** `genesis_hash` match
(`chain/crates/network/src/message.rs`). So the spec *is* the network's identity:
load the same file, join the same chain; load a different one, you are quietly on
a different chain that no honest peer will talk to.

## `testnet-1.json`

The first cross-machine SOV network — a faithful mainnet rehearsal.

| Field | Value | Why |
|---|---|---|
| `chain_id` | `sov-testnet-1` | distinct from `sov-mainnet` |
| `policy` | `mainnet_like` | **no pre-mine** — the whole 21M cap is mined |
| emission | 12.5 XUS / block, halving every 840,000 blocks | identical to mainnet |
| coinbase | 100% to the miner, on coinbase **and** fees, **no tax, no burn** | identical to mainnet |
| `pow` | `sha256d` | single-box mineable; isolates consensus/networking from RandomX build complexity. The **RandomX dress rehearsal** before mainnet flips this to `randomx`. |
| `block_time_ms` | `60000` | 60-second blocks for a watchable testnet |
| accounts | one anchor `genesis.node.sov`, **balance 0** | genesis needs ≥1 account to fix the hash; zero balance = no pre-mine. Its key is derived from the documented seed `sha256("sov-testnet-1:genesis-anchor:v1")` and holds nothing forever — it is a public, throwaway anchor, not anyone's wallet. |

**Frozen genesis identity (every platform must reproduce this):**

```
genesis hash : b315c403fcb7f4dbd5d78f9aa963217aa0d19e95bb86c57ce8b7850ff9a038ff
state root   : e3f66fe0f5faa0379de0827970d8f807068afc1ad84f8844ea73de267eb842ce
genesis supply: 0
```

These are pinned in the test
`daemon::tests::testnet_1_frozen_genesis_is_byte_for_byte_deterministic`
(`chain/crates/rpc/src/daemon.rs`), which rebuilds genesis from this exact file
on whatever OS runs `cargo test`. If macOS and Windows ever disagreed, that test
would fail before a node could even try (and fail) to handshake.

## Byte-for-byte determinism across macOS and Windows

The node is **100% deterministic** across operating systems because nothing in
the consensus path depends on the platform:

- **No wall clock, no RNG, no floats** in the state-transition function. Block
  timestamps are header *data* (re-read on replay), not read from the local
  clock; the only `SystemTime` use is the node-acceptance future-drift check,
  which lives *outside* the deterministic state transition.
- **Ordered state.** Every state store is a `BTreeMap` (sorted iteration), and
  the state root is a sparse Merkle tree whose root is proven independent of
  insertion order (`state::smt` `root_is_independent_of_insertion_order`).
- **Fixed-width, little-endian encoding.** Consensus types serialize with Borsh
  (LE by spec) and contain only fixed-width integers — no `usize`, no maps, no
  floats — so the bytes are identical on any 64-bit target.
- **Deterministic PoW.** SHA-256d is byte-exact everywhere; RandomX is
  deterministic by design (a PoW that wasn't would not function).

Because the genesis hash gates the handshake, this determinism is also
*enforced*: a node that computed different bytes simply could not join.

## Stand up testnet-1 across two machines

Both machines clone the repo (this spec ships with it) and build the binaries
(`cd chain && cargo build --release` — needs `cmake` on `PATH` for the RandomX
dependency, even when mining sha256d). Then each wraps a **local** node — with
its **own** fresh miner key — around this frozen spec; nothing secret is shared.

**Mac (seed):**
```sh
cd chain
./target/release/sov-testnet join --spec specs/testnet-1.json --out testnet1 --name mac.node.sov
./target/release/sov-testnet up   --out testnet1
ipconfig getifaddr en0        # share this LAN IP; open inbound TCP 9645
```

**Windows (validator):** see `windows/README.md` — it runs the same `join` with
`--seed-peer <MacIP>:9645`, then `up`. Both load the identical `testnet-1.json`,
so both compute genesis `b315c403…`, the handshake succeeds, blocks gossip, and
the heaviest-work chain converges — verified live: two nodes reach identical
block hashes and identical `{mined,total}` supply.

## Mainnet

`sov-mainnet` will be the same shape with `chain_id: sov-mainnet`, `pow:
randomx`, the mainnet block time — frozen and pinned the same way, only after testnet-1 validates the
wallet end to end.
