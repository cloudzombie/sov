# xus-miner

`xus-miner` is a standalone native desktop and headless CPU miner for SOV/XUS.
It connects directly to a SOV Station/node JSON-RPC endpoint (normally port
`8645`) or, optionally, to a `sov-stratum` pool/bridge. It does not run a node,
hold a wallet seed, or decide consensus.

For direct solo mining, enter the node endpoint and your **public account ID**:

```text
Endpoint: 192.168.0.244:8645
User:     <public SOV account ID receiving coinbase rewards>
Password: unused in direct mode
```

Leaving User as `xus-miner` requests no override and uses the SOV node's
configured miner account. Supplying a public account ID requests that account
explicitly. In both cases the miner reads the `proposer` encoded in the returned
block template and reports it as `COINBASE CONFIRMED`; if an explicit account
does not match the template, the miner refuses to hash.

When the node is on another computer, enable **Expose node RPC on LAN** in SOV
Station and restart the node. SOV Station's own mining switch may remain on or
off; it is independent of external mining.

The miner validates every job before hashing it, uses SOV's real `sov-pow`
RandomX/SHA-256d implementation, writes the trailing little-endian eight-byte
nonce at the job-provided offset, checks the full 256-bit SOV share target, and
submits the resulting nonce and seal to the bridge.

## Native GUI

Build and open the operator console:

```sh
cd xus-miner
cargo build --release
./target/release/xus-miner
```

The GUI provides:

- visible connection, authentication, reconnecting, mining, and failure states;
- start/stop control with an isolated miner child process;
- live hashrate history, height, uptime, job, algorithm, and share health;
- a unified low-overhead PoW flight recorder with smoothed/raw hashrate,
  block-height markers, current-round probability, mempool activity cells,
  measured network hashrate, and consensus target cadence;
- next-block estimates calculated from the template's inclusive 256-bit target
  and the miner's smoothed local hashrate (both expected/mean and 50% window);
- bounded engine logs and an explicit per-worker RandomX memory estimate;
- a template-confirmed Coinbase field in Active Work, diagnostics, and the
  startup engine log;
- validated pool, worker, thread, reconnect, and telemetry settings;
- a non-persistent memory confirmation before any multi-worker run;
- settings persistence without ever saving the Stratum password.

The GUI passes the password to its child engine over standard input instead of
exposing it in process arguments. Closing the window terminates the child and
releases its RandomX worker memory.

Mining is probabilistic: the displayed solo block ETA is `expected hashes ÷
smoothed local hashes/second`, not a guaranteed countdown. The round meter uses
`1 − exp(−Σ(hashes tried ÷ expected hashes at that target))` and resets only
when chain height advances; a routine template refresh at the same height does
not fake a reset or retroactively reprice earlier work.
For a Stratum pool, the ordinary job target is a variable-difficulty share
target, not the consensus block target, so block ETA remains unavailable unless
the bridge explicitly supplies `network_target_full`/`network_target`.

The GUI makes reward routing explicit:

- **My bridge / my coinbase** means the connected `sov-stratum` process must
  request templates using a public account controlled by your SOV Station
  wallet. The wallet retains the spending keys; neither the bridge nor miner
  needs them.
- **External pool / contributor** does not imply payment. The current bridge
  logs per-session shares but has no automatic payout implementation, and a
  Stratum worker label is not a payout address.

Direct mining requires an updated node supporting `sov_getBlockTemplate` and
`sov_submitBlock`. In direct mode the User field is sent as the public coinbase
account. A Stratum bridge remains supported for pool operation.

## Headless/server mode

Passing `--headless` preserves the terminal and cloud-server workflow:

```sh
./target/release/xus-miner \
  --headless \
  --pool 127.0.0.1:3333 \
  --user <public-account-or-worker-label> \
  --workers 1
```

Start the existing bridge against a synchronized SOV node before starting the
miner:

```sh
./target/release/sov-stratum \
  --node 127.0.0.1:8645 \
  --bind 0.0.0.0:3333 \
  --coinbase <coinbase-account>
```

Use `--help` for all options. `tcp://` and `stratum+tcp://` pool prefixes are
accepted. Operators that automate the miner can use `--json-events` for
newline-delimited structured telemetry and `--password-stdin` to keep a
Stratum password out of the process list.

## Current constraints

- The connection is plaintext TCP. Use a trusted network or a secured tunnel.
- Each worker currently uses `sov-pow`'s thread-local fast RandomX VM and may
  allocate approximately 2.3 GiB. The default is one worker.
- The current bridge records shares but has no PPLNS payout implementation. Its
  configured coinbase account receives the block. A public operator must not
  promise automatic or trustless payouts until that layer exists.
- This is a correctness-first reference miner, not yet an XMRig-performance
  replacement.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit --deny warnings
```

The integration test launches the real headless engine used by the GUI against
a mock Stratum server. It verifies password delivery over stdin, the structured
GUI telemetry contract, login, full SOV-format job validation, a share whose
hash is independently recomputed from its nonce, one-in-flight-share
backpressure, pushed job replacement, and automatic reconnect.
