# Native Station diagnostics

The Rust client can produce a public JSON diagnostic report without opening the
GUI, loading a wallet, reading configuration files or changing node/miner state:

```sh
sov-station diagnostics
sov-station diagnostics 127.0.0.1:8645
```

On macOS, use the installed executable directly:

```sh
"/Applications/SOV Station.app/Contents/MacOS/sov-station" diagnostics 127.0.0.1:8645
```

Output goes to stdout. Each probe has a three-second deadline covering DNS,
connection, response streaming and parsing. The command makes twelve read-only
probes; an unreachable or incomplete node still produces JSON with separate
`ok: false` results. It never submits a transaction, requests mining work or
toggles mining. Missing values stay absent or `null`; they are not assumed zero.

The report includes application/platform versions, chain identity, recomputed
head-header hashes, state root, total and shielded supply, peer protocol versions,
authenticated-peer counts, sync status, network PoW/difficulty/hashrate, mempool
counts, quantum policy and pool-v2 capabilities/root/value. Local mining status
and local hashrate are `null` because these RPCs do not expose them.

Only explicitly selected public fields are copied. Wallet/seed/key material,
configuration secrets, peer addresses, block transaction bodies and raw server
error messages are omitted. The command also avoids persistent panic logging,
so its error paths do not write to the wallet directory. Aggregate blockchain
supply and pool values are public network data, not a wallet-balance report.

`chainDomainStart` and `chainDomainEnd` use the normal client's canonical-genesis
check: a node claiming `sov-mainnet` or `sov-testnet-1` with a different pinned
genesis is refused. Custom chain identities are reported without a canonical
pin. Plain TCP JSON-RPC does not cryptographically authenticate the endpoint;
`rpcCryptographicallyAuthenticated` and `consensusRevalidated` therefore remain
false. A matching genesis alone does not prove that the reported head/state is
the consensus chain.

`snapshot` compares the starting/ending heads and identities, the queried state
root, peer identity, reported heights, supply conservation and pool-v2 value.
`consistent: false` indicates conflicting observations, which can also occur
while a node mines or synchronizes. `consistent: null` means required readings
were unavailable; `partial` and `failedProbes` identify incomplete collection.
These flags help diagnose a running node; they are not an atomic consensus
snapshot or an independent post-quantum security certification.
