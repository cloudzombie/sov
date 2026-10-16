# Operating a public non-custodial SOV pool

The pool process does not hold a key and does not sign payouts. A found block's
coinbase is the finder's login account. That finder, on their own machine,
signs ordinary transfers for everyone else in the PPLNS window. The pool checks
those signatures and relays them to the node.

SOV consensus still has a single coinbase recipient. A block that does not pay
the window is a valid SOV block if some other path submits it. This pool
refuses to submit one. That is an incentive and a bridge rule, not a consensus
rule. Multi-output coinbase would make it a consensus rule, and it would be a
hard fork. It is not in this deploy.

## Layout

- `sov-rpcd` bound to `127.0.0.1` only. Do not publish the RPC port.
- `sov-stratum` on `:3333`, reached by miners through TLS.
- Stats HTTP (`--stats-bind`) can be public. It is read-only except
  `POST /api/payout-txs`, which accepts only transfers that match the current
  payout schedule and carry a valid signature.
- `sov-miner-payout` runs on the miner host, next to `xus-miner`. It does not
  run on the pool host. The seed never crosses the pool.

The node keeps at most 64 block templates, one per coinbase account. A 65th
distinct login evicts the oldest template. Miners past that still receive work,
but a template can go stale sooner than the usual 120 seconds. Raise that only
by changing the node; this pool does not.

## systemd

`/etc/sov/pool-node.json` — RPC stays on localhost, and this node does not mine:

```json
{
  "rpc_addr": "127.0.0.1:8645",
  "data_dir": "/var/lib/sov/pool-node",
  "mine": false,
  "upnp": false
}
```

`/etc/sov/keystore.json` has no miner seeds: `{"miners":[]}`.

```ini
# /etc/systemd/system/sov-pool.service
[Unit]
Description=SOV non-custodial stratum pool
After=network-online.target sov-rpcd.service
Wants=sov-rpcd.service

[Service]
ExecStart=/usr/local/bin/sov-stratum \
  --node 127.0.0.1:8645 \
  --bind 127.0.0.1:3333 \
  --stats-bind 0.0.0.0:8080 \
  --refresh-secs 30 \
  --start-diff 1000 \
  --min-diff 100
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`--refresh-secs` must stay under 120. The node forgets a template after that.
A refresh puts that miner's payout transactions back into the mempool, then
asks for a template with `coinbaseTxsOnly` so only the finder's transfers are
in the block. Another miner's signed payout stays in the mempool for their own
template and is not mined here.

The pool node admits a transfer the signer cannot yet cover, up to the next
coinbase, because that transfer is valid in the block that pays them. Use this
repo's `sov-rpcd`. An older node rejects the payout before it can enter the
template.

Firewall: allow 3333 only from the TLS terminator, and 8080 if you publish
stats. Do not allow 8645 from anywhere but this host.

## TLS

Stratum is plaintext JSON lines. Terminate TLS outside the process.

stunnel, client-facing `443` or `3333`, backend `127.0.0.1:3333`:

```ini
[sov-stratum]
accept = 3333
connect = 127.0.0.1:3333
cert = /etc/sov/pool.fullchain.pem
key = /etc/sov/pool.key.pem
```

nginx `stream` does the same job. Miners then use `stratum+ssl://pool.example:3333`.
The pool binary does not speak TLS itself.

## What miners run

`xus-miner` connects with `--pool host:3333 --user <account>`. The account is a
SOV account id or a checksummed `xust1…` address. An optional `/worker` suffix
is a label, not a payee.

`xus-miner` does not hold the wallet seed and cannot sign the payout
transfers. On the same machine:

```sh
sov-miner-payout --pool http://pool.example:8080 --seed-hex <64-hex-seed>
```

`--print-account` prints the implicit account id for that seed. Re-run the
payout tool when the schedule changes (a new window after a block, or when the
tool exits without `satisfied`). If the schedule is already satisfied it does
not sign again.

## Stats

`GET /api/stats` is what MiningPoolStats and minerstat scrape. Hashrate is the
sum of accepted share difficulties over the recent window, divided by the span
of those shares. It is 0 when nobody has submitted a share. Connected miners
are distinct logged-in payout accounts. Workers are logged-in sessions.
Pre-login connections are not counted. `fee` is 0 and `payoutScheme` is
`PPLNS`. `lastBlock` stays null until this pool's node actually imports a block.

`GET /api/miner/<account>` and `GET /api/payouts/<account>` are the per-miner
views. The payout document lists the transfers that account must sign, the
next nonce, and the signing domain (`null` while the tx-domain fork is dormant).

## Share difficulty and block difficulty

The sharechain aims at a share about every 10 seconds. The SOV chain aims at a
block about every 150 seconds, so a share is on the order of 15× easier than a
block while both are at their targets. The two retargets are independent. An
emergency difficulty adjustment on the chain can make every share also a block.
If the share target is clamped up to the network target, the share is weighted
at network difficulty — the work the miner actually proved.

Empty window (no prior shares): the finder keeps the coinbase, and no transfer
is required. Once anyone else has a share, a block that does not pay them is
not forwarded.

## Trust that remains

Miners trust the pool to stay online and to submit a block that already pays
them. They do not trust it with a key, and a block reward does not pass through
an operator wallet. Availability is not the same thing as custody.
