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
- `sov-stratum` on `:3333`. Pass `--tls-cert` and `--tls-key` to terminate TLS
  in the process, or leave them unset and put stunnel in front.
- Stats HTTP (`--stats-bind`) can be public. It is read-only except
  `POST /api/payout-txs`, which accepts only transfers that match the current
  payout schedule and carry a valid signature. The same payload arrives on the
  miner's stratum connection as a `payout` notice, and the signed reply is
  `payout_txs`.
- Sharechain gossip listens on `--share-bind` (default `0.0.0.0:3434`). Each
  share carries the header preimage, so a peer re-seals it before accepting.
  Dial other pools with repeatable `--share-peer`. `--share-bind none` closes
  the port.
- The node keeps 4096 block templates and drops the least recently used. A
  lookup refreshes the entry, so a miner who is still submitting is not the
  one evicted. Templates still expire after 120 seconds.

The seed stays on the miner. `xus-miner --seed-hex` signs payouts in that
process. `sov-miner-payout` does the same job for a miner binary that has no
seed flag. Neither runs on the pool host.

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
  --bind 0.0.0.0:3333 \
  --tls-cert /etc/sov/pool.fullchain.pem \
  --tls-key /etc/sov/pool.key.pem \
  --stats-bind 0.0.0.0:8080 \
  --share-bind 0.0.0.0:3434 \
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

Firewall: allow 3333 from miners, 3434 from sharechain peers, and 8080 if
you publish stats. Do not allow 8645 from anywhere but this host.

## TLS

`--tls-cert` and `--tls-key` are PEM paths. Set both or neither. With both
set, the stratum port speaks TLS and miners use `stratum+ssl://pool.example:3333`.
The rate limit still sees the TCP peer, not the local splice.

stunnel remains fine when you want the pool process on plaintext:

```ini
[sov-stratum]
accept = 3333
connect = 127.0.0.1:3333
cert = /etc/sov/pool.fullchain.pem
key = /etc/sov/pool.key.pem
```

In that layout, bind the pool to `127.0.0.1:3333` and do not pass `--tls-cert`.

## What miners run

`xus-miner` connects with `--pool host:3333 --user <account> --seed-hex <64-hex>`.
The account is a SOV account id or a checksummed `xust1…` address, and it must
be the implicit account of that seed. An optional `/worker` suffix is a label,
not a payee. The seed is not written to the socket, the log, or the JSON event
stream. The pool pushes a `payout` notice when the schedule changes; the miner
replies with signed transfers.

A miner binary that cannot hold a seed can still use the separate tool, on the
miner host only:

```sh
sov-miner-payout --pool http://pool.example:8080 --seed-hex <64-hex-seed>
```

`--print-account` on that tool prints the implicit account id. If the schedule
is already satisfied it does not sign again.

## Uncles

A share that loses a race to a heavier share is an orphan. The next share may
cite it. Cited uncles earn 75% of their work in the PPLNS window. A share that
stays on the sharechain tip keeps full weight even if the SOV node later
prefers a different block at that height: the work happened, and this pool
does not submit a block that fails to pay the window.

## Fee reserve

A transfer's fee is debited before the balance check, then credited back to
the block proposer. One fee has to sit in the finder's balance for the debit
to succeed, even when that finder's own share of the reward is smaller than
the fee. The pool asks `sov_estimateFee` and splits `reward - fee` across the
window. The reserved grains stay with the proposer, which is where consensus
returns the fee. They are not a pool fee. `fee` in the stats JSON stays 0.
`feeReserveGrains` is the amount held back so the transfer can execute.

If the fee would consume the whole coinbase of a non-empty window, the pool
keeps the full map and withholds the block rather than treating the window as
empty.

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
