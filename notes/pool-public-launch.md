# SOV pools for public consumption — the workstream

_Drafted 2026-08-08 from a full read of the tree. Supersedes the Phase-3 status in
[STATUS.md](STATUS.md) and the payout design question in
[activation-pool-mining.md](activation-pool-mining.md), both of which are out of date._

---

## 1. What already exists (verified, not recalled)

| component | state | LOC | tests | CI |
|---|---|---|---|---|
| `tools/sov-stratum` | built (Phase 2) | 2,483 | 53 | fmt + clippy + test |
| `tools/sov-sharechain` | **built** (Phase 3) | 1,824 | 36 | fmt + clippy + test |
| `cloudzombie/xus-miner` | **speaks SOV stratum** | — | — | own repo |

**STATUS.md is wrong** and is corrected by this note: it claims *"Phase 3 (sharechain/PPLNS)
SCOPED, not built."* In fact `tools/sov-sharechain` has, tested and in CI: the share DAG,
heaviest-work fork choice, uncle credit, a bounded PPLNS window, exact payout computation, the
block-must-pay-the-window rule (including the cheating-finder case), an LWMA share retarget that
**delegates to the chain's own `Difficulty::lwma`** rather than reimplementing it, a bounded
gossip wire format, and a working Noise/ML-KEM gossip socket loop.

### 1.1 The design is better than the roadmap assumed — Phase 4's hard fork is NOT needed

The old plan (`.github/RELEASE-0.1.92.md` §3–4) treated SOV's single-recipient coinbase as the
blocker and scheduled a **multi-output coinbase hard fork** to solve it. The sharechain removes
that requirement entirely, and it did so by checking the runtime rather than assuming:
`apply_coinbase` runs **before** `apply_transactions`, on both production and import. The producer
is credited before that block's transactions execute, so **the payout transfers can spend the very
coinbase they are distributing** — as ordinary signed transactions, with no operator float and no
special authorization path.

Payout is then enforced by the same rule miners already follow to earn credit: a block must pay
the recent share window, or the share is invalid and the network builds past it. **A finder who
keeps the reward has mined an orphan.** Nobody has to be honest.

Consequence for the roadmap: **Phase 4 (multi-output coinbase) can be struck.** No consensus
change, no hard fork, no new signal bit is required to run a non-custodial pool on SOV. That is
the single most important fact in this note.

### 1.2 The one gap that blocks everything

**`sov-stratum` and `sov-sharechain` are not wired together.** Neither depends on the other:

- `sov-stratum` → `sov-rpc`, `sov-pow`, `sov-primitives`
- `sov-sharechain` → `sov-primitives`, `sov-mining`, `sov-network`

`tools/sov-stratum/src/main.rs:523` still reads *"will accrue once the decentralized sharechain
lands"*. It landed; nothing connected it. **So the bridge as it stands today pays the entire
coinbase of any block it finds to the single `--coinbase` account.** That is a custodial pool —
precisely the trust model the sharechain was written to abolish. Running it publicly in its
current shape would mean asking strangers to trust an operator, which contradicts the whole point.

---

## 2. "Will it run on sovxus.org?" — No. And mostly, it runs nowhere.

### 2.1 The architecture answer

The sharechain is a **P2Pool-style decentralized pool**. There is deliberately **no central pool
server**. Each miner runs their own `sov-sharechain` node and their own `sov-stratum` bridge
locally; the sharechain nodes gossip shares to each other peer-to-peer on their own port with
their own message type. Payout correctness comes from a rule every participant checks
independently — not from an operator, and not from a website.

So the question "where do we host the pool" has an unusual answer: **you don't host the pool. You
ship it, seed it, and document it.** Three things genuinely need to exist publicly:

1. **Share-gossip seed nodes** — peer discovery, analogous to DNS seeds. Small, stateless-ish, and
   the only piece that must be reachable.
2. **A getting-started surface** — downloads, docs, and a read-only stats page. This is what
   sovxus.org should carry.
3. **Nothing else.** No custody, no accounts, no operator keys. The pool holds no funds at any
   point, so there is no hot wallet to defend.

### 2.2 Why sovxus.org specifically cannot host the mining side

Measured on the explorer droplet `104.236.244.93` (2026-08-08):

```
MemTotal 984 MB · MemAvailable 271 MB · 1 core · SwapTotal 0 · disk 24G (17% used)
already running: nginx, sovereign-explorer, sov-faucet, sov-swap-coordinator
```

**984 MB, one core, no swap, four services already resident.** The stratum bridge alone holds a
light RandomX VM (~256 MiB, process-wide) and re-seals **every submitted share** on a dedicated
verifier thread — CPU-bound work, on the single core currently serving the explorer, the faucet
and the swap desk. Putting it there would starve all four and take down the explorer and faucet
with it.

**And not sfo3 either:** 2.0 GB, 1 core, no swap, the network's only public RPC, and already
proven unable to start v0.2.10 ([[v0210-startup-oom]]). It is the most load-bearing and least
spare machine in the fleet.

Static docs, downloads, and a stats page on sovxus.org are fine — nginx already serves that class
of thing and it costs nothing. **The mining path must not go on either droplet.**

### 2.3 So how does a pool get "created"? Three roles, and anyone can play any of them

There is no registration, no listing, and no operator status to apply for. A participant runs some
combination of three things:

| role | what it does | who runs it |
|---|---|---|
| **hasher** | grinds RandomX (`xus-miner`) | everyone |
| **bridge** (`sov-stratum`) | hands out jobs, re-seals every share | anyone |
| **sharechain node** | share DAG + gossip + payout rule | anyone |

Two topologies fall out, and both are first-class:

1. **Solo-but-pooled (the recommended default).** Run all three yourself and point your hasher at
   `localhost`. Nobody connects to you, yet you still earn a share of every block the *whole*
   sharechain finds, because your shares are gossiped and the PPLNS window is global. This is the
   P2Pool model and it is how most participants should run.
2. **A public node.** Identical, except you expose the stratum port. Others connect with their own
   payout account in `login` (P0b) and their shares credit **them**. You are providing bandwidth,
   uptime and a node — not custody. **This is "becoming a pool", and it requires no permission
   from anyone.**

**What a public-node operator can and cannot do.** They *cannot steal*: payouts are enforced by
the block-must-pay-the-window rule that every sharechain node checks independently, so an operator
who alters or omits payouts has their share rejected and mines an orphan. They *can* censor —
refuse your connection, or withhold jobs. That is a liveness attack, not a theft one, and the
remedy is to connect to a different node or run your own in thirty seconds.

State this plainly in the public docs: **non-custodial is not the same as trustless in every
dimension.** Custody risk is genuinely eliminated; availability still depends on whichever bridge
you point at.

### 2.4 The zero-cost bootstrap

No new infrastructure is required to launch, which matters given the current DO billing
constraint:

- **The owner's Mac is already the network's dominant miner** — 9,670 of ~19,514 blocks, running
  Station at ~50% duty for days at a stretch. It runs the first `sov-sharechain` node and the
  first `sov-stratum` bridge. That is a complete, working, non-custodial pool of one.
- **A second sharechain seed** is wanted for gossip redundancy but is not needed on day one, and
  when it is, it can be any cheap or free host — it carries no funds and no keys, so its
  compromise costs share gossip, not money.
- **sovxus.org** serves the page. Already paid for, already running nginx.

Note the pleasant property: because the pool is non-custodial and holds no keys, **the hosting
security bar is far lower than a normal pool** — there is nothing on those machines worth
stealing.

---

## 3. The workstream

Ordered so that each step is independently useful and nothing ships half-trusted.

### P0 — Wire the bridge to the sharechain  ★ the whole thing depends on this

Make `sov-stratum` depend on `sov-sharechain` and replace per-session share tallying with real
sharechain accounting.

- Every verified share becomes a sharechain share (the bridge already re-seals every submission
  with the real `pow_seal` — that work is done and is exactly what the sharechain needs).
- A share that also clears the network target builds a block whose **transaction set includes the
  PPLNS window payouts** computed by `sov-sharechain`, then submits via `sov_submitBlock`.
- Remove the `--coinbase`-takes-everything path, or gate it behind an explicit
  `--solo` flag so nobody runs a custodial pool by accident.
- **Acceptance:** a block found by the bridge pays the window, and a deliberately cheating build
  (payouts omitted or altered) is rejected by the sharechain's own `accept` — proven by test, not
  by inspection. The cheating-finder case is already covered in `sov-sharechain`; this asserts the
  bridge is bound by it.

### P0b — Per-miner payout accounts from the stratum `login`  ★ this is what makes a node joinable

**Without this, exposing a bridge is a hashrate-donation trap.** Today
`tools/sov-stratum/src/main.rs:651` handles login like this:

```rust
// `params.login` carries the miner's wallet/worker label; the
// coinbase is pool-level config here, so it is logged, not obeyed.
if let Some(who) = params.get("login").and_then(Value::as_str) {
    log(&format!("{peer}: login `{who}`"));
}
```

The login is **logged and discarded**, and `struct Miner` (line 222) has no payout field at all —
just `id`, `session`, `peer`, `writer`, `difficulty`, `window`, `accepted`, `rejected`,
`logged_in`, `alive`. Every share therefore credits the single pool-level `--coinbase`. If a
stranger connected to your bridge today, **they would be mining for you.**

Work:

- Parse `login` as the miner's **own payout account** — the Monero-dialect convention is that the
  login *is* the wallet address, which is why the field already arrives.
- Add the account to `Miner`, and credit each accepted share to **that** account in the sharechain,
  not to `--coinbase`.
- **Validate it at login and reject a malformed one immediately**, with a clear error. A miner who
  mines for an hour against a typo'd address must never discover it at payout time — and note that
  a transparent account id has **no checksum today** ([release-v0.2.11.md](release-v0.2.11.md)
  §3A.2), so a single mistyped hex character is a silently valid, unspendable address. The
  `xust1…` checksummed form from §3A.3 matters more here than anywhere else in the system: this is
  a stranger typing an address into a config file once and walking away.
- `--coinbase` remains only as the `--solo` fallback for a bridge with no sharechain.
- **Acceptance:** two miners with different payout accounts on one bridge each accrue their own
  share weight, and a found block pays both per the window.

### P1 — Share-target selection and peer seeding

The two items `sov-sharechain`'s README names as the remaining operational work:

- **Choose the share target relative to network difficulty.** Shares aim at a 10s interval against
  a network targeting 150s. Document the ratio, how it tracks difficulty, and what happens across
  an EDA event — difficulty can halve repeatedly during a stall (observed live on 2026-08-07,
  2.04× in one step), and share accounting must stay sane through that.
- **Seed list**: how a fresh sharechain node finds peers, with a documented bootstrap.

### P2 — Public-endpoint hardening (this is where strangers arrive)

Not optional, and the security bar here is higher than anything else in the tree because it faces
the open internet:

- **TLS on the stratum port.** There is none today; the README says "run it on a trusted network
  or behind a proxy." A public pool is by definition not a trusted network. Terminate TLS in the
  bridge or document an nginx/stunnel front convincingly enough that operators actually do it.
- **Miner authentication and abuse controls.** Today there is per-session share verification only.
  Fake work earns nothing (every share is re-sealed), so the risk is **resource exhaustion, not
  theft**: connection floods, share spam forcing re-seals on the verifier thread, slowloris on the
  JSON line protocol. Needs per-IP connection caps, share-rate limits, and ban scoring — the same
  posture `p2p.rs` already takes for block relay.
- **Bounded everything on the wire.** `sov-sharechain`'s gossip decoder already sets the standard:
  every length bounded before allocation, decode is total, and *nothing decoded is trusted*. The
  stratum JSON path should be audited to the same bar.

### P3 — Miner compatibility, stated honestly

- **`xus-miner` already speaks the SOV extensions** — `nonce_offset`, `nonceOffset`, `target_full`,
  `rx/0`, `login`, `stratum+tcp://` parsing, with unit tests over job parsing. Its README already
  documents connecting to a `sov-stratum` pool. **There is a working first-party client**, and
  `sov-stratum`'s README predates it — fix that README, it currently undersells the state.
- **Stock xmrig still cannot mine SOV**, and no bridge-side trick can fix it: xmrig hard-codes
  Monero's 4-byte nonce at offset 39, while SOV's nonce is a trailing little-endian u64 at
  `blob.len() − 8` behind a variable-length `proposer`. The blob *is* the hash preimage; rearranging
  it changes the seal. Keep saying so plainly — the README's "we do not claim stock-xmrig support
  we cannot demonstrate" is the right posture and must survive any marketing pass.
- Optional and upstreamable: a small xmrig patch honoring `nonce_offset`/`nonce_size`/`target_full`.

### P3b — Miner-side template construction (the DATUM property), stated accurately

**Owner directive 2026-08-08: miners must be able to choose their own transactions.** Agreed on the
principle. But the tree already delivers most of it, and being precise about *where* the gap is
changes what we should build.

#### What already exists

`sov-stratum --node <addr>` points the bridge at **whatever node you tell it to**, and
`sov_getBlockTemplate` builds the candidate from **that node's own mempool**. So in the
**solo-but-pooled** topology (§2.3, the recommended default) the miner runs their own node, their
own mempool policy selects the transactions, and their own bridge grinds it. **Template
sovereignty is already total there — it is a property of the default topology, not a missing
feature.** `sov_getBlockTemplate` even accepts a `coinbaseAccount` override
(`chain/crates/rpc/src/lib.rs:1951`).

That is precisely DATUM's thesis — the miner builds its own block from its own mempool policy —
and SOV gets it for free because the P2Pool model already assumes every participant runs a node.
DATUM needed a protocol to retrofit this onto centralized Bitcoin pools; a sharechain does not.

#### Where the gap actually is, and why it is awkward

The gap is only the **public-node** topology: a remote hasher connecting to somebody else's bridge
receives *that operator's* template and cannot choose its contents.

The awkward part is that this is close to self-contradictory. **Building a template requires a
node with a mempool.** Anyone running a node should simply run their own bridge and sharechain
node — which is the default topology, and which already gives them everything. A hasher that runs
*no node* has no mempool to select from and therefore fundamentally cannot choose transactions;
there is nothing to hand it. DATUM does not solve this either — a DATUM miner runs `bitcoind`
locally. It is inherent, not an implementation shortfall.

#### So the deliverable is packaging, not protocol

1. **Make the sovereign topology the easy path.** One command that brings up node + sharechain
   node + bridge + miner and just works. Today that is four moving parts and a README. **This is
   the highest-leverage item in this whole section** — template sovereignty already exists and is
   losing to convenience, so the fix is to make the sovereign path *more* convenient than the
   custodial one, not to add a feature.
2. **Say so in the docs.** "Run this and you choose your own transactions" is a genuine
   differentiator against every custodial pool, and right now nothing tells anyone it is true.
3. **For remote hashers, offer a policy hint, and be honest about its limits.** Let a connecting
   miner express preferences (e.g. minimum tip, exclude-listed tx ids) that the operator's node
   applies when building. This is *weaker* than sovereignty — the operator still executes it and
   could ignore it — so the docs must not oversell it. The only real answer for a miner who
   distrusts an operator's transaction selection is to run the local stack.
4. **Optional, later: accept a miner-supplied template.** A connecting miner that *does* run a node
   could submit its own candidate. Two constraints make this safe and bounded:
   - The block must still **pay the PPLNS window**, or the sharechain rejects the share (§1.1).
     Miners choose the *other* transactions freely; they cannot touch the payouts.
   - An invalid template costs only **wasted work** — `sov_submitBlock` runs the node's full
     `import_block` re-validation, so a bad candidate is rejected and can never reach consensus.

   It is genuinely optional because anyone able to use it can already run the local stack.

#### Why this matters less today than it will

**98.0% of SOV blocks are currently empty** (17,850 of 19,844 measured 2026-08-08; 10,840
transactions in the chain's entire history). There is no fee market and nothing to censor yet.
Transaction-selection centralization becomes real the moment blockspace has value — so the right
move is to establish sovereign-by-default *now*, while it costs nothing and before habits form
around a convenient custodial default.

### P4 — The public surface on sovxus.org

Static only, served by the nginx already running there:

- What the pool is, and **why it is not custodial** — the one-paragraph version of §1.1, because
  that property is the actual product.
- Downloads/links for `xus-miner` and `sov-stratum`, with a copy-paste quickstart.
- A read-only stats page (share window, participants, recent payouts) fed by a sharechain node
  elsewhere. **Read-only, and it must never become the thing miners depend on** — if the stats page
  is down the pool keeps working, and the page should say so.

### P5 — Rehearse before anyone else touches it

- Drive the whole path on the `tools/e2e-vm` rig (real multi-node isolated testnet, the standing
  pre-tag gate): two sharechain nodes, gossip between them, a bridge, a miner, a block found, the
  window paid, and a cheating build rejected.
- Only then point it at mainnet, and only then tell anyone about it.

---

## 4. What must NOT happen

- **No custodial launch.** Running today's bridge publicly means strangers mining to one account
  on trust. If the sharechain wiring is not done, the pool is not ready — the fix is to wait, not
  to ship the trusting version "temporarily".
- **No mining service on the explorer or sfo3 droplets** (§2.2). Both are too small and both carry
  services the network depends on.
- **No consensus change.** Phase 4's multi-output coinbase is unnecessary (§1.1); nothing in this
  workstream touches block or transaction encoding, emission, difficulty, the chain spec, or any
  KAT vector. Both crates are separate cargo workspaces and no consensus crate is edited.
- **No secret material in the pool path.** Neither crate handles keys today — the coinbase account
  id is public and no seed enters either process. Keep it that way; it is why a compromised seed
  node costs gossip rather than money.

## 5. Cost

**Zero to launch.** The Mac runs the first node and bridge; sovxus.org serves a static page from
nginx it is already running. A second gossip seed is wanted eventually, carries no funds or keys,
and can be the cheapest host available. Nothing here requires touching the DigitalOcean account.

## 6. Open question for the owner

**Does the pool launch before or after the v0.2.11 fleet fix?** They are independent — the pool
needs no node upgrade and no consensus change — but a public pool draws new nodes onto a network
whose only public relay is a 2 GB box that cannot run the current release
([release-v0.2.11.md](release-v0.2.11.md) §1). Inviting strangers before that is fixed means
inviting them through a front door we already know is fragile. Recommendation: **P0–P1 and P5 can
proceed now; hold the public announcement (P4) until v0.2.11 is deployed.**
