# SOV v0.1.85

A consensus stall-recovery + security + compatibility release. All changes are on `main`
and tested; this is the tag/release description for when v0.1.85 is cut.

## ⛏ Emergency Difficulty Adjustment — the 2026-07-16 stall, fixed for good

On 2026-07-16 (~07:19 UTC) most of the network's hashpower went offline (a home-internet
outage at the dominant miners) and mainnet froze at height 6731 for 8+ hours: LWMA can only
retarget **when a block arrives**, so with difficulty tuned for ~516 H/s and ~6 H/s
remaining, blocks took ~4 hours each — the small-chain death spiral. Nothing in consensus
could recover quickly; the chain would have crawled for days.

**The fix (consensus, this release):** a block whose own committed timestamp is more than
6× the target block time (15 min) past its parent's is *required* — and therefore allowed —
an easier target: the scheduled difficulty is **halved once per full 15-minute stall
interval**, capped at 2^8 (256×) per block. A stalled chain automatically becomes minable
by whatever hashpower remains, each recovered block feeds LWMA a lower difficulty, and the
schedule reconverges. Deterministic for producer and importer alike (both derive it from
the header's committed timestamp), so `bits` remain exactly checkable.

Safety properties:
- **Activation is timestamp-gated at 2026-07-16 22:00:00 UTC** — every earlier block
  (including the stall's own multi-hour blocks) revalidates byte-identically; genesis and
  KAT vectors untouched.
- The per-block cap (2^8) equals what the existing 2-hour future-drift acceptance rule
  could yield (2h / 15min = 8 intervals): lying forward in time buys nothing beyond the
  drift already tolerated, and the MTP lower bound + monotonicity box the timestamp as
  before.
- Eased blocks carry proportionally **less chain work**, so heaviest-work fork choice and
  reorg security are unchanged — a cheap-block chain cannot outweigh an honest one.
- Miners rebuild their template when a stall crosses the next easing boundary (previously
  a stalled miner ground the stale, too-hard template forever).

## 🔒 Security (from the 2026-07-15 internal adversarial audit)

- **HIGH — IntentSettle multisig bypass, fixed.** The multisig gate only guarded the tx
  signer (the solver); an intent's passive **owner** was authorized purely by its retained
  single key, and `SetMultisig` never clears that key — so a compromised/old key that signed
  an intent could drain a multisig account with the M-of-N threshold never consulted.
  `IntentSettle` now refuses when the owner carries a multisig policy.
- **Oracle circuit-breaker (MED).** `OracleUpdate` rejects a single move greater than 10× in
  either direction, bounding a compromised price-feed key's per-block ability to over-mint
  xUSD against unchanged collateral.
- **P2P inbox cap (MED, DoS).** The receive queue is bounded (drop-oldest) so a worker that
  stalls during a slow reorg can't be driven to unbounded memory by peers.
- **RPC per-IP rate limit (MED, DoS).** A token-bucket throttle on the public JSON-RPC
  (20 req/s sustained, 100 burst; loopback exempt) so an unauthenticated
  `sov_submitTransaction` flood can't pin the node's CPU.

## 🍎 macOS (Apple Silicon) compatibility

- SOV Station is ad-hoc signed but **not** Apple-notarized (notarization needs a paid Apple
  Developer account), so a downloaded copy is quarantined and Gatekeeper blocks it on M1 as
  *"damaged."* **Right-click → Open does not fix this on Apple Silicon.** After moving the app
  to Applications, run once in Terminal:
  ```
  xattr -cr "/Applications/SOV Station.app"
  ```
  The READ ME now says this, and the build signs the binary explicitly (dropping the
  deprecated `--deep`).

## 👛 SOV Station

- **Import from a raw 32-byte hex seed**, not just a 24-word mnemonic. The Import field now
  accepts either. This lets a seed-only wallet (e.g. one produced by the XUS↔ZEC atomic-swap
  desk) be imported and spent; the account is reproduced via `hybrid_from_seed`, byte-identical
  to the SDK.

## Safety

Genesis `cb0272ff…` unchanged. The consensus-tightening changes (multisig, oracle) reject
transaction classes that are astronomically unlikely to exist in mainnet history, and the
EDA is timestamp-gated past all existing history; KAT vectors + frozen-genesis tests are
byte-identical. **This is a coordinated upgrade — every node (both relays, every miner,
every SOV Station) must run v0.1.85 before the 22:00 UTC activation**: an un-upgraded node
would reject post-stall eased blocks and fork itself off.
