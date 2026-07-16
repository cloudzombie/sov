# SOV v0.1.85

A security + compatibility release. All changes are on `main` and tested; this is the
tag/release description for when v0.1.85 is cut.

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
transaction classes that are astronomically unlikely to exist in mainnet history; KAT vectors
+ frozen-genesis tests are byte-identical. **This is a coordinated upgrade — update both
relays and the miner together.**
