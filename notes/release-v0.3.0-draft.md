# SOV v0.3.0 — DRAFT release notes — **PLANNED, NOT SHIPPED**

> **STATUS: PLANNED — NOT SHIPPED. No v0.3.0 tag exists. No v0.3.0 binary
> exists. Nothing described below is implemented, merged, or armed.** This
> file is a drafting aid written alongside `notes/v0.3.0-program.md` so that
> the release, when and if it is cut, is described honestly from day one. Per
> the version contract (`notes/release-version-contract.md`), a version number
> must never imply a capability a binary lacks — which is why this banner
> leads the file and stays until a real tag replaces it.

**What this release IS (planned):** the v0.2.0 consensus line, plus a
transparent UTXO value lane ("cash lane") landed as additive, dormant code
behind a new BIP-9 deployment (`utxo-lane`, bit 3, defined but NOT armed):
UTXO output/transaction types with hybrid Ed25519 + ML-DSA-65 spend
authorization, the account⇄UTXO turnstile with consensus-enforced
conservation (`utxo_value` can never go negative, and must equal the
committed set sum), the dual-lane mempool under the existing blockspace
auction, wallet/CLI/RPC/KAT/SDK plumbing, and Station's cash-UTXO bucket.

**What this release is NOT — read this before assuming otherwise:** v0.3.0
does **not** replace the account ledger. Accounts, nonces, xUSD vaults,
names, multisig, tokens, intents, and both shielded pools continue to work
exactly as before, on the account layer, unchanged. It does **not** activate
anything: on mainnet the UTXO lane is dormant — a v0.3.0 node validates
byte-identically to a v0.2.x node until (and unless) a later, separate
arming release bakes an activation schedule and miners signal it in, after
the external audit the program document names as a hard gate. It does
**not** migrate, convert, move, or touch any existing balance or shielded
note: there is no snapshot event, no conversion height, and nothing to opt
out of, because nothing moves unless its owner deposits it through the
turnstile. And it is **not** a fee-market change — tips, RBF, and the
dynamic floor work as they have since v0.1.98, extended across both lanes.

## Consensus

No consensus change until activation. Genesis remains
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d`, frozen
and unaltered. All new state (the UTXO set commitment, the `utxo_value`
scalar) is absent-when-empty: every pre-activation block, root, and KAT
vector is byte-identical with the feature compiled in, proven by replaying
the real mainnet log. Pre-activation, any block carrying a UTXO-lane
transaction or an `UtxoDeposit` action is invalid on every node
(`FeatureInactive` — the same dormant gate the fee auction used).

## Upgrading

Drop-in from v0.2.x (planned). No data migration, no resync, no
configuration change, no wallet action. Existing balances and shielded
notes (v1 and v2) are unaffected and remain fully spendable — this release
adds no restriction to any existing pool or account, in keeping with law F8.

## Version contract

`node/Cargo.toml` is the single version source; the tag equals it exactly;
the release gate refuses any mismatch and additionally refuses to cut
v0.3.0 if the UTXO KAT families are absent or stale. Until that gate passes
and a tag exists, "v0.3.0" names a plan, not a binary.
