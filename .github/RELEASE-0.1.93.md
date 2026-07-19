# SOV v0.1.93 — Cross-network replay hard fork: chain-bound transaction & intent signatures (dormant, miner-signaled)

> **This release closes the crown-jewel finding of the Codex external audit: cross-network
> ("ghost chain") signature replay.** Every SOV-family chain derives the same implicit account id
> from the same key (`hex(blake3(pubkey))`), and until now a transaction's signature covered only
> `borsh(Transaction)` — with **no chain-id, genesis, or domain binding**
> (`Transaction::signing_bytes` was a bare `borsh::to_vec(self)`). So a signature captured on one
> SOV-lineage network was valid, byte-for-byte, on **every** other one: coins could be moved on
> chain B by replaying a signature the owner only ever authorized on chain A.
>
> The fix binds each signature to one specific network. It ships **dormant**: gated behind a
> miner-signaled deployment that is **inactive by default**, so pre-activation behavior is
> **byte-identical** to before — genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d`
> and **every** KAT vector reproduce exactly. Nothing on the live chain changes until a coordinated,
> miner-signaled activation that this release does **not** trigger. This is Bitcoin's playbook: never
> touch genesis; fork forward at an activation point.

---

## 0) The vulnerability, precisely

- **Root cause.** `chain/crates/types/src/transaction.rs`: `Transaction::signing_bytes()` returned
  `borsh::to_vec(self)` over `{signer, public_key, nonce, action}` — nothing network-specific.
  `Intent::signing_bytes()` (`chain/crates/intents/src/lib.rs`) had the same shape.
- **Why it replays.** Implicit account ids are `hash(pubkey)`, identical on every SOV-family chain.
  A given `(nonce, action)` therefore produces identical signing bytes on every chain, so one
  Ed25519/hybrid signature verifies everywhere. Nonce ordering stops *same-chain* replay; it does
  nothing for *cross-chain* replay.
- **Blast radius.** Any second SOV-lineage network (a testnet, a fork, a staging chain, a future
  sister chain) becomes a signature oracle against mainnet accounts, and vice-versa.

This was already the top item of the coordinated hard-fork bundle in `.github/RELEASE-0.1.90.md`
(Codex audit response) and overlaps the Luna audit's domain-separation findings.

## 1) The fix — a network-bound signing domain

A signature now optionally binds to a [`SigningDomain`] = `{chain_id, genesis_hash}`. The
**post-activation** signing preimage is:

```
transaction:  "sov:tx:v1"     ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh(Transaction)
intent:       "sov:intent:v1" ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh(Intent)
```

This mirrors the domain separators already in the codebase (`sov:multisig:v1`, `sov:rotate:v1`),
extended with **network** binding. The two `0x00` separators plus the fixed-length genesis make the
layout injective; the four distinct tags keep the transaction, intent, multisig, and rotation
preimages mutually non-collidable. A verifier always frames with **its own** chain-id and genesis,
so a signature made for a different network never matches — cross-network replay is closed in both
directions (a legacy un-bound signature is also rejected once the domain is active; no silent
fallback).

**The transaction/intent *id* is deliberately unchanged** — it remains the hash of the un-framed
`borsh` bytes. Only the *signature* preimage gains the binding. This is what keeps ids stable across
the fork and, critically, keeps **every existing KAT vector byte-identical** (the KAT pins
`signing_bytes_hex`, the id, and the legacy verify — all unchanged).

### The dormant gate

- New consensus deployment **`tx-domain`**, registered through the *same* proven BIP-9/BIP-8
  miner-signaling machinery as the PQ sunset (`sov_governance::Deployment`, `state_at`), resolved
  per block height by `Blockchain::resolved_tx_domain(height)` — a structural twin of
  `resolved_pq_with`. **Config defaults to `None` (unscheduled/inactive).**
- Signature verification is now context-aware. `verify_signature()` /
  `SignedIntent::verify()` are unchanged (they delegate to `…_in(None)`); the new
  `verify_signature_in(Option<&SigningDomain>)` / `verify_in(...)` take the domain. `None`
  reproduces the legacy preimage **exactly**; `Some(domain)` requires the binding.
- The domain is threaded through `BlockContext.tx_domain` (sibling of the existing `pq` field) and
  resolved per height, so historical (pre-activation) blocks validate under `None` and only blocks
  at/after activation require the binding. Enforced at **all three** authoritative points:
  block execution (`apply_transaction`, `execution.rs`), block import
  (`Block::all_signatures_valid_in` at `blockchain.rs`'s `validate_candidate`), and intent
  settlement (`execution.rs`). Mempool admission tracks it too (the node refreshes
  `Mempool::set_domain` on every tip advance), so a post-activation node neither admits a legacy
  signature nor wrongly rejects a correctly-bound one.

## 2) What landed (cited to code)

| Layer | Change | File |
|---|---|---|
| primitives | `SigningDomain{chain_id, genesis}` + injective `frame(tag, body)` | `chain/crates/primitives/src/signing_domain.rs` |
| types | `Transaction::signing_bytes_in`, `SignedTransaction::{sign_in, verify_signature_in}`; legacy delegates to `_in(None)` | `chain/crates/types/src/transaction.rs` |
| types | `Block::all_signatures_valid_in(domain)` | `chain/crates/types/src/block.rs` |
| intents | `Intent::{signing_bytes_in, sign_in}`, `SignedIntent::verify_in` | `chain/crates/intents/src/lib.rs` |
| runtime | `BlockContext.tx_domain`; gated `apply_transaction` + intent-settlement verify | `chain/crates/runtime/src/execution.rs` |
| chain | `tx_domain_deployment` field + `set_tx_domain_deployment` + `resolved_tx_domain[_with]`; wired into the 3 real `BlockContext` sites, `validate_candidate` signature check, and `deployment_states` observability | `chain/crates/chain/src/blockchain.rs` |
| mempool | internal `domain` + `set_domain`; admission verifies under it | `chain/crates/mempool/src/lib.rs` |
| node | `refresh_mempool_domain()` on construction + every tip advance | `chain/crates/node/src/node.rs` |
| katgen | `tx_domain: None` (vectors stay legacy/byte-identical) | `chain/crates/rpc/src/bin/sov-katgen.rs` |

Everything is **additive**. No existing method signature changed; no default code path changed.

## 3) Proof — the byte-identical (dormant) invariant and the new behavior

**Byte-identical when dormant (the trust-root guarantee):**
- `cargo test -p sov-verify` — the KAT reproduces byte-for-byte (`signing_bytes_hex`, tx id, and the
  legacy verify are all unchanged because the legacy path is untouched).
- Genesis pins green: `mainnet_genesis_builds_and_is_frozen`, `genesis_hash_pin_is_enforced`,
  `testnet_1_frozen_genesis_is_byte_for_byte_deterministic` (`sov-rpc`), `mainnet_genesis_is_still_frozen`
  (`rpc/tests/block_template.rs`). Genesis hash unchanged: `cb0272ff…e72d`.
- `blockchain::tests::tx_domain_is_dormant_by_default` — a chain with no `tx-domain` scheduled
  resolves no domain at any height and mines a plain legacy transfer normally.

**New behavior (byte-for-byte + adversarial):**
- `signing_domain::tests::*` — `frame` layout is byte-exact; different chain-id / genesis / tag all
  yield different bytes.
- `transaction::tests::domain_framing_is_byte_exact` — the bound preimage equals
  `tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis ‖ legacy-bytes` exactly, and the legacy bytes are a suffix
  (id unaffected).
- `transaction::tests::legacy_and_domain_none_are_byte_identical` — `signing_bytes() == signing_bytes_in(None)`.
- `transaction::tests::domain_bound_signature_rejects_legacy_and_cross_network` — a mainnet-bound
  signature verifies only under mainnet's domain; rejected under another network's domain, as a
  legacy signature, and by a legacy verifier.
- `transaction::tests::legacy_signature_is_rejected_once_domain_is_active` — no silent fallback.
- `transaction::tests::signing_is_deterministic` — pure functions; RFC-8032 deterministic signatures.
- `transaction::tests::concurrent_verification_is_race_free` — 16 threads verify a shared signed tx
  under the same domain with consistent verdicts (verification is `&self`, mutation-free — no data race).
- `blockchain::tests::miner_signaled_tx_domain_activates_and_binds_signatures_end_to_end` — drives
  the deployment to activation via committed header signals; **pre-activation** a legacy transfer
  mines; **post-activation** the producer excludes a legacy transfer, a smuggled legacy block is
  rejected on import, a cross-network-bound transfer is excluded, and the correctly-bound transfer is
  included and imported.

## 4) Activation is NOT triggered here — the coordinated rollout

Because this is a **hard fork** (post-activation, an un-upgraded node rejects a correctly-bound
transaction), every node must upgrade **before** the activation height. It ships dormant precisely so
upgraded and un-upgraded nodes stay byte-identical until a coordinated flag day. The runbook:

1. Ship v0.1.93 (dormant) to all nodes; confirm on-chain via `sov_getDeployments` that `tx-domain`
   is registered and `Defined`/inactive.
2. **Phase-2 client work — required before activation:** update every signer to `sign_in(Some(domain))`
   for a post-activation target — the Rust wallet, the TS SDK (the KAT second client), SOV Station,
   `sov-conformance`, and `tx-cannon`. (These are unchanged in v0.1.93 and continue to sign the legacy
   way, which is correct while dormant.)
3. Schedule the deployment (start/timeout/period/threshold, BIP-8 lock-in) and let miners signal it
   to `Active` at a window boundary — the exact machinery proven for the PQ sunset.

## 5) Backwards compatibility

While dormant (the state this release ships in), old miners **do not fork**: blocks are byte-identical,
signatures verify on the identical legacy preimage, genesis and KAT are untouched. The only fork point
is the future coordinated activation, which is deliberately not set here.
