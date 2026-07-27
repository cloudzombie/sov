# sov-sharechain

A **non-custodial** pool for SOV: who gets paid is decided by a rule every
participant checks, not by an operator everyone has to trust.

## The problem it solves

Solo mining means waiting a very long time between blocks. Pooling fixes the
variance, but the usual way to pool is custodial — everyone mines to the
operator's address and trusts them to pay it out. That trust *is* the problem.

## How it removes the trust

A **share** is the same RandomX computation a block is, just against an easier
target. Shares are frequent, so they are a usable unit of accounting, and miners
build a chain of them.

When a share *also* meets the network target, it carries a real SOV block — and
the block **must pay out the recent share window**. If it does not, the share is
invalid and the rest of the network builds past it. A finder who keeps the reward
has mined an orphan.

So the payout is enforced by the same rule miners are already following to earn
credit. Nobody has to be honest.

## What it does not do

- **No consensus surface.** SOV sees ordinary blocks with ordinary transfers.
  Nothing here changes block/transaction encoding, the state root, emission,
  difficulty, the chain spec, or any KAT vector. This is a separate cargo
  workspace and no consensus crate is edited.
- **No new cryptography.** Share seals are the node's `pow_seal`; transport is
  the node's Noise/ML-KEM channel.
- **No keys.** Payout account ids are public and no secret material enters this
  process. The block producer signs its own payout transfers.

## Why payouts can spend the same block's coinbase

Checked against the runtime, not assumed: `apply_coinbase` runs **before**
`apply_transactions`, both when a block is produced and when it is imported. The
producer is credited with the reward before that block's transactions execute,
so the payout transfers can spend the coinbase they are distributing — no
operator float, and no special authorization path, because they are ordinary
transactions signed under whatever tx-domain regime is active.

This resolves the open design question recorded in
`notes/activation-pool-mining.md`.

## Status

The accounting core is built and tested: share DAG, heaviest-work fork choice,
uncle credit, bounded PPLNS window, exact payout computation, and the
block-must-pay-the-window rule (including the cheating-finder case).

**Not yet built:** the P2P channel that gossips shares between peers, and the
LWMA retarget that holds the share interval near 10s. Both are additive and
neither changes the rules above.
