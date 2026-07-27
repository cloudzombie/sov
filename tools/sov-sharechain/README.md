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

The **share retarget** is in: `next_share_difficulty()` delegates to the chain's
own `Difficulty::lwma` — the identical LWMA-1 used for blocks — over the last 45
shares, aiming at a 10s interval. It is deliberately not a second implementation:
a difficulty rule copied into another crate is another thing that can drift, and
share accounting depends on it being exactly right.

The LWMA's clamp on each solve time matters more here than on the chain. Share
timestamps are **self-reported by whoever found them**, so a miner who lies about
timing must not be able to move everyone's difficulty — there is a test for
exactly that, and one for a share claiming to precede its parent.

### Gossip

Shares gossip on their **own port** with their **own** message type. They are
deliberately *not* added to `sov-network`'s `NetMessage`: that enum is decoded by
the transport every consensus peer depends on for block and transaction relay,
and running a second protocol through the same decoder would widen the blast
radius of a bug here from "the pool misbehaves" to "block relay misbehaves".

What *is* reused is `sov_network::PqChannel` — the same Noise + ML-KEM sealing
the node uses — for the bytes on the wire. The cryptography is reused; the
decoder is not shared.

It is worth being precise about what that channel does and does not buy, because
a secure channel is easy to over-trust. Encryption gives confidentiality and peer
authentication. It gives **nothing** about whether a share is honest: an
authenticated peer can send a forged share exactly as easily as an anonymous one.
Share integrity comes from the seal and from `ShareChain::accept`, which every
peer runs independently. So the decoder's rule is: **decode is total, and nothing
it produces is trusted** — a decoded message is a claim, and it becomes state
only after the sharechain's rules accept it.

Every length is bounded before a byte is allocated, because the length is
attacker-chosen. The tests assert what that is worth: every truncation of every
message, and every single-bit corruption of a batch, must return rather than
panic or allocate wildly — a panic in a decoder is a remote crash.

The socket loop is in: `GossipNode` binds a listener, dials peers, keeps a peer
set, and runs a read thread per link. Two nodes complete a real Noise + ML-KEM
handshake and a share crosses the wire intact — asserted end to end, including
the receiver validating it with `ShareChain::accept` rather than trusting it
because it arrived over an encrypted link.

Bounds exist because each is a limit on what a stranger can make the process do:
`MAX_PEERS` (slots are finite; without a cap one host fills them all and no
honest peer gets in), and an inbox bounded in **bytes** rather than messages,
because a message count says nothing about memory.

## Status

Complete: share DAG, heaviest-work fork choice, uncle credit, bounded PPLNS
window, exact payouts, the block-must-pay-the-window rule, the LWMA share
retarget, the gossip wire format, and the gossip socket loop. 34 tests.

What remains is operational rather than structural — running it: choosing a
share target relative to network difficulty, seeding a peer list, and the
sharechain-across-tx-domain-activation question flagged in
`notes/activation-pool-mining.md`.
