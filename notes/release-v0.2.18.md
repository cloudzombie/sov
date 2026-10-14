# SOV Station v0.2.18 — V2 spend recovery, wallet and node repair

Publication of v0.2.17 was canceled after Ubuntu CI exposed an allocation abort
in historical Winterfell proof verification. The outer proof length was bounded,
but nested Merkle vector and digest counts were not. This release validates all
trace, constraint, and FRI opening lengths before decoding, checks their domain
depths, and bounds FRI layer and partition fields. Deterministic regressions cover
huge nested counts and overflow exponents, and mutation tests exercise the full
verifier. Valid proof encoding, genesis, and activation schedules are unchanged.

The Rust client now scans both V2 receiving keys in one authenticated history
pass. A new bounded RPC returns contiguous full blocks and ordered receipts,
pinned to a canonical snapshot. Each page contains at most 256 blocks and 8 MiB
of JSON. Reorganizations fail explicitly; older nodes use bounded concurrent
requests. Existing encrypted caches are reused and concurrent scans of one
wallet share a lock. Progress reports actual blocks, requests, and elapsed time.

A local optimized test over an isolated copy of 27,936 mainnet blocks measured
3.503 seconds and 120 history requests for a cold scan, then 0.024 seconds and
zero history requests for a warm scan. These are local measurements, not a
network latency guarantee. The fixture uses a synthetic wallet seed and no
production signing keys. Functional tests also recover and spend both old and
fresh notes against an activated local chain.

The withdrawal Max selection now follows completed scans until the user edits
or reviews the amount, and it resets when the wallet or network changes. Two
notes of 100,000 and 25,000 XUS offer 125,000 XUS gross. A 1,300 XUS fee yields
123,700 XUS net without replacing the gross input. Actual proof and withdrawal
window limits remain visible separately from the wallet balance.

Relay nodes evict transactions whose V2 inputs are spent when their canonical
head changes, including when they do not mine. This check reads the fixed-size
public input prefix and does not rerun proofs. Startup restores also recheck
account authorization and apply the existing proof-version admission policy.
Historical block validation and activation schedules are unchanged.

`sov_getTransactionStatus` distinguishes included, pending, queued, rejected,
and unknown from one node snapshot. Rejection records contain the public txid,
reason, observed height and head hash; they are bounded and persisted separately
from consensus state. Receipts and current pool membership take precedence.
Station preserves public rejection history across restart and continues tracking
it because a local rejection is not a final chain receipt. An absent transaction
or failed RPC never becomes a claimed confirmation or an automatic resend.

This release restores the activation path for replacement-proof V2 spends with
a distinct mainnet readiness deployment, `shielded-v2-suite2-recovery` on bit 6.
The published bit-5 schedule and historical votes remain unchanged. Its readiness
window starts at 28,512 and requires 260 of 288 blocks; successful first-window readiness locks
in at 28,800 and enables spending at 29,088. It times out at 29,376 without forced
lock-in. Upgraded miner templates signal the new deployment. Pool RPC and Station
show both activation state and actual vote progress. Existing notes use their
original seeds, commitments and nullifiers with the replacement proof; neither
a deposit migration nor a wallet reset is required. Real RPC recovery tests cover
old notes, mixed notes, private transfers, withdrawals, and cold replay after the
recovery deployment activates.

A matched client/miner/relay upgrade is required for protocol-3 authentication;
older peers cannot authenticate with it. Keep existing chain data and wallet
seeds. New unmasked proof-version-1 carriers remain refused because a copied
withdrawal can be reauthorized to an unrelated payout signer. Historical blocks
remain verifiable. Mainnet legacy-key retirement remains unarmed, and independent
proof and quantum-soundness review remain outstanding.

Peer discovery now announces a bounded address set when Hello authentication
completes, in addition to requesting addresses. This repairs the ordering race
where the other endpoint correctly discarded an early unauthenticated request
and discovery never resumed. A deterministic regression forces that ordering;
unauthenticated address-book poisoning remains rejected. Stratum protocol tests
also use the actual bridge-owned ephemeral listener, removing a released-port
race under parallel test execution.
