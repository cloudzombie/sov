# SOV Station v0.2.18 — V2 wallet repair and bounded historical proof verification

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

This release inherits v0.2.16's protocol-3 peer authentication and suite-2
activation policy. A matched client/miner/relay upgrade is required; older peers
cannot authenticate with protocol 3. Do not reset chain data or replace wallet
seeds. Mainnet legacy-key retirement remains unarmed, and independent proof and
quantum-soundness review remain outstanding.
