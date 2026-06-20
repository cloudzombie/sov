# SOV ↔ Bitcoin BIP Adoption Ledger

An honest mapping of the Bitcoin Core BIPs in `bips.md` onto SOV. SOV is an
**account-based** chain (NEAR-style named accounts), signs with **Ed25519**
(RFC 8032), encodes with **Borsh**, secures consensus with **Doomslug PoS
finality over a PoW mint**, and provides privacy via an **Orchard/Halo2 shielded
pool**. So many Bitcoin BIPs — which are specific to UTXOs, Script, secp256k1,
SegWit, or Bitcoin's P2P wire — **do not apply**; that is a design difference,
not a gap. Where a BIP encodes a *goal* (sound emission, timestamp integrity,
HD wallets, soft-fork signaling), SOV adopts the goal, adapted to its model.

No overclaiming: "Adopted" means the rule or its property is actually implemented
and tested in this repo; "Adapted" means the same goal achieved differently;
"N/A" means Bitcoin-mechanism-specific with no SOV analogue needed.

## Adopted / adapted (implemented + tested here)

| BIP(s) | Goal | SOV status | Where |
|---|---|---|---|
| 9, 8 | Version-bits soft-fork deployment & signaling | **Adapted** — miner/hashpower-signaled feature gates | `sov-governance` |
| 32, 39, 43, 44 | Hierarchical-deterministic wallets | **Adapted** — BIP-39 mnemonic + **SLIP-0010 Ed25519** + BIP-44 path (BIP-32 itself is secp256k1) | `sdk/src/hd.ts` (Rust parity in progress) |
| 42 | Subsidy schedule must terminate (no overflow resumption) | **Adopted (property)** — emission halts exactly at budget; the overflow-resumption bug is structurally impossible | `MiningPolicy::reward`; proof in `sov-verify` |
| 110 | Cap arbitrary data per transaction | **Adopted** — `max_code_bytes` consensus limit on `Deploy` | `sov-runtime`, `sov-mining` |
| 113 | Median-Time-Past timestamp rule | **Adopted** — block timestamp must exceed the median of the last 11 blocks | `Blockchain::median_time_past`, `import_block` |
| 34 | Commit block height in the block | **Adopted (spirit)** — height is an authenticated header field | `BlockHeader.height` |
| 30 | No duplicate-txid double-spend | **Adapted** — replay prevented by per-account **nonces**, not UTXO txid checks | `sov-runtime` authorization |
| 327, 328, 373 | Threshold / multi-party signing (MuSig2) | **Adapted** — **FROST-Ed25519** threshold signatures for custody | `sov-mpc`, bridge custody |
| 65, 68, 112 | Time/height locks | **Adapted (partial)** — stake locks & vesting use height locks; general script timelocks are N/A | `sov-staking`, vesting |

## Not applicable (Bitcoin-mechanism-specific)

Grouped with the reason each class has no SOV analogue:

- **Script / opcodes / P2SH** (11, 13, 16, 65-opcode, 112-opcode, 147, 379 miniscript, 380–387/390 descriptors): SOV has no Bitcoin Script; programmability is a **Wasm VM** (`sov-vm`) instead.
- **SegWit & witness** (141, 143, 144, 145): no UTXO/witness model.
- **secp256k1 / Schnorr / Taproot** (340, 341, 342, 350, 86, 371): SOV signs with **Ed25519**; the goal (compact, secure signatures) is met by a different curve.
- **Address formats** (13 P2SH-addr, 173/350 Bech32(m), 21 URI, 176 bits): SOV uses **human-readable named accounts** (`usa.reserve.sov`), not derived address strings.
- **P2P wire protocol** (31, 35, 37, 61, 90, 94, 111, 130, 133, 152, 155, 157, 158, 159, 324, 325, 339): SOV has its own **authenticated handshake + gossip** transport (`sov-network`); these are Bitcoin's wire messages/service bits.
- **PSBT** (174, 370, 371, 373): SOV transactions are **Borsh**-encoded with a single canonical signing payload; no partially-signed-tx interchange format.
- **Mining RPC** (22, 23 getblocktemplate): SOV mining is over **JSON-RPC** (`sov-rpc-miner`), its own protocol.
- **Wallet UX / misc** (70/71/72 payment protocol [deprecated in Bitcoin too], 14 user-agent, 35 mempool msg): out of scope or client-specific.
- **RBF / mempool policy** (not a single BIP): SOV mempool is **nonce-ordered**; replacement semantics differ by construction.

## Notes

- The HD-wallet row is the one place SOV deliberately **diverges from the BIP
  text to keep the goal**: BIP-32's derivation is secp256k1-only, so SOV uses
  SLIP-0010 (the Ed25519 generalization) on the BIP-44 path — standard practice
  for Ed25519 chains, pinned to the SLIP-0010 + BIP-39 test vectors.
- This ledger is descriptive of the current repo. As SOV adds capabilities
  (e.g. general timelocks), rows move from N/A to Adapted; this file is the
  single place that mapping is tracked.
