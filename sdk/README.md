# @sov/sdk

High-level JavaScript/TypeScript client library for the **SOV blockchain**.

A standalone Node/TypeScript project (its own `package.json` and `tsconfig.json`)
that lives beside `chain/` (the Rust blockchain), `explorer/`, and `dashboard/`.
It does **not** depend on the Rust workspace.

## What it gives you

| Area | Status |
| --- | --- |
| **Units** — SOV ↔ grains (8 decimals, 21M cap, BigInt) | ✅ Real & unit-tested |
| **AccountId** — validation + hierarchy helpers | ✅ Real & unit-tested |
| **Keys** — Ed25519 generate / from-seed / sign / verify | ✅ Real & unit-tested |
| **Types** — `Account` / `Transaction` / `Block` interfaces | ✅ Mirror the chain's JSON shapes |
| **Borsh + tx id** — canonical encoding & Blake3 id | ✅ Byte-for-byte vs the node (KAT vectors) |
| **Transaction builder** — build + sign a node-submittable tx | ✅ Real & unit-tested |
| **`SovClient`** — typed JSON-RPC client over `fetch` | ✅ Real; verified live against `sov-rpcd` |
| **`Wallet`** — balance/nonce, transfer/stake, await inclusion | ✅ Real; verified by a live e2e |

This project follows the SOV hard rule: **no dummy, fabricated, or placeholder
data, ever.** Every RPC method returns real chain state; transactions the SDK
builds are accepted by a real node.

## Wire compatibility (the important part)

The node's **canonical** signing-and-hashing payload is the **Borsh** encoding of
a `Transaction` (`chain/crates/types/src/transaction.rs`), and a transaction's id
is the **Blake3** of those bytes. `src/borsh.ts` reproduces that layout exactly,
and `test/borsh.test.ts` proves it **byte-for-byte** against known-answer vectors
generated from the Rust node:

```bash
# regenerate the vectors from the chain (already committed at sdk/vectors/):
cargo run -p sov-rpc --bin sov-katgen > sdk/vectors/transactions.json
```

The KAT suite checks the signing bytes, transaction id, Ed25519 signature, and
full signed-transaction Borsh for every sample action. A live end-to-end test
(`test/e2e.test.ts`) goes further: the SDK builds and signs a transfer, a running
node **accepts and includes it**, and the recipient balance moves.

## Quick start

```ts
import { SovClient, Wallet, Keypair } from "@sov/sdk";

const client = new SovClient({ endpoint: "http://127.0.0.1:8645" });

// Read chain state
console.log(await client.getHeight(), await client.getSupply());

// Send a transfer from a keypair-backed wallet
const wallet = Wallet.fromSeed(client, seed32, "usa.reserve.sov");
const { id } = await wallet.transfer("ecb.reserve.sov", "1.5"); // 1.5 SOV
const inclusion = await wallet.awaitInclusion(id);
console.log(`included in block ${inclusion.height}, final=${inclusion.final}`);
```

Low-level building blocks are exported too — `buildAndSign`, `encodeTransaction`,
`transactionId`, `sovToGrains`/`grainsToSov`, `assertValidAccountId`, and the
`PublicKey`/`Signature`/`Keypair` classes.

## Modules

```
sdk/
  src/
    units.ts       SOV <-> grains (BigInt, 8 decimals, 21M cap)
    account.ts     AccountId validation + hierarchy helpers
    keys.ts        Ed25519 keys / sign / verify (@noble)
    types.ts       Account / Tx / Block interfaces (chain JSON shapes)
    borsh.ts       canonical Borsh encoder + Blake3 tx id
    tx-builder.ts  build + sign node-submittable transactions
    rpc.ts         SovClient — typed JSON-RPC over fetch
    wallet.ts      Wallet — high-level helpers over the client
    index.ts       barrel
  test/            vitest suites (incl. KAT + a gated live e2e)
  vectors/         KAT vectors generated from the Rust node
```

## Install, build, test

```bash
npm install
npm run build       # tsc -> dist/
npm test            # vitest run (offline; the live e2e is skipped)

# run the live e2e against a running devnet node:
SOV_RPC=http://127.0.0.1:8645 \
SOV_SEED=0202…02 \
  npx vitest run test/e2e.test.ts
```

The offline suite is **92 tests** (units, account, keys, Borsh KAT, tx-builder,
rpc, wallet); the 2 live e2e tests run only when `SOV_RPC` is set.

## Dependencies

Two audited libraries only: [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519)
(RFC 8032 Ed25519, interoperable with the node's ed25519-dalek) and
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (Blake3 + SHA-512).
