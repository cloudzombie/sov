#!/usr/bin/env node
// Generate a local Sovereign devnet for the explorer to index: a chain-spec, node
// config, and keystore with REAL Ed25519 public keys derived from seeds (using
// Node's built-in crypto — no dependencies). The derivation matches the chain's
// `Keypair::from_seed`: the 32-byte seed is the RFC 8032 ed25519 secret seed.
//
//   node devnet/gen-devnet.mjs
//
// Then run, from the chain workspace:
//   <sovereign-rpc-daemon> \
//     ../explorer/devnet/node-config.json \
//     ../explorer/devnet/chain-spec.json \
//     ../explorer/devnet/keystore.json

import { createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// PKCS#8 / SPKI wrappers for a raw ed25519 key (fixed ASN.1 prefixes).
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Raw 32-byte ed25519 public key (lowercase hex, no 0x) for a 32-byte seed. */
function pubkeyHex(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32).toString('hex');
}

const seedHex = (b) => Buffer.alloc(32, b).toString('hex');

// Validator val01 holds the entire stake (so it finalizes on its own); usa is a
// funded treasury. Balances are decimal-grain strings (1 XUS = 1e8 grains). This
// mirrors the proven devnet split that fits the 21M cap under the `test` policy.
const VAL_SEED = 1;
const USA_SEED = 2;

const chainSpec = {
  chain_id: 'sovereign-explorer-devnet',
  timestamp_ms: Date.now(),
  policy: 'test',
  accounts: [
    { account: 'val01.node.sovereign', public_key: pubkeyHex(VAL_SEED), stake: '100000000000000' }, // 1,000,000 XUS
    { account: 'usa.reserve.sovereign', public_key: pubkeyHex(USA_SEED), balance: '100000000000' }, // 1,000 XUS
  ],
};

const nodeConfig = {
  rpc_addr: '127.0.0.1:8645',
  rpc_workers: 2,
  data_dir: join(HERE, 'data'),
  block_time_ms: 1000,
  mempool_capacity: 16384,
  max_block_txs: 4096,
};

const keystore = {
  validators: [{ account: 'val01.node.sovereign', seed_hex: seedHex(VAL_SEED) }],
};

mkdirSync(join(HERE, 'data'), { recursive: true });
writeFileSync(join(HERE, 'chain-spec.json'), JSON.stringify(chainSpec, null, 2));
writeFileSync(join(HERE, 'node-config.json'), JSON.stringify(nodeConfig, null, 2));
writeFileSync(join(HERE, 'keystore.json'), JSON.stringify(keystore, null, 2));

console.log('Wrote devnet config to', HERE);
console.log('  chain id   :', chainSpec.chain_id);
console.log('  val01 key  :', chainSpec.accounts[0].public_key);
console.log('  usa key    :', chainSpec.accounts[1].public_key);
console.log('  rpc        :', nodeConfig.rpc_addr);
console.log('  usa seed   :', seedHex(USA_SEED), '(fund transfers with Sovereign wallet)');
