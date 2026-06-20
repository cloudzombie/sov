// Unit test for block normalization: the RPC's snake_case block + digest are
// mapped to the store's record shape. The input mirrors a real block-by-height
// + block-digest response captured from a live node.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeBlock } from '../src/indexer.js';

test('normalizeBlock maps real RPC shapes', () => {
  const block = {
    header: {
      height: 1,
      prev_hash: '0x' + 'd5'.repeat(32),
      tx_root: '0x' + 'ef'.repeat(32),
      receipts_root: '0x' + '30'.repeat(32),
      state_root: '0x' + '18'.repeat(32),
      timestamp_ms: 1_780_000_000_000,
      proposer: 'val01.node.sovereign',
    },
    transactions: [
      {
        transaction: {
          signer: 'usa.reserve.sovereign',
          public_key: '0x' + '81'.repeat(32),
          nonce: 0,
          action: { type: 'transfer', to: 'ecb.reserve.sovereign', amount: '10000000000' },
        },
        signature: '0x' + '7f'.repeat(64),
      },
    ],
  };
  const digest = { hash: '0x' + 'ac'.repeat(32), txIds: ['0x' + '21'.repeat(32)] };

  const rec = normalizeBlock(block, digest, true);
  assert.equal(rec.height, 1);
  assert.equal(rec.hash, '0x' + 'ac'.repeat(32));
  assert.equal(rec.prevHash, '0x' + 'd5'.repeat(32));
  assert.equal(rec.stateRoot, '0x' + '18'.repeat(32));
  assert.equal(rec.proposer, 'val01.node.sovereign');
  assert.equal(rec.final, true);
  assert.equal(rec.txCount, 1);

  const t = rec.transactions[0];
  assert.equal(t.id, '0x' + '21'.repeat(32), 'canonical tx id from digest');
  assert.equal(t.index, 0);
  assert.equal(t.signer, 'usa.reserve.sovereign');
  assert.equal(t.action.type, 'transfer');
  assert.equal(t.action.to, 'ecb.reserve.sovereign');
  assert.equal(t.blockHeight, 1);
  assert.equal(t.blockHash, rec.hash);
});
