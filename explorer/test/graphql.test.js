// Unit tests for the hand-rolled GraphQL engine: arguments, nested selections,
// aliases, and error handling.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { executeGraphql } from '../src/graphql.js';

const roots = {
  hello: () => 'world',
  block: (a) => ({ height: a.height, hash: '0xabc', transactions: [{ id: 't1' }, { id: 't2' }] }),
  who: (a) => ({ name: a.name, admin: a.admin, note: a.note }),
  boom: () => {
    throw new Error('resolver failed');
  },
};

test('resolves a scalar field', async () => {
  const r = await executeGraphql('{ hello }', {}, roots);
  assert.deepEqual(r, { data: { hello: 'world' } });
});

test('integer args, nested selection, and alias', async () => {
  const r = await executeGraphql('query { b: block(height: 5) { height transactions { id } } }', {}, roots);
  assert.deepEqual(r.data.b, { height: 5, transactions: [{ id: 't1' }, { id: 't2' }] });
});

test('string, boolean, and null arguments parse', async () => {
  const r = await executeGraphql('{ who(name: "ada", admin: true, note: null) { name admin note } }', {}, roots);
  assert.deepEqual(r.data.who, { name: 'ada', admin: true, note: null });
});

test('unknown field yields an error but does not abort the query', async () => {
  const r = await executeGraphql('{ hello nope }', {}, roots);
  assert.equal(r.data.hello, 'world');
  assert.ok(r.errors.some((e) => /nope/.test(e.message)));
});

test('a throwing resolver is isolated', async () => {
  const r = await executeGraphql('{ boom hello }', {}, roots);
  assert.equal(r.data.boom, null);
  assert.equal(r.data.hello, 'world');
  assert.ok(r.errors.length === 1);
});

test('syntax errors are reported, not thrown', async () => {
  const r = await executeGraphql('{ block(height: ', {}, roots);
  assert.ok(r.errors[0].message.startsWith('Syntax error'));
});
