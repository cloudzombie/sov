// REST API over the indexed store: read-only JSON. Returns `null` for paths
// outside `/api/` so the server falls through to static file serving. Live,
// balance-sensitive reads (accounts, supply) hit the node directly; historical
// reads (blocks, transactions) come from the index.

function json(status, body) {
  return { status, body: JSON.stringify(body) };
}

function clamp(v, lo, hi, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.max(lo, Math.min(hi, Math.trunc(n)));
}

export async function handleRest(method, pathname, query, ctx) {
  if (!pathname.startsWith('/api/')) return null;
  if (method !== 'GET') return json(405, { error: 'GET only' });

  const { store, rpc } = ctx;
  const parts = pathname.split('/').filter(Boolean); // ['api', <sub>, <arg>]
  const sub = parts[1];
  const arg = parts[2] !== undefined ? decodeURIComponent(parts[2]) : undefined;

  try {
    switch (sub) {
      case 'status':
        return json(200, store.stats());

      case 'blocks':
        return json(200, store.recentBlocks(clamp(query.get('limit'), 1, 200, 25)));

      case 'txs':
        return json(200, store.recentTxs(clamp(query.get('limit'), 1, 200, 25)));

      case 'block': {
        if (arg === undefined) return json(400, { error: 'missing block reference' });
        const ref = /^\d+$/.test(arg) ? Number(arg) : arg.toLowerCase();
        const block = store.block(ref);
        return block
          ? json(200, block)
          : json(404, { error: 'block not in the indexed window' });
      }

      case 'tx': {
        if (!arg) return json(400, { error: 'missing transaction id' });
        const tx = store.tx(arg.toLowerCase());
        return tx ? json(200, tx) : json(404, { error: 'transaction not indexed' });
      }

      case 'account': {
        if (!arg) return json(400, { error: 'missing account' });
        let id = arg;
        let resolvedFrom = null;
        let account = await rpc.account(id).catch(() => null);
        // If it isn't a funded account but IS a registered SNS name, resolve the
        // name to the account it points to (so a name is trackable/resolvable).
        if (!account) {
          const target = await rpc.resolveName(id).catch(() => null);
          if (target) {
            resolvedFrom = id;
            id = target;
            account = await rpc.account(id).catch(() => null);
          }
        }
        // SNS names that resolve to this account (reverse lookup).
        const names = await rpc.namesOf(id).catch(() => []);
        return json(200, { id, resolvedFrom, account, names, transactions: store.accountTxs(id, 50) });
      }

      // Sovereign Name Service: a page of registered names. Live from the node so
      // it reflects the current registry. Params: ?offset & ?limit.
      case 'names': {
        const offset = clamp(query.get('offset'), 0, 1e9, 0);
        const limit = clamp(query.get('limit'), 1, 200, 100);
        return json(200, await rpc.listNames(offset, limit));
      }

      // A single SNS name → its record (owner + registration height), or null.
      case 'name': {
        if (!arg) return json(400, { error: 'missing name' });
        return json(200, (await rpc.getName(arg)) ?? null);
      }

      case 'supply':
        return json(200, store.supply ?? (await rpc.supply()));

      case 'observed-miners':
        return json(200, { miners: store.observedMiners() });

      case 'validators': {
        return json(200, { validators: store.validators() });
      }

      case 'miners':
        return json(200, store.miners);

      case 'analytics':
        return json(200, { stats: store.stats(), supplySeries: store.supplySeries });

      case 'search': {
        const result = store.search(query.get('q') ?? '');
        // An unknown 0x-hash may be an older block outside our window — ask the node.
        if (result.kind === 'hash') {
          const blk = await rpc.blockByHash(result.ref).catch(() => null);
          if (blk) return json(200, { kind: 'block', ref: blk.header.height, known: true });
        }
        return json(200, result);
      }

      default:
        return json(404, { error: `unknown endpoint /api/${sub ?? ''}` });
    }
  } catch (e) {
    return json(502, { error: `upstream node error: ${e.message}` });
  }
}
