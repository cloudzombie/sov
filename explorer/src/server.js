#!/usr/bin/env node
// The Sovereign block explorer server: indexes a live node and serves a REST API, a
// GraphQL endpoint, a WebSocket live feed, and the static web UI — all from
// Node's standard library, no external dependencies.
//
//   sovereign-explorer [rpc_url] [port]
//   SOVEREIGN_RPC=http://host:8645 PORT=8730 node src/server.js

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';

import { SovereignRpc } from './rpc.js';
import { Store } from './store.js';
import { Indexer } from './indexer.js';
import { handleRest } from './rest.js';
import { executeGraphql, schemaRoots } from './graphql.js';
import { WsHub } from './ws.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB_DIR = normalize(join(HERE, '..', 'web'));

const RPC_URL = process.env.SOVEREIGN_RPC || process.argv[2] || 'http://127.0.0.1:8645';
const PORT = Number(process.env.PORT || process.argv[3] || 8730);

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
};

const rpc = new SovereignRpc(RPC_URL);
const store = new Store();
const wsHub = new WsHub();
const indexer = new Indexer(rpc, store, {
  onBlock: (b) => wsHub.broadcast({ type: 'block', block: blockSummary(b) }),
  onTx: (t) =>
    wsHub.broadcast({
      type: 'tx',
      tx: { id: t.id, signer: t.signer, action: t.action, blockHeight: t.blockHeight },
    }),
  // The node was re-genesised / rolled back: tell live clients to drop their view
  // and reload, so no stale block lingers in the UI.
  onReset: () => wsHub.broadcast({ type: 'reset' }),
});

function blockSummary(b) {
  return {
    height: b.height,
    hash: b.hash,
    proposer: b.proposer,
    txCount: b.txCount,
    timestampMs: b.timestampMs,
    final: b.final,
  };
}

function send(res, status, body, contentType = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'content-type': contentType, 'access-control-allow-origin': '*' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

async function serveStatic(res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const full = normalize(join(WEB_DIR, rel));
  if (full !== WEB_DIR && !full.startsWith(WEB_DIR + (process.platform === 'win32' ? '\\' : '/'))) {
    return send(res, 403, 'forbidden', 'text/plain');
  }
  try {
    const data = await readFile(full);
    const ext = full.slice(full.lastIndexOf('.'));
    send(res, 200, data, CONTENT_TYPES[ext] || 'application/octet-stream');
  } catch {
    send(res, 404, 'not found', 'text/plain');
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  if (pathname === '/graphql') {
    if (req.method !== 'POST') return send(res, 405, JSON.stringify({ errors: [{ message: 'POST only' }] }));
    const body = await readBody(req);
    let query = body;
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed.query === 'string') query = parsed.query;
    } catch {
      // body is a raw GraphQL query string
    }
    const result = await executeGraphql(query, { store, rpc }, schemaRoots);
    return send(res, 200, JSON.stringify(result));
  }

  const rest = await handleRest(req.method, pathname, url.searchParams, { store, rpc });
  if (rest) return send(res, rest.status, rest.body);

  return serveStatic(res, pathname);
});

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/ws') wsHub.handleUpgrade(req, socket);
  else socket.destroy();
});

server.listen(PORT, () => {
  console.log(`sovereign-explorer: web UI + API on http://127.0.0.1:${PORT}`);
  console.log(`sovereign-explorer: indexing live node at ${RPC_URL}`);
  indexer.start(1000);
});
