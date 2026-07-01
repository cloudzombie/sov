// Sovereign Explorer — single-page UI. Hash-routed, fetches the REST API, and follows
// a WebSocket live feed. All values shown are real chain data served by the node.

const $ = (id) => document.getElementById(id);
const view = $('view');

// ---- formatting -----------------------------------------------------------

const COIN_SYMBOL = 'XUS';
const GRAINS = 100000000n; // 1 XUS = 1e8 grains

function group(s) {
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
function fmtCoin(grains) {
  if (grains === null || grains === undefined) return '—';
  let g;
  try {
    g = BigInt(grains);
  } catch {
    return String(grains);
  }
  const neg = g < 0n;
  if (neg) g = -g;
  let s = group((g / GRAINS).toString());
  const frac = g % GRAINS;
  if (frac > 0n) s += '.' + frac.toString().padStart(8, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + s;
}
function fmtNum(n) {
  return group(String(n ?? 0));
}
function fmtDecimal(n, digits = 2) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '—';
  return Number(n).toFixed(digits).replace(/\.?0+$/, '');
}
function fmtUsd(n) {
  if (n === null || n === undefined) return '— USD';
  return `${fmtNum(n)} USD`;
}
function fmtBytes(bytes) {
  if (bytes === null || bytes === undefined) return '—';
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${fmtDecimal(value, value >= 100 ? 0 : 2)} ${units[i]}`;
}

/** Format a hash rate (hashes/second) with SI-scaled units. */
function fmtHashrate(hps) {
  if (hps === null || hps === undefined) return '—';
  const n = Number(hps);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'];
  let value = n;
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i += 1;
  }
  return `${fmtDecimal(value, value >= 100 ? 0 : 2)} ${units[i]}`;
}
function shortHash(h, head = 10, tail = 8) {
  if (!h) return '—';
  return h.length > head + tail + 2 ? `${h.slice(0, head)}…${h.slice(-tail)}` : h;
}
function timeAgo(ms) {
  if (!ms) return '—';
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(ms).toLocaleDateString();
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function pct(x) {
  if (x === null || x === undefined || Number.isNaN(Number(x))) return '—';
  return (Number(x) * 100).toFixed(2) + '%';
}
function statItem(label, value, sub = '') {
  return `<div class="stat-item">
    <div>
      <div class="stat-label">${esc(label)}</div>
      <div class="stat-value">${value}</div>
      ${sub ? `<div class="stat-sub">${esc(sub)}</div>` : ''}
    </div>
    <span class="stat-arrow" aria-hidden="true">↗</span>
  </div>`;
}

async function api(path) {
  const res = await fetch('/api' + path);
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(e.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function setView(html) {
  view.innerHTML = html;
}
function errView(msg) {
  setView(`<div class="empty">⚠ ${esc(msg)}<br /><span class="dim">Is a Sovereign node running and reachable?</span></div>`);
}

// ---- links + render helpers -----------------------------------------------

const blockLink = (h) => `<a href="#/block/${h}" class="mono">#${fmtNum(h)}</a>`;
const blockHashLink = (hash) => `<a href="#/block/${hash}" class="mono">${shortHash(hash)}</a>`;
const txLink = (id) => `<a href="#/tx/${id}" class="mono">${shortHash(id)}</a>`;
const acctLink = (a) => `<a href="#/account/${encodeURIComponent(a)}" class="mono">${esc(a)}</a>`;
// Like acctLink but abbreviates a long implicit id (a35755d3…4c1e24); short
// human names (founder.tax.sov) are left whole.
const acctLinkShort = (a) =>
  `<a href="#/account/${encodeURIComponent(a)}" class="mono" title="${esc(a)}">${esc(shortHash(a, 8, 6))}</a>`;

function actionBadge(action) {
  const t = action?.type ?? 'unknown';
  return `<span class="badge act">${esc(t)}</span>`;
}
function actionSummary(action) {
  if (!action) return '';
  switch (action.type) {
    case 'transfer':
      return `→ ${acctLink(action.to)} · <b>${fmtCoin(action.amount)}</b> ${COIN_SYMBOL}`;
    case 'token_issue':
      return `<b>${fmtCoin(action.amount)}</b> ${esc(action.symbol)} · to ${acctLink(action.to)}`;
    case 'token_transfer':
      return `asset ${shortHash(action.asset, 8, 6)} → ${acctLink(action.to)} · <b>${fmtCoin(action.amount)}</b>`;
    case 'token_burn':
      return `asset ${shortHash(action.asset, 8, 6)} · <b>${fmtCoin(action.amount)}</b>`;
    case 'shielded':
      return `shielded bundle (${fmtBytes((action.bundle || []).length)})`;
    case 'htlc_lock':
      return `HTLC lock → ${acctLink(action.recipient)} · <b>${fmtCoin(action.amount)}</b> ${COIN_SYMBOL}`;
    case 'htlc_claim':
      return `HTLC claim ${shortHash(action.htlc_id, 8, 6)}`;
    case 'htlc_refund':
      return `HTLC refund ${shortHash(action.htlc_id, 8, 6)}`;
    case 'call':
      return `→ ${acctLink(action.contract)} · gas ${fmtNum(action.gas_limit)}`;
    case 'deploy':
      return `WASM contract (${fmtNum((action.code || []).length)} bytes)`;
    case 'claim_vesting':
      return `claim vested allocation`;
    case 'register_name':
      return `register SNS name <b>${esc(action.name)}</b>`;
    case 'transfer_name':
      return `name <b>${esc(action.name)}</b> → ${acctLink(action.to)}`;
    case 'nft_mint':
      return `mint NFT in <b>${esc(action.symbol)}</b> → ${acctLink(action.to)}`;
    case 'nft_transfer':
      return `NFT → ${acctLink(action.to)}`;
    case 'nft_set_meta':
      return `set NFT metadata`;
    default:
      return '';
  }
}
function finalBadge(final) {
  return final
    ? `<span class="badge final">Final</span>`
    : `<span class="badge pending">Pending</span>`;
}

// ---- views ----------------------------------------------------------------

async function renderOverview() {
  setView('<div class="loading">Loading overview…</div>');
  const [status, blocks, txs, supply] = await Promise.all([
    api('/status'),
    api('/blocks?limit=12'),
    api('/txs?limit=12'),
    api('/supply').catch(() => null),
  ]);
  const s = status;
  const all = s.allTime ?? {};
  const day = s.last24h ?? {};
  const mempool = s.mempool ?? {};
  setView(`
    <section class="hero-strip">
      <div>
        <h1>Sovereign</h1>
        <p>${esc(s.chainId || 'Chain')} · height ${fmtNum(s.tipHeight < 0 ? 0 : s.tipHeight)}</p>
      </div>
      <div class="hero-meta">
        <span>Genesis ${shortHash(s.genesisHash, 10, 6)}</span>
        <span>${fmtNum(s.blocksIndexed)} indexed blocks</span>
      </div>
    </section>

    <div class="stat-columns">
      <section class="stat-card">
        <h2>All time</h2>
        ${statItem('Circulation', `${fmtCoin(all.circulationGrains)} ${COIN_SYMBOL}`, `${pct(s.mintedOfCap)} of 21,000,000 cap minted`)}
        ${statItem('Shielded supply', supply ? `${fmtDecimal(supply.shieldedPercent ?? 0, 2)}%` : '—', supply ? `${fmtCoin(supply.shielded)} ${COIN_SYMBOL} private of ${fmtCoin(supply.total)} (Zcash-style)` : 'node unreachable')}
        ${statItem('Market cap', fmtUsd(all.marketCapUsd), 'price feed not configured')}
        ${statItem('Market dominance', all.marketDominance === null || all.marketDominance === undefined ? '—' : pct(all.marketDominance), 'market feed not configured')}
        ${statItem('Blockchain size', fmtBytes(all.blockchainSizeBytes), 'indexed window')}
        ${statItem('Network nodes', all.networkNodes === null || all.networkNodes === undefined ? '—' : fmtNum(all.networkNodes), 'miner registry entries')}
        ${statItem('Difficulty', all.difficulty === null || all.difficulty === undefined ? '—' : esc(fmtNum(all.difficulty)), 'SHA-256d')}
      </section>

      <section class="stat-card">
        <h2>24h statistics</h2>
        ${statItem('Transactions', fmtNum(day.transactions))}
        ${statItem('Transactions per second', fmtDecimal(day.transactionsPerSecond ?? 0, 4))}
        ${statItem('Blocks', fmtNum(day.blocks))}
        ${statItem('Volume', `${fmtCoin(day.volumeGrains)} ${COIN_SYMBOL}`, `transparent ${COIN_SYMBOL} volume`)}
        ${statItem('Median transaction fee', fmtUsd(day.medianTransactionFeeUsd), 'fee index not exposed by node')}
        ${statItem('Average transaction fee', fmtUsd(day.averageTransactionFeeUsd), 'fee index not exposed by node')}
        ${statItem('Hashrate', fmtHashrate(day.hashrate), day.hashrate == null ? 'measuring — needs a few blocks' : 'estimated from recent block work')}
      </section>

      <section class="stat-card">
        <h2>Mempool</h2>
        ${statItem('Transactions', fmtNum(mempool.transactions))}
        ${statItem('Transactions per second', mempool.transactionsPerSecond === null || mempool.transactionsPerSecond === undefined ? '—' : fmtDecimal(mempool.transactionsPerSecond, 4))}
        ${statItem('Outputs', mempool.outputs === null || mempool.outputs === undefined ? '—' : fmtNum(mempool.outputs))}
        ${statItem('Fee total', fmtUsd(mempool.feeTotalUsd), 'fee index not exposed by node')}
        ${statItem('Size', fmtBytes(mempool.sizeBytes), 'mempool bytes not exposed')}
      </section>
    </div>

    <div class="grid2">
      <div>
        <h2>Latest Blocks</h2>
        <div class="panel"><table><thead><tr><th>Height</th><th>Miner</th><th class="right">Txs</th><th class="right">Coinbase</th><th>Age</th><th></th></tr></thead>
        <tbody id="ov-blocks">${blocks.map(blockRow).join('') || emptyRow(6)}</tbody></table></div>
      </div>
      <div>
        <h2>Latest Transactions</h2>
        <div class="panel"><table><thead><tr><th>Tx</th><th>Type</th><th>Age</th><th>Signer</th><th class="right">Block</th></tr></thead>
        <tbody id="ov-txs">${txs.map(txRow).join('') || emptyRow(5)}</tbody></table></div>
      </div>
    </div>
  `);
}

function blockRow(b) {
  const coinbase = b.coinbase ? fmtCoin(b.coinbase.reward) + ' ' + COIN_SYMBOL : '<span class="dim">—</span>';
  return `<tr><td>${blockLink(b.height)}</td><td>${acctLinkShort(b.proposer)}</td><td class="right num">${b.txCount}</td><td class="right num">${coinbase}</td><td class="dim" title="${esc(new Date(b.timestampMs).toLocaleString())}">${timeAgo(b.timestampMs)}</td><td>${finalBadge(b.final)}</td></tr>`;
}
function txRow(t) {
  return `<tr><td>${txLink(t.id)}</td><td>${actionBadge(t.action)}</td><td class="dim" title="${esc(new Date(t.timestampMs).toLocaleString())}">${timeAgo(t.timestampMs)}</td><td>${acctLinkShort(t.signer)}</td><td class="right">${blockLink(t.blockHeight)}</td></tr>`;
}
function emptyRow(cols) {
  return `<tr><td colspan="${cols}" class="empty">No data yet — waiting for blocks.</td></tr>`;
}

async function renderBlocks() {
  setView('<div class="loading">Loading blocks…</div>');
  const blocks = await api('/blocks?limit=60');
  setView(`
    <h1>Blocks</h1>
    <div class="panel"><table><thead><tr><th>Height</th><th>Hash</th><th>Miner</th><th class="right">Txs</th><th class="right">Coinbase</th><th>Timestamp</th><th></th></tr></thead>
    <tbody>${blocks.map((b) => `<tr><td>${blockLink(b.height)}</td><td>${blockHashLink(b.hash)}</td><td>${acctLinkShort(b.proposer)}</td><td class="right num">${b.txCount}</td><td class="right num">${b.coinbase ? fmtCoin(b.coinbase.reward) + ' ' + COIN_SYMBOL : '<span class="dim">—</span>'}</td><td class="dim">${new Date(b.timestampMs).toLocaleString()}</td><td>${finalBadge(b.final)}</td></tr>`).join('') || emptyRow(7)}</tbody></table></div>
  `);
}

async function renderBlock(ref) {
  setView('<div class="loading">Loading block…</div>');
  let b;
  try {
    b = await api('/block/' + encodeURIComponent(ref));
  } catch (e) {
    return errView(e.message);
  }
  const txs = b.transactions || [];
  setView(`
    <div class="crumb"><a href="#/blocks">Blocks</a> / Block #${fmtNum(b.height)}</div>
    <h1>Block #${fmtNum(b.height)} ${finalBadge(b.final)}</h1>
    <div class="panel"><table class="kv">
      <tr><td class="k">Hash</td><td class="v">${esc(b.hash)}</td></tr>
      <tr><td class="k">Parent</td><td class="v">${b.height > 0 ? blockHashLink(b.prevHash) : '<span class="dim">genesis</span>'}</td></tr>
      <tr><td class="k">Miner</td><td class="v">${acctLink(b.proposer)}</td></tr>
      <tr><td class="k">Timestamp</td><td class="v">${new Date(b.timestampMs).toLocaleString()} <span class="dim">(${esc(b.timestampMs)} ms)</span></td></tr>
      <tr><td class="k">Transactions</td><td class="v">${b.txCount}</td></tr>
      <tr><td class="k">State root</td><td class="v">${esc(b.stateRoot)}</td></tr>
      <tr><td class="k">Tx root</td><td class="v">${esc(b.txRoot)}</td></tr>
      <tr><td class="k">Receipts root</td><td class="v">${esc(b.receiptsRoot)}</td></tr>
      <tr><td class="k">Finality</td><td class="v">${b.final ? 'Final — buried past the Nakamoto confirmation depth' : 'Pending — waiting for more confirmations'}</td></tr>
    </table></div>
    ${coinbasePanel(b.coinbase)}
    <h2>Transactions</h2>
    <div class="panel"><table><thead><tr><th>Tx</th><th>Type</th><th>Signer</th><th>Detail</th></tr></thead>
    <tbody>${txs.map((t) => `<tr><td>${txLink(t.id)}</td><td>${actionBadge(t.action)}</td><td>${acctLinkShort(t.signer)}</td><td>${actionSummary(t.action)}</td></tr>`).join('') || emptyRow(4)}</tbody></table></div>
  `);
}

/** Human label for a coinbase recipient's role. */
function coinbaseRole(role) {
  return (
    { miner: 'Miner (proof-of-work)', 'founder-tax': 'Founder tax', 'dev-tax': 'Dev tax' }[role] ||
    esc(role)
  );
}

/** The Coinbase panel: a block's real issuance — the minted subsidy and its
 * miner / founder-tax / dev-tax split. Shown for every mined block (genesis
 * mints nothing, so it has no coinbase). */
function coinbasePanel(cb) {
  if (!cb) return '';
  const reward = Number(cb.reward) || 0;
  const rows = (cb.recipients || [])
    .map((r) => {
      const share = reward > 0 ? ((Number(r.amount) / reward) * 100).toFixed(0) : '0';
      return `<tr><td>${acctLink(r.account)}</td><td>${coinbaseRole(r.role)} <span class="dim">${share}%</span></td><td>${fmtCoin(r.amount)} ${COIN_SYMBOL}</td></tr>`;
    })
    .join('');
  return `
    <h2>Coinbase <span class="dim">— newly minted this block</span></h2>
    <div class="panel"><table class="kv">
      <tr><td class="k">Subsidy minted</td><td class="v">${fmtCoin(cb.reward)} ${COIN_SYMBOL}</td></tr>
    </table></div>
    <div class="panel"><table><thead><tr><th>Recipient</th><th>Share</th><th>Amount</th></tr></thead>
    <tbody>${rows || emptyRow(3)}</tbody></table></div>`;
}

async function renderTx(id) {
  setView('<div class="loading">Loading transaction…</div>');
  let t;
  try {
    t = await api('/tx/' + encodeURIComponent(id));
  } catch (e) {
    return errView(e.message);
  }
  setView(`
    <div class="crumb">Transaction</div>
    <h1>Transaction ${actionBadge(t.action)}</h1>
    <div class="panel"><table class="kv">
      <tr><td class="k">Id</td><td class="v">${esc(t.id)}</td></tr>
      <tr><td class="k">Block</td><td class="v">${blockLink(t.blockHeight)} · ${blockHashLink(t.blockHash)}</td></tr>
      <tr><td class="k">Position</td><td class="v">#${t.index} in block</td></tr>
      <tr><td class="k">Signer</td><td class="v">${acctLink(t.signer)}</td></tr>
      <tr><td class="k">Nonce</td><td class="v">${fmtNum(t.nonce)}</td></tr>
      <tr><td class="k">Action</td><td class="v">${esc(t.action?.type)} — ${actionSummary(t.action)}</td></tr>
      <tr><td class="k">Public key</td><td class="v">${esc(t.publicKey)}</td></tr>
      <tr><td class="k">Signature</td><td class="v">${esc(t.signature)}</td></tr>
      <tr><td class="k">Timestamp</td><td class="v">${new Date(t.timestampMs).toLocaleString()}</td></tr>
    </table></div>
  `);
}

async function renderAccount(idRaw) {
  const id = decodeURIComponent(idRaw);
  setView('<div class="loading">Loading account…</div>');
  let data;
  try {
    data = await api('/account/' + encodeURIComponent(id));
  } catch (e) {
    return errView(e.message);
  }
  const a = data.account;
  const acct = data.id || id; // the resolved account (if `id` was an SNS name)
  const txs = data.transactions || [];
  const names = data.names || [];
  const locked = a?.locked ?? '0';
  const kv = a
    ? `
      <tr><td class="k">Liquid balance</td><td class="v">${fmtCoin(a.balance)} ${COIN_SYMBOL}</td></tr>
      <tr><td class="k">Locked (vesting)</td><td class="v">${fmtCoin(locked)} ${COIN_SYMBOL} ${locked !== '0' && a.unlock_height !== undefined ? `<span class="dim">(unlocks at height ${fmtNum(a.unlock_height)})</span>` : ''}</td></tr>
      <tr><td class="k">Nonce</td><td class="v">${fmtNum(a.nonce)}</td></tr>
      <tr><td class="k">Key</td><td class="v">${a.key ? esc(a.key) : '<span class="dim">none (receive-only)</span>'}</td></tr>
      <tr><td class="k">Type</td><td class="v">${a.code ? 'WASM contract' : 'account'}</td></tr>`
    : `<tr><td class="v empty" colspan="2">This account is not funded on-chain (it holds no state).</td></tr>`;
  setView(`
    <div class="crumb">Account${data.resolvedFrom ? ` · resolved from SNS name` : ''}</div>
    <h1 class="mono">${esc(acct)}</h1>
    ${data.resolvedFrom ? `<p class="dim">↳ <span class="mono">${esc(data.resolvedFrom)}</span> resolves here</p>` : ''}
    ${names.length ? `<p class="dim">SNS: ${names.map((n) => `<span class="mono">${esc(n)}</span>`).join(', ')}</p>` : ''}
    <div class="panel"><table class="kv">${kv}</table></div>
    <h2>Indexed Transactions</h2>
    <div class="panel"><table><thead><tr><th>Tx</th><th>Type</th><th>Detail</th><th class="right">Block</th></tr></thead>
    <tbody>${txs.map((t) => `<tr><td>${txLink(t.id)}</td><td>${actionBadge(t.action)}</td><td>${t.signer === acct ? actionSummary(t.action) : `from ${acctLink(t.signer)}`}</td><td class="right">${blockLink(t.blockHeight)}</td></tr>`).join('') || emptyRow(4)}</tbody></table></div>
    <p class="note">Transaction history is from the explorer's indexed window; balances are read live from the node.</p>
  `);
}

async function renderMiners() {
  setView('<div class="loading">Loading miners…</div>');
  const [observed, miners] = await Promise.all([api('/observed-miners'), api('/miners')]);
  setView(`
    <h1>Miners</h1>
    <div class="cards">
      <div class="card"><div class="label">Active miners</div><div class="value num">${observed.miners.length}</div><div class="sub">observed in indexed blocks</div></div>
      <div class="card"><div class="label">Registered miners</div><div class="value num">${miners.length}</div><div class="sub">reported by the node</div></div>
      <div class="card"><div class="label">Consensus</div><div class="value mono" style="font-size:16px">Nakamoto</div><div class="sub">heaviest-work fork choice</div></div>
    </div>
    <h2>Observed Block Miners</h2>
    <div class="panel"><table><thead><tr><th>Miner</th><th class="right">Blocks mined</th><th class="right">Last height</th></tr></thead>
    <tbody>${observed.miners.map((x) => `<tr><td>${acctLink(x.account)}</td><td class="right num">${fmtNum(x.blocksMined)}</td><td class="right">${blockLink(x.lastHeight)}</td></tr>`).join('') || emptyRow(3)}</tbody></table></div>
    <h2>Miner Registry</h2>
    <div class="panel"><table><thead><tr><th>Miner</th><th class="right">Blocks mined</th><th class="right">First seen</th><th class="right">Last seen</th></tr></thead>
    <tbody>${miners.map((m) => `<tr><td>${acctLink(m.account)}</td><td class="right num">${fmtNum(m.blocksMined ?? m.mineTxs ?? 0)}</td><td class="right">${blockLink(m.firstSeenHeight)}</td><td class="right">${blockLink(m.lastSeenHeight)}</td></tr>`).join('') || emptyRow(4)}</tbody></table></div>
  `);
}

function snsCard(n) {
  return `<div class="sns-card">
    <div class="sns-head">
      <a class="sns-name" href="#/account/${encodeURIComponent(n.name)}">${esc(n.name)}</a>
      <span class="chip sns">SNS · NFT</span>
    </div>
    <div class="sns-row"><span class="k">resolves to</span> ${acctLinkShort(n.owner)}</div>
    <div class="sns-row"><span class="k">registered</span> ${blockLink(n.registeredHeight)}</div>
  </div>`;
}

async function renderSns() {
  setView('<div class="loading">Loading names…</div>');
  // The Sovereign Name Service: human-readable *.sov names that resolve to
  // accounts. Each name is a non-fungible token in the reserved SNS collection.
  const page = await api('/names?limit=200');
  const names = page.names ?? [];
  const total = page.total ?? names.length;
  setView(`
    <section class="hero-strip">
      <div>
        <h1>SNS</h1>
        <p>Sovereign Name Service · ${fmtNum(total)} name${total === 1 ? '' : 's'} registered</p>
      </div>
      <div class="hero-meta">
        <span>names are NFTs</span>
        <span>name → account resolver</span>
      </div>
    </section>

    <div class="sns-lookup">
      <input id="sns-q" type="text" placeholder="resolve a name — e.g. alice.sov" autocomplete="off" spellcheck="false" />
      <button id="sns-go" class="sns-btn">Resolve</button>
    </div>

    ${
      names.length
        ? `<div class="sns-grid">${names.map(snsCard).join('')}</div>`
        : `<div class="panel empty-state"><div class="es-title">No names registered yet</div><div class="dim">Register one in SOV Station → Wallet → Sovereign Name Service.</div></div>`
    }

    <p class="note">Each name is a non-fungible token (token id = the name) in the reserved SNS collection — owned, transferable, and resolvable. The registry and resolution are consensus state every node agrees on.</p>
  `);
  const go = () => {
    const v = (document.getElementById('sns-q')?.value || '').trim();
    if (v) location.hash = '#/account/' + encodeURIComponent(v);
  };
  document.getElementById('sns-go')?.addEventListener('click', go);
  document.getElementById('sns-q')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') go();
  });
}

async function renderAnalytics() {
  setView('<div class="loading">Loading analytics…</div>');
  const { stats, supplySeries } = await api('/analytics');
  setView(`
    <h1>Analytics</h1>
    <div class="cards">
      <div class="card"><div class="label">Total supply</div><div class="value num">${fmtCoin(stats.supply?.total)}<span class="unit">${COIN_SYMBOL}</span></div></div>
      <div class="card"><div class="label">Mined (PoW)</div><div class="value num">${fmtCoin(stats.supply?.mined)}<span class="unit">${COIN_SYMBOL}</span></div><div class="sub">${pct(stats.mintedOfCap)} of 21M cap</div><div class="bar"><i style="width:${Math.min(100, (stats.mintedOfCap ?? 0) * 100)}%"></i></div></div>
      <div class="card"><div class="label">Shielded supply</div><div class="value num">${fmtDecimal(stats.supply?.shieldedPercent ?? 0, 2)}<span class="unit">%</span></div><div class="sub">${fmtCoin(stats.supply?.shielded)} ${COIN_SYMBOL} private (Zcash-style)</div><div class="bar"><i style="width:${Math.min(100, stats.supply?.shieldedPercent ?? 0)}%"></i></div></div>
      <div class="card"><div class="label">Finality depth</div><div class="value num">6</div><div class="sub">confirmation convention</div></div>
      <div class="card"><div class="label">Mempool</div><div class="value num">${fmtNum(stats.mempoolSize)}</div></div>
      <div class="card"><div class="label">Blocks indexed</div><div class="value num">${fmtNum(stats.blocksIndexed)}</div></div>
      <div class="card"><div class="label">Transactions indexed</div><div class="value num">${fmtNum(stats.transactionsIndexed)}</div></div>
    </div>
    <h2>Issuance Over Time</h2>
    <div class="panel" style="padding:18px">${issuanceChart(supplySeries)}
      <div class="legend"><span><i style="background:#3f6fff"></i>Mined (PoW)</span></div>
    </div>
    <p class="note">Issuance is sampled live as the explorer follows the chain — each point is the chain's committed supply at that height. The 21,000,000 ${COIN_SYMBOL} hard cap is enforced on-chain by exact-integer accounting.</p>
  `);
}

function issuanceChart(series) {
  if (!series || series.length < 2) {
    return '<div class="empty">Collecting issuance samples as new blocks arrive…</div>';
  }
  const W = 1000;
  const H = 200;
  const pad = 8;
  const xs = series.map((p) => p.height);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const coin = (g) => Number(BigInt(g) / 1000000n) / 100; // coin units with 2dp, safe
  const mined = series.map((p) => coin(p.mined));
  const maxY = Math.max(1, ...mined);
  const X = (x) => pad + ((x - minX) / Math.max(1, maxX - minX)) * (W - 2 * pad);
  const Y = (y) => H - pad - (y / maxY) * (H - 2 * pad);
  const path = (vals) => vals.map((y, i) => `${i === 0 ? 'M' : 'L'}${X(xs[i]).toFixed(1)},${Y(y).toFixed(1)}`).join(' ');
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <line class="axis" x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" />
    <path class="series-mined" d="${path(mined)}" />
  </svg>`;
}

async function renderValidity() {
  setView('<div class="loading">Loading validity view…</div>');
  const blocks = await api('/blocks?limit=40');
  const finalCount = blocks.filter((b) => b.final).length;
  setView(`
    <h1>Validity &amp; Finality</h1>
    <p class="note">
      Every Sovereign block carries three Merkle/state roots, and finality is a
      confirmation depth on the heaviest-work chain.
      A block's state transition is re-executed and re-checked on every node that
      imports it, and the chain's invariants (supply ≤ 21M cap, value conservation,
      no unauthorized mint) are enforced by exact-integer accounting. This view shows
      the live finality and committed roots of recent blocks.
    </p>
    <div class="cards">
      <div class="card"><div class="label">Recent window</div><div class="value num">${blocks.length}</div><div class="sub">blocks</div></div>
      <div class="card"><div class="label">Final</div><div class="value num">${finalCount}</div><div class="sub">past confirmation depth</div></div>
      <div class="card"><div class="label">Pending</div><div class="value num">${blocks.length - finalCount}</div><div class="sub">waiting for confirmations</div></div>
    </div>
    <div class="panel"><table><thead><tr><th>Height</th><th>State root</th><th>Tx root</th><th>Receipts root</th><th>Finality</th></tr></thead>
    <tbody>${blocks
      .map(
        (b) =>
          `<tr><td>${blockLink(b.height)}</td><td class="mono dim">${shortHash(b.stateRoot, 10, 6)}</td><td class="mono dim">${shortHash(b.txRoot, 10, 6)}</td><td class="mono dim">${shortHash(b.receiptsRoot, 10, 6)}</td><td>${finalBadge(b.final)}</td></tr>`,
      )
      .join('') || emptyRow(5)}</tbody></table></div>
  `);
}

async function resolveSearch(q) {
  try {
    const r = await api('/search?q=' + encodeURIComponent(q));
    if (r.kind === 'block') location.hash = '#/block/' + r.ref;
    else if (r.kind === 'tx') location.hash = '#/tx/' + r.ref;
    else if (r.kind === 'account') location.hash = '#/account/' + encodeURIComponent(r.ref);
    else errView(`Nothing found for “${q}”.`);
  } catch (e) {
    errView(e.message);
  }
}

// ---- router ---------------------------------------------------------------

function route() {
  const hash = location.hash.replace(/^#/, '') || '/';
  const [, head, arg] = hash.split('/');
  setActiveNav(hash);
  if (!head) return renderOverview();
  if (head === 'blocks') return renderBlocks();
  if (head === 'block') return renderBlock(arg);
  if (head === 'tx') return renderTx(arg);
  if (head === 'account') return renderAccount(arg);
  if (head === 'miners' || head === 'validators') return renderMiners();
  if (head === 'analytics') return renderAnalytics();
  if (head === 'sns') return renderSns();
  if (head === 'validity') return renderValidity();
  return renderOverview();
}

function setActiveNav(hash) {
  const top = '#/' + (hash.split('/')[1] || '');
  for (const a of document.querySelectorAll('.nav a')) {
    a.classList.toggle('active', a.getAttribute('href') === top);
  }
}

window.addEventListener('hashchange', () => route().catch((e) => errView(e.message)));

$('search').addEventListener('submit', (e) => {
  e.preventDefault();
  const q = $('q').value.trim();
  if (q) resolveSearch(q);
});

// ---- live feed + header status --------------------------------------------

function drawSealStars() {
  const g = $('seal-stars');
  if (!g) return;
  let s = '';
  for (let i = 0; i < 13; i++) {
    const a = (i / 13) * Math.PI * 2 - Math.PI / 2;
    const x = 32 + Math.cos(a) * 28;
    const y = 32 + Math.sin(a) * 28;
    s += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="1.1" />`;
  }
  g.innerHTML = s;
}

function pushTicker(text) {
  const items = $('ticker-items');
  const t = $('ticker');
  if (!items) return;
  t.hidden = false;
  const chip = document.createElement('span');
  chip.className = 'ticker-chip';
  chip.innerHTML = text;
  items.prepend(chip);
  while (items.children.length > 14) items.lastChild.remove();
}

function setConn(state) {
  const c = $('conn');
  const txt = $('conn-text');
  c.className = 'conn ' + state;
  txt.textContent = state === 'live' ? 'live' : state === 'down' ? 'offline' : 'connecting…';
}

function connectWs() {
  let ws;
  try {
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  } catch {
    setConn('down');
    return;
  }
  ws.onopen = () => setConn('live');
  ws.onclose = () => {
    setConn('down');
    setTimeout(connectWs, 2500);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (msg.type === 'reset') {
      // The node was re-genesised / rolled back; the old view is dead. Reload to
      // re-render against the fresh chain.
      pushTicker('<b>chain reset</b> · reloading…');
      setTimeout(() => location.reload(), 400);
    } else if (msg.type === 'block') {
      const b = msg.block;
      pushTicker(`<b>Block #${fmtNum(b.height)}</b> · ${b.txCount} tx`);
      if ((location.hash.replace(/^#/, '') || '/') === '/') {
        const tb = $('ov-blocks');
        if (tb) {
          tb.insertAdjacentHTML('afterbegin', blockRow(b));
          while (tb.children.length > 12) tb.lastChild.remove();
        }
      }
    } else if (msg.type === 'tx') {
      pushTicker(`tx <b>${esc(msg.tx.action?.type || 'tx')}</b> · ${shortHash(msg.tx.id)}`);
    }
  };
}

async function pollStatus() {
  try {
    const s = await api('/status');
    $('foot-chain').textContent = s.chainId ? `${s.chainId} · height ${fmtNum(s.tipHeight < 0 ? 0 : s.tipHeight)}` : '';
  } catch {
    /* node not reachable yet */
  }
}

drawSealStars();
connectWs();
pollStatus();
setInterval(pollStatus, 5000);
route().catch((e) => errView(e.message));
