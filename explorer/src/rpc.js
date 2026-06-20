// JSON-RPC 2.0 client for a live Sovereign node.
//
// Uses the Node 18+ global `fetch`; no external dependencies. Every method here
// maps 1:1 to the node's current RPC endpoints, so the explorer only ever displays
// data the node actually serves.

export class SovereignRpc {
  constructor(url) {
    this.url = url;
    this._id = 0;
  }

  /** Invoke a JSON-RPC method, returning its `result` or throwing on error. */
  async call(method, params = {}) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: ++this._id, method, params });
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    if (!res.ok) throw new Error(`RPC ${method}: HTTP ${res.status}`);
    const json = await res.json();
    if (json.error) {
      throw new Error(`RPC ${method}: ${json.error.message} (code ${json.error.code})`);
    }
    return json.result;
  }

  chainId() { return this.call('sov_chainId'); }
  height() { return this.call('sov_getHeight'); }
  head() { return this.call('sov_getHead'); }
  blockByHeight(height) { return this.call('sov_getBlockByHeight', { height }); }
  blockByHash(hash) { return this.call('sov_getBlockByHash', { hash }); }
  blockDigest(height) { return this.call('sov_getBlockDigest', { height }); }
  supply() { return this.call('sov_getSupply'); }
  account(account) { return this.call('sov_getAccount', { account }); }
  difficulty() { return this.call('sov_getDifficulty'); }
  stateRoot() { return this.call('sov_getStateRoot'); }
  isFinal(hash) { return this.call('sov_isFinal', { hash }); }
  miners() { return this.call('sov_getMiners'); }
  mempoolSize() { return this.call('sov_getMempoolSize'); }

  // Sovereign Name Service (SNS): names that resolve to accounts.
  listNames(offset = 0, limit = 100) { return this.call('sov_listNames', { offset, limit }); }
  resolveName(name) { return this.call('sov_resolveName', { name }); }
  getName(name) { return this.call('sov_getName', { name }); }
  namesOf(account) { return this.call('sov_namesOf', { account }); }
}
