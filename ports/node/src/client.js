'use strict';
// The agent side over HTTP (spec/PORTING.md items 9 and 10): a small JSON client, the Reporter and the
// CommandPoller. Only Node's http/https modules; redirects are never followed (they would carry the
// bearer token elsewhere); one connection per request.
//
//   const rep = new Reporter('http://watch.example:8730', process.env.SMARTWATCH_INGEST_TOKEN).start();
//   rep.record('planner', 'coder');          // wherever one agent sends a message to another
//   await rep.close();                       // stops the loop and sends what is left
//
//   const poller = new CommandPoller(new Client(url, token), 'coder', (cmd) => restartMyAgent()).start();
const http = require('http');
const https = require('https');
const { checkEvent } = require('./engine');

const MAX_RESPONSE = 32 * 1024 * 1024;
const BATCH = 10000;
const REFUSED = new Set([400, 401, 403, 413]);

class ClientError extends Error {
  constructor(status, body) {
    const msg = body && typeof body === 'object' ? body.error : body;
    super(`HTTP ${status}: ${String(msg).slice(0, 300)}`);
    this.status = status;
    this.body = body;
    this.code = body && typeof body === 'object' ? body.code || null : null;
  }
}

// Percent-encode an id for a path segment ("/" becomes %2F), as Python's quote(x, safe='').
const quoteId = (x) => encodeURIComponent(x).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

class Client {
  constructor(url, token = null, timeoutMs = 5000) {
    if (!/^https?:\/\//.test(String(url))) throw new Error('the monitor URL must start with http:// or https://');
    this.url = String(url).replace(/\/+$/, '');
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  // Resolves to the parsed JSON answer (or text); rejects with ClientError on a non-2xx status and
  // with an Error on network failures, timeouts and cut-off answers.
  request(method, path, body = undefined) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let req = null;
      const finish = (err, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          if (req) req.destroy();
          reject(err);
        } else resolve(value);
      };
      const timer = setTimeout(() => finish(new Error(`no answer within ${this.timeoutMs} ms`)), this.timeoutMs);
      try {
        const u = new URL(this.url + path);
        const headers = { Accept: 'application/json' };
        let data = null;
        if (method === 'POST') {
          headers['Content-Type'] = 'application/json';
          data = Buffer.from(body === undefined ? '' : JSON.stringify(body), 'utf8');
          headers['Content-Length'] = String(data.length);
        }
        if (this.token) headers.Authorization = 'Bearer ' + this.token;
        const mod = u.protocol === 'https:' ? https : http;
        req = mod.request(u, { method, headers, agent: false }, (res) => {
          const chunks = [];
          let size = 0;
          res.on('data', (c) => {
            size += c.length;
            if (size > MAX_RESPONSE) finish(new ClientError(res.statusCode, 'answer larger than 32 MiB'));
            else chunks.push(c);
          });
          res.on('error', (e) => finish(e));
          res.on('aborted', () => finish(new Error('the answer was cut off')));
          res.on('close', () => { if (!res.complete) finish(new Error('the answer was cut off')); });
          res.on('end', () => {
            if (!res.complete) return finish(new Error('the answer was cut off'));
            const text = Buffer.concat(chunks).toString('utf8');
            let v = text;
            if (text[0] === '{' || text[0] === '[') {
              try { v = JSON.parse(text); } catch (e) {
                if (res.statusCode >= 200 && res.statusCode < 300) return finish(e);
              }
            }
            if (res.statusCode < 200 || res.statusCode >= 300) return finish(new ClientError(res.statusCode, v));
            finish(null, v);
          });
        });
        req.on('error', (e) => finish(e));
        req.end(data);
      } catch (e) {
        finish(e);
      }
    });
  }

  events(events) { return this.request('POST', '/v1/events', { events }); }

  async commands(agentId) {
    const r = await this.request('GET', `/v1/agents/${quoteId(agentId)}/commands`);
    if (!r || typeof r !== 'object' || !Array.isArray(r.commands)) throw new Error('malformed commands answer');
    return r.commands;
  }

  ack(resetId, agentId = null) {
    return this.request('POST', `/v1/resets/${quoteId(resetId)}/ack`, agentId ? { agent_id: agentId } : {});
  }
}

class Reporter {
  constructor(urlOrClient, token = null, { intervalMs = 1000, jitterMs = 200, maxKeys = 100000, bucketMs = 1000, clock = Date.now } = {}) {
    this.client = urlOrClient instanceof Client ? urlOrClient : new Client(urlOrClient, token);
    if (!Number.isInteger(bucketMs) || bucketMs < 1 || bucketMs > 60000) throw new RangeError('bucketMs must be from 1 to 60000');
    Object.assign(this, { intervalMs, jitterMs, maxKeys, bucketMs, clock });
    this._buf = new Map();          // "src\ndst\nts" -> {src, dst, ts, count}
    this._sending = Promise.resolve(0);
    this._timer = null;
    this._running = false;
    this.sent = 0;                  // messages the monitor accepted
    this.dropped = 0;               // messages lost to the maxKeys bound
    this.rejected = 0;              // messages the monitor refused
    this.errors = 0;                // failed sends (kept for the next one)
    this.lastError = null;
  }

  // Never blocks on the network. Throws EventError for an invalid event.
  record(src, dst, count = 1, tsMs = undefined) {
    const ts = tsMs === undefined ? Math.floor(this.clock()) : tsMs;
    checkEvent(src, dst, ts, count);
    const t = ts - (ts % this.bucketMs);
    this._put(src, dst, t, count);
  }

  _put(src, dst, t, count) {
    const k = src + '\n' + dst + '\n' + t;
    const e = this._buf.get(k);
    if (e !== undefined) e.count = Math.min(e.count + count, 1000000000);
    else if (this._buf.size < this.maxKeys) this._buf.set(k, { src, dst, ts: t, count });
    else this.dropped += count;
  }

  // Send everything recorded so far; resolves to the messages accepted. Sends never overlap.
  flush() {
    const run = this._sending.catch(() => 0).then(() => this._send());
    this._sending = run;
    return run;
  }

  async _send() {
    const buf = this._buf;
    this._buf = new Map();
    const items = Array.from(buf.values()).sort((x, y) => (x.ts - y.ts) || (x.src < y.src ? -1 : x.src > y.src ? 1 : 0) || (x.dst < y.dst ? -1 : x.dst > y.dst ? 1 : 0));
    let accepted = 0;
    for (let i = 0; i < items.length; i += BATCH) {
      const part = items.slice(i, i + BATCH);
      const evs = part.map((e) => ({ src: e.src, dst: e.dst, ts_ms: e.ts, count: e.count }));
      let res;
      try {
        res = await this.client.events(evs);
      } catch (e) {
        this.lastError = e;
        if (e instanceof ClientError && REFUSED.has(e.status)) {
          this.rejected += part.reduce((s, x) => s + x.count, 0);
          continue;
        }
        this.errors += 1;
        for (const x of items.slice(i)) this._put(x.src, x.dst, x.ts, x.count);
        break;
      }
      const bad = new Set();
      if (res && typeof res === 'object' && Array.isArray(res.rejected)) {
        for (const r of res.rejected) if (r && Number.isInteger(r.index) && r.index >= 0 && r.index < evs.length) bad.add(r.index);
      }
      let nBad = 0;
      for (const j of bad) nBad += evs[j].count;
      this.rejected += nBad;
      const acc = evs.reduce((s, x) => s + x.count, 0) - nBad;
      accepted += acc;
      this.sent += acc;
    }
    return accepted;
  }

  start() {
    if (this._running) return this;
    this._running = true;
    const loop = () => {
      const wait = this.intervalMs + (Math.random() * 2 - 1) * this.jitterMs;
      this._timer = setTimeout(async () => {
        if (!this._running) return;
        try { await this.flush(); } catch (e) { this.lastError = e; }
        if (this._running) loop();
      }, Math.max(0, wait));
      this._timer.unref();
    };
    loop();
    return this;
  }

  // Stop the loop and send what is left; resolves to the messages accepted by this last send.
  async close() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
    return this.flush();
  }
}

// Pull reset commands for one agent, run onReset(command) (it may return a promise) and acknowledge
// each one once it returned without throwing. A command whose handler threw is not acknowledged and
// comes back on the next poll.
class CommandPoller {
  constructor(client, agentId, onReset, intervalMs = 1000, onError = null) {
    Object.assign(this, { client, agentId, onReset, intervalMs, onError });
    this.handled = [];
    this.lastError = null;
    this._timer = null;
    this._running = false;
  }

  async pollOnce() {
    let n = 0;
    for (const cmd of await this.client.commands(this.agentId)) {
      if (!cmd || typeof cmd !== 'object' || cmd.type !== 'reset') continue;
      try {
        await this.onReset(cmd);
      } catch (e) {
        this.lastError = e;
        if (this.onError) try { this.onError(e); } catch (e2) { /* ignored */ }
        continue;
      }
      await this.client.ack(cmd.reset_id, this.agentId);
      this.handled.push(cmd.reset_id);
      n++;
    }
    return n;
  }

  start() {
    if (this._running) return this;
    this._running = true;
    const loop = () => {
      this._timer = setTimeout(async () => {
        if (!this._running) return;
        try { await this.pollOnce(); } catch (e) {
          this.lastError = e;
          if (this.onError) try { this.onError(e); } catch (e2) { /* a callback must not stop the loop */ }
        }
        if (this._running) loop();
      }, this.intervalMs);
      this._timer.unref();
    };
    loop();
    return this;
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
  }
}

module.exports = { Client, ClientError, Reporter, CommandPoller, quoteId };
