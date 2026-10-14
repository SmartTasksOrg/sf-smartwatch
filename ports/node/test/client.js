'use strict';
// Reporter and CommandPoller against an in-process fake monitor. Usage: node test/client.js
const http = require('http');
const assert = require('assert');
const { Client, Reporter, CommandPoller, quoteId } = require('../src');

async function main() {
  assert.strictEqual(quoteId("team/tester:a@b c~!'()*"), 'team%2Ftester%3Aa%40b%20c~%21%27%28%29%2A');
  let n = 0;
  const bodies = [];
  const acks = [];
  const srv = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      if (req.headers.authorization !== 'Bearer tok') { res.writeHead(401); return res.end(); }
      if (req.method === 'POST' && req.url === '/v1/events') {
        bodies.push(JSON.parse(raw));
        n++;
        if (n === 1) { res.writeHead(503); return res.end(); }
        if (n === 2) { res.writeHead(400); return res.end('{"code":"WATCH-BAD-EVENT","error":"no"}'); }
        res.writeHead(207);
        return res.end('{"accepted":1,"rejected":[{"index":0,"code":"WATCH-CLOCK-SKEW","error":"x"}]}');
      }
      if (req.method === 'GET' && req.url === '/v1/agents/team%2Ftester/commands') {
        res.writeHead(200);
        return res.end('{"commands":[{"type":"reset","reset_id":"r1","reason":"","created_ms":1},{"type":"reset","reset_id":"r2","reason":"","created_ms":2}]}');
      }
      if (req.method === 'POST' && req.url.startsWith('/v1/resets/')) {
        acks.push(req.url + ' ' + raw);
        res.writeHead(200);
        return res.end('{}');
      }
      res.writeHead(404);
      return res.end();
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  try {
    const rep = new Reporter(url, 'tok');
    rep.record('b', 'a', 2, 1500);
    rep.record('a', 'b', 3, 1999);
    rep.record('a', 'b', 1, 500);
    assert.strictEqual(await rep.flush(), 0);                  // 503: kept
    assert.strictEqual(await rep.flush(), 0);                  // 400: refused, dropped
    assert.deepStrictEqual([rep.errors, rep.rejected, rep.sent], [1, 6, 0]);
    assert.deepStrictEqual(bodies[1].events, [
      { src: 'a', dst: 'b', ts_ms: 0, count: 1 }, { src: 'a', dst: 'b', ts_ms: 1000, count: 3 },
      { src: 'b', dst: 'a', ts_ms: 1000, count: 2 }]);
    rep.record('a', 'b', 4, 3000);
    rep.record('a', 'c', 5, 3000);
    assert.strictEqual(await rep.close(), 5);                  // 207, index 0 rejected

    const p = new CommandPoller(new Client(url, 'tok'), 'team/tester', (cmd) => { if (cmd.reset_id === 'r2') throw new Error('handler failed'); });
    assert.strictEqual(await p.pollOnce(), 1);
    assert.deepStrictEqual(acks, ['/v1/resets/r1/ack {"agent_id":"team/tester"}']);
  } finally {
    srv.close();
  }
  console.log('node: client tests passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
