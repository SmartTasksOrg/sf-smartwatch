'use strict';
// Runs spec/conformance against this port, check for check as src/sf_smartwatch/conformance.py does.
// Usage: node test/conformance.js [vector dir]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sw = require('../src');

const dir = process.argv[2] || path.join(__dirname, '..', '..', '..', 'spec', 'conformance');
const load = (n) => JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8'));

// JSON value equality: key order does not matter.
function same(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => same(x, b[i]));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return same(ka, kb) && ka.every((k) => same(a[k], b[k]));
}
const show = (v) => { try { return sw.dumps(v).slice(0, 300); } catch (e) { return String(JSON.stringify(v)).slice(0, 300); } };
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const pick = (c, keys) => Object.fromEntries(keys.filter((k) => has(c, k)).map((k) => [k, c[k]]));
const expand = (items) => (Array.isArray(items) ? items
  : Array.from({ length: Math.max(0, items.to - items.from) }, (_, i) => items.prefix + String(items.from + i)));

let total = 0;
const fails = [];
function check(name, got, want) {
  total++;
  if (!same(got, want)) fails.push(`${name}: got ${show(got)}, want ${show(want)}`);
}

for (const c of load('canonical.json').cases) {
  const t = sw.dumps(c.input);
  check('canonical/' + c.name, [t, crypto.createHash('sha256').update(t, 'utf8').digest('hex')], [c.canonical, c.sha256]);
}

load('hashing.json').cases.forEach((c, i) => {
  const h64 = sw.fnv1a64(c.seed, c.text);
  const h32 = sw.fnv1a32(c.seed, c.text);
  const got = { fnv1a32: h32, fnv1a64: h64.toString(), mix64: sw.mix64(h64).toString(), bucket: h32 % (1 << 20) };
  check(`hashing/${i}`, got, pick(c, Object.keys(got)));
});

for (const c of load('hll.json').cases) {
  const h = new sw.HyperLogLog(c.seed);
  for (const x of expand(c.items)) h.add(x);
  check('hll/' + c.name, { estimate: h.estimate(), digest: h.digest() }, { estimate: c.estimate, digest: c.digest });
}

load('density.json').cases.forEach((c, i) => {
  check(`density/${i}`, sw.densityMicro(c.messages, c.possible_pairs, c.window_ms), c.density_micro);
});

for (const c of load('policies.json').cases) {
  let got;
  try {
    sw.validate(c.policy);
    got = { ok: true };
  } catch (e) {
    if (!(e instanceof sw.PolicyError)) throw e;
    got = { ok: false, code: e.code };
  }
  check('policies/' + c.name, got, pick(c, ['ok', 'code']));
}

for (const c of load('calibration.json').cases) {
  let got;
  try {
    got = { ok: true, thresholds: sw.thresholds(c.densities, c.permille) };
  } catch (e) {
    if (!(e instanceof RangeError)) throw e;
    got = { ok: false };
  }
  check('calibration/' + c.name, got, pick(c, ['ok', 'thresholds']));
}

for (const c of load('monitor.json').cases) {
  const eng = new sw.Engine(new sw.Policy(c.policy));
  c.steps.forEach((st, i) => {
    let got;
    try {
      if (st.op === 'add') got = { ok: true, outputs: eng.add(st.src, st.dst, st.ts_ms, st.count) };
      else if (st.op === 'flush') got = { ok: true, outputs: eng.flush(st.now_ms) };
      else got = eng.snapshot();
    } catch (e) {
      if (!(e instanceof sw.EventError)) throw e;
      got = { ok: false, code: e.code };
    }
    check(`monitor/${c.name} step ${i} (${st.op})`, got, st.expect);
  });
}

for (const c of load('audit.json').cases) {
  const r = sw.verify(c.records);
  check('audit/' + c.name, { ok: r.ok, index: r.index }, c.result);
}

for (const f of fails) console.log('FAIL', f);
console.log(fails.length ? `node: FAILED, ${fails.length} of ${total} vectors` : `node: ${total}/${total} vectors passed`);
process.exit(fails.length ? 1 : 0);
