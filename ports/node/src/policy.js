'use strict';
// Policy validation (spec/SEMANTICS.md section 3). Any violation throws PolicyError (WATCH-BAD-POLICY).
const { PolicyError } = require('./errors');
const { isObject } = require('./canonical');

const ID = /^[A-Za-z0-9._:@/-]{1,128}$/;
const LEVEL_NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const MAX_INT = Number.MAX_SAFE_INTEGER;

const DEFAULT_POLICY = {
  schema: 'smartwatch.policy/v1',
  environment: 'default',
  window_ms: 1000,
  late_windows: 2,
  max_empty_windows: 10,
  min_agents: 3,
  levels: [
    { name: 'elevated', min_density_micro: 2000000 },
    { name: 'high', min_density_micro: 5000000 },
    { name: 'critical', min_density_micro: 10000000 },
  ],
  hysteresis_permille: 100,
  reset: { level: 'critical', sustain_ms: 5000, mode: 'confirm', confirm_timeout_ms: 5000,
    on_timeout: 'reset', cooldown_ms: 60000, max_agents: 10, hot_pair_min_count: 1 },
  limits: { max_pairs_exact: 100000, max_agents_exact: 50000, top_k: 10, candidates: 1024 },
  hash_seed: 'default/smartwatch',
};

// A JSON integer within [lo, hi]. JSON.parse cannot tell 1.0 from 1 (see README).
const isInt = (v, lo, hi) => typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;

function sameKeys(o, ref) {
  if (!isObject(o)) return false;
  const a = Object.keys(o).sort();
  const b = Object.keys(ref).sort();
  return a.length === b.length && a.every((k, i) => k === b[i]);
}

function wellFormed(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

function validate(doc) {
  const bad = (msg) => { throw new PolicyError(msg); };
  if (!sameKeys(doc, DEFAULT_POLICY)) bad('the policy must have exactly the fields ' + Object.keys(DEFAULT_POLICY).sort().join(', '));
  if (doc.schema !== 'smartwatch.policy/v1') bad('schema must be "smartwatch.policy/v1"');
  if (typeof doc.environment !== 'string' || !ID.test(doc.environment)) bad('environment must match [A-Za-z0-9._:@/-]{1,128}');
  for (const [k, lo, hi] of [['window_ms', 100, 60000], ['late_windows', 0, 60], ['max_empty_windows', 0, 3600],
    ['min_agents', 2, 1000000], ['hysteresis_permille', 0, 900]]) {
    if (!isInt(doc[k], lo, hi)) bad(`${k} must be an integer from ${lo} to ${hi}`);
  }
  const lv = doc.levels;
  if (!Array.isArray(lv) || lv.length < 1 || lv.length > 8) bad('levels must be a list of 1 to 8 levels');
  const names = new Set();
  let prev = 0;
  for (const x of lv) {
    if (!sameKeys(x, { name: 0, min_density_micro: 0 })) bad('each level must be {"name", "min_density_micro"}');
    if (typeof x.name !== 'string' || !LEVEL_NAME.test(x.name) || x.name === 'normal' || names.has(x.name)) {
      bad('level names must match [a-z][a-z0-9_-]{0,31}, be unique and not "normal"');
    }
    if (!isInt(x.min_density_micro, 1, MAX_INT) || x.min_density_micro <= prev) {
      bad('min_density_micro must be a positive integer, strictly increasing from level to level');
    }
    names.add(x.name);
    prev = x.min_density_micro;
  }
  const r = doc.reset;
  if (!sameKeys(r, DEFAULT_POLICY.reset)) bad('reset must have exactly the fields ' + Object.keys(DEFAULT_POLICY.reset).sort().join(', '));
  if (typeof r.level !== 'string' || !names.has(r.level)) bad('reset.level must be one of the level names');
  if (!['auto', 'confirm', 'off'].includes(r.mode)) bad('reset.mode must be auto, confirm or off');
  if (!['reset', 'cancel'].includes(r.on_timeout)) bad('reset.on_timeout must be reset or cancel');
  for (const [k, lo, hi] of [['sustain_ms', 0, 3600000], ['confirm_timeout_ms', 0, 3600000], ['cooldown_ms', 0, 86400000],
    ['max_agents', 1, 1000], ['hot_pair_min_count', 1, 1000000000]]) {
    if (!isInt(r[k], lo, hi)) bad(`reset.${k} must be an integer from ${lo} to ${hi}`);
  }
  const li = doc.limits;
  if (!sameKeys(li, DEFAULT_POLICY.limits)) bad('limits must have exactly the fields ' + Object.keys(DEFAULT_POLICY.limits).sort().join(', '));
  for (const [k, lo, hi] of [['max_pairs_exact', 1, 10000000], ['max_agents_exact', 1, 10000000], ['top_k', 1, 100],
    ['candidates', 1, 65536]]) {
    if (!isInt(li[k], lo, hi)) bad(`limits.${k} must be an integer from ${lo} to ${hi}`);
  }
  if (typeof doc.hash_seed !== 'string' || !wellFormed(doc.hash_seed)) bad('hash_seed must be a valid Unicode string');
  const n = Buffer.byteLength(doc.hash_seed, 'utf8');
  if (n < 1 || n > 256) bad('hash_seed must be a string of 1 to 256 bytes');
  return doc;
}

class Policy {
  constructor(doc) {
    this.doc = validate(JSON.parse(JSON.stringify(doc === undefined || doc === null ? DEFAULT_POLICY : doc)));
  }

  levelIndex(name) {
    return this.doc.levels.findIndex((x) => x.name === name);
  }
}

module.exports = { Policy, validate, DEFAULT_POLICY, ID, MAX_INT, isInt };
