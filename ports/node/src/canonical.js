'use strict';
// Canonical JSON (spec/SEMANTICS.md section 8): ASCII keys sorted byte-wise, no whitespace, strings
// escaped only as \" \\ \b \f \n \r \t and \u00XX (lower-case hex) for the other characters below
// U+0020, integers only, true/false/null, arrays in order. A value with a fractional number has no
// canonical form (TypeError).
const crypto = require('crypto');

const SHORT = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' };

function str(s) {
  let out = '"';
  for (const ch of s) {
    if (Object.prototype.hasOwnProperty.call(SHORT, ch)) out += SHORT[ch];
    else if (ch.codePointAt(0) < 0x20) out += '\\u' + ch.codePointAt(0).toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// ASCII keys compare the same by UTF-16 code unit and by byte.
const byBytes = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function dumps(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new TypeError('canonical JSON allows integers only');
    if (!Number.isSafeInteger(v)) throw new TypeError('canonical JSON: integer outside the exact range of a double');
    return Object.is(v, -0) ? '0' : String(v);
  }
  if (typeof v === 'string') return str(v);
  if (Array.isArray(v)) return '[' + v.map(dumps).join(',') + ']';
  if (isObject(v)) {
    const keys = Object.keys(v);
    for (const k of keys) if (!/^[\x00-\x7f]*$/.test(k)) throw new TypeError('canonical JSON object keys must be ASCII');
    keys.sort(byBytes);
    return '{' + keys.map((k) => str(k) + ':' + dumps(v[k])).join(',') + '}';
  }
  throw new TypeError('canonical JSON cannot encode ' + typeof v);
}

const encode = (v) => Buffer.from(dumps(v), 'utf8');
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

module.exports = { dumps, encode, sha256Hex, isObject };
