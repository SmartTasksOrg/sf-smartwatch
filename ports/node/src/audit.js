'use strict';
// Audit chain verification (spec/SEMANTICS.md section 8). hash = sha256(canonical(record without "hash")).
const { encode, sha256Hex, isObject } = require('./canonical');

const GENESIS = '0'.repeat(64);

function recordHash(record) {
  const body = {};
  for (const k of Object.keys(record)) if (k !== 'hash') body[k] = record[k];
  return sha256Hex(encode(body));
}

// -> {ok, index (null when ok), message}
function verify(records) {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!isObject(r) || r.seq !== i) return { ok: false, index: i, message: `record ${i}: seq is not ${i}` };
    if (r.prev !== prev) return { ok: false, index: i, message: `record ${i}: prev does not match the hash of record ${i - 1}` };
    let h;
    try {
      h = recordHash(r);
    } catch (e) {
      if (e instanceof TypeError || e instanceof RangeError) return { ok: false, index: i, message: `record ${i}: has no canonical form` };
      throw e;
    }
    if (r.hash !== h) return { ok: false, index: i, message: `record ${i}: hash does not match its content` };
    prev = h;
  }
  return { ok: true, index: null, message: `${records.length} records, chain intact, head ${prev}` };
}

module.exports = { verify, recordHash, GENESIS };
