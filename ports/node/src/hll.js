'use strict';
// HyperLogLog, p = 14 (spec/SEMANTICS.md section 5): 16,384 one-byte registers.
const crypto = require('crypto');
const { bytesOf, fnv1a64Parts, mix64 } = require('./hashing');

const P = 14;
const M = 1 << P;
const ALPHA = 0.7213 / (1 + 1.079 / M);
const MAXRHO = 64 - P + 1;                 // 51
const MAX_INT = Number.MAX_SAFE_INTEGER;   // 2^53 - 1
const W_MASK = (1n << 50n) - 1n;
const TWO32 = 4294967296;

function bitLength50(w) {                  // w < 2^50, exact in a Number
  if (w === 0) return 0;
  const hi = Math.floor(w / TWO32);
  if (hi > 0) return 64 - Math.clz32(hi);
  return 32 - Math.clz32(w);
}

class HyperLogLog {
  constructor(seed) {
    this.seed = seed;
    this.reg = new Uint8Array(M);
  }

  add(item) {
    const [hi, lo] = fnv1a64Parts(bytesOf(this.seed, item));
    const h = mix64((BigInt(hi) << 32n) | BigInt(lo));
    const j = Number(h >> 50n);
    const rho = MAXRHO - bitLength50(Number(h & W_MASK));
    if (rho > this.reg[j]) this.reg[j] = rho;
  }

  estimate() {
    const counts = new Array(MAXRHO + 1).fill(0);
    for (let i = 0; i < M; i++) counts[this.reg[i]]++;
    let z = 0.0;
    for (let v = MAXRHO; v >= 0; v--) if (counts[v]) z += counts[v] * Math.pow(2, -v);
    let e = ALPHA * M * M / z;
    if (e <= 2.5 * M && counts[0] > 0) e = M * Math.log(M / counts[0]);
    return Math.min(Math.floor(e + 0.5), MAX_INT);
  }

  digest() {
    return crypto.createHash('sha256').update(this.reg).digest('hex');
  }
}

module.exports = { HyperLogLog };
