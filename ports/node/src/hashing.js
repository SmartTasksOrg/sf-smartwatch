'use strict';
// Seeded FNV-1a 32/64 over UTF-8(seed) ‖ 0x00 ‖ UTF-8(text), and mix64 (MurmurHash3 fmix64)
// (spec/SEMANTICS.md section 4). FNV-1a 64 runs on two 32-bit halves held in Numbers (fast enough for
// the HyperLogLog); mix64 uses BigInt. 64-bit results are BigInt.
const M64 = (1n << 64n) - 1n;
const TWO32 = 4294967296;

function bytesOf(seed, text) {
  const s = Buffer.from(seed, 'utf8');
  const t = Buffer.from(text, 'utf8');
  const b = Buffer.allocUnsafe(s.length + 1 + t.length);
  s.copy(b, 0);
  b[s.length] = 0;
  t.copy(b, s.length + 1);
  return b;
}

function fnv1a32Bytes(b) {
  let h = 2166136261;
  for (let i = 0; i < b.length; i++) h = Math.imul(h ^ b[i], 16777619) >>> 0;
  return h;
}

// FNV-1a 64: prime = 2^40 + 0x1b3, so h × prime = (h << 40) + h × 0x1b3 (mod 2^64).
// Returns [hi, lo] as unsigned 32-bit Numbers.
function fnv1a64Parts(b) {
  let hi = 0xcbf29ce4;
  let lo = 0x84222325;
  for (let i = 0; i < b.length; i++) {
    lo = (lo ^ b[i]) >>> 0;
    const a = lo * 0x1b3;                       // < 2^41: exact
    const carry = Math.floor(a / TWO32);
    hi = (hi * 0x1b3 + carry + ((lo << 8) >>> 0)) % TWO32;  // < 2^53: exact
    lo = a % TWO32;
  }
  return [hi, lo];
}

const fnv1a32 = (seed, text) => fnv1a32Bytes(bytesOf(seed, text));

function fnv1a64(seed, text) {
  const [hi, lo] = fnv1a64Parts(bytesOf(seed, text));
  return (BigInt(hi) << 32n) | BigInt(lo);
}

function mix64(h) {
  h ^= h >> 33n;
  h = (h * 0xFF51AFD7ED558CCDn) & M64;
  h ^= h >> 33n;
  h = (h * 0xC4CEB9FE1A85EC53n) & M64;
  h ^= h >> 33n;
  return h;
}

module.exports = { fnv1a32, fnv1a64, mix64, bytesOf, fnv1a32Bytes, fnv1a64Parts };
