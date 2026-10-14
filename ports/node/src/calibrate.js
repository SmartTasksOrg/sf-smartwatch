'use strict';
// Calibration thresholds (spec/SEMANTICS.md section 7): nearest-rank permille percentiles of observed
// densities, made strictly increasing and at least 1.
const PROFILES = { prod: [950, 990, 999], staging: [900, 950, 990] };

function thresholds(densities, permille) {
  const xs = Array.from(densities, (d) => {
    if (typeof d !== 'number' || !Number.isSafeInteger(d) || d < 0) throw new RangeError('densities are non-negative integers');
    return d;
  }).sort((a, b) => a - b);
  if (xs.length === 0) throw new RangeError('no densities to calibrate from');
  const out = [];
  let prev = 0;
  for (const p of permille) {
    if (typeof p !== 'number' || !Number.isInteger(p) || p < 1 || p > 1000) {
      throw new RangeError('percentiles are integers from 1 to 1000 (permille)');
    }
    const rank = Math.floor((p * xs.length + 999) / 1000);   // p * N < 2^53 for any real list
    let v = xs[Math.max(rank, 1) - 1];
    v = Math.max(v, prev + 1, 1);
    out.push(v);
    prev = v;
  }
  return out;
}

module.exports = { thresholds, PROFILES };
