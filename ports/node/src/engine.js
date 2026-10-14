'use strict';
// The SmartWatch engine (spec/SEMANTICS.md section 6): count messages between agents per window,
// compute coupling density, grade it and decide when a reset is due. Deterministic: no clock, no
// randomness.
//
//   const eng = new Engine(new Policy(doc));
//   eng.add('planner', 'coder', 1700000000123, 4);   // -> array of outputs (often empty)
//   eng.flush(nowMs);                                // close the windows the clock says are complete
//   eng.snapshot();
const { fnv1a32 } = require('./hashing');
const { HyperLogLog } = require('./hll');
const { Policy, ID, MAX_INT } = require('./policy');
const { EventError } = require('./errors');

const BUCKETS = 1 << 20;
const MICRO = 1000000;
const MAX_AGENTS = 100000000;

const isInt = (v, lo, hi) => typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;

function checkEvent(src, dst, tsMs, count) {
  if (typeof src !== 'string' || !ID.test(src) || typeof dst !== 'string' || !ID.test(dst)) {
    throw new EventError('src and dst must match [A-Za-z0-9._:@/-]{1,128}');
  }
  if (!isInt(tsMs, 0, MAX_INT)) throw new EventError('ts_ms must be an integer from 0 to 2^53 - 1');
  if (!isInt(count, 1, 1000000000)) throw new EventError('count must be an integer from 1 to 10^9');
}

// min(2^53 - 1, floor((double(messages) × 1e9) / (double(possible_pairs) × double(window_ms)))), 0 without pairs.
function densityMicro(messages, possiblePairs, windowMs) {
  if (possiblePairs <= 0) return 0;
  return Math.min(MAX_INT, Math.floor((messages * 1e9) / (possiblePairs * windowMs)));
}

// a + b for 0 <= a, b <= 2^53 - 1: when the exact sum exceeds 2^53 - 1, the double sum is >= 2^53.
const sat = (a, b) => Math.min(MAX_INT, a + b);

// floor(x / d) for 0 <= x <= 2^53 - 1 and d >= 1, exactly (x / d in doubles can round up).
const idiv = (x, d) => (x - (x % d)) / d;

// n (n - 1) / 2 exactly for n <= 10^8 (the product itself can exceed 2^53).
const halfPairs = (n) => (n % 2 === 0 ? (n / 2) * (n - 1) : n * ((n - 1) / 2));

const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);  // ASCII ids: UTF-16 order = byte order

// Candidate order: (estimate, a, b) ascending.
function candLess(x, y) {
  if (x.est !== y.est) return x.est < y.est;
  if (x.a !== y.a) return x.a < y.a;
  return x.b < y.b;
}

class MinHeap {
  constructor() { this.h = []; }
  get size() { return this.h.length; }
  peek() { return this.h[0]; }
  push(x) {
    const h = this.h;
    h.push(x);
    let i = h.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (!candLess(h[i], h[p])) break;
      [h[i], h[p]] = [h[p], h[i]];
      i = p;
    }
  }
  pop() {
    const h = this.h;
    const top = h[0];
    const last = h.pop();
    if (h.length > 0) {
      h[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let m = i;
        if (l < h.length && candLess(h[l], h[m])) m = l;
        if (r < h.length && candLess(h[r], h[m])) m = r;
        if (m === i) break;
        [h[i], h[m]] = [h[m], h[i]];
        i = m;
      }
    }
    return top;
  }
}

class Window {
  constructor() {
    this.pairs = new Map();     // text "a\nb" -> {a, b, count}
    this.agents = new Set();
    this.total = 0;
    this.selfMessages = 0;
    this.buckets = null;        // Float64Array of 2^20 counters (integers up to 2^53 - 1), on overflow
    this.cand = new Map();      // text -> {a, b, est}
    this.heap = new MinHeap();  // candidate entries; stale ones are skipped
    this.hllPairs = null;
    this.hllAgents = null;
    this.pairsOver = false;
    this.agentsOver = false;
  }
}

class Engine {
  constructor(policy) {
    this.policy = policy instanceof Policy ? policy : new Policy(policy);
    const d = this.policy.doc;
    this.windowMs = d.window_ms;
    this.late = d.late_windows;
    this.maxEmpty = d.max_empty_windows;
    this.seed = d.hash_seed;
    this.lim = d.limits;
    this.levels = d.levels;
    this.reset = d.reset;
    this.resetIdx = this.policy.levelIndex(this.reset.level);
    this.acc = new Map();
    this.nextEmit = null;
    this.high = null;
    this.empties = 0;
    this.level = -1;
    this.streakStart = null;
    this.triggered = false;
    this.lastTrigger = null;
    this.stats = { events: 0, messages: 0, late_dropped: 0, skipped_windows: 0, windows: 0 };
  }

  add(src, dst, tsMs, count = 1) {
    checkEvent(src, dst, tsMs, count);
    const w = idiv(tsMs, this.windowMs);
    if (this.nextEmit === null) {
      this.nextEmit = w;
      this.high = w;
    }
    if (w < this.nextEmit) {
      this.stats.late_dropped = sat(this.stats.late_dropped, count);
      return [];
    }
    this.stats.events = sat(this.stats.events, 1);
    this.stats.messages = sat(this.stats.messages, count);
    let acc = this.acc.get(w);
    if (acc === undefined) {
      acc = new Window();
      this.acc.set(w, acc);
    }
    this._count(acc, src, dst, count);
    if (w > this.high) this.high = w;
    return this._close();
  }

  flush(nowMs) {
    if (!isInt(nowMs, 0, MAX_INT)) throw new EventError('now_ms must be an integer from 0 to 2^53 - 1');
    if (this.nextEmit === null) return [];
    const w = idiv(nowMs, this.windowMs);
    if (w > this.high) this.high = w;
    return this._close();
  }

  _count(acc, src, dst, count) {
    if (src === dst) {
      acc.selfMessages = sat(acc.selfMessages, count);
      return;
    }
    acc.total = sat(acc.total, count);
    for (const a of [src, dst]) {
      if (acc.agents.has(a)) continue;
      if (acc.agentsOver) acc.hllAgents.add(a);
      else if (acc.agents.size < this.lim.max_agents_exact) acc.agents.add(a);
      else {
        acc.agentsOver = true;
        acc.hllAgents = new HyperLogLog(this.seed);
        for (const x of acc.agents) acc.hllAgents.add(x);
        acc.hllAgents.add(a);
      }
    }
    const [ka, kb] = src < dst ? [src, dst] : [dst, src];
    const text = ka + '\n' + kb;
    const p = acc.pairs.get(text);
    if (p !== undefined) {
      p.count = sat(p.count, count);
      return;
    }
    if (!acc.pairsOver && acc.pairs.size < this.lim.max_pairs_exact) {
      acc.pairs.set(text, { a: ka, b: kb, count });
      return;
    }
    if (!acc.pairsOver) {
      acc.pairsOver = true;
      acc.hllPairs = new HyperLogLog(this.seed);
      for (const k of acc.pairs.keys()) acc.hllPairs.add(k);
      acc.buckets = new Float64Array(BUCKETS);
    }
    acc.hllPairs.add(text);
    const i = fnv1a32(this.seed, text) % BUCKETS;
    acc.buckets[i] = sat(acc.buckets[i], count);
    const est = acc.buckets[i];
    const cand = acc.cand;
    if (cand.has(text) || cand.size < this.lim.candidates) {
      const e = { a: ka, b: kb, est };
      cand.set(text, e);
      acc.heap.push(e);
    } else {
      // the candidate with the smallest (estimate, a, b); heap entries that are no longer the
      // candidate's current entry are stale and skipped
      const heap = acc.heap;
      while (cand.get(heap.peek().a + '\n' + heap.peek().b) !== heap.peek()) heap.pop();
      const low = heap.peek();
      const mine = { a: ka, b: kb, est };
      if (candLess(low, mine)) {
        heap.pop();
        cand.delete(low.a + '\n' + low.b);
        cand.set(text, mine);
        heap.push(mine);
      }
    }
    if (acc.heap.size > 4 * cand.size + 64) {
      acc.heap = new MinHeap();
      for (const e of cand.values()) acc.heap.push(e);
    }
  }

  _close() {
    const out = [];
    while (this.nextEmit + this.late < this.high) {
      const w = this.nextEmit;
      const acc = this.acc.get(w);
      if (acc !== undefined) {
        this.acc.delete(w);
        this.empties = 0;
        for (const o of this._emit(w, acc)) out.push(o);
        this.nextEmit = w + 1;
      } else if (this.empties < this.maxEmpty) {
        this.empties += 1;
        for (const o of this._emit(w, new Window())) out.push(o);
        this.nextEmit = w + 1;
      } else {
        let nxt = this.high - this.late;
        for (const k of this.acc.keys()) if (k >= w && k < nxt) nxt = k;
        this.stats.skipped_windows += nxt - w;
        this.nextEmit = nxt;
        this.streakStart = null;
        this.triggered = false;
        if (this.level !== -1) {
          out.push({ kind: 'level', window: w, from: this._name(this.level), to: 'normal', density_micro: 0 });
          this.level = -1;
        }
      }
    }
    return out;
  }

  _emit(w, acc) {
    this.stats.windows += 1;
    const n = acc.agentsOver ? Math.min(acc.hllAgents.estimate(), MAX_AGENTS) : acc.agents.size;
    const possible = halfPairs(n);
    const distinct = acc.pairsOver ? Math.min(acc.hllPairs.estimate(), possible) : acc.pairs.size;
    const density = densityMicro(acc.total, possible, this.windowMs);
    const ratio = possible ? Math.min(MICRO, Math.floor((distinct * 1e6) / possible)) : 0;
    const entries = [];
    for (const p of acc.pairs.values()) entries.push({ a: p.a, b: p.b, count: p.count, exact: true });
    for (const [k, e] of acc.cand) if (!acc.pairs.has(k)) entries.push({ a: e.a, b: e.b, count: e.est, exact: false });
    entries.sort((x, y) => (y.count - x.count) || cmpStr(x.a, y.a) || cmpStr(x.b, y.b));
    const top = entries.slice(0, this.lim.top_k);
    const before = this.level;
    this.level = this._grade(density, n);
    const name = this._name(this.level);
    const out = [{
      kind: 'window', window: w, start_ms: w * this.windowMs, messages: acc.total, self_messages: acc.selfMessages,
      agents: n, pairs: distinct, possible_pairs: possible, density_micro: density, pair_ratio_micro: ratio,
      exact: !(acc.pairsOver || acc.agentsOver), level: name, top,
    }];
    if (this.level !== before) out.push({ kind: 'level', window: w, from: this._name(before), to: name, density_micro: density });
    const r = this._resetDue(w, top, density);
    if (r !== null) out.push(r);
    return out;
  }

  _name(i) { return i < 0 ? 'normal' : this.levels[i].name; }

  _grade(density, agents) {
    if (agents < this.policy.doc.min_agents) return -1;
    let raw = -1;
    this.levels.forEach((lv, i) => { if (density >= lv.min_density_micro) raw = i; });
    if (raw >= this.level) return raw;
    const h = BigInt(this.policy.doc.hysteresis_permille);
    const d = BigInt(density) * 1000n;           // exceeds 2^53: exact integers
    for (let j = this.level; j > raw; j--) {
      if (d >= BigInt(this.levels[j].min_density_micro) * (1000n - h)) return j;
    }
    return raw;
  }

  _resetDue(w, top, density) {
    const r = this.reset;
    if (this.level < this.resetIdx) {
      this.streakStart = null;
      this.triggered = false;
      return null;
    }
    if (this.streakStart === null) this.streakStart = w;
    if (r.mode === 'off' || this.triggered) return null;
    if ((w - this.streakStart + 1) * this.windowMs < r.sustain_ms) return null;
    if (this.lastTrigger !== null && (w - this.lastTrigger) * this.windowMs < r.cooldown_ms) return null;
    this.triggered = true;
    this.lastTrigger = w;
    const agents = [];
    for (const t of top) {
      if (t.count < r.hot_pair_min_count) break;
      for (const a of [t.a, t.b]) if (!agents.includes(a) && agents.length < r.max_agents) agents.push(a);
    }
    return { kind: 'reset', window: w, mode: r.mode, level: this._name(this.level), density_micro: density,
      sustained_ms: (w - this.streakStart + 1) * this.windowMs, agents };
  }

  snapshot() {
    return { level: this._name(this.level), next_window: this.nextEmit, open_windows: this.acc.size, ...this.stats };
  }
}

module.exports = { Engine, checkEvent, densityMicro, sat, BUCKETS };
