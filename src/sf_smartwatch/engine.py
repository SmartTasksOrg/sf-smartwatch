"""The SmartWatch engine: count messages between agents per window, compute coupling density, grade it,
and decide when a reset is due. Deterministic: no clock, no randomness; time comes from the events
(``ts_ms``) and from ``flush(now_ms)``. spec/SEMANTICS.md is the contract; spec/conformance/monitor.json
tests it step by step.

    eng = Engine(policy)
    out = eng.add("planner", "coder", ts_ms=1700000000123, count=4)   # -> list of outputs (often empty)
    out = eng.flush(now_ms)                                           # close windows by the clock

Outputs, in order: {"kind": "window", ...} for each closed window, followed by that window's
{"kind": "level", ...} (when the graded level changed) and {"kind": "reset", ...} (when a reset is due).
"""
from __future__ import annotations

import heapq
import math
from array import array

from .hashing import fnv1a32
from .hll import HyperLogLog
from .policy import ID, MAX_INT, Policy

BUCKETS = 1 << 20          # the council's "1M buckets": 2^20 = 1,048,576 unsigned 64-bit counters (8 MiB), allocated on overflow
MICRO = 1_000_000
MAX_AGENTS = 100_000_000   # an agent estimate above this is reported as this (keeps n(n-1)/2 below 2^53)


class EventError(ValueError):
    code = 'WATCH-BAD-EVENT'


def check_event(src, dst, ts_ms, count):
    if not isinstance(src, str) or not ID.match(src) or not isinstance(dst, str) or not ID.match(dst):
        raise EventError('src and dst must match [A-Za-z0-9._:@/-]{1,128}')
    if isinstance(ts_ms, bool) or not isinstance(ts_ms, int) or not 0 <= ts_ms <= MAX_INT:
        raise EventError('ts_ms must be an integer from 0 to 2^53 - 1')
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1_000_000_000:
        raise EventError('count must be an integer from 1 to 10^9')


def density_micro(messages: int, possible_pairs: int, window_ms: int) -> int:
    """Coupling density in millionths of a message per possible pair per second:
    min(2^53 - 1, floor( (double(messages) * 1e9) / (double(possible_pairs) * double(window_ms)) )), 0 without pairs.
    IEEE doubles with this exact order of operations, so every engine gets the same integer."""
    if possible_pairs <= 0:
        return 0
    return min(MAX_INT, int(math.floor((float(messages) * 1e9) / (float(possible_pairs) * float(window_ms)))))


def sat(a: int, b: int) -> int:
    """Every counter saturates at 2^53 - 1 (the largest integer every JSON parser keeps exactly)."""
    return min(MAX_INT, a + b)


def pair_key(a: str, b: str) -> tuple:
    """Unordered pair: (smaller, larger) by code point order (the same as byte order for ASCII ids)."""
    return (a, b) if a < b else (b, a)


class _Window:
    __slots__ = ('pairs', 'agents', 'total', 'self_messages', 'buckets', 'cand', 'hll_pairs', 'hll_agents',
                 'pairs_over', 'agents_over', 'heap')

    def __init__(self):
        self.pairs: dict = {}
        self.agents: set = set()
        self.total = 0
        self.self_messages = 0
        self.buckets = None
        self.cand: dict = {}
        self.heap: list = []
        self.hll_pairs = None
        self.hll_agents = None
        self.pairs_over = False
        self.agents_over = False


class Engine:
    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()
        d = self.policy.doc
        self.window_ms = d['window_ms']
        self.late = d['late_windows']
        self.max_empty = d['max_empty_windows']
        self.seed = d['hash_seed']
        self.lim = d['limits']
        self.levels = d['levels']
        self.reset = d['reset']
        self.reset_idx = self.policy.level_index(self.reset['level'])
        self.acc: dict[int, _Window] = {}
        self.next_emit: int | None = None
        self.high = None
        self.empties = 0
        self.level = -1                  # index into levels; -1 is "normal"
        self.streak_start: int | None = None
        self.triggered = False
        self.last_trigger: int | None = None
        self.stats = {'events': 0, 'messages': 0, 'late_dropped': 0, 'skipped_windows': 0, 'windows': 0}

    # ------------------------------------------------------------------ input
    def add(self, src: str, dst: str, ts_ms: int, count: int = 1) -> list:
        check_event(src, dst, ts_ms, count)
        w = ts_ms // self.window_ms
        if self.next_emit is None:
            self.next_emit = w
            self.high = w
        if w < self.next_emit:
            self.stats['late_dropped'] = sat(self.stats['late_dropped'], count)
            return []
        self.stats['events'] = sat(self.stats['events'], 1)
        self.stats['messages'] = sat(self.stats['messages'], count)
        acc = self.acc.get(w)
        if acc is None:
            acc = self.acc[w] = _Window()
        self._count(acc, src, dst, count)
        if w > self.high:
            self.high = w
        return self._close()

    def flush(self, now_ms: int) -> list:
        """Close the windows the clock says are complete (also when no event arrives)."""
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or not 0 <= now_ms <= MAX_INT:
            raise EventError('now_ms must be an integer from 0 to 2^53 - 1')
        if self.next_emit is None:
            return []
        w = now_ms // self.window_ms
        if w > self.high:
            self.high = w
        return self._close()

    def _count(self, acc: _Window, src, dst, count):
        if src == dst:
            acc.self_messages = sat(acc.self_messages, count)
            return
        acc.total = sat(acc.total, count)
        for a in (src, dst):
            if a not in acc.agents:
                if acc.agents_over:
                    acc.hll_agents.add(a)
                elif len(acc.agents) < self.lim['max_agents_exact']:
                    acc.agents.add(a)
                else:
                    acc.agents_over = True
                    acc.hll_agents = HyperLogLog(self.seed)
                    for x in acc.agents:
                        acc.hll_agents.add(x)
                    acc.hll_agents.add(a)
        key = pair_key(src, dst)
        if key in acc.pairs:
            acc.pairs[key] = sat(acc.pairs[key], count)
            return
        if not acc.pairs_over and len(acc.pairs) < self.lim['max_pairs_exact']:
            acc.pairs[key] = count
            return
        text = key[0] + '\n' + key[1]
        if not acc.pairs_over:
            acc.pairs_over = True
            acc.hll_pairs = HyperLogLog(self.seed)
            for k in acc.pairs:
                acc.hll_pairs.add(k[0] + '\n' + k[1])
            acc.buckets = array('Q', bytes(8 * BUCKETS))
        acc.hll_pairs.add(text)
        i = fnv1a32(self.seed, text) % BUCKETS
        acc.buckets[i] = sat(acc.buckets[i], count)
        est = acc.buckets[i]
        cand = acc.cand
        if key in cand or len(cand) < self.lim['candidates']:
            cand[key] = est
            heapq.heappush(acc.heap, (est, key))
        else:
            # the candidate with the smallest (estimate, pair); estimates only grow, so heap entries whose
            # estimate is no longer the candidate's own are stale and skipped
            heap = acc.heap
            while heap[0][1] not in cand or cand[heap[0][1]] != heap[0][0]:
                heapq.heappop(heap)
            low_est, low_key = heap[0]
            if (est, key) > (low_est, low_key):
                heapq.heappop(heap)
                del cand[low_key]
                cand[key] = est
                heapq.heappush(heap, (est, key))
        if len(acc.heap) > 4 * len(cand) + 64:
            acc.heap = [(v, k) for k, v in cand.items()]
            heapq.heapify(acc.heap)

    # ------------------------------------------------------------------ closing windows
    def _close(self) -> list:
        out = []
        while self.next_emit + self.late < self.high:
            w = self.next_emit
            acc = self.acc.pop(w, None)
            if acc is not None:
                self.empties = 0
                out += self._emit(w, acc)
                self.next_emit = w + 1
            elif self.empties < self.max_empty:
                self.empties += 1
                out += self._emit(w, _Window())
                self.next_emit = w + 1
            else:
                bound = self.high - self.late
                nxt = min([k for k in self.acc if k >= w] + [bound])
                self.stats['skipped_windows'] += nxt - w
                self.next_emit = nxt
                self.streak_start, self.triggered = None, False
                if self.level != -1:                     # silence: the level falls to normal
                    out.append({'kind': 'level', 'window': w, 'from': self._name(self.level), 'to': 'normal',
                                'density_micro': 0})
                    self.level = -1
        return out

    def _emit(self, w: int, acc: _Window) -> list:
        self.stats['windows'] += 1
        n = min(acc.hll_agents.estimate(), MAX_AGENTS) if acc.agents_over else len(acc.agents)
        possible = n * (n - 1) // 2
        distinct = min(acc.hll_pairs.estimate(), possible) if acc.pairs_over else len(acc.pairs)
        density = density_micro(acc.total, possible, self.window_ms)
        ratio = min(MICRO, int(math.floor(float(distinct) * 1e6 / float(possible)))) if possible else 0
        entries = [(c, a, b, True) for (a, b), c in acc.pairs.items()]
        entries += [(c, a, b, False) for (a, b), c in acc.cand.items() if (a, b) not in acc.pairs]
        entries.sort(key=lambda e: (-e[0], e[1], e[2]))
        top = [{'a': a, 'b': b, 'count': c, 'exact': ex} for c, a, b, ex in entries[:self.lim['top_k']]]
        before = self.level
        self.level = self._grade(density, n)
        name = self._name(self.level)
        res = {'kind': 'window', 'window': w, 'start_ms': w * self.window_ms, 'messages': acc.total,
               'self_messages': acc.self_messages, 'agents': n, 'pairs': distinct, 'possible_pairs': possible,
               'density_micro': density, 'pair_ratio_micro': ratio, 'exact': not (acc.pairs_over or acc.agents_over),
               'level': name, 'top': top}
        out = [res]
        if self.level != before:
            out.append({'kind': 'level', 'window': w, 'from': self._name(before), 'to': name, 'density_micro': density})
        r = self._reset_due(w, top, density)
        if r is not None:
            out.append(r)
        return out

    def _name(self, i: int) -> str:
        return 'normal' if i < 0 else self.levels[i]['name']

    def _grade(self, density: int, agents: int) -> int:
        if agents < self.policy.doc['min_agents']:
            return -1
        raw = -1
        for i, lv in enumerate(self.levels):
            if density >= lv['min_density_micro']:
                raw = i
        if raw >= self.level:
            return raw
        h = self.policy.doc['hysteresis_permille']
        keep = raw
        for j in range(self.level, raw, -1):            # stay at the highest level not yet left by its margin
            if density * 1000 >= self.levels[j]['min_density_micro'] * (1000 - h):
                keep = j
                break
        return keep

    def _reset_due(self, w: int, top: list, density: int):
        r = self.reset
        if self.level < self.reset_idx:
            self.streak_start, self.triggered = None, False
            return None
        if self.streak_start is None:
            self.streak_start = w
        if r['mode'] == 'off' or self.triggered:
            return None
        if (w - self.streak_start + 1) * self.window_ms < r['sustain_ms']:
            return None
        if self.last_trigger is not None and (w - self.last_trigger) * self.window_ms < r['cooldown_ms']:
            return None
        self.triggered = True
        self.last_trigger = w
        agents = []
        for t in top:
            if t['count'] < r['hot_pair_min_count']:
                break
            for a in (t['a'], t['b']):
                if a not in agents and len(agents) < r['max_agents']:
                    agents.append(a)
        return {'kind': 'reset', 'window': w, 'mode': r['mode'], 'level': self._name(self.level),
                'density_micro': density, 'sustained_ms': (w - self.streak_start + 1) * self.window_ms,
                'agents': agents}

    def snapshot(self) -> dict:
        return {'level': self._name(self.level), 'next_window': self.next_emit, 'open_windows': len(self.acc),
                **self.stats}
