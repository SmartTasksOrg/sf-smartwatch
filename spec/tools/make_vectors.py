#!/usr/bin/env python3
"""Generate spec/conformance/*.json from the Python reference.

    python spec/tools/make_vectors.py            # write the files
    python spec/tools/make_vectors.py --check    # exit 1 if the files differ from what would be written
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartwatch import canonical  # noqa: E402
from sf_smartwatch.audit import GENESIS, record_hash, verify  # noqa: E402
from sf_smartwatch.calibrate import thresholds  # noqa: E402
from sf_smartwatch.engine import Engine, EventError, density_micro  # noqa: E402
from sf_smartwatch.hashing import fnv1a32, fnv1a64, mix64  # noqa: E402
from sf_smartwatch.hll import HyperLogLog  # noqa: E402
from sf_smartwatch.policy import DEFAULT_POLICY, Policy, PolicyError, validate  # noqa: E402

OUT = os.path.join(ROOT, 'spec', 'conformance')
CHECK = '--check' in sys.argv
DIFF: list = []
T0 = 1_700_000_000_000


def write(name, obj):
    text = json.dumps(obj, indent=1, ensure_ascii=True) + '\n'
    path = os.path.join(OUT, name)
    if CHECK:
        try:
            cur = open(path, encoding='utf-8').read()
        except OSError:
            cur = None
        if cur != text:
            print(f'{name}: differs from the generator')
            DIFF.append(name)
        return
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def expand(items):
    """Items are a list of strings, or {"prefix", "from", "to"}: prefix + decimal i for from <= i < to."""
    if isinstance(items, dict):
        return [items['prefix'] + str(i) for i in range(items['from'], items['to'])]
    return items


# ---------------------------------------------------------------- canonical, hashing, hll, density
def canonical_vectors():
    inputs = [('empty object', {}), ('empty array', []), ('null', None), ('true', True), ('false', False), ('zero', 0),
              ('negative', -42), ('max safe integer', 2 ** 53 - 1), ('sorted keys', {'b': 1, 'a': 2, 'B': 3, '_': 4, 'a1': 5, 'a0': 6}),
              ('nested', {'z': [1, {'y': None, 'x': [True, False]}], 'a': {'c': 'd'}}),
              ('escapes', 'quote " backslash \\ slash / bs \b ff \f nl \n cr \r tab \t'), ('control characters', '\x00\x01\x1f\x7f'),
              ('non-ASCII as is', 'ü 漢字 🙂    '), ('empty string', '')]
    cases = []
    for name, v in inputs:
        t = canonical.dumps(v)
        cases.append({'name': name, 'input': v, 'canonical': t, 'sha256': hashlib.sha256(t.encode()).hexdigest()})
    return {'description': 'canonical(input) equals "canonical" byte for byte; sha256 of its UTF-8 bytes', 'cases': cases}


def hashing_vectors():
    pairs = [('', ''), ('', 'a'), ('a', ''), ('default/smartwatch', 'planner\ncoder'), ('prod/pod-7', 'a\nb'),
             ('ns/pod', 'agent-0'), ('ns/pod', 'agent-1'), ('ns/pod', 'üñí/漢字'), ('seed', 'x' * 300), ('🙂', '\u0000')]
    cases = []
    for seed, text in pairs:
        h64 = fnv1a64(seed, text)
        cases.append({'seed': seed, 'text': text, 'fnv1a32': fnv1a32(seed, text), 'fnv1a64': str(h64),
                      'mix64': str(mix64(h64)), 'bucket': fnv1a32(seed, text) % (1 << 20)})
    return {'description': ('fnv1a32/fnv1a64 over UTF-8(seed) + 0x00 + UTF-8(text); 64-bit values as decimal strings; '
                            'mix64 = MurmurHash3 fmix64 of fnv1a64; bucket = fnv1a32 mod 2^20'), 'cases': cases}


def hll_vectors():
    specs = [('empty', 'ns/pod', []), ('one', 'ns/pod', ['a']), ('ten', 'ns/pod', {'prefix': 'agent-', 'from': 0, 'to': 10}),
             ('duplicates count once', 'ns/pod', ['a', 'b', 'a', 'b', 'a']),
             ('1,000 (linear counting)', 'ns/pod', {'prefix': 'agent-', 'from': 0, 'to': 1000}),
             ('20,000 (raw estimate)', 'ns/pod', {'prefix': 'agent-', 'from': 0, 'to': 20000}),
             ('100,000 pairs', 'prod/pod-7', {'prefix': 'x\ny', 'from': 0, 'to': 100000}),
             ('another seed', 'staging/pod-2', {'prefix': 'agent-', 'from': 0, 'to': 20000})]
    cases = []
    for name, seed, items in specs:
        h = HyperLogLog(seed)
        for x in expand(items):
            h.add(x)
        cases.append({'name': name, 'seed': seed, 'items': items, 'estimate': h.estimate(), 'digest': h.digest()})
    return {'description': ('add every item (expand {"prefix","from","to"} to prefix + decimal i) to a new p=14 '
                            'HyperLogLog with this seed; estimate and the sha256 of the 16,384 registers must match'),
            'cases': cases}


def density_vectors():
    rows = [(0, 0, 1000), (10, 0, 1000), (20, 10, 1000), (1, 3, 1000), (2, 3, 1000), (1000, 45, 1000), (7, 3, 300),
            (123456789, 199990000, 1000), (10 ** 12, 49995000, 60000), (2 ** 53 - 1, 1, 100), (1, 2 ** 53 - 1, 60000),
            (999999, 1000000, 1000), (3, 1, 3)]
    return {'description': 'density_micro(messages, possible_pairs, window_ms) per SEMANTICS.md',
            'cases': [{'messages': m, 'possible_pairs': p, 'window_ms': w, 'density_micro': density_micro(m, p, w)}
                      for m, p, w in rows]}


# ---------------------------------------------------------------- policies, calibration
def policy_vectors():
    cases = []

    def add(name, doc):
        try:
            validate(copy.deepcopy(doc))
            cases.append({'name': name, 'policy': doc, 'ok': True})
        except PolicyError as e:
            cases.append({'name': name, 'policy': doc, 'ok': False, 'code': e.code})

    base = copy.deepcopy(DEFAULT_POLICY)

    def mod(f):
        d = copy.deepcopy(base)
        f(d)
        return d
    add('the default policy', base)
    add('one level', mod(lambda d: (d.__setitem__('levels', [{'name': 'hot', 'min_density_micro': 5}]), d['reset'].__setitem__('level', 'hot'))))
    add('missing field', mod(lambda d: d.pop('limits')))
    add('extra field', mod(lambda d: d.__setitem__('extra', 1)))
    add('schema wrong', mod(lambda d: d.__setitem__('schema', 'smartwatch.policy/v2')))
    add('window 99 ms', mod(lambda d: d.__setitem__('window_ms', 99)))
    add('window 60000 ms', mod(lambda d: d.__setitem__('window_ms', 60000)))
    add('window 1000.5 ms', mod(lambda d: d.__setitem__('window_ms', 1000.5)))
    add('window true', mod(lambda d: d.__setitem__('window_ms', True)))
    add('levels not increasing', mod(lambda d: d['levels'][1].__setitem__('min_density_micro', 2_000_000)))
    add('level named normal', mod(lambda d: d['levels'][0].__setitem__('name', 'normal')))
    add('level name with a capital', mod(lambda d: d['levels'][0].__setitem__('name', 'Elevated')))
    add('duplicate level names', mod(lambda d: d['levels'][1].__setitem__('name', 'elevated')))
    add('threshold zero', mod(lambda d: d['levels'][0].__setitem__('min_density_micro', 0)))
    add('nine levels', mod(lambda d: d.__setitem__('levels', [{'name': f'l{i}', 'min_density_micro': i + 1} for i in range(9)])))
    add('no levels', mod(lambda d: d.__setitem__('levels', [])))
    add('reset level unknown', mod(lambda d: d['reset'].__setitem__('level', 'extreme')))
    add('reset level a list', mod(lambda d: d['reset'].__setitem__('level', ['critical'])))
    add('reset mode unknown', mod(lambda d: d['reset'].__setitem__('mode', 'ask')))
    add('reset on_timeout unknown', mod(lambda d: d['reset'].__setitem__('on_timeout', 'wait')))
    add('reset max_agents 0', mod(lambda d: d['reset'].__setitem__('max_agents', 0)))
    add('reset extra field', mod(lambda d: d['reset'].__setitem__('x', 1)))
    add('hysteresis 901', mod(lambda d: d.__setitem__('hysteresis_permille', 901)))
    add('min_agents 1', mod(lambda d: d.__setitem__('min_agents', 1)))
    add('environment with a space', mod(lambda d: d.__setitem__('environment', 'prod eu')))
    add('top_k 101', mod(lambda d: d['limits'].__setitem__('top_k', 101)))
    add('hash seed empty', mod(lambda d: d.__setitem__('hash_seed', '')))
    add('hash seed of 256 bytes', mod(lambda d: d.__setitem__('hash_seed', 'é' * 128)))
    add('hash seed of 258 bytes', mod(lambda d: d.__setitem__('hash_seed', 'é' * 129)))
    add('not an object', ['smartwatch.policy/v1'])
    return {'description': 'validate the policy: ok, or the code', 'cases': cases}


def calibration_vectors():
    cases = []

    def add(name, dens, pm):
        try:
            cases.append({'name': name, 'densities': dens, 'permille': pm, 'ok': True, 'thresholds': thresholds(dens, pm)})
        except ValueError:
            cases.append({'name': name, 'densities': dens, 'permille': pm, 'ok': False})
    add('one to a hundred, prod', list(range(1, 101)), [950, 990, 999])
    add('one to a hundred, staging', list(range(100, 0, -1)), [900, 950, 990])
    add('all equal', [7] * 50, [950, 990, 999])
    add('all zero', [0] * 30, [950, 990, 999])
    add('one value', [42], [500, 950])
    add('thirty windows (30 s at 1 s)', [1000 * (i % 7) + 13 * i for i in range(30)], [950, 990, 999])
    add('p1000 is the maximum', [5, 1, 9, 3], [1000])
    add('p1 is the minimum', [5, 1, 9, 3], [1])
    add('no densities', [], [950])
    add('a fractional density', [1, 2.5, 3], [950])
    add('a negative density', [1, -2, 3], [950])
    add('percentile 0', [1, 2], [0])
    add('percentile 1001', [1, 2], [1001])
    return {'description': 'thresholds(densities, permille) per SEMANTICS.md, Calibration; ok false means refused', 'cases': cases}


# ---------------------------------------------------------------- monitor
def policy_with(**over):
    d = copy.deepcopy(DEFAULT_POLICY)
    for k, v in over.items():
        if k in ('reset', 'limits'):
            d[k].update(v)
        else:
            d[k] = v
    return d


def run_case(name, doc, steps):
    eng = Engine(Policy(doc))
    out = []
    for st in steps:
        op = st['op']
        try:
            if op == 'add':
                r = {'ok': True, 'outputs': eng.add(st['src'], st['dst'], st['ts_ms'], st['count'])}
            elif op == 'flush':
                r = {'ok': True, 'outputs': eng.flush(st['now_ms'])}
            else:
                r = eng.snapshot()
        except EventError as e:
            r = {'ok': False, 'code': e.code}
        out.append(dict(st, expect=r))
    return {'name': name, 'policy': doc, 'steps': out}


def mesh(agents, ts, count=1):
    """Every ordered pair of agents sends ``count`` messages at ts (+ a few ms per agent)."""
    s = []
    for i, a in enumerate(agents):
        for b in agents:
            if a != b:
                s.append({'op': 'add', 'src': a, 'dst': b, 'ts_ms': ts + i, 'count': count})
    return s


def monitor_vectors():
    cases = []
    five = [f'a{i}' for i in range(5)]
    # 1 graded levels, sustain, auto reset, cooldown, hysteresis
    steps = []
    loads = [1, 1, 3, 6, 12, 12, 12, 12, 12, 12, 9, 4, 4, 1, 1, 12, 12, 12, 12, 12, 12, 12]
    for s_, c in enumerate(loads):
        steps += mesh(five, T0 + s_ * 1000, c)
    steps.append({'op': 'flush', 'now_ms': T0 + 40_000})
    steps.append({'op': 'stats'})
    cases.append(run_case('graded levels, sustained critical, auto reset, cooldown',
                          policy_with(reset={'mode': 'auto', 'sustain_ms': 3000, 'cooldown_ms': 10000}), steps))
    # 2 confirm mode and hot_pair_min_count / max_agents
    steps = []
    for s_ in range(8):
        steps += mesh(five, T0 + s_ * 1000, 1)
        steps.append({'op': 'add', 'src': 'a1', 'dst': 'a3', 'ts_ms': T0 + s_ * 1000 + 500, 'count': 400})
        steps.append({'op': 'add', 'src': 'a4', 'dst': 'a0', 'ts_ms': T0 + s_ * 1000 + 600, 'count': 300})
    steps.append({'op': 'flush', 'now_ms': T0 + 20_000})
    cases.append(run_case('confirm mode; reset names the agents of the hottest pairs',
                          policy_with(reset={'mode': 'confirm', 'max_agents': 3, 'hot_pair_min_count': 100}), steps))
    # 3 late and out-of-order events
    steps = mesh(['x', 'y', 'z'], T0, 1)
    steps += [{'op': 'add', 'src': 'x', 'dst': 'y', 'ts_ms': T0 + 2500, 'count': 2},
              {'op': 'add', 'src': 'y', 'dst': 'z', 'ts_ms': T0 + 999, 'count': 5},
              {'op': 'add', 'src': 'x', 'dst': 'z', 'ts_ms': T0 + 3100, 'count': 1},
              {'op': 'add', 'src': 'z', 'dst': 'x', 'ts_ms': T0 + 400, 'count': 9},
              {'op': 'add', 'src': 'x', 'dst': 'y', 'ts_ms': T0 + 1500, 'count': 3},
              {'op': 'add', 'src': 'x', 'dst': 'y', 'ts_ms': T0 + 3000, 'count': 1},
              {'op': 'add', 'src': 'y', 'dst': 'x', 'ts_ms': T0 + 200, 'count': 4},
              {'op': 'stats'}]
    cases.append(run_case('late events within late_windows count; older ones are dropped', policy_with(), steps))
    # 4 self messages, too few agents
    steps = [{'op': 'add', 'src': 'p', 'dst': 'p', 'ts_ms': T0, 'count': 50},
             {'op': 'add', 'src': 'p', 'dst': 'q', 'ts_ms': T0 + 1, 'count': 500},
             {'op': 'add', 'src': 'q', 'dst': 'p', 'ts_ms': T0 + 2, 'count': 500},
             {'op': 'flush', 'now_ms': T0 + 3000}, {'op': 'stats'}]
    cases.append(run_case('self messages are not coupling; two agents stay normal (min_agents 3)', policy_with(), steps))
    # 5 gaps
    steps = mesh(five, T0, 12) + mesh(five, T0 + 1000, 12) + mesh(five, T0 + 60_000, 1)
    steps += [{'op': 'flush', 'now_ms': T0 + 90_000}, {'op': 'stats'}]
    cases.append(run_case('a long silence: at most max_empty_windows empty windows, the rest skipped',
                          policy_with(max_empty_windows=3), steps))
    steps = mesh(five, T0, 12) + mesh(five, T0 + 1000, 12) + mesh(five, T0 + 9000, 12)
    steps += [{'op': 'flush', 'now_ms': T0 + 20_000}]
    cases.append(run_case('no empty windows allowed: a gap drops the level to normal', policy_with(max_empty_windows=0), steps))
    # 6 sketch mode
    steps = []
    agents = [f'n{i}' for i in range(9)]
    for i, a in enumerate(agents):
        for j, b in enumerate(agents):
            if i < j:
                steps.append({'op': 'add', 'src': a, 'dst': b, 'ts_ms': T0 + i * 10 + j, 'count': 1 + (i * 7 + j * 3) % 11})
    steps.append({'op': 'add', 'src': 'n8', 'dst': 'n7', 'ts_ms': T0 + 900, 'count': 50})
    steps.append({'op': 'add', 'src': 'n0', 'dst': 'n1', 'ts_ms': T0 + 901, 'count': 40})
    steps += [{'op': 'flush', 'now_ms': T0 + 5000}, {'op': 'stats'}]
    cases.append(run_case('sketch mode: exact limits reached, HyperLogLog counts, bucket estimates, bounded candidates',
                          policy_with(limits={'max_pairs_exact': 5, 'max_agents_exact': 4, 'top_k': 6, 'candidates': 3}), steps))
    # 7 invalid events
    steps = [{'op': 'add', 'src': 'a b', 'dst': 'c', 'ts_ms': T0, 'count': 1},
             {'op': 'add', 'src': 'a', 'dst': '', 'ts_ms': T0, 'count': 1},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': -1, 'count': 1},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': 2 ** 53, 'count': 1},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': T0, 'count': 0},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': T0, 'count': 1000000001},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': T0, 'count': 1.5},
             {'op': 'add', 'src': 'a', 'dst': 'b', 'ts_ms': T0, 'count': True},
             {'op': 'add', 'src': 'x' * 129, 'dst': 'b', 'ts_ms': T0, 'count': 1},
             {'op': 'add', 'src': 'ü', 'dst': 'b', 'ts_ms': T0, 'count': 1},
             {'op': 'flush', 'now_ms': -5},
             {'op': 'add', 'src': 'svc:a@ns/x-1.2', 'dst': 'b', 'ts_ms': T0, 'count': 1},
             {'op': 'stats'}]
    cases.append(run_case('invalid events are refused and change nothing', policy_with(), steps))
    # 8 mode off
    steps = []
    for s_ in range(8):
        steps += mesh(five, T0 + s_ * 1000, 12)
    steps.append({'op': 'flush', 'now_ms': T0 + 12_000})
    cases.append(run_case('mode off: levels and alerts, never a reset', policy_with(reset={'mode': 'off', 'sustain_ms': 0}), steps))
    # 9 hysteresis hovering
    steps = []
    for s_, c in enumerate([10, 10, 9, 10, 9, 8, 10, 4, 5, 3]):
        steps += mesh(five, T0 + s_ * 1000, c)
    steps.append({'op': 'flush', 'now_ms': T0 + 15_000})
    cases.append(run_case('hysteresis: hovering just under a threshold keeps the level',
                          policy_with(hysteresis_permille=150, reset={'mode': 'off'}), steps))
    # 10 window 250 ms
    steps = []
    for s_ in range(10):
        steps += mesh(five, T0 + s_ * 250, 3)
    steps.append({'op': 'flush', 'now_ms': T0 + 5000})
    cases.append(run_case('window 250 ms: density is per second', policy_with(window_ms=250, late_windows=1), steps))
    return {'description': ('a new engine per case with "policy"; run the steps in order: add (src, dst, ts_ms, count), '
                            'flush (now_ms), stats; each result equals "expect"'), 'cases': cases}


# ---------------------------------------------------------------- audit
def audit_vectors():
    events = [('level', T0, {'window': 1700000000, 'from': 'normal', 'to': 'critical', 'density_micro': 82000000}),
              ('reset_proposed', T0 + 1, {'reset_id': 'r-1', 'agents': ['a0', 'a1'], 'mode': 'confirm', 'deadline_ms': T0 + 5001}),
              ('reset_decision', T0 + 2, {'reset_id': 'r-1', 'decision': 'confirm', 'by': 'jwt:alice', 'note': 'arrêt «urgent» \n2'}),
              ('reset_delivered', T0 + 3, {'reset_id': 'r-1', 'agent_id': 'a0', 'via': 'webhook', 'attempts': 2, 'ok': True})]
    recs, prev = [], GENESIS
    for i, (ev, ts, fields) in enumerate(events):
        r = dict(fields)
        r.update(seq=i, ts_ms=ts, event=ev, prev=prev)
        r['hash'] = record_hash(r)
        prev = r['hash']
        recs.append(r)
    cases = [{'name': 'a valid chain', 'records': recs}]
    bad = copy.deepcopy(recs); bad[2]['note'] = 'edited'
    cases.append({'name': 'a field edited', 'records': bad})
    bad = copy.deepcopy(recs); del bad[1]
    cases.append({'name': 'a record removed', 'records': bad})
    bad = copy.deepcopy(recs); bad[1], bad[2] = bad[2], bad[1]
    cases.append({'name': 'two records swapped', 'records': bad})
    cases.append({'name': 'empty', 'records': []})
    bad = copy.deepcopy(recs); bad[1]['seq'] = True; bad[1]['hash'] = record_hash(bad[1])
    for j in (2, 3):
        bad[j]['prev'] = bad[j - 1]['hash']; bad[j]['hash'] = record_hash(bad[j])
    cases.append({'name': 'seq true instead of 1 (hashes recomputed)', 'records': bad})
    bad = copy.deepcopy(recs); bad[3]['attempts'] = 2.5
    cases.append({'name': 'a fractional number', 'records': bad})
    for c in cases:
        ok, idx, _ = verify(c['records'])
        c['result'] = {'ok': ok, 'index': idx}
    return {'description': 'record = fields + seq, ts_ms, event, prev; hash = sha256(canonical(record without hash)); '
                           'verify gives ok and the index of the first bad record (null when ok)', 'cases': cases}


def main():
    os.makedirs(OUT, exist_ok=True)
    write('canonical.json', canonical_vectors())
    write('hashing.json', hashing_vectors())
    write('hll.json', hll_vectors())
    write('density.json', density_vectors())
    write('policies.json', policy_vectors())
    write('calibration.json', calibration_vectors())
    write('monitor.json', monitor_vectors())
    write('audit.json', audit_vectors())
    if CHECK:
        if DIFF:
            sys.exit(1)
        print('vectors are up to date')


if __name__ == '__main__':
    main()
