"""Run the shared vectors (spec/conformance/*.json) against this implementation.

    sf-smartwatch vectors [DIR]       # DIR defaults to the copy shipped in the wheel

Every port has a runner that does the same; spec/PORTING.md describes the file formats.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import canonical
from .audit import verify
from .calibrate import thresholds
from .engine import Engine, EventError, density_micro
from .hashing import fnv1a32, fnv1a64, mix64
from .hll import HyperLogLog
from .policy import Policy, PolicyError, validate

FILES = ('canonical.json', 'hashing.json', 'hll.json', 'density.json', 'policies.json', 'calibration.json',
         'monitor.json', 'audit.json')


def _load(d, name):
    with open(os.path.join(d, name), encoding='utf-8') as f:
        return json.load(f)


def _expand(items):
    if isinstance(items, dict):
        return [items['prefix'] + str(i) for i in range(items['from'], items['to'])]
    return items


def run_dir(d: str):
    total, fails = 0, []

    def check(name, got, want):
        nonlocal total
        total += 1
        if got != want:
            fails.append(f'{name}: got {json.dumps(got, sort_keys=True)[:300]}, want {json.dumps(want, sort_keys=True)[:300]}')

    for c in _load(d, 'canonical.json')['cases']:
        t = canonical.dumps(c['input'])
        check('canonical/' + c['name'], [t, hashlib.sha256(t.encode()).hexdigest()], [c['canonical'], c['sha256']])
    for i, c in enumerate(_load(d, 'hashing.json')['cases']):
        h64 = fnv1a64(c['seed'], c['text'])
        got = {'fnv1a32': fnv1a32(c['seed'], c['text']), 'fnv1a64': str(h64), 'mix64': str(mix64(h64)),
               'bucket': fnv1a32(c['seed'], c['text']) % (1 << 20)}
        check(f'hashing/{i}', got, {k: c[k] for k in got})
    for c in _load(d, 'hll.json')['cases']:
        h = HyperLogLog(c['seed'])
        for x in _expand(c['items']):
            h.add(x)
        check('hll/' + c['name'], {'estimate': h.estimate(), 'digest': h.digest()},
              {'estimate': c['estimate'], 'digest': c['digest']})
    for i, c in enumerate(_load(d, 'density.json')['cases']):
        check(f'density/{i}', density_micro(c['messages'], c['possible_pairs'], c['window_ms']), c['density_micro'])
    for c in _load(d, 'policies.json')['cases']:
        try:
            validate(c['policy'])
            got = {'ok': True}
        except PolicyError as e:
            got = {'ok': False, 'code': e.code}
        check('policies/' + c['name'], got, {k: c[k] for k in ('ok', 'code') if k in c})
    for c in _load(d, 'calibration.json')['cases']:
        try:
            got = {'ok': True, 'thresholds': thresholds(c['densities'], c['permille'])}
        except ValueError:
            got = {'ok': False}
        check('calibration/' + c['name'], got, {k: c[k] for k in ('ok', 'thresholds') if k in c})
    for c in _load(d, 'monitor.json')['cases']:
        eng = Engine(Policy(c['policy']))
        for i, st in enumerate(c['steps']):
            op = st['op']
            try:
                if op == 'add':
                    got = {'ok': True, 'outputs': eng.add(st['src'], st['dst'], st['ts_ms'], st['count'])}
                elif op == 'flush':
                    got = {'ok': True, 'outputs': eng.flush(st['now_ms'])}
                else:
                    got = eng.snapshot()
            except EventError as e:
                got = {'ok': False, 'code': e.code}
            check(f'monitor/{c["name"]} step {i} ({op})', got, st['expect'])
    for c in _load(d, 'audit.json')['cases']:
        ok, idx, _ = verify(c['records'])
        check('audit/' + c['name'], {'ok': ok, 'index': idx}, c['result'])
    return total, fails
