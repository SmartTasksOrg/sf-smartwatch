"""The policy: one JSON document per environment (spec/policy.schema.json, spec/SEMANTICS.md "Policy").

    p = Policy.load("policy.json")          # raises PolicyError (code WATCH-BAD-POLICY)
    p = Policy()                            # DEFAULT_POLICY: thresholds are placeholders, calibrate them

The default thresholds are not calibrated for any system: run ``sf-smartwatch calibrate`` on your own
traffic and use the policy it writes (docs/calibration.md).
"""
from __future__ import annotations

import copy
import json
import re

ID = re.compile(r'[A-Za-z0-9._:@/-]{1,128}\Z')
LEVEL_NAME = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
MAX_INT = 2 ** 53 - 1

DEFAULT_POLICY = {
    'schema': 'smartwatch.policy/v1',
    'environment': 'default',
    'window_ms': 1000,
    'late_windows': 2,
    'max_empty_windows': 10,
    'min_agents': 3,
    'levels': [
        {'name': 'elevated', 'min_density_micro': 2_000_000},
        {'name': 'high', 'min_density_micro': 5_000_000},
        {'name': 'critical', 'min_density_micro': 10_000_000},
    ],
    'hysteresis_permille': 100,
    'reset': {'level': 'critical', 'sustain_ms': 5000, 'mode': 'confirm', 'confirm_timeout_ms': 5000,
              'on_timeout': 'reset', 'cooldown_ms': 60000, 'max_agents': 10, 'hot_pair_min_count': 1},
    'limits': {'max_pairs_exact': 100000, 'max_agents_exact': 50000, 'top_k': 10, 'candidates': 1024},
    'hash_seed': 'default/smartwatch',
}

FIELDS = set(DEFAULT_POLICY)
RESET_FIELDS = set(DEFAULT_POLICY['reset'])
LIMIT_FIELDS = set(DEFAULT_POLICY['limits'])


class PolicyError(ValueError):
    code = 'WATCH-BAD-POLICY'


def _int(v, lo, hi) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def validate(doc) -> dict:
    def bad(msg):
        raise PolicyError(msg)

    if not isinstance(doc, dict) or set(doc) != FIELDS:
        bad('the policy must have exactly the fields ' + ', '.join(sorted(FIELDS)))
    if not isinstance(doc['schema'], str) or doc['schema'] != 'smartwatch.policy/v1':
        bad('schema must be "smartwatch.policy/v1"')
    if not isinstance(doc['environment'], str) or not ID.match(doc['environment']):
        bad('environment must match [A-Za-z0-9._:@/-]{1,128}')
    for k, lo, hi in (('window_ms', 100, 60000), ('late_windows', 0, 60), ('max_empty_windows', 0, 3600),
                      ('min_agents', 2, 1_000_000), ('hysteresis_permille', 0, 900)):
        if not _int(doc[k], lo, hi):
            bad(f'{k} must be an integer from {lo} to {hi}')
    lv = doc['levels']
    if not isinstance(lv, list) or not 1 <= len(lv) <= 8:
        bad('levels must be a list of 1 to 8 levels')
    names, prev = set(), 0
    for x in lv:
        if not isinstance(x, dict) or set(x) != {'name', 'min_density_micro'}:
            bad('each level must be {"name", "min_density_micro"}')
        if not isinstance(x['name'], str) or not LEVEL_NAME.match(x['name']) or x['name'] == 'normal' or x['name'] in names:
            bad('level names must match [a-z][a-z0-9_-]{0,31}, be unique and not "normal"')
        if not _int(x['min_density_micro'], 1, MAX_INT) or x['min_density_micro'] <= prev:
            bad('min_density_micro must be a positive integer, strictly increasing from level to level')
        names.add(x['name'])
        prev = x['min_density_micro']
    r = doc['reset']
    if not isinstance(r, dict) or set(r) != RESET_FIELDS:
        bad('reset must have exactly the fields ' + ', '.join(sorted(RESET_FIELDS)))
    if not isinstance(r['level'], str) or r['level'] not in names:
        bad('reset.level must be one of the level names')
    if not isinstance(r['mode'], str) or r['mode'] not in ('auto', 'confirm', 'off'):
        bad('reset.mode must be auto, confirm or off')
    if not isinstance(r['on_timeout'], str) or r['on_timeout'] not in ('reset', 'cancel'):
        bad('reset.on_timeout must be reset or cancel')
    for k, lo, hi in (('sustain_ms', 0, 3_600_000), ('confirm_timeout_ms', 0, 3_600_000), ('cooldown_ms', 0, 86_400_000),
                      ('max_agents', 1, 1000), ('hot_pair_min_count', 1, 1_000_000_000)):
        if not _int(r[k], lo, hi):
            bad(f'reset.{k} must be an integer from {lo} to {hi}')
    li = doc['limits']
    if not isinstance(li, dict) or set(li) != LIMIT_FIELDS:
        bad('limits must have exactly the fields ' + ', '.join(sorted(LIMIT_FIELDS)))
    for k, lo, hi in (('max_pairs_exact', 1, 10_000_000), ('max_agents_exact', 1, 10_000_000), ('top_k', 1, 100),
                      ('candidates', 1, 65536)):
        if not _int(li[k], lo, hi):
            bad(f'limits.{k} must be an integer from {lo} to {hi}')
    if not isinstance(doc['hash_seed'], str) or not 1 <= len(doc['hash_seed'].encode('utf-8', 'replace')) <= 256:
        bad('hash_seed must be a string of 1 to 256 bytes')
    try:
        doc['hash_seed'].encode('utf-8')
    except UnicodeEncodeError:
        bad('hash_seed must be valid Unicode')
    return doc


class Policy:
    def __init__(self, doc: dict | None = None):
        self.doc = validate(copy.deepcopy(doc if doc is not None else DEFAULT_POLICY))

    @classmethod
    def load(cls, path: str) -> 'Policy':
        with open(path, encoding='utf-8') as f:
            try:
                return cls(json.load(f))
            except ValueError as e:
                if isinstance(e, PolicyError):
                    raise
                raise PolicyError(f'{path}: not JSON ({e})') from None

    def __getattr__(self, k):
        d = self.__dict__.get('doc')
        if d is not None and k in d:
            return d[k]
        raise AttributeError(k)

    def level_index(self, name: str) -> int:
        return [x['name'] for x in self.doc['levels']].index(name)
