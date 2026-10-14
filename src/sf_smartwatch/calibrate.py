"""Calibration: thresholds from the densities your own system produced (council: sample 30 s, percentile
thresholds per environment, prod p95 and staging p90 as the baseline).

    levels = thresholds([d1, d2, ...], [950, 990, 999])     # permille percentiles, nearest rank
    doc = calibrated_policy(base_policy_doc, densities, environment="prod")

Nearest rank: sort the densities ascending; the p-permille value is sorted[ceil(p * N / 1000) - 1]
(the first value when that index is below 0). Thresholds must increase strictly: a value not above the
previous one becomes previous + 1. A threshold of 0 becomes 1. Vectors: spec/conformance/calibration.json.
"""
from __future__ import annotations

import copy

from .policy import validate

PROFILES = {
    'prod': [950, 990, 999],         # elevated at p95 (the council's prod baseline), high p99, critical p99.9
    'staging': [900, 950, 990],      # elevated at p90 (the council's staging baseline)
}
NAMES = ['elevated', 'high', 'critical']


def thresholds(densities, permille) -> list:
    for d in densities:
        if isinstance(d, bool) or not isinstance(d, int) or d < 0:
            raise ValueError('densities are non-negative integers')
    xs = sorted(densities)
    if not xs:
        raise ValueError('no densities to calibrate from')
    out, prev = [], 0
    for p in permille:
        if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 1000:
            raise ValueError('percentiles are integers from 1 to 1000 (permille)')
        rank = (p * len(xs) + 999) // 1000
        v = xs[max(rank, 1) - 1]
        v = max(v, prev + 1, 1)
        out.append(v)
        prev = v
    return out


def calibrated_policy(base: dict, densities, environment: str, permille=None, names=None) -> dict:
    pm = permille or PROFILES.get(environment, PROFILES['prod'])
    if names:
        nm = list(names)
    elif len(pm) <= len(NAMES):
        nm = NAMES[:len(pm)]
    else:
        nm = [f'level{i + 1}' for i in range(len(pm))]
    if len(nm) != len(pm):
        raise ValueError('as many names as percentiles')
    vals = thresholds(densities, pm)
    doc = copy.deepcopy(base)
    doc['environment'] = environment
    doc['levels'] = [{'name': n, 'min_density_micro': v} for n, v in zip(nm, vals)]
    if doc['reset']['level'] not in nm:
        doc['reset']['level'] = nm[-1]
    return validate(doc)
