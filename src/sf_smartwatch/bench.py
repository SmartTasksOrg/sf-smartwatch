"""Time the engine and the service on this machine (no network).

    sf-smartwatch bench [--events 200000] [--out bench.json]

Cases: exact counting with 20 agents; sketch mode (estimates) with 5,000 agents and the exact limits
lowered to 1,000 pairs; Watcher.ingest in batches of 1,000 (what one POST /v1/events does, without HTTP).
Numbers depend on the machine; the benchmark prints them, it does not judge them.
"""
from __future__ import annotations

import json
import platform
import random
import time

from .engine import Engine
from .policy import DEFAULT_POLICY, Policy
from .service import Watcher
from .synth import T0


def _gen(n, agents, seed=3):
    rng = random.Random(seed)
    names = [f'a{i}' for i in range(agents)]
    out = []
    for k in range(n):
        a, b = rng.sample(names, 2)
        out.append((a, b, T0 + k // 50, 1))           # 50 events per millisecond: 50,000 per 1 s window
    return out


def run(n_events: int = 200_000, out_path: str | None = None, out=print) -> dict:
    res = {'python': platform.python_version(), 'machine': platform.machine(), 'events': n_events, 'cases': []}
    for name, agents, limits in (('exact, 20 agents', 20, None),
                                 ('sketch, 5000 agents, 1000 exact pairs', 5000,
                                  {'max_pairs_exact': 1000, 'max_agents_exact': 1000, 'top_k': 10, 'candidates': 1024})):
        doc = dict(DEFAULT_POLICY)
        if limits:
            doc['limits'] = limits
        eng = Engine(Policy(doc))
        evs = _gen(n_events, agents)
        t = time.perf_counter()
        for a, b, ts, c in evs:
            eng.add(a, b, ts, c)
        eng.flush(evs[-1][2] + 10_000)
        dt = time.perf_counter() - t
        res['cases'].append({'case': 'engine: ' + name, 'seconds': round(dt, 3), 'events_per_s': int(n_events / dt)})
    w = Watcher(Policy(), clock=lambda: T0 + 10_000)
    evs = [{'src': a, 'dst': b, 'ts_ms': ts, 'count': c} for a, b, ts, c in _gen(n_events, 20)]
    t = time.perf_counter()
    for i in range(0, len(evs), 1000):
        w.ingest(evs[i:i + 1000])
    dt = time.perf_counter() - t
    res['cases'].append({'case': 'Watcher.ingest, batches of 1000, 20 agents', 'seconds': round(dt, 3),
                         'events_per_s': int(n_events / dt)})
    for c in res['cases']:
        out(f'{c["case"]:<48} {c["events_per_s"]:>10,} events/s  ({c["seconds"]} s)')
    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=2)
            f.write('\n')
    return res
