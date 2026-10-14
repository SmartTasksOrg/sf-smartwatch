"""Synthetic traffic for tests, calibration practice and the benchmark. Deterministic for a given seed.

    events(agents=6, seconds=120, rate=2.0, burst=(60, 90, 3, 40.0), seed=1, start_ms=T0)

Each second, every unordered pair of agents exchanges about ``rate`` messages (Gaussian, sd 30 %, never
below 0), each one at a random millisecond of that second and in a random direction. During a burst
(from_s, to_s, hot_agents, hot_rate) the pairs among the first ``hot_agents`` agents exchange about
``hot_rate`` messages per second instead. Agents are named agent-0, agent-1, ...
Real traffic is not like this: calibrate on your own (docs/calibration.md).
"""
from __future__ import annotations

import random

T0 = 1_700_000_000_000


def events(agents: int = 6, seconds: int = 120, rate: float = 2.0, burst=None, seed: int = 1, start_ms: int = T0):
    if agents < 2 or seconds < 1 or rate < 0:
        raise ValueError('agents >= 2, seconds >= 1, rate >= 0')
    rng = random.Random(seed)
    names = [f'agent-{i}' for i in range(agents)]
    for s in range(seconds):
        batch = []
        for i in range(agents):
            for j in range(i + 1, agents):
                r = rate
                if burst and burst[0] <= s < burst[1] and j < burst[2]:
                    r = burst[3]
                n = max(0, int(round(rng.gauss(r, r * 0.3)))) if r > 0 else 0
                for _ in range(n):
                    a, b = (names[i], names[j]) if rng.random() < 0.5 else (names[j], names[i])
                    batch.append({'src': a, 'dst': b, 'ts_ms': start_ms + s * 1000 + rng.randrange(1000), 'count': 1})
        batch.sort(key=lambda e: e['ts_ms'])
        yield from batch
