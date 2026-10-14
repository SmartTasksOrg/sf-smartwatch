import random

import pytest

from sf_smartwatch.engine import Engine, EventError, density_micro
from sf_smartwatch.hll import HyperLogLog
from sf_smartwatch.policy import DEFAULT_POLICY, MAX_INT, Policy

T0 = 1_700_000_000_000


def pol(**over):
    import copy
    d = copy.deepcopy(DEFAULT_POLICY)
    for k, v in over.items():
        if k in ('reset', 'limits'):
            d[k].update(v)
        else:
            d[k] = v
    return Policy(d)


def windows(outs):
    return [o for o in outs if o['kind'] == 'window']


def test_density_example_from_the_docs():
    assert density_micro(200, 10, 1000) == 20_000_000
    assert density_micro(5, 0, 1000) == 0
    assert density_micro(MAX_INT, 1, 100) == MAX_INT


def test_density_does_not_depend_on_window_length():
    a, b = Engine(pol(window_ms=1000)), Engine(pol(window_ms=500))
    out_a, out_b = [], []
    for i in range(4):
        for x, y in (('p', 'q'), ('q', 'r'), ('r', 'p')):
            out_a += a.add(x, y, T0 + i * 250, 10)
            out_b += b.add(x, y, T0 + i * 250, 10)
    out_a += a.flush(T0 + 10_000)
    out_b += b.flush(T0 + 10_000)
    da = [w['density_micro'] for w in windows(out_a) if w['messages']]
    db = [w['density_micro'] for w in windows(out_b) if w['messages']]
    assert da == [40_000_000] and db == [40_000_000, 40_000_000]


def test_more_agents_with_the_same_traffic_per_pair_keep_density():
    def run(n):
        e = Engine(pol())
        names = [f'a{i}' for i in range(n)]
        out = []
        for i in range(n):
            for j in range(i + 1, n):
                out += e.add(names[i], names[j], T0, 3)
        return windows(out + e.flush(T0 + 5000))[0]['density_micro']
    assert run(4) == run(20) == 3_000_000


def test_invalid_event_changes_nothing():
    e = Engine(pol())
    before = e.snapshot()
    for bad in (('a', 'b', T0, 0), ('a', 'b', -1, 1), ('a b', 'c', T0, 1), ('a', 'b', T0, True), ('a', 'b', 1.0, 1)):
        with pytest.raises(EventError):
            e.add(*bad)
    assert e.snapshot() == before


def test_window_closes_after_late_windows():
    e = Engine(pol(late_windows=2))
    e.add('a', 'b', T0, 1)
    assert e.flush(T0 + 2999) == []
    assert windows(e.flush(T0 + 3000))[0]['window'] == T0 // 1000


def test_sketch_mode_reports_estimates_and_keeps_hot_pairs():
    e = Engine(pol(limits={'max_pairs_exact': 50, 'max_agents_exact': 40, 'top_k': 5, 'candidates': 16}))
    rng = random.Random(1)
    names = [f'n{i}' for i in range(200)]
    for _ in range(3000):
        a, b = rng.sample(names, 2)
        e.add(a, b, T0 + rng.randrange(1000), 1)
    e.add('hot-a', 'hot-b', T0 + 500, 900)
    w = windows(e.flush(T0 + 5000))[0]
    assert not w['exact']
    assert abs(w['agents'] - 202) <= 6
    assert w['top'][0]['a'] == 'hot-a' and w['top'][0]['count'] >= 900 and w['top'][0]['exact'] is False


def test_hll_accuracy():
    for n in (100, 5000, 50000):
        h = HyperLogLog('t/seed')
        for i in range(n):
            h.add(f'item-{i}')
        assert abs(h.estimate() - n) / n < 0.03


def test_one_reset_per_stay_and_cooldown():
    e = Engine(pol(levels=[{'name': 'critical', 'min_density_micro': 1_000_000}],
                   reset={'level': 'critical', 'mode': 'auto', 'sustain_ms': 2000, 'cooldown_ms': 0}))
    outs = []
    for s in range(10):
        for x, y in (('a', 'b'), ('b', 'c'), ('c', 'a')):
            outs += e.add(x, y, T0 + s * 1000, 5)
    outs += e.flush(T0 + 20_000)
    resets = [o for o in outs if o['kind'] == 'reset']
    assert len(resets) == 1 and resets[0]['sustained_ms'] == 2000
    assert set(resets[0]['agents']) == {'a', 'b', 'c'}


def test_counters_saturate():
    e = Engine(pol())
    for _ in range(3):
        e.add('a', 'b', T0, 1_000_000_000)
    assert e.snapshot()['messages'] == 3_000_000_000
    w = e.acc[T0 // 1000]
    w.total = MAX_INT - 1
    e.add('a', 'b', T0, 5)
    assert w.total == MAX_INT
