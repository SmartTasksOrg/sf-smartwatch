"""The built-in demo: a monitor on 127.0.0.1, five agents reporting over HTTP, a burst of coordination
among three of them, a reset proposal, a confirmation, the reset commands reaching the agents, the level
falling back, and the audit chain checked. About 10 seconds; writes nothing to disk.

    sf-smartwatch demo
"""
from __future__ import annotations

import random
import threading
import time

from .audit import AuditLog, verify
from .client import Client, CommandPoller, Reporter
from .policy import DEFAULT_POLICY, Policy
from .server import Config, make_server
from .service import Watcher, start_ticker

AGENTS = ['planner', 'coder', 'tester', 'reviewer', 'writer']
HOT = AGENTS[:3]


def demo_policy() -> dict:
    d = dict(DEFAULT_POLICY)
    d.update(environment='demo', window_ms=500, late_windows=1, max_empty_windows=10, min_agents=3,
             levels=[{'name': 'elevated', 'min_density_micro': 2_000_000},
                     {'name': 'high', 'min_density_micro': 5_000_000},
                     {'name': 'critical', 'min_density_micro': 8_000_000}],
             hysteresis_permille=100,
             reset={'level': 'critical', 'sustain_ms': 1000, 'mode': 'confirm', 'confirm_timeout_ms': 10000,
                    'on_timeout': 'cancel', 'cooldown_ms': 60000, 'max_agents': 10, 'hot_pair_min_count': 5},
             limits=dict(DEFAULT_POLICY['limits']), hash_seed='demo/smartwatch')
    return d


def run(out=print) -> int:
    audit = AuditLog(None)
    w = Watcher(Policy(demo_policy()), audit=audit)
    srv = make_server(w, Config(insecure_dev=True), '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stop_tick = start_ticker(w, 0.05)
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    out(f'monitor on {url}; window 500 ms; levels elevated 2.0, high 5.0, critical 8.0 messages per pair per second;')
    out('a reset is proposed after 1 s at critical and needs a human to confirm it.')
    rep = Reporter(url, interval_s=0.2, jitter_s=0.05, bucket_ms=100).start()
    got: list = []
    pollers = [CommandPoller(Client(url), a, on_reset=lambda c, a=a: got.append((a, c['reset_id'])), interval_s=0.2).start()
               for a in AGENTS]
    rng = random.Random(7)
    phase = {'burst': False}
    stop = threading.Event()

    def traffic():
        while not stop.wait(0.1):
            a, b = rng.sample(AGENTS, 2)
            rep.record(a, b)
            if phase['burst']:
                for _ in range(10):
                    x, y = rng.sample(HOT, 2)
                    rep.record(x, y)
    threading.Thread(target=traffic, daemon=True).start()
    seen_levels: list = []
    ok = False
    try:
        def wait_for(pred, timeout_s):
            end = time.monotonic() + timeout_s
            while time.monotonic() < end:
                lv = w.state()['level']
                if not seen_levels or seen_levels[-1] != lv:
                    seen_levels.append(lv)
                    out(f'  level: {lv}')
                if pred():
                    return True
                time.sleep(0.05)
            return False

        out('1. calm traffic: about one message every 100 ms between random agents')
        time.sleep(1.5)
        wait_for(lambda: len(w.recent_windows(1)) > 0, 3)
        out(f'   last window: {w.recent_windows(1)[0]["density_micro"]} micro')
        out(f'2. burst: {", ".join(HOT)} exchange about 100 messages per second')
        phase['burst'] = True
        if not wait_for(lambda: w.proposal_list('open'), 10):
            out('FAILED: no reset proposal within 10 s')
            return 1
        p = w.proposal_list('open')[0]
        out(f'3. proposal {p["proposal_id"]}: reset {", ".join(p["agents"])} '
            f'(density {p["density_micro"]} micro, level {p["level"]})')
        r = Client(url).decide(p['proposal_id'], 'confirm', note='demo: confirmed')
        out(f'4. confirmed by {r["decided_by"]}; {len(r["resets"])} reset commands issued')
        if not wait_for(lambda: len(got) >= len(r['resets']), 5):
            out('FAILED: the agents did not receive their reset commands')
            return 1
        for a, rid in sorted(got):
            out(f'   {a} received {rid} and acknowledged it')
        phase['burst'] = False
        out('5. the burst stops (the agents were reset)')
        if not wait_for(lambda: w.state()['level'] == 'normal', 6):
            out('FAILED: the level did not fall back to normal')
            return 1
        acked = all(w.reset_get(rid)['status'] == 'acked' for rid in r['resets'])
        good, idx, msg = verify(audit.records)
        out(f'6. audit: {msg}')
        events = [x['event'] for x in audit.records]
        out(f'   events: {", ".join(events)}')
        ok = good and acked and seen_levels[-1] == 'normal'
        out('demo OK' if ok else 'demo FAILED')
        return 0 if ok else 1
    finally:
        stop.set()
        for pl in pollers:
            pl.stop()
        rep.close()
        stop_tick.set()
        srv.shutdown()
        srv.server_close()
