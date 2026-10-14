#!/usr/bin/env python3
"""Interop test: one port's reporter and command poller against the Python monitor, over HTTP.

    python3 ports/conformance/interop.py -- <command that starts the port's interop program>

The program is started as  <command> URL AGENT_IDS SECONDS  with SMARTWATCH_INGEST_TOKEN set
(spec/PORTING.md, "The interop program"). The monitor runs an auto-reset policy (window 1 s, reset after
2 s at critical) that the program's traffic trips. Checks:
  1. the program prints SENT n, and n equals both the expected count and what the monitor counted;
  2. every agent receives an automatic reset (RESET lines) and the monitor sees it acknowledged;
  3. a reset sent by hand with a JWT to the agent whose id contains "/" arrives and is acknowledged.
Exit 0 when every check passes within the time limits.
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartwatch.audit import AuditLog, verify  # noqa: E402
from sf_smartwatch.client import Client  # noqa: E402
from sf_smartwatch.jwtauth import JWTVerifier, make_hs256  # noqa: E402
from sf_smartwatch.policy import DEFAULT_POLICY, Policy  # noqa: E402
from sf_smartwatch.server import Config, make_server  # noqa: E402
from sf_smartwatch.service import Watcher, start_ticker  # noqa: E402

AGENTS = ['planner', 'coder', 'team/tester']
SECONDS = 4
INGEST, OPERATOR = 'interop-ingest-token-0123456789', 'interop-operator-token-0123456789'
SECRET = b'interop-jwt-secret-0123456789-abcdef'


def policy() -> dict:
    d = dict(DEFAULT_POLICY)
    d.update(environment='interop', levels=[{'name': 'elevated', 'min_density_micro': 1_000_000},
                                            {'name': 'high', 'min_density_micro': 5_000_000},
                                            {'name': 'critical', 'min_density_micro': 10_000_000}],
             reset={'level': 'critical', 'sustain_ms': 2000, 'mode': 'auto', 'confirm_timeout_ms': 5000,
                    'on_timeout': 'cancel', 'cooldown_ms': 600000, 'max_agents': 10, 'hot_pair_min_count': 1},
             limits=dict(DEFAULT_POLICY['limits']))
    return d


def fail(msg):
    print('FAILED: ' + msg)
    sys.exit(1)


def main():
    if '--' not in sys.argv:
        fail('usage: interop.py -- <command>')
    cmd = sys.argv[sys.argv.index('--') + 1:]
    audit = AuditLog(None)
    w = Watcher(Policy(policy()), audit=audit)
    cfg = Config(INGEST, OPERATOR, JWTVerifier(hs256_secret=SECRET))
    srv = make_server(w, cfg, '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stop = start_ticker(w)
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    env = dict(os.environ, SMARTWATCH_INGEST_TOKEN=INGEST)
    p = subprocess.Popen(cmd + [url, ','.join(AGENTS), str(SECONDS)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, text=True)
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [lines.put(x.strip()) for x in p.stdout], daemon=True).start()
    threading.Thread(target=lambda: [sys.stderr.write('  [port] ' + x) for x in p.stderr], daemon=True).start()
    resets: dict = {}
    sent = None

    def read_until(pred, timeout_s):
        nonlocal sent
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            if pred():
                return True
            try:
                x = lines.get(timeout=0.1)
            except queue.Empty:
                if p.poll() is not None and lines.empty():
                    return pred()
                continue
            parts = x.split(' ')
            if parts[0] == 'SENT' and len(parts) == 2:
                sent = int(parts[1])
            elif parts[0] == 'RESET' and len(parts) == 3:
                resets.setdefault(parts[1], []).append(parts[2])
            else:
                print(f'  [port stdout] {x}')
        return pred()
    try:
        expected = SECONDS * 10 * len(AGENTS) * (len(AGENTS) - 1)
        if not read_until(lambda: sent is not None, SECONDS + 30):
            fail('no SENT line')
        counted = w.engine.snapshot()['messages']
        if sent != expected or counted != expected:
            fail(f'SENT {sent}, monitor counted {counted}, expected {expected}')
        print(f'1. sent and counted {expected} messages')
        if not read_until(lambda: all(a in resets for a in AGENTS), 15):
            fail(f'automatic resets reached only {sorted(resets)}')
        time.sleep(0.5)
        auto = [rid for a in AGENTS for rid in resets[a]]
        st = [w.reset_get(rid)['status'] for rid in auto]
        if any(s != 'acked' for s in st):
            fail(f'automatic resets not all acknowledged: {st}')
        print(f'2. automatic resets received and acknowledged by {", ".join(AGENTS)}')
        tok = make_hs256(SECRET, {'sub': 'interop', 'scope': 'reset:agent', 'exp': int(time.time()) + 300})
        r = Client(url, tok).reset('team/tester', 'interop: by hand', 'interop-1')
        if not read_until(lambda: r['reset_id'] in resets.get('team/tester', []), 10):
            fail('the manual reset did not arrive')
        time.sleep(0.5)
        if w.reset_get(r['reset_id'])['status'] != 'acked':
            fail('the manual reset was not acknowledged')
        print('3. manual reset (JWT) of team/tester received and acknowledged')
        ok, _, msg = verify(audit.records)
        if not ok:
            fail('audit chain: ' + msg)
        print(f'interop OK ({msg})')
    finally:
        try:
            p.stdin.close()
        except OSError:
            pass
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        stop.set()
        srv.shutdown()
        srv.server_close()


if __name__ == '__main__':
    main()
