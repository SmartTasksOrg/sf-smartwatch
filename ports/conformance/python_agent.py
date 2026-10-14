#!/usr/bin/env python3
"""The Python reference of the interop program (spec/PORTING.md, "The interop program").

    python3 ports/conformance/python_agent.py URL AGENT_IDS SECONDS     (token in SMARTWATCH_INGEST_TOKEN)
"""
from __future__ import annotations

import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from sf_smartwatch.client import Client, CommandPoller, Reporter  # noqa: E402


def main():
    url, ids, seconds = sys.argv[1], sys.argv[2].split(','), int(sys.argv[3])
    token = os.environ.get('SMARTWATCH_INGEST_TOKEN')
    lock = threading.Lock()

    def handler(agent):
        def on_reset(cmd):
            with lock:
                print(f'RESET {agent} {cmd["reset_id"]}', flush=True)
        return on_reset
    pollers = [CommandPoller(Client(url, token), a, handler(a), interval_s=0.2).start() for a in ids]
    rep = Reporter(url, token).start()
    t0 = time.monotonic()
    for r in range(seconds * 10):
        for a in ids:
            for b in ids:
                if a != b:
                    rep.record(a, b, 1)
        time.sleep(max(0.0, t0 + (r + 1) * 0.1 - time.monotonic()))
    rep.close()
    with lock:
        print(f'SENT {rep.sent}', flush=True)
    sys.stdin.read()
    for p in pollers:
        p.stop()


if __name__ == '__main__':
    main()
