"""Three toy agents that report their messages to a SmartWatch monitor and obey its reset commands.

    sf-smartwatch serve --insecure-dev --audit /tmp/audit.jsonl &        # a local monitor, no credentials
    python examples/agents_with_reporter.py http://127.0.0.1:8730

The agents chat calmly, then the planner and the coder start a tight loop. With the default policy the
density climbs; after 5 s at "critical" a proposal appears (sf-smartwatch proposals --url ...). Confirm
it (sf-smartwatch decide --url ... ID confirm) and watch the two agents reset and calm down.
Ctrl-C stops the agents.
"""
import random
import sys
import threading
import time

from sf_smartwatch import Client, CommandPoller, Reporter

URL = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8730'
AGENTS = ['planner', 'coder', 'tester']
rep = Reporter(URL).start()
looping = {'on': False}


def make_reset(agent):
    def on_reset(cmd):
        print(f'{agent}: reset {cmd["reset_id"]} ({cmd["reason"]}): clearing my context')
        looping['on'] = False                     # a real agent would drop its state or restart its worker
    return on_reset


pollers = [CommandPoller(Client(URL), a, make_reset(a)).start() for a in AGENTS]
rng = random.Random(1)
start = time.monotonic()
try:
    while True:
        a, b = rng.sample(AGENTS, 2)
        rep.record(a, b)
        if time.monotonic() - start > 10 and not looping.get('done'):
            looping['on'], looping['done'] = True, True
            print('planner and coder start a tight loop')
        if looping['on']:
            for _ in range(20):
                rep.record('planner', 'coder')
                rep.record('coder', 'planner')
        time.sleep(0.2)
except KeyboardInterrupt:
    pass
finally:
    for p in pollers:
        p.stop()
    rep.close()
