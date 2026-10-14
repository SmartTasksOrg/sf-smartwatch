import copy
import json

import pytest

from sf_smartwatch.audit import AuditError, AuditLog, verify, verify_file
from sf_smartwatch.policy import DEFAULT_POLICY, Policy
from sf_smartwatch.service import Refused, Watcher, Webhooks, sign_body

T0 = 1_700_000_000_000


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def policy(mode='confirm', on_timeout='reset', timeout=60000, min_count=1):
    d = copy.deepcopy(DEFAULT_POLICY)
    d['levels'] = [{'name': 'critical', 'min_density_micro': 1_000_000}]
    d['reset'].update(level='critical', mode=mode, sustain_ms=2000, confirm_timeout_ms=timeout, on_timeout=on_timeout,
                      cooldown_ms=0, hot_pair_min_count=min_count)
    return Policy(d)


def burst(w, clock, seconds=6):
    for s in range(seconds):
        clock.t = T0 + s * 1000
        w.ingest([{'src': x, 'dst': y, 'ts_ms': clock.t, 'count': 5} for x, y in (('a', 'b'), ('b', 'c'), ('c', 'a'))])
        w.tick()
    clock.t = T0 + seconds * 1000 + 3000
    w.tick()


def make(mode='confirm', **kw):
    c = Clock()
    sent = []
    w = Watcher(policy(mode, **kw), clock=c, alert_webhook='http://alerts.invalid/', reset_webhook='http://resets.invalid/',
                webhooks=Webhooks(b'k' * 32, post=lambda u, b, h: sent.append((u, b, h)) or 200))
    return w, c, sent


def test_auto_mode_issues_resets_and_pull_ack():
    w, c, _ = make('auto')
    burst(w, c)
    assert {r['agent_id'] for r in w.recent_resets()} == {'a', 'b', 'c'}
    cmds = w.commands('a')
    assert len(cmds) == 1 and cmds[0]['type'] == 'reset'
    r = w.ack(cmds[0]['reset_id'], 'a')
    assert r['status'] == 'acked' and w.commands('a') == []
    with pytest.raises(Refused):
        w.ack(w.commands('b')[0]['reset_id'], 'a')         # someone else's reset
    assert verify(w.audit.records)[0]


def test_confirm_mode_needs_a_decision():
    w, c, _ = make()
    burst(w, c)
    [p] = w.proposal_list('open')
    assert w.recent_resets() == []
    d = w.decide(p['proposal_id'], 'confirm', 'jwt:alice')
    assert d['status'] == 'confirmed' and len(d['resets']) == 3
    with pytest.raises(Refused) as e:
        w.decide(p['proposal_id'], 'cancel', 'jwt:bob')
    assert e.value.status == 409
    events = [r['event'] for r in w.audit.records]
    assert 'proposal' in events and 'proposal-confirmed' in events and events.count('reset') == 3


def test_cancel_and_escalate():
    w, c, sent = make()
    burst(w, c)
    [p] = w.proposal_list('open')
    w.urls['escalation'] = 'http://esc.invalid/'
    w.decide(p['proposal_id'], 'escalate', 'jwt:alice', 'need the owner')
    assert w.decide(p['proposal_id'], 'cancel', 'jwt:owner')['status'] == 'cancelled'
    assert w.recent_resets() == []


@pytest.mark.parametrize('on_timeout,status,n', [('reset', 'timed-out-reset', 3), ('cancel', 'timed-out-cancel', 0)])
def test_timeout(on_timeout, status, n):
    w, c, _ = make(on_timeout=on_timeout)
    burst(w, c)
    [p] = w.proposal_list('open')
    c.t = p['deadline_ms']
    w.tick()
    assert w.proposal_list()[0]['status'] == status and len(w.recent_resets()) == n


def test_no_hot_pair_means_no_proposal():
    w, c, _ = make(min_count=10_000)
    burst(w, c)
    assert w.proposal_list() == []
    assert any(r['event'] == 'reset-skipped' for r in w.audit.records)


def test_manual_reset_idempotency():
    w, c, _ = make()
    a = w.manual_reset('team/x', 'jwt:alice', 'by hand', 'key-1')
    b = w.manual_reset('team/x', 'jwt:alice', 'by hand', 'key-1')
    assert a['reset_id'] == b['reset_id'] and b['replayed']
    other = w.manual_reset('team/x', 'jwt:bob', 'by hand', 'key-1')      # keys are per caller
    assert other['reset_id'] != a['reset_id']
    with pytest.raises(Refused) as e:
        w.manual_reset('team/y', 'jwt:alice', '', 'key-1')
    assert e.value.status == 422
    with pytest.raises(Refused):
        w.manual_reset('bad id', 'jwt:alice')


def test_ingest_reports_bad_events_by_index_and_refuses_clock_skew():
    w, c, _ = make()
    r = w.ingest([{'src': 'a', 'dst': 'b', 'ts_ms': T0}, {'src': 'a', 'dst': 'b', 'ts_ms': T0 + 2001},
                  {'src': 'a b', 'dst': 'b', 'ts_ms': T0}, {'src': 'a', 'dst': 'b', 'ts_ms': T0, 'x': 1}, 'no'])
    assert r['accepted'] == 1
    assert [(x['index'], x['code']) for x in r['rejected']] == [(1, 'WATCH-CLOCK-SKEW'), (2, 'WATCH-BAD-EVENT'),
                                                                (3, 'WATCH-BAD-EVENT'), (4, 'WATCH-BAD-EVENT')]
    with pytest.raises(Refused):
        w.ingest([{}] * 10_001)


def test_webhooks_are_signed_and_retried():
    calls = []

    def post(url, body, headers):
        calls.append((body, headers))
        return 500 if len(calls) < 3 else 204
    h = Webhooks(b's' * 32, post=post)
    assert not h.deliver_one('reset', 'http://x.invalid/', {'a': 1})
    body, headers = calls[0]
    assert headers['X-SmartWatch-Signature'] == sign_body(b's' * 32, int(headers['X-SmartWatch-Timestamp']), body)
    t = [0.0]
    h2 = Webhooks(b's' * 32, post=post, clock=lambda: t[0])
    h2.send('reset', 'http://x.invalid/', {'a': 1})
    h2.start()
    import time
    for _ in range(100):
        t[0] += 1
        time.sleep(0.01)
        if len(calls) >= 3 and h2.pending() == 0:
            break
    h2.stop()
    assert len(calls) == 3 and json.loads(calls[-1][0]) == {'a': 1}


def test_audit_file_reopens_and_refuses_a_broken_chain(tmp_path):
    p = str(tmp_path / 'a.jsonl')
    a = AuditLog(p)
    a.append('x', ts_ms=1, n=1)
    a.append('y', ts_ms=2, n=2)
    b = AuditLog(p)
    assert b.head == a.head
    b.append('z', ts_ms=3)
    assert verify_file(p)[0]
    lines = open(p).read().splitlines()
    lines[1] = lines[1].replace('"n":2', '"n":3')
    open(p, 'w').write('\n'.join(lines) + '\n')
    assert verify_file(p) [:2] == (False, 1)
    with pytest.raises(AuditError):
        AuditLog(p)
