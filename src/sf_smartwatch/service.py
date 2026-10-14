"""The monitor as a service: the engine plus clocks, reset proposals, human decisions, reset delivery,
webhooks and the audit log. The HTTP server (server.py) and the in-process API both use this class.

    w = Watcher(Policy.load("policy.json"), audit=AuditLog("audit.jsonl"))
    w.ingest([{"src": "planner", "dst": "coder", "ts_ms": 1700000000123, "count": 4}])
    w.tick()                 # call often (the server does, every 100 ms): closes windows, times out proposals

What happens to a reset the engine asks for (policy ``reset.mode``):
    auto     one reset command per affected agent, at once
    confirm  a proposal; a human confirms or cancels it within ``confirm_timeout_ms``; on timeout the
             policy's ``on_timeout`` decides (``reset``: the commands go out; ``cancel``: nothing happens)
    off      nothing (levels and alerts only)
A reset command reaches the agent in up to three ways: the agent (or its supervisor) pulls it from
``GET /v1/agents/{id}/commands`` and acknowledges it; ``SMARTWATCH_RESET_WEBHOOK`` receives it (signed);
an in-process ``on_reset`` callback receives it. The monitor never kills a process itself.
"""
from __future__ import annotations

import collections
import hashlib
import hmac
import heapq
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .audit import AuditLog
from .engine import Engine, EventError, check_event
from .metrics import Metrics
from .policy import ID, MAX_INT, Policy

log = logging.getLogger('sf_smartwatch.service')

MAX_EVENTS_PER_BATCH = 10_000
MAX_CLOCK_SKEW_MS = 2_000            # events stamped further ahead are refused; up to this, counted at 'now'
WINDOW_HISTORY = 600
RESET_HISTORY = 10_000
MAX_PENDING_PER_AGENT = 100
WEBHOOK_ATTEMPTS = 5
WEBHOOK_TIMEOUT_S = 5.0
IDEMPOTENCY_KEEP = 10_000
MAX_OPEN_PROPOSALS = 1000


def wall_ms() -> int:
    return time.time_ns() // 1_000_000


class Refused(Exception):
    def __init__(self, status: int, reason: str, code: str | None = None):
        super().__init__(reason)
        self.status, self.reason, self.code = status, reason, code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def sign_body(secret: bytes, ts_ms: int, body: bytes) -> str:
    """X-SmartWatch-Signature: sha256=hex(HMAC-SHA256(secret, "<ts_ms>." + body))."""
    return 'sha256=' + hmac.new(secret, str(ts_ms).encode() + b'.' + body, hashlib.sha256).hexdigest()


LANES = {'reset': 'reset', 'escalation': 'escalation'}      # every other kind (level, proposal) uses "alert"


def redact_url(url: str) -> str:
    """scheme://host[:port]/... for log lines: never the user info, the query or the fragment."""
    p = urllib.parse.urlsplit(url)
    return f'{p.scheme}://{p.hostname or ""}{":" + str(p.port) if p.port else ""}{p.path}'


def check_webhook_url(url: str) -> None:
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname:
        raise ValueError('webhook URLs must be http:// or https:// with a host')
    if p.username is not None or p.password is not None:
        raise ValueError('webhook URLs must not carry a user name or password (put a secret in SMARTWATCH_WEBHOOK_SECRET)')


class Webhooks:
    """At-least-once delivery with backoff (1, 2, 4, 8 s; 5 attempts). Three lanes, each with its own
    worker thread and bounded queue, so that a dead alert receiver never delays a reset webhook:
    "reset", "escalation" and "alert" (level changes and proposals). Every body is signed when a secret
    is set; receivers check the signature and the timestamp."""

    def __init__(self, secret: bytes | None = None, metrics: Metrics | None = None, clock=time.monotonic, post=None):
        self.secret, self.metrics, self.clock = secret, metrics, clock
        self._post = post or self._http_post
        self._heaps: dict[str, list] = {'reset': [], 'escalation': [], 'alert': []}
        self._n = 0
        self._cv = threading.Condition()
        self._stop = False
        self._threads: list = []
        self.dropped = 0

    def start(self):
        if not self._threads:
            for lane in self._heaps:
                t = threading.Thread(target=self._run, args=(lane,), daemon=True, name='webhooks-' + lane)
                t.start()
                self._threads.append(t)

    def stop(self):
        with self._cv:
            self._stop = True
            self._cv.notify_all()

    def send(self, kind: str, url: str | None, payload: dict):
        if not url:
            return
        heap = self._heaps[LANES.get(kind, 'alert')]
        with self._cv:
            if len(heap) >= 10_000:
                self.dropped += 1
                if self.metrics:
                    self.metrics.webhooks.inc(kind=kind, result='dropped')
                return
            self._n += 1
            heapq.heappush(heap, (self.clock(), self._n, 1, kind, url, payload))
            self._cv.notify_all()

    def pending(self) -> int:
        with self._cv:
            return sum(len(h) for h in self._heaps.values())

    def _http_post(self, url: str, body: bytes, headers: dict) -> int:
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        try:
            with _OPENER.open(req, timeout=WEBHOOK_TIMEOUT_S) as r:
                r.read(65536)
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def deliver_one(self, kind: str, url: str, payload: dict) -> bool:
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        ts = wall_ms()
        headers = {'Content-Type': 'application/json', 'X-SmartWatch-Event': kind, 'X-SmartWatch-Timestamp': str(ts)}
        if self.secret:
            headers['X-SmartWatch-Signature'] = sign_body(self.secret, ts, body)
        try:
            status = self._post(url, body, headers)
        except Exception as e:                          # network errors: retried
            log.warning('webhook %s to %s failed: %s', kind, redact_url(url), type(e).__name__)
            return False
        return 200 <= status < 300

    def _run(self, lane: str):
        heap = self._heaps[lane]
        while True:
            with self._cv:
                while not self._stop and (not heap or heap[0][0] > self.clock()):
                    self._cv.wait(timeout=None if not heap else max(0.0, heap[0][0] - self.clock()))
                if self._stop:
                    return
                due, n, attempt, kind, url, payload = heapq.heappop(heap)
            ok = self.deliver_one(kind, url, payload)
            if self.metrics:
                self.metrics.webhooks.inc(kind=kind, result='ok' if ok else ('retry' if attempt < WEBHOOK_ATTEMPTS else 'failed'))
            if not ok and attempt < WEBHOOK_ATTEMPTS:
                with self._cv:
                    self._n += 1
                    heapq.heappush(heap, (self.clock() + 2 ** (attempt - 1), self._n, attempt + 1, kind, url, payload))
                    self._cv.notify_all()


class Watcher:
    def __init__(self, policy: Policy | None = None, audit: AuditLog | None = None, clock=wall_ms,
                 alert_webhook=None, reset_webhook=None, escalation_webhook=None, webhook_secret: bytes | None = None,
                 on_reset=None, on_alert=None, webhooks: Webhooks | None = None, metrics: Metrics | None = None):
        self.policy = policy or Policy()
        self.engine = Engine(self.policy)
        self.audit = audit or AuditLog(None)
        self.clock = clock
        self.metrics = metrics or Metrics()
        self.urls = {'alert': alert_webhook, 'reset': reset_webhook, 'escalation': escalation_webhook}
        self.hooks = webhooks or Webhooks(webhook_secret, self.metrics)
        self.on_reset, self.on_alert = on_reset, on_alert
        self.lock = threading.RLock()
        self.windows: collections.deque = collections.deque(maxlen=WINDOW_HISTORY)
        self.proposals: dict[str, dict] = {}
        self.resets: collections.OrderedDict = collections.OrderedDict()
        self.queues: dict[str, collections.OrderedDict] = {}
        self.idem: collections.OrderedDict = collections.OrderedDict()
        self.broken: str | None = None
        self.started_ms = clock()
        self.audit.append('started', ts_ms=self.started_ms, policy_environment=self.policy.doc['environment'],
                          reset_mode=self.policy.doc['reset']['mode'])

    # ------------------------------------------------------------------ audit
    def _audit(self, event: str, **fields) -> dict:
        """Append to the audit log. If that fails (disk full, I/O error), the monitor stops changing state:
        every later change is refused with 503 until it is restarted on a writable log."""
        try:
            return self.audit.append(event, **fields)
        except Exception as e:
            self.broken = f'the audit log could not be written ({type(e).__name__}: {e})'
            log.critical('%s; refusing every change until restarted', self.broken)
            raise Refused(503, self.broken, 'WATCH-AUDIT-FAILED') from None

    def _writable(self):
        if self.broken:
            raise Refused(503, self.broken + '; restart the monitor on a writable audit log', 'WATCH-AUDIT-FAILED')

    # ------------------------------------------------------------------ ingest
    def ingest(self, events) -> dict:
        """Add a batch. Each event is checked on its own: bad ones are reported by index, the rest count."""
        self._writable()
        if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_BATCH:
            raise Refused(400, f'events must be a list of at most {MAX_EVENTS_PER_BATCH}', 'WATCH-BAD-EVENT')
        t0 = time.perf_counter()
        accepted, rejected, msgs = 0, [], 0
        with self.lock:
            now = self.clock()
            outs = []
            for i, ev in enumerate(events):
                if not isinstance(ev, dict) or set(ev) - {'src', 'dst', 'ts_ms', 'count'} or \
                        not {'src', 'dst', 'ts_ms'} <= set(ev):
                    rejected.append({'index': i, 'code': 'WATCH-BAD-EVENT',
                                     'error': 'an event is {"src", "dst", "ts_ms", "count" (optional, default 1)}'})
                    continue
                src, dst, ts, count = ev['src'], ev['dst'], ev['ts_ms'], ev.get('count', 1)
                try:
                    check_event(src, dst, ts, count)
                except EventError as e:
                    rejected.append({'index': i, 'code': e.code, 'error': str(e)})
                    continue
                if ts > now + MAX_CLOCK_SKEW_MS:
                    rejected.append({'index': i, 'code': 'WATCH-CLOCK-SKEW',
                                     'error': 'ts_ms is more than 2 s ahead of the monitor clock'})
                    continue
                # never let a reporter's clock move the windows ahead of the monitor's own: an event a
                # little ahead counts now, so one event cannot close the windows everyone else is filling
                ts = min(ts, now)
                late_before = self.engine.stats['late_dropped']
                outs += self.engine.add(src, dst, ts, count)
                if self.engine.stats['late_dropped'] != late_before:
                    self.metrics.events.inc(result='late')
                    rejected.append({'index': i, 'code': 'WATCH-LATE',
                                     'error': 'the window of ts_ms has closed (older than late_windows)'})
                else:
                    accepted += 1
                    msgs += count
            try:
                self._handle(outs, now)
            except Refused:
                pass                      # the audit log failed (self.broken is set); the events were counted
        self.metrics.events.inc(accepted, result='accepted')
        if rejected:
            self.metrics.events.inc(len(rejected), result='rejected')
        self.metrics.messages.inc(msgs)
        self.metrics.ingest_ms.observe((time.perf_counter() - t0) * 1000)
        return {'accepted': accepted, 'rejected': rejected}

    def tick(self, now_ms: int | None = None) -> None:
        if self.broken:
            return
        with self.lock:
            now = self.clock() if now_ms is None else now_ms
            self._handle(self.engine.flush(min(now, MAX_INT)), now)
            for p in list(self.proposals.values()):
                if p['status'] == 'open' and now >= p['deadline_ms']:
                    self._timeout(p, now)

    # ------------------------------------------------------------------ engine outputs
    def _handle(self, outs: list, now: int) -> None:
        for o in outs:
            k = o['kind']
            if k == 'window':
                self.windows.append(o)
                m = self.metrics
                m.windows.inc()
                m.density.set(o['density_micro'])
                m.pair_ratio.set(o['pair_ratio_micro'])
                m.agents.set(o['agents'])
                m.pairs.set(o['pairs'])
                m.sketch.set(0 if o['exact'] else 1)
                m.level.set(self._level_num(o['level']))
                m.top_pairs.set_rows((t['a'], t['b'], t['count']) for t in o['top'])
            elif k == 'level':
                self.metrics.level_changes.inc(to=o['to'])
                self._audit('level', ts_ms=now, window=o['window'], level_from=o['from'], level_to=o['to'],
                                  density_micro=o['density_micro'])
                self._alert('level', o)
            elif k == 'reset':
                self._reset_due(o, now)
        self.metrics.skipped.set(self.engine.stats['skipped_windows'])
        self.metrics.late.set(self.engine.stats['late_dropped'])

    def _level_num(self, name: str) -> int:
        return 0 if name == 'normal' else self.policy.level_index(name) + 1

    def _alert(self, kind: str, payload: dict):
        body = {'kind': kind, 'environment': self.policy.doc['environment'], **payload}
        self.hooks.send(kind, self.urls['alert'], body)
        if self.on_alert:
            try:
                self.on_alert(body)
            except Exception:
                log.exception('on_alert callback failed')

    def _reset_due(self, o: dict, now: int):
        if not o['agents']:
            self._audit('reset-skipped', ts_ms=now, window=o['window'], level=o['level'],
                              density_micro=o['density_micro'], why='no pair reached hot_pair_min_count')
            return
        if o['mode'] == 'auto':
            self.metrics.proposals.inc(outcome='auto')
            self._audit('reset-auto', ts_ms=now, window=o['window'], level=o['level'],
                              density_micro=o['density_micro'], agents=o['agents'])
            for a in o['agents']:
                self._issue(a, 'auto', 'monitor', now, window=o['window'])
            return
        open_now = sum(1 for v in self.proposals.values() if v['status'] == 'open')
        if open_now >= MAX_OPEN_PROPOSALS:
            self._audit('proposal-dropped', ts_ms=now, window=o['window'], level=o['level'],
                        density_micro=o['density_micro'], agents=o['agents'],
                        why=f'{MAX_OPEN_PROPOSALS} proposals are already open')
            return
        pid = 'p-' + secrets.token_hex(8)
        p = {'proposal_id': pid, 'status': 'open', 'created_ms': now,
             'deadline_ms': now + self.policy.doc['reset']['confirm_timeout_ms'],
             'on_timeout': self.policy.doc['reset']['on_timeout'], 'window': o['window'], 'level': o['level'],
             'density_micro': o['density_micro'], 'sustained_ms': o['sustained_ms'], 'agents': o['agents'],
             'decided_by': None, 'decided_ms': None, 'resets': [], 'escalated': False}
        self._audit('proposal', ts_ms=now, proposal_id=pid, window=o['window'], level=o['level'],
                    density_micro=o['density_micro'], agents=o['agents'], deadline_ms=p['deadline_ms'],
                    on_timeout=p['on_timeout'])
        self.proposals[pid] = p
        while len(self.proposals) > 1000:                 # keep the open ones
            old = next((k for k, v in self.proposals.items() if v['status'] != 'open'), None)
            if old is None:
                break
            del self.proposals[old]
        self.metrics.proposals.inc(outcome='created')
        self._alert('proposal', {k: p[k] for k in ('proposal_id', 'deadline_ms', 'on_timeout', 'window', 'level',
                                                   'density_micro', 'agents')})

    def _timeout(self, p: dict, now: int):
        if p['on_timeout'] == 'reset':
            p['status'], p['decided_by'], p['decided_ms'] = 'timed-out-reset', 'timeout', now
            self.metrics.proposals.inc(outcome='timeout_reset')
            self._audit('proposal-timeout', ts_ms=now, proposal_id=p['proposal_id'], outcome='reset')
            p['resets'] = [self._issue(a, 'timeout', 'timeout', now, proposal_id=p['proposal_id'])['reset_id']
                           for a in p['agents']]
        else:
            p['status'], p['decided_by'], p['decided_ms'] = 'timed-out-cancel', 'timeout', now
            self.metrics.proposals.inc(outcome='timeout_cancel')
            self._audit('proposal-timeout', ts_ms=now, proposal_id=p['proposal_id'], outcome='cancel')

    # ------------------------------------------------------------------ decisions
    def decide(self, proposal_id: str, action: str, by: str, note: str = '') -> dict:
        """confirm / cancel / escalate an open proposal. ``by`` names who acted (the token's sub)."""
        self._writable()
        if action not in ('confirm', 'cancel', 'escalate'):
            raise Refused(404, 'unknown action')
        if not isinstance(note, str) or len(note.encode('utf-8')) > 500:
            raise Refused(400, 'note must be a string of at most 500 bytes')
        with self.lock:
            now = self.clock()
            p = self.proposals.get(proposal_id)
            if p is None:
                raise Refused(404, 'no such proposal')
            if p['status'] == 'open' and now >= p['deadline_ms']:
                self._timeout(p, now)
            if p['status'] != 'open':
                raise Refused(409, f'the proposal is already {p["status"]}', 'WATCH-DECIDED')
            if action == 'escalate':
                p['escalated'] = True
                self.metrics.proposals.inc(outcome='escalated')
                self._audit('proposal-escalated', ts_ms=now, proposal_id=proposal_id, by=by, note=note)
                body = {'kind': 'escalation', 'environment': self.policy.doc['environment'], 'by': by, 'note': note,
                        **{k: p[k] for k in ('proposal_id', 'deadline_ms', 'level', 'density_micro', 'agents')}}
                self.hooks.send('escalation', self.urls['escalation'], body)
                return dict(p)
            p['decided_by'], p['decided_ms'] = by, now
            if action == 'confirm':
                p['status'] = 'confirmed'
                self.metrics.proposals.inc(outcome='confirmed')
                self._audit('proposal-confirmed', ts_ms=now, proposal_id=proposal_id, by=by, note=note,
                                  latency_ms=now - p['created_ms'])
                p['resets'] = [self._issue(a, 'confirmed', by, now, proposal_id=proposal_id)['reset_id'] for a in p['agents']]
            else:
                p['status'] = 'cancelled'
                self.metrics.proposals.inc(outcome='cancelled')
                self._audit('proposal-cancelled', ts_ms=now, proposal_id=proposal_id, by=by, note=note)
            self.metrics.decision_ms.observe(now - p['created_ms'])
            return dict(p)

    def manual_reset(self, agent_id: str, by: str, reason: str = '', idempotency_key: str | None = None) -> dict:
        self._writable()
        if not isinstance(agent_id, str) or not ID.match(agent_id):
            raise Refused(400, 'agent_id must match [A-Za-z0-9._:@/-]{1,128}', 'WATCH-BAD-EVENT')
        if not isinstance(reason, str) or len(reason.encode('utf-8')) > 500:
            raise Refused(400, 'reason must be a string of at most 500 bytes')
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128
                                            or not idempotency_key.isascii() or not idempotency_key.isprintable()):
            raise Refused(400, 'Idempotency-Key must be 1 to 128 printable ASCII characters')
        with self.lock:
            if idempotency_key is not None:
                k = (by, idempotency_key)
                prev = self.idem.get(k)
                if prev is not None:
                    if prev[0] != agent_id:
                        raise Refused(422, 'this Idempotency-Key was used for another agent', 'WATCH-IDEMPOTENCY')
                    return dict(self.resets.get(prev[1]) or {'reset_id': prev[1], 'agent_id': agent_id}, replayed=True)
            r = self._issue(agent_id, 'manual', by, self.clock(), note=reason)
            if idempotency_key is not None:
                self.idem[(by, idempotency_key)] = (agent_id, r['reset_id'])
                while len(self.idem) > IDEMPOTENCY_KEEP:
                    self.idem.popitem(last=False)
            return dict(r)

    # ------------------------------------------------------------------ reset commands
    def _issue(self, agent: str, reason: str, by: str, now: int, **extra) -> dict:
        rid = 'r-' + secrets.token_hex(8)
        r = {'reset_id': rid, 'agent_id': agent, 'reason': reason, 'by': by, 'created_ms': now, 'status': 'pending',
             'delivered_ms': None, 'acked_ms': None, **extra}
        # the record first: a reset that could not be recorded is never queued, sent or called back
        self._audit('reset', ts_ms=now, reset_id=rid, agent_id=agent, reason=reason, by=by,
                    **{k: v for k, v in extra.items() if v is not None})
        self.resets[rid] = r
        while len(self.resets) > RESET_HISTORY:
            old_id, old = self.resets.popitem(last=False)
            self._unqueue(old['agent_id'], old_id)
        q = self.queues.setdefault(agent, collections.OrderedDict())
        q[rid] = True
        while len(q) > MAX_PENDING_PER_AGENT:
            q.popitem(last=False)
        self.metrics.resets.inc(reason=reason)
        payload = {'kind': 'reset', 'environment': self.policy.doc['environment'],
                   **{k: r[k] for k in ('reset_id', 'agent_id', 'reason', 'by', 'created_ms')}}
        self.hooks.send('reset', self.urls['reset'], payload)
        if self.on_reset:
            try:
                self.on_reset(dict(r))
            except Exception:
                log.exception('on_reset callback failed')
        return r

    def _unqueue(self, agent: str, rid: str):
        q = self.queues.get(agent)
        if q is not None:
            q.pop(rid, None)
            if not q:
                del self.queues[agent]

    def commands(self, agent_id: str) -> list:
        """Pending reset commands for one agent (oldest first); marks them delivered."""
        if not isinstance(agent_id, str) or not ID.match(agent_id):
            raise Refused(400, 'agent_id must match [A-Za-z0-9._:@/-]{1,128}')
        with self.lock:
            now = self.clock()
            out = []
            for rid in list(self.queues.get(agent_id, ())):
                r = self.resets.get(rid)
                if r is None:
                    continue
                if r['delivered_ms'] is None:
                    r['delivered_ms'] = now
                    r['status'] = 'delivered'
                out.append({'type': 'reset', 'reset_id': rid, 'reason': r['reason'], 'created_ms': r['created_ms']})
            return out

    def ack(self, reset_id: str, agent_id: str) -> dict:
        """The agent's side confirms a reset. ``agent_id`` must be the reset's agent."""
        self._writable()
        if not isinstance(agent_id, str) or not ID.match(agent_id):
            raise Refused(400, 'agent_id (the agent the reset is for) is required')
        with self.lock:
            r = self.resets.get(reset_id)
            if r is None:
                raise Refused(404, 'no such reset')
            if r['agent_id'] != agent_id:
                raise Refused(409, 'this reset is for another agent')
            if r['acked_ms'] is None:
                now = self.clock()
                r['acked_ms'], r['status'] = now, 'acked'
                if r['delivered_ms'] is None:
                    r['delivered_ms'] = now
                self._unqueue(r['agent_id'], reset_id)
                self.metrics.acks.inc()
                self.metrics.ack_ms.observe(now - r['created_ms'])
                self._audit('reset-acked', ts_ms=now, reset_id=reset_id, agent_id=r['agent_id'],
                                  latency_ms=now - r['created_ms'])
            return dict(r)

    def reset_get(self, reset_id: str) -> dict:
        with self.lock:
            r = self.resets.get(reset_id)
            if r is None:
                raise Refused(404, 'no such reset')
            return dict(r)

    # ------------------------------------------------------------------ views
    def state(self) -> dict:
        with self.lock:
            last = self.windows[-1] if self.windows else None
            return {'environment': self.policy.doc['environment'], 'level': self.engine._name(self.engine.level),
                    'reset_mode': self.policy.doc['reset']['mode'], 'engine': self.engine.snapshot(),
                    'last_window': last, 'open_proposals': sum(1 for p in self.proposals.values() if p['status'] == 'open'),
                    'pending_resets': sum(len(q) for q in self.queues.values()), 'audit_head': self.audit.head,
                    'audit_failed': self.broken,
                    'policy': self.policy.doc}

    def recent_windows(self, n: int = 60) -> list:
        with self.lock:
            return list(self.windows)[-n:] if n > 0 else []

    def proposal_list(self, status: str | None = None) -> list:
        with self.lock:
            return [dict(p) for p in self.proposals.values() if status is None or p['status'] == status]

    def recent_resets(self, n: int = 50) -> list:
        with self.lock:
            return [dict(r) for r in list(self.resets.values())[-n:]]


def start_ticker(w: Watcher, every_s: float = 0.1) -> threading.Event:
    stop = threading.Event()

    def loop():
        while not stop.wait(every_s):
            try:
                w.tick()
            except Exception:
                log.exception('tick failed')
    threading.Thread(target=loop, daemon=True, name='tick').start()
    return stop
