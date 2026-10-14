"""Clients for the monitor: a JSON client, a Reporter for the agent side and a CommandPoller.

    rep = Reporter("https://watch.example:8730", token=os.environ["SMARTWATCH_INGEST_TOKEN"])
    rep.start()
    rep.record("planner", "coder")          # call wherever one agent sends a message to another
    ...
    rep.close()                             # flushes what is left

    poller = CommandPoller(client, "coder", on_reset=lambda cmd: restart_my_agent())
    poller.start()                          # pulls reset commands, runs on_reset, acknowledges

The Reporter adds up messages per (src, dst, second) in memory (``bucket_ms``, default 1000: keep it a
divisor of the policy's ``window_ms``, so that a bucket never straddles two windows) and sends them every second (with up to
200 ms of random jitter so that many reporters do not hit the monitor at the same instant). If the
monitor cannot be reached, the batch is kept and sent with the next one; at most ``max_keys`` distinct
(src, dst, second) keys are kept, beyond that new messages are counted in ``dropped`` and lost.
``record`` never blocks on the network.
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .engine import check_event

log = logging.getLogger('sf_smartwatch.client')
MAX_RESPONSE = 32 * 1024 * 1024
BATCH = 10_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would send the bearer token to wherever the answer points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class ClientError(Exception):
    def __init__(self, status: int, body):
        msg = body.get('error') if isinstance(body, dict) else body
        super().__init__(f'HTTP {status}: {msg}')
        self.status, self.body = status, body
        self.code = body.get('code') if isinstance(body, dict) else None


def quote_id(x: str) -> str:
    return urllib.parse.quote(x, safe='')


class Client:
    def __init__(self, url: str, token: str | None = None, timeout_s: float = 5.0):
        if not url.startswith(('http://', 'https://')):
            raise ValueError('the monitor URL must start with http:// or https://')
        self.url, self.token, self.timeout_s = url.rstrip('/'), token, timeout_s

    def request(self, method: str, path: str, query: dict | None = None, body=None, headers=None):
        u = self.url + path + ('?' + urllib.parse.urlencode(query) if query else '')
        data = None if body is None else json.dumps(body).encode()
        h = {'Accept': 'application/json'}
        if method == 'POST':
            h['Content-Type'] = 'application/json'
            data = data if data is not None else b''
        if self.token:
            h['Authorization'] = 'Bearer ' + self.token
        h.update(headers or {})
        req = urllib.request.Request(u, data=data, headers=h, method=method)
        try:
            with _OPENER.open(req, timeout=self.timeout_s) as r:
                raw = r.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise ClientError(r.status, 'answer larger than 32 MiB')
                if raw[:1] in (b'{', b'['):
                    try:
                        return json.loads(raw)
                    except ValueError:
                        raise ClientError(r.status, 'the answer is not complete JSON') from None
                return raw.decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            raw = e.read(65536)
            try:
                b = json.loads(raw)
            except ValueError:
                b = raw.decode('utf-8', 'replace')[:300]
            raise ClientError(e.code, b) from None

    def events(self, events: list):
        return self.request('POST', '/v1/events', body={'events': events})

    def commands(self, agent_id: str):
        return self.request('GET', f'/v1/agents/{quote_id(agent_id)}/commands')['commands']

    def ack(self, reset_id: str, agent_id: str):
        return self.request('POST', f'/v1/resets/{quote_id(reset_id)}/ack', body={'agent_id': agent_id})

    def state(self):
        return self.request('GET', '/v1/state')

    def windows(self, last: int = 60):
        return self.request('GET', '/v1/windows', {'last': last})['windows']

    def proposals(self, status: str | None = None):
        return self.request('GET', '/v1/proposals', {'status': status} if status else None)['proposals']

    def reset_get(self, reset_id: str):
        return self.request('GET', f'/v1/resets/{quote_id(reset_id)}')

    def decide(self, proposal_id: str, action: str, note: str = ''):
        return self.request('POST', f'/v1/proposals/{quote_id(proposal_id)}/{action}', body={'note': note})

    def reset(self, agent_id: str, reason: str = '', idempotency_key: str | None = None):
        return self.request('POST', f'/api/v1/agents/{quote_id(agent_id)}/reset', body={'reason': reason},
                            headers={'Idempotency-Key': idempotency_key} if idempotency_key else None)


class Reporter:
    def __init__(self, url_or_client, token: str | None = None, interval_s: float = 1.0, jitter_s: float = 0.2,
                 max_keys: int = 100_000, bucket_ms: int = 1000, clock=time.time):
        self.client = url_or_client if isinstance(url_or_client, Client) else Client(url_or_client, token)
        if not 1 <= bucket_ms <= 60000:
            raise ValueError('bucket_ms must be from 1 to 60000')
        self.interval_s, self.jitter_s, self.max_keys, self.clock = interval_s, jitter_s, max_keys, clock
        self.bucket_ms = bucket_ms
        self._buf: dict[tuple, int] = {}
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.sent = 0                 # messages the monitor accepted
        self.dropped = 0              # messages lost to the max_keys bound
        self.rejected = 0             # messages the monitor refused (bad ids, clock skew)
        self.errors = 0               # failed sends (kept for the next one)

    def record(self, src: str, dst: str, count: int = 1, ts_ms: int | None = None) -> None:
        ts = int(self.clock() * 1000) if ts_ms is None else ts_ms
        check_event(src, dst, ts, count)
        key = (src, dst, ts - ts % self.bucket_ms)
        with self._lock:
            if key in self._buf:
                self._buf[key] = min(self._buf[key] + count, 1_000_000_000)
            elif len(self._buf) < self.max_keys:
                self._buf[key] = count
            else:
                self.dropped += count

    def flush(self) -> int:
        """Send everything recorded so far; returns the messages accepted. Safe to call from any thread."""
        with self._send_lock:
            with self._lock:
                buf, self._buf = self._buf, {}
            items = sorted(buf.items(), key=lambda kv: (kv[0][2], kv[0][0], kv[0][1]))
            accepted = 0
            for i in range(0, len(items), BATCH):
                part = items[i:i + BATCH]
                evs = [{'src': s, 'dst': d, 'ts_ms': t, 'count': c} for (s, d, t), c in part]
                try:
                    res = self.client.events(evs)
                except (OSError, ClientError) as e:
                    if isinstance(e, ClientError) and 200 <= e.status < 300:
                        # the monitor answered 2xx but the answer was unreadable: it probably counted the
                        # batch, so it is not sent again (a resend would count it twice)
                        self.errors += 1
                        log.warning('unreadable answer from the monitor; %d messages not confirmed',
                                    sum(c for _, c in part))
                        continue
                    if isinstance(e, ClientError) and e.status in (400, 401, 403, 413):
                        log.warning('the monitor refused a batch: %s', e)
                        self.rejected += sum(c for _, c in part)
                        continue
                    self.errors += 1
                    log.warning('sending to the monitor failed (kept for the next send): %s', e)
                    with self._lock:
                        for (k, c) in items[i:]:
                            if k in self._buf:
                                self._buf[k] = min(self._buf[k] + c, 1_000_000_000)
                            elif len(self._buf) < self.max_keys:
                                self._buf[k] = c
                            else:
                                self.dropped += c
                    break
                if not isinstance(res, dict) or not isinstance(res.get('rejected', []), list):
                    self.errors += 1             # an answer we do not understand: not resent (it may have counted)
                    log.warning('unexpected answer from the monitor; %d messages not confirmed', sum(e['count'] for e in evs))
                    continue
                bad = {r['index'] for r in res.get('rejected', []) if isinstance(r, dict) and isinstance(r.get('index'), int)
                       and 0 <= r['index'] < len(evs)}
                n_bad = sum(evs[j]['count'] for j in bad)
                self.rejected += n_bad
                acc = sum(e['count'] for e in evs) - n_bad
                accepted += acc
                self.sent += acc
            return accepted

    def _run(self):
        while not self._stop.wait(self.interval_s + random.uniform(-self.jitter_s, self.jitter_s)):
            try:
                self.flush()
            except Exception:
                log.exception('reporter flush failed')

    def start(self) -> 'Reporter':
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name='smartwatch-reporter')
            self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.flush()


class CommandPoller:
    """Pull reset commands for one agent, run ``on_reset(command)`` and acknowledge each one once it
    returned without raising. A command whose handler raised is not acknowledged and comes back on the
    next poll (so the handler must tolerate repeats: use ``command["reset_id"]`` to tell)."""

    def __init__(self, client: Client, agent_id: str, on_reset, interval_s: float = 1.0):
        self.client, self.agent_id, self.on_reset, self.interval_s = client, agent_id, on_reset, interval_s
        self._stop = threading.Event()
        self._thread = None
        self.handled: list = []

    def poll_once(self) -> int:
        n = 0
        for cmd in self.client.commands(self.agent_id):
            if cmd.get('type') != 'reset':
                continue
            try:
                self.on_reset(cmd)
            except Exception:
                log.exception('on_reset failed for %s; not acknowledged', cmd.get('reset_id'))
                continue
            self.client.ack(cmd['reset_id'], self.agent_id)
            self.handled.append(cmd['reset_id'])
            n += 1
        return n

    def _run(self):
        while not self._stop.wait(self.interval_s):
            try:
                self.poll_once()
            except (OSError, ClientError) as e:
                log.warning('polling commands failed: %s', e)
            except Exception:                    # never let the poller die: the agent would miss every reset
                log.exception('polling commands failed')

    def start(self) -> 'CommandPoller':
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name='smartwatch-commands')
            self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
