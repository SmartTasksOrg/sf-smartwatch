"""Regression tests for the findings of the pre-release review (CHANGELOG, "Fixed before release")."""
import errno
import http.client
import json
import socket
import threading
import time

import pytest

from sf_smartwatch.audit import AuditError, AuditLog, verify_file
from sf_smartwatch.jwtauth import JWTError, JWTVerifier, make_hs256
from sf_smartwatch.policy import DEFAULT_POLICY, Policy
from sf_smartwatch.server import Config, RateLimiter, make_server
from sf_smartwatch.service import Refused, Watcher, Webhooks, check_webhook_url, redact_url

T0 = 1_700_000_000_000
INGEST, OPER = 'ingest-token-0123456789', 'operator-token-0123456789'
SECRET = b'jwt-secret-for-tests-0123456789abcdef'


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def serve(w, **cfg):
    srv = make_server(w, Config(INGEST, OPER, **cfg), '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


# 1 (high): one event stamped ahead must not close everyone else's windows
def test_future_event_cannot_blind_the_monitor():
    c = Clock()
    w = Watcher(Policy(), clock=c)
    r = w.ingest([{'src': 'x', 'dst': 'y', 'ts_ms': T0 + 59_000}])
    assert r['rejected'][0]['code'] == 'WATCH-CLOCK-SKEW'
    r = w.ingest([{'src': 'x', 'dst': 'y', 'ts_ms': T0 + 1_500}])        # a little ahead: counted now
    assert r['accepted'] == 1 and w.engine.high == T0 // 1000
    r = w.ingest([{'src': 'a', 'dst': 'b', 'ts_ms': T0}])
    assert r['accepted'] == 1 and not r['rejected']


# 12: late events are reported
def test_late_events_are_reported():
    c = Clock()
    w = Watcher(Policy(), clock=c)
    w.ingest([{'src': 'a', 'dst': 'b', 'ts_ms': T0}])
    c.t = T0 + 10_000
    w.tick()
    r = w.ingest([{'src': 'a', 'dst': 'b', 'ts_ms': T0}])
    assert r['accepted'] == 0 and r['rejected'][0]['code'] == 'WATCH-LATE'


# 3: no Basic outside /ui, POST must be JSON and not from a web page
def test_csrf_defences():
    import base64
    w = Watcher(Policy())
    srv, port = serve(w)
    try:
        basic = {'Authorization': 'Basic ' + base64.b64encode(f'x:{OPER}'.encode()).decode()}
        assert req(port, 'POST', '/api/v1/agents/coder/reset', b'', dict(basic, **{'Content-Type': 'application/json'}))[0] == 401
        assert req(port, 'GET', '/ui', headers=basic)[0] == 200
        bearer = {'Authorization': 'Bearer ' + OPER}
        assert req(port, 'POST', '/api/v1/agents/coder/reset', b'', bearer)[0] == 415
        assert req(port, 'POST', '/api/v1/agents/coder/reset', b'',
                   dict(bearer, **{'Content-Type': 'application/json', 'Origin': 'https://evil.example'}))[0] == 403
        assert req(port, 'POST', '/api/v1/agents/coder/reset', b'', dict(bearer, **{'Content-Type': 'application/json'}))[0] == 202
    finally:
        srv.shutdown()
        srv.server_close()


# 4: an acknowledgement must name the reset's agent
def test_ack_is_bound_to_the_agent():
    w = Watcher(Policy())
    r = w.manual_reset('coder', 'test')
    with pytest.raises(Refused):
        w.ack(r['reset_id'], None)
    with pytest.raises(Refused):
        w.ack(r['reset_id'], 'planner')
    assert w.ack(r['reset_id'], 'coder')['status'] == 'acked'
    assert 'coder' not in w.queues                     # 21: empty queues are removed


# 5: the operator token reads only
def test_operator_token_cannot_ingest_or_ack():
    w = Watcher(Policy())
    srv, port = serve(w)
    try:
        h = {'Authorization': 'Bearer ' + OPER, 'Content-Type': 'application/json'}
        assert req(port, 'POST', '/v1/events', b'{"events": []}', h)[0] == 401
        assert req(port, 'GET', '/v1/agents/a/commands', headers=h)[0] == 401
    finally:
        srv.shutdown()
        srv.server_close()


# 6: X-Forwarded-For: the last value of the last line
def test_forwarded_for_uses_the_proxys_line():
    w = Watcher(Policy())
    srv, port = serve(w, operator_allow='10.9.9.9/32', trusted_proxies='127.0.0.1')
    try:
        s = socket.create_connection(('127.0.0.1', port))
        s.sendall((f'GET /v1/state HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {OPER}\r\n'
                   'X-Forwarded-For: 10.9.9.9\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n').encode())
        assert s.recv(100).split()[1] == b'403'
        s.close()
        h = {'Authorization': 'Bearer ' + OPER, 'X-Forwarded-For': '203.0.113.5, 10.9.9.9'}
        assert req(port, 'GET', '/v1/state', headers=h)[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()


# 7: one address cannot take every connection slot
def test_connections_per_address_are_capped():
    w = Watcher(Policy())
    srv, port = serve(w)
    socks = []
    try:
        for _ in range(40):
            s = socket.create_connection(('127.0.0.1', port))
            s.sendall(b'GET /hea')
            socks.append(s)
        time.sleep(0.3)
        closed = 0
        for s in socks[32:]:
            s.settimeout(2)
            try:
                closed += s.recv(10) == b''
            except (ConnectionResetError, socket.timeout):
                closed += 1
        assert closed == 8
    finally:
        for s in socks:
            s.close()
        srv.shutdown()
        srv.server_close()


# 9, 10: an audit failure stops changes; a short write is rolled back
def test_audit_failure_stops_changes(monkeypatch):
    w = Watcher(Policy())

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(w.audit, 'append', boom)
    with pytest.raises(Refused) as e:
        w.manual_reset('coder', 'test')
    assert e.value.status == 503 and w.broken
    with pytest.raises(Refused):
        w.ingest([])
    assert w.state()['audit_failed']


def test_short_audit_write_is_rolled_back(tmp_path, monkeypatch):
    import os
    p = str(tmp_path / 'a.jsonl')
    a = AuditLog(p)
    a.append('x', ts_ms=1)
    size = os.path.getsize(p)
    real = os.write

    def half_then_full(fd, data):            # the disk fills up in the middle of the record
        if b'"y"' in bytes(data):
            real(fd, data[:10])
            raise OSError(errno.ENOSPC, 'No space left on device')
        return real(fd, data)
    monkeypatch.setattr(os, 'write', half_then_full)
    with pytest.raises(AuditError):
        a.append('y', ts_ms=2)
    monkeypatch.setattr(os, 'write', real)
    assert os.path.getsize(p) == size and verify_file(p)[0]
    assert AuditLog(p).head == a.head


def test_partial_write_is_completed(tmp_path, monkeypatch):
    import os
    p = str(tmp_path / 'a.jsonl')
    a = AuditLog(p)
    real = os.write
    monkeypatch.setattr(os, 'write', lambda fd, data: real(fd, data[:7]))    # the OS writes 7 bytes at a time
    a.append('x', ts_ms=1, note='a longer record than seven bytes')
    monkeypatch.setattr(os, 'write', real)
    assert verify_file(p)[0]


# 11, 13: webhook lanes; no credentials in URLs or logs
def test_webhook_lanes_do_not_block_each_other():
    calls = []

    def post(url, body, headers):
        calls.append(headers['X-SmartWatch-Event'])
        if 'alert' in url:
            time.sleep(0.5)
            return 500
        return 204
    h = Webhooks(None, post=post)
    for _ in range(5):
        h.send('level', 'http://alert.invalid/', {})
    h.send('reset', 'http://reset.invalid/', {})
    h.start()
    time.sleep(0.3)
    h.stop()
    assert 'reset' in calls


def test_webhook_urls_with_credentials_are_refused_and_redacted():
    with pytest.raises(ValueError):
        check_webhook_url('https://user:secret@hooks.example/x')
    check_webhook_url('https://hooks.example/x')
    assert 'secret' not in redact_url('https://user:secret@hooks.example/x?token=secret')


# 14: control characters do not reach the server log
def test_request_line_is_escaped_in_the_log(caplog):
    w = Watcher(Policy())
    srv, port = serve(w)
    try:
        with caplog.at_level('INFO', logger='sf_smartwatch.server'):
            s = socket.create_connection(('127.0.0.1', port))
            s.sendall(b'GET /\x1b[2J\x07 HTTP/1.1\r\nHost: x\r\n\r\n')
            s.recv(1000)
            s.close()
            time.sleep(0.2)
        assert not any('\x1b' in r.getMessage() for r in caplog.records)
    finally:
        srv.shutdown()
        srv.server_close()


# 15: the CLI shows escape sequences escaped
def test_cli_escapes_server_text():
    from sf_smartwatch.cli import _safe
    assert _safe('\x1b]0;owned\x07ok') == '\\x1b]0;owned\\x07ok'


# 17: a full limiter table does not unlock locked keys
def test_rate_limiter_keeps_lockouts():
    t = [0.0]
    rl = RateLimiter(2, 60.0, clock=lambda: t[0])
    rl.allow('bad'), rl.allow('bad')
    assert not rl.allow('bad')
    for i in range(100_001):
        rl.allow(f'k{i}')
    assert rl.exhausted('bad')


# 18: exp must be a finite number not too far ahead
@pytest.mark.parametrize('exp', [float('nan'), float('inf'), 1e400, 10 ** 12])
def test_jwt_exp_must_be_sane(exp):
    v = JWTVerifier(hs256_secret=SECRET)
    tok = make_hs256(SECRET, {'scope': 'reset:agent', 'exp': 0}).split('.')
    import base64
    claims = json.dumps({'scope': 'reset:agent', 'exp': exp}).encode()
    body = base64.urlsafe_b64encode(claims).rstrip(b'=').decode()
    import hashlib
    import hmac
    sig = base64.urlsafe_b64encode(hmac.new(SECRET, f'{tok[0]}.{body}'.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
    with pytest.raises(JWTError):
        v.verify(f'{tok[0]}.{body}.{sig}', 'reset:agent')


# 19: calibrate refuses bad densities in window input
def test_calibrate_refuses_bad_window_densities(tmp_path):
    import subprocess
    import sys
    p = tmp_path / 'w.jsonl'
    p.write_text('\n'.join(json.dumps({'kind': 'window', 'agents': 5, 'density_micro': 2.7}) for _ in range(40)))
    r = subprocess.run([sys.executable, '-m', 'sf_smartwatch', 'calibrate', '--input', str(p), '--environment', 'x'],
                       capture_output=True, text=True)
    assert r.returncode != 0


# 20: placeholder tokens are refused
def test_placeholder_tokens_are_refused():
    with pytest.raises(SystemExit):
        make_server(Watcher(Policy()), Config('replace-with-a-long-random-value', OPER), '127.0.0.1', 0)


# robustness suite findings (private evidence, 2026-10-14)
def test_unrecorded_reset_is_never_queued(monkeypatch):
    w = Watcher(Policy())

    def full(*a, **k):
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(w.audit, 'append', full)
    with pytest.raises(Refused):
        w.manual_reset('coder', 'op')
    assert w.commands('coder') == [] and w.recent_resets() == []


def test_truncated_answer_does_not_break_reporter_or_poller():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from sf_smartwatch.client import Client, CommandPoller, Reporter

    class Cut(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cut(self):
            n = int(self.headers.get('Content-Length') or 0)
            self.rfile.read(n)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '9')
            self.end_headers()
            self.wfile.write(b'{"accep')
        do_GET = do_POST = _cut
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Cut)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    try:
        rep = Reporter(url, 'x')
        rep.record('a', 'b', 3)
        assert rep.flush() == 0 and rep.errors == 1 and not rep._buf      # not resent: it may have counted
        p = CommandPoller(Client(url, 'x', timeout_s=1), 'a', lambda c: None, interval_s=0.05).start()
        time.sleep(0.3)
        assert p._thread.is_alive()
        p.stop()
    finally:
        srv.shutdown()
        srv.server_close()


def test_huge_integer_times_in_jwts_are_refused_not_crashing():
    v = JWTVerifier(hs256_secret=SECRET)
    for claims in ({'scope': 'reset:agent', 'exp': 10 ** 400}, {'scope': 'reset:agent', 'exp': int(time.time()) + 60, 'nbf': 10 ** 400}):
        with pytest.raises(JWTError):
            v.verify(make_hs256(SECRET, claims), 'reset:agent')


def test_short_body_gets_408():
    import sf_smartwatch.server as server_mod
    w = Watcher(Policy())
    srv, port = serve(w)
    try:
        s = socket.create_connection(('127.0.0.1', port))
        s.settimeout(20)
        s.sendall((f'POST /v1/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {INGEST}\r\n'
                   'Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"ev').encode())
        assert s.recv(100).split()[1] == b'408'
        s.close()
    finally:
        srv.shutdown()
        srv.server_close()
    assert server_mod is not None
