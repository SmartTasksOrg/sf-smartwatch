"""SmartWatch over HTTP (stdlib only). Spec: spec/openapi.yaml.

    sf-smartwatch serve --policy policy.json --audit audit.jsonl [--host 0.0.0.0 --port 8730]

Credentials (required unless --insecure-dev, which binds 127.0.0.1 only). The roles are separate:
    SMARTWATCH_INGEST_TOKEN     reporters and agents only: POST /v1/events, GET /v1/agents/{id}/commands,
                                POST /v1/resets/{id}/ack
    SMARTWATCH_OPERATOR_TOKEN   operators only, read-only: state, windows, proposals, resets, and /ui (HTTP
                                Basic, any user name, the token as password; Basic is accepted nowhere else)
    reset authority             POST /api/v1/agents/{id}/reset and POST /v1/proposals/{id}/{confirm|cancel|escalate}:
                                a JWT with the scope "reset:agent" when SMARTWATCH_JWT_HS256_SECRET or
                                SMARTWATCH_JWT_PUBLIC_KEY is set (the operator token is then NOT enough);
                                otherwise the operator token
Operator and reset endpoints check the IP allowlist first (SMARTWATCH_OPERATOR_ALLOW, comma-separated
addresses or CIDRs, when set), then the credential, then a per-address rate limit (60 per minute). An
address with more than 20 failed credential checks in a minute gets 429 for every further wrong one (a
valid credential still passes). Ingest is limited per address too (SMARTWATCH_INGEST_RATE per minute,
default 6000). Behind a reverse proxy set SMARTWATCH_TRUSTED_PROXIES. Requests: POST bodies are
application/json and requests from web pages (an Origin header) are refused; at most 1 MiB for
/v1/events and 256 KiB otherwise, Content-Length required, 10 s socket timeout, at most 256 connections
and 32 per address (a trusted proxy is exempt and must limit its clients itself), each closed after
30 s; every error answer closes the connection. Put the monitor behind a TLS proxy: it speaks plain HTTP.
"""
from __future__ import annotations

import base64
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .jwtauth import JWTError, JWTVerifier
from .service import Refused, Watcher

log = logging.getLogger('sf_smartwatch.server')
MAX_BODY = 256 * 1024
MAX_EVENTS_BODY = 1024 * 1024
RESET_SCOPE = 'reset:agent'
_CONTROL = {c: f'\\x{c:02x}' for c in list(range(32)) + list(range(127, 160))}
PLACEHOLDER = 'replace-with'
MAX_CONNECTIONS_PER_ADDRESS = 32


class RateLimiter:
    """Token bucket per key: ``rate`` requests per ``per_s`` seconds."""

    def __init__(self, rate: int = 10, per_s: float = 60.0, clock=None):
        import time
        self.rate, self.per_s, self.clock = rate, per_s, clock or time.monotonic
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def exhausted(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            if key not in self._b:
                return False
            tokens, last = self._b[key]
            return min(self.rate, tokens + (now - last) * self.rate / self.per_s) < 1

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            if len(self._b) > 100000:
                # forget only the keys that have refilled completely (they are as if new); a key that is
                # still locked out stays, so rotating addresses cannot wipe a lockout
                self._b = {k: (t, l) for k, (t, l) in self._b.items()
                           if min(self.rate, t + (now - l) * self.rate / self.per_s) < self.rate}
                if len(self._b) > 100000:
                    return False
            tokens, last = self._b.get(key, (float(self.rate), now))
            tokens = min(self.rate, tokens + (now - last) * self.rate / self.per_s)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return False
            self._b[key] = (tokens - 1, now)
            return True


def parse_allowlist(text):
    if not text:
        return None
    return [ipaddress.ip_network(x.strip(), strict=False) for x in text.split(',') if x.strip()]


def ip_allowed(ip: str, nets) -> bool:
    if nets is None:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


class Config:
    def __init__(self, ingest_token=None, operator_token=None, jwt: JWTVerifier | None = None, operator_allow=None,
                 insecure_dev=False, operator_rate=60, auth_fail_rate=20, ingest_rate=6000, trusted_proxies=None):
        self.ingest_token, self.operator_token, self.jwt = ingest_token, operator_token, jwt
        self.operator_limiter = RateLimiter(operator_rate, 60.0)
        self.auth_fail_limiter = RateLimiter(auth_fail_rate, 60.0)
        self.ingest_limiter = RateLimiter(ingest_rate, 60.0)
        self.operator_allow = parse_allowlist(operator_allow) if isinstance(operator_allow, str) else operator_allow
        self.insecure_dev = insecure_dev
        self.trusted_proxies = parse_allowlist(trusted_proxies) if isinstance(trusted_proxies, str) else trusted_proxies

    @classmethod
    def from_env(cls, insecure_dev=False):
        e = os.environ
        jwt = None
        sec, pub = e.get('SMARTWATCH_JWT_HS256_SECRET'), e.get('SMARTWATCH_JWT_PUBLIC_KEY')
        if sec or pub:
            pem = None
            if pub:
                with open(pub, 'rb') as f:
                    pem = f.read()
            jwt = JWTVerifier(sec.encode() if sec else None, pem, e.get('SMARTWATCH_JWT_ISSUER') or None,
                              e.get('SMARTWATCH_JWT_AUDIENCE') or None)
        rate = e.get('SMARTWATCH_INGEST_RATE', '6000')
        if not rate.isdigit() or int(rate) < 1:
            raise SystemExit('SMARTWATCH_INGEST_RATE must be a positive integer (requests per minute per address)')
        return cls(e.get('SMARTWATCH_INGEST_TOKEN'), e.get('SMARTWATCH_OPERATOR_TOKEN'), jwt,
                   e.get('SMARTWATCH_OPERATOR_ALLOW'), insecure_dev, ingest_rate=int(rate),
                   trusted_proxies=e.get('SMARTWATCH_TRUSTED_PROXIES'))


class _HTTPError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


_SEG = r'([A-Za-z0-9._:@%-]{1,384})'         # one path segment; ids with "/" are sent percent-encoded (%2F)
ROUTES = [
    ('GET', re.compile(r'/healthz\Z'), 'healthz', None),
    ('GET', re.compile(r'/metrics\Z'), 'metrics', None),
    ('POST', re.compile(r'/v1/events\Z'), 'events', 'ingest'),
    ('GET', re.compile(r'/v1/agents/' + _SEG + r'/commands\Z'), 'commands', 'ingest'),
    ('POST', re.compile(r'/v1/resets/' + _SEG + r'/ack\Z'), 'ack', 'ingest'),
    ('GET', re.compile(r'/v1/state\Z'), 'state', 'operator'),
    ('GET', re.compile(r'/v1/windows\Z'), 'windows', 'operator'),
    ('GET', re.compile(r'/v1/proposals\Z'), 'proposals', 'operator'),
    ('GET', re.compile(r'/v1/resets/' + _SEG + r'\Z'), 'reset_get', 'operator'),
    ('GET', re.compile(r'/v1/resets\Z'), 'resets', 'operator'),
    ('POST', re.compile(r'/v1/proposals/' + _SEG + r'/(confirm|cancel|escalate)\Z'), 'decide', 'reset'),
    ('POST', re.compile(r'/api/v1/agents/' + _SEG + r'/reset\Z'), 'manual_reset', 'reset'),
    ('GET', re.compile(r'/ui\Z'), 'ui', 'operator'),
]


def make_handler(w: Watcher, cfg: Config):
    class H(BaseHTTPRequestHandler):
        server_version = 'sf-smartwatch/' + __version__
        protocol_version = 'HTTP/1.1'
        timeout = 10

        def log_message(self, fmt, *args):
            text = (fmt % args).translate(_CONTROL)
            log.info('%s %s', self.client_address[0], text)

        def _send(self, code, obj, ctype='application/json', headers=None):
            body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
            if code >= 400:
                self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if code >= 400:
                self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _body(self, limit) -> bytes:
            if self.headers.get('Transfer-Encoding'):
                raise _HTTPError(411, 'send Content-Length; chunked bodies are not accepted')
            raw = self.headers.get('Content-Length')
            if raw is None or not raw.isdigit() or int(raw) > limit:
                raise _HTTPError(413 if raw and raw.isdigit() else 411,
                                 f'Content-Length missing, invalid or above {limit // 1024} KiB')
            n = int(raw)
            return self.rfile.read(n) if n else b''

        def _json(self, raw: bytes, empty_ok=False) -> dict:
            if not raw and empty_ok:
                return {}
            v = json.loads(raw or b'null')
            if not isinstance(v, dict):
                raise ValueError('body must be a JSON object')
            return v

        def _client_ip(self):
            peer = self.client_address[0]
            if cfg.trusted_proxies and ip_allowed(peer, cfg.trusted_proxies):
                # the proxy's own addition is the last value of the last header line (some proxies add a
                # line instead of extending the client's): never the first line, which the client wrote
                lines = self.headers.get_all('X-Forwarded-For') or []
                last = lines[-1].split(',')[-1].strip() if lines else ''
                try:
                    ipaddress.ip_address(last)
                    return last
                except ValueError:
                    return peer
            return peer

        def _presented(self, basic_ok=False):
            """The credential. HTTP Basic only for the status page: a browser keeps Basic credentials and
            would send them with a cross-site form, so every other endpoint takes Bearer only."""
            got = self.headers.get('Authorization', '')
            if got.startswith('Bearer '):
                return got[7:]
            if got.startswith('Basic ') and basic_ok:
                try:
                    return base64.b64decode(got[6:], validate=True).decode('utf-8').split(':', 1)[1]
                except (ValueError, IndexError, UnicodeDecodeError):
                    return None
            return None

        @staticmethod
        def _eq(tok, ref):
            return bool(ref) and hmac.compare_digest(tok.encode(), ref.encode())

        def _who(self, role, basic_ok=False):
            """The acting identity for the audit log, or None when the credential does not open ``role``.
            Roles are separate: the ingest token only ingests, the operator token only reads (and resets
            when no JWT key is configured), a JWT with reset:agent only resets and decides."""
            if cfg.insecure_dev:
                return 'insecure-dev'
            tok = self._presented(basic_ok)
            if tok is None:
                return None
            if role == 'reset':
                if cfg.jwt is None:
                    return 'operator-token' if self._eq(tok, cfg.operator_token) else None
                try:
                    claims = cfg.jwt.verify(tok, RESET_SCOPE)
                except JWTError:
                    return None
                sub = claims.get('sub')
                return ('jwt:' + sub)[:200] if isinstance(sub, str) and sub else 'jwt'
            if role == 'operator' and self._eq(tok, cfg.operator_token):
                return 'operator-token'
            if role == 'ingest' and self._eq(tok, cfg.ingest_token):
                return 'ingest-token'
            return None

        def _dispatch(self, method):
            parts = urllib.parse.urlsplit(self.path)
            route = None
            for m, rx, name, role in ROUTES:
                mt = rx.match(parts.path)
                if mt and m == method:
                    route = (name, role, tuple(urllib.parse.unquote(g) for g in mt.groups()))
                    break
                if mt:
                    route = route or ('', '', None)
            if route is None:
                return self._send(404, {'error': 'not found'})
            if route[2] is None:
                return self._send(405, {'error': 'method not allowed'})
            name, role, args = route
            ip = self._client_ip()
            try:
                if role in ('operator', 'reset') and not ip_allowed(ip, cfg.operator_allow):
                    return self._send(403, {'error': 'source address not allowed'})
                who = self._who(role, basic_ok=(name == 'ui')) if role else None
                if role and who is None:
                    # an address with many failures is answered 429 (a valid credential still passes, so a
                    # stranger behind the same NAT cannot lock the reporters out)
                    if not cfg.auth_fail_limiter.allow(ip):
                        return self._send(429, {'error': 'too many failed credential checks from this address'})
                    extra = {'WWW-Authenticate': 'Basic realm="smartwatch"'} if name == 'ui' else \
                        ({'WWW-Authenticate': 'Bearer'} if role == 'reset' else None)
                    return self._send(401, {'error': 'missing or wrong credential'}, headers=extra)
                if not cfg.insecure_dev:
                    lim = cfg.ingest_limiter if role == 'ingest' else (cfg.operator_limiter if role else None)
                    if lim is not None and not lim.allow(ip):
                        return self._send(429, {'error': 'rate limit'})
                if method == 'POST':
                    ctype = (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
                    if ctype != 'application/json':
                        raise _HTTPError(415, 'POST bodies are application/json (send the header even with an empty body)')
                    if self.headers.get('Origin') is not None or self.headers.get('Sec-Fetch-Site') not in (None, 'none', 'same-origin'):
                        raise _HTTPError(403, 'requests from web pages are refused')
                if method == 'GET' and (self.headers.get('Transfer-Encoding') or
                                        (self.headers.get('Content-Length') or '0') != '0'):
                    raise _HTTPError(400, 'GET requests have no body')
                raw = self._body(MAX_EVENTS_BODY if name == 'events' else MAX_BODY) if method == 'POST' else b''
                q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items()}
                return getattr(self, 'r_' + name)(raw, q, who, *args)
            except _HTTPError as e:
                return self._send(e.code, {'error': str(e)})
            except TimeoutError:                         # a body shorter than its Content-Length
                self.close_connection = True
                try:
                    return self._send(408, {'error': 'the request body did not arrive in time'})
                except OSError:
                    return None
            except Refused as e:
                body = {'error': e.reason}
                if e.code:
                    body['code'] = e.code
                return self._send(e.status, body)
            except (ValueError, KeyError, TypeError, RecursionError) as e:
                return self._send(400, {'error': str(e) or 'bad request'})
            except Exception:
                log.exception('handler failed')
                return self._send(500, {'error': 'internal error'})

        def do_GET(self):
            self._dispatch('GET')

        def do_POST(self):
            self._dispatch('POST')

        def do_PUT(self):
            self._dispatch('PUT')

        def do_DELETE(self):
            self._dispatch('DELETE')

        # -- routes
        def r_healthz(self, raw, q, who):
            self._send(200, {'ok': True, 'version': __version__})

        def r_metrics(self, raw, q, who):
            self._send(200, w.metrics.expose(), 'text/plain; version=0.0.4')

        def r_events(self, raw, q, who):
            b = self._json(raw)
            if set(b) != {'events'}:
                raise ValueError('the body is {"events": [...]}')
            res = w.ingest(b['events'])
            self._send(200 if not res['rejected'] else 207 if res['accepted'] else 400, res)

        def r_commands(self, raw, q, who, agent):
            self._send(200, {'agent_id': agent, 'commands': w.commands(agent)})

        def r_ack(self, raw, q, who, rid):
            b = self._json(raw, empty_ok=True)
            agent = b.get('agent_id')
            if agent is not None and not isinstance(agent, str):
                raise ValueError('agent_id must be a string')
            self._send(200, w.ack(rid, agent))

        def r_state(self, raw, q, who):
            self._send(200, w.state())

        def r_windows(self, raw, q, who):
            n = q.get('last', '60')
            if not n.isdigit() or not 1 <= int(n) <= 600:
                raise ValueError('last must be an integer from 1 to 600')
            self._send(200, {'windows': w.recent_windows(int(n))})

        def r_proposals(self, raw, q, who):
            st = q.get('status')
            self._send(200, {'proposals': w.proposal_list(st)})

        def r_reset_get(self, raw, q, who, rid):
            self._send(200, w.reset_get(rid))

        def r_resets(self, raw, q, who):
            self._send(200, {'resets': w.recent_resets(50)})

        def r_decide(self, raw, q, who, pid, action):
            b = self._json(raw, empty_ok=True)
            self._send(200, w.decide(pid, action, who, b.get('note', '')))

        def r_manual_reset(self, raw, q, who, agent):
            b = self._json(raw, empty_ok=True)
            r = w.manual_reset(agent, who, b.get('reason', ''), self.headers.get('Idempotency-Key'))
            self._send(202, r, headers={'Location': f'/v1/resets/{r["reset_id"]}'})

        def r_ui(self, raw, q, who):
            self._send(200, render_ui(w), 'text/html; charset=utf-8',
                       headers={'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
                                'X-Frame-Options': 'DENY'})

    return H


def render_ui(w: Watcher) -> str:
    """A read-only page: level, the last 30 windows, open proposals, recent resets. No script."""
    e = html.escape
    s = w.state()
    lvl = s['level']
    cls = 'ok' if lvl == 'normal' else ('halt' if lvl == s['policy']['reset']['level'] else 'warn')
    banner = f'<p class="b {cls}">Level: {e(lvl)}</p>'
    rows = ''.join(f'<tr><td>{x["window"]}</td><td>{x["messages"]}</td><td>{x["agents"]}</td><td>{x["pairs"]}</td>'
                   f'<td>{x["density_micro"]}</td><td>{e(x["level"])}</td><td>{"" if x["exact"] else "estimate"}</td>'
                   f'<td>{e(", ".join(t["a"] + "↔" + t["b"] + " " + str(t["count"]) for t in x["top"][:3]))}</td></tr>'
                   for x in reversed(w.recent_windows(30))) or '<tr><td colspan="8">no window closed yet</td></tr>'
    props = ''.join(f'<tr><td><code>{e(p["proposal_id"])}</code></td><td>{e(p["status"])}</td><td>{e(p["level"])}</td>'
                    f'<td>{p["density_micro"]}</td><td>{e(", ".join(p["agents"]))}</td><td>{p["deadline_ms"]}</td>'
                    f'<td>{e(p["on_timeout"])}</td></tr>' for p in reversed(w.proposal_list()[-20:])) \
        or '<tr><td colspan="7">none</td></tr>'
    resets = ''.join(f'<tr><td><code>{e(r["reset_id"])}</code></td><td>{e(r["agent_id"])}</td><td>{e(r["reason"])}</td>'
                     f'<td>{e(r["by"])}</td><td>{e(r["status"])}</td><td>{r["created_ms"]}</td></tr>'
                     for r in reversed(w.recent_resets(20))) or '<tr><td colspan="6">none</td></tr>'
    th = lambda *c: '<thead><tr>' + ''.join(f'<th scope="col">{x}</th>' for x in c) + '</tr></thead>'  # noqa: E731
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>SmartWatch {e(s["environment"])}</title>
<style>body{{font:15px/1.45 system-ui,sans-serif;margin:16px;color:#111;background:#fff}}table{{border-collapse:collapse;width:100%;margin:8px 0 20px}}
td,th{{border-bottom:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}.b{{padding:10px;font-weight:600;border:2px solid}}
.halt{{border-color:#a00;color:#a00}}.warn{{border-color:#a60;color:#7a4a00}}.ok{{border-color:#060;color:#060}}code{{font-size:13px}}
.wrap{{overflow-x:auto}}
@media (prefers-color-scheme: dark){{body{{background:#111;color:#eee}}td,th{{border-color:#444}}.halt{{color:#f88;border-color:#f88}}.warn{{color:#fc6;border-color:#fc6}}.ok{{color:#8d8;border-color:#8d8}}}}</style>
</head><body><main><h1>SmartWatch: {e(s["environment"])}</h1>{banner}
<p>Reset mode {e(s["reset_mode"])}; open proposals {s["open_proposals"]}; pending reset commands {s["pending_resets"]};
audit head <code>{e(s["audit_head"][:16])}</code>. Density is in millionths of a message per possible pair per second.
This page refreshes every 5 seconds and changes nothing: decisions go through the API with a reset credential.</p>
<h2>Windows (latest 30)</h2><div class="wrap"><table>{th("Window", "Messages", "Agents", "Pairs", "Density", "Level", "Mode", "Top pairs")}<tbody>{rows}</tbody></table></div>
<h2>Proposals</h2><div class="wrap"><table>{th("Id", "Status", "Level", "Density", "Agents", "Deadline (ms)", "On timeout")}<tbody>{props}</tbody></table></div>
<h2>Reset commands</h2><div class="wrap"><table>{th("Id", "Agent", "Reason", "By", "Status", "Created (ms)")}<tbody>{resets}</tbody></table></div>
</main></body></html>'''


CONNECTION_DEADLINE_S = 30


def _close_quietly(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class WatchHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024

    def __init__(self, addr, handler, max_threads=256, per_address=MAX_CONNECTIONS_PER_ADDRESS, trusted_proxies=None):
        super().__init__(addr, handler)
        self._slots = threading.BoundedSemaphore(max_threads)
        self._open: set = set()
        self._open_lock = threading.Lock()
        self._per_addr: dict[str, int] = {}
        self.per_address, self.trusted_proxies = per_address, trusted_proxies

    def _take_address(self, ip: str) -> bool:
        """At most ``per_address`` open connections per peer address (not for a trusted proxy, which
        carries everyone's connections and must buffer and limit them itself)."""
        if self.trusted_proxies and ip_allowed(ip, self.trusted_proxies):
            return True
        with self._open_lock:
            n = self._per_addr.get(ip, 0)
            if n >= self.per_address:
                return False
            self._per_addr[ip] = n + 1
            return True

    def _give_address(self, ip: str):
        with self._open_lock:
            n = self._per_addr.get(ip, 0)
            if n <= 1:
                self._per_addr.pop(ip, None)
            else:
                self._per_addr[ip] = n - 1

    def shutdown(self):
        super().shutdown()
        with self._open_lock:
            socks = list(self._open)
        for sk in socks:
            _close_quietly(sk)

    def process_request(self, request, client_address):
        if not self._take_address(client_address[0]):
            self.shutdown_request(request)
            return
        if not self._slots.acquire(blocking=False):
            self._give_address(client_address[0])
            self.shutdown_request(request)
            return
        with self._open_lock:
            self._open.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._open_lock:
                self._open.discard(request)
            self._slots.release()
            self._give_address(client_address[0])
            raise

    def process_request_thread(self, request, client_address):
        timer = threading.Timer(CONNECTION_DEADLINE_S, _close_quietly, args=(request,))
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            with self._open_lock:
                self._open.discard(request)
            self._slots.release()
            self._give_address(client_address[0])


def make_server(w: Watcher, cfg: Config, host='127.0.0.1', port=8730) -> WatchHTTPServer:
    if not cfg.insecure_dev and not (cfg.ingest_token and cfg.operator_token):
        raise SystemExit('set SMARTWATCH_INGEST_TOKEN and SMARTWATCH_OPERATOR_TOKEN (or use --insecure-dev on 127.0.0.1)')
    if cfg.insecure_dev and host not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('--insecure-dev only binds 127.0.0.1')
    if cfg.ingest_token and cfg.ingest_token == cfg.operator_token:
        raise SystemExit('SMARTWATCH_INGEST_TOKEN and SMARTWATCH_OPERATOR_TOKEN must differ')
    for name, t in (('SMARTWATCH_INGEST_TOKEN', cfg.ingest_token), ('SMARTWATCH_OPERATOR_TOKEN', cfg.operator_token)):
        if t and len(t) < 16 and not cfg.insecure_dev:
            raise SystemExit(f'{name} must be at least 16 characters')
        if t and PLACEHOLDER in t and not cfg.insecure_dev:
            raise SystemExit(f'{name} is still the example value from deploy/.env.example: set a random one')
    return WatchHTTPServer((host, port), make_handler(w, cfg), trusted_proxies=cfg.trusted_proxies)
