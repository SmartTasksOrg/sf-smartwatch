"""sf-smartwatch command line. ``sf-smartwatch --help`` lists the commands; docs/operations.md walks
through them. Credentials come from the environment, never from the command line (it shows in process
lists): the server reads SMARTWATCH_* (server.py); the client commands present SMARTWATCH_TOKEN (the
operator token, or for ``reset`` and ``decide`` a JWT when the monitor requires one).
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
import time

from . import __version__


def _read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


class _Stdout:
    def __enter__(self):
        return sys.stdout

    def __exit__(self, *exc):
        sys.stdout.flush()

    def write(self, s):
        return sys.stdout.write(s)

    def close(self):
        sys.stdout.flush()


def _open_out(path):
    return _Stdout() if path in (None, '-') else open(path, 'x', encoding='utf-8', newline='\n')


def _jsonl(path):
    f = sys.stdin if path == '-' else open(path, encoding='utf-8')
    with f:
        for i, line in enumerate(f, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError:
                    raise SystemExit(f'{path}, line {i}: not JSON') from None


_CONTROL = {c: f'\\x{c:02x}' for c in list(range(32)) + list(range(127, 160))}


def _safe(text) -> str:
    """Text from the monitor or an identity provider, made safe to print: control characters (terminal
    escape sequences, bells, carriage returns) are shown as \\xNN."""
    return str(text).translate(_CONTROL)


def _client(a):
    from .client import Client
    return Client(a.url, os.environ.get('SMARTWATCH_TOKEN'), timeout_s=a.timeout)


def c_serve(a):
    from .audit import AuditLog
    from .policy import Policy
    from .server import Config, make_server
    from .service import Watcher, start_ticker
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    e = os.environ
    cfg = Config.from_env(insecure_dev=a.insecure_dev)
    secret = e.get('SMARTWATCH_WEBHOOK_SECRET')
    hooks = [e.get(k) for k in ('SMARTWATCH_ALERT_WEBHOOK', 'SMARTWATCH_RESET_WEBHOOK', 'SMARTWATCH_ESCALATION_WEBHOOK')]
    from .service import check_webhook_url
    for u in hooks:
        if u:
            try:
                check_webhook_url(u)
            except ValueError as e:
                raise SystemExit(str(e)) from None
    if any(hooks) and not secret:
        logging.warning('webhooks are configured without SMARTWATCH_WEBHOOK_SECRET: receivers cannot check who sent them')
    policy = Policy.load(a.policy) if a.policy else Policy()
    if not a.policy:
        logging.warning('no --policy: using the default thresholds, which are not calibrated for your system')
    w = Watcher(policy, audit=AuditLog(a.audit), alert_webhook=hooks[0], reset_webhook=hooks[1],
                escalation_webhook=hooks[2], webhook_secret=secret.encode() if secret else None)
    w.hooks.start()
    srv = make_server(w, cfg, a.host, a.port)
    stop = start_ticker(w)
    logging.info('sf-smartwatch %s on %s:%d, environment %s, reset mode %s, audit %s', __version__, a.host,
                 srv.server_address[1], policy.doc['environment'], policy.doc['reset']['mode'], a.audit)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        w.hooks.stop()
        srv.server_close()


def c_validate(a):
    from .policy import Policy, PolicyError
    try:
        p = Policy.load(a.policy)
    except PolicyError as e:
        raise SystemExit(f'{a.policy}: {e.code}: {e}')
    except OSError as e:
        raise SystemExit(f'{a.policy}: {e.strerror}')
    lv = ', '.join(f'{x["name"]} >= {x["min_density_micro"]}' for x in p.doc['levels'])
    print(f'{a.policy}: valid; environment {p.doc["environment"]}; window {p.doc["window_ms"]} ms; levels {lv}; '
          f'reset at {p.doc["reset"]["level"]} after {p.doc["reset"]["sustain_ms"]} ms, mode {p.doc["reset"]["mode"]}')


def _densities(a, policy):
    from .engine import Engine
    out, eng = [], Engine(policy)
    min_agents = policy.doc['min_agents']
    last_ts = 0
    from .engine import EventError
    for x in _jsonl(a.input):
        if not isinstance(x, dict):
            raise SystemExit('each line must be a JSON object')
        if x.get('kind') != 'window':
            try:
                eng_args = (x['src'], x['dst'], x['ts_ms'], x.get('count', 1))
            except KeyError:
                raise SystemExit('an event needs src, dst and ts_ms') from None
        if x.get('kind') == 'window':
            if x.get('agents', 0) >= min_agents:
                out.append(x.get('density_micro'))           # calibrate refuses anything but an integer >= 0
            continue
        try:
            outs = eng.add(*eng_args)
        except EventError as e:
            raise SystemExit(f'bad event {json.dumps(x)[:200]}: {e}') from None
        for o in outs:
            if o['kind'] == 'window' and o['agents'] >= min_agents:
                out.append(o['density_micro'])
        last_ts = max(last_ts, x['ts_ms'])
    if last_ts:
        for o in eng.flush(last_ts + (policy.doc['late_windows'] + 2) * policy.doc['window_ms']):
            if o['kind'] == 'window' and o['agents'] >= min_agents:
                out.append(o['density_micro'])
    return out


def c_calibrate(a):
    from .calibrate import PROFILES, calibrated_policy
    from .policy import Policy
    base = Policy.load(a.base) if a.base else Policy()
    ds = _densities(a, base)
    if any(isinstance(d, bool) or not isinstance(d, int) or d < 0 for d in ds):
        raise SystemExit('densities must be integers >= 0 (density_micro); the input has others')
    if len(ds) < a.min_windows:
        raise SystemExit(f'{len(ds)} windows with at least {base.doc["min_agents"]} agents; need {a.min_windows} '
                         f'(--min-windows). The council asks for a 30 s sample at least; more is better.')
    pm = [int(x) for x in a.permille.split(',')] if a.permille else PROFILES[a.profile]
    names = a.names.split(',') if a.names else None
    doc = calibrated_policy(base.doc, ds, a.environment, pm, names)
    xs = sorted(ds)
    print(f'{len(ds)} windows; density min {xs[0]}, median {xs[len(xs) // 2]}, max {xs[-1]} (micro)', file=sys.stderr)
    for lv, p in zip(doc['levels'], pm):
        print(f'  {lv["name"]:<10} p{p / 10:g}  {lv["min_density_micro"]}', file=sys.stderr)
    text = json.dumps(doc, indent=2, sort_keys=True) + '\n'
    with _open_out(a.out) as f:
        f.write(text)
    if a.configmap:
        body = ''.join('    ' + line + '\n' for line in text.rstrip('\n').split('\n'))
        meta = f'  name: {a.configmap_name}\n' + (f'  namespace: {a.namespace}\n' if a.namespace else '')
        with open(a.configmap, 'x', encoding='utf-8', newline='\n') as f:
            f.write(f'apiVersion: v1\nkind: ConfigMap\nmetadata:\n{meta}data:\n  policy.json: |\n{body}')
        print(f'wrote {a.configmap}', file=sys.stderr)


def c_synth(a):
    from .synth import T0, events
    burst = None
    if a.burst:
        parts = a.burst.split(',')
        if len(parts) != 4:
            raise SystemExit('--burst FROM_S,TO_S,HOT_AGENTS,HOT_RATE, for example 60,90,3,40')
        burst = (int(parts[0]), int(parts[1]), int(parts[2]), float(parts[3]))
    with _open_out(a.out) as f:
        for e in events(a.agents, a.seconds, a.rate, burst, a.seed, a.start_ms if a.start_ms is not None else T0):
            f.write(json.dumps(e, separators=(',', ':')) + '\n')


def c_replay(a):
    from .engine import Engine
    from .policy import Policy
    pol = Policy.load(a.policy) if a.policy else Policy()
    eng = Engine(pol)
    n_win, levels, resets, peak, last_ts = 0, {}, [], 0, 0
    f = _open_out(a.out) if a.out else None

    def take(outs):
        nonlocal n_win, peak
        for o in outs:
            if f:
                f.write(json.dumps(o, separators=(',', ':'), sort_keys=True) + '\n')
            if o['kind'] == 'window':
                n_win += 1
                peak = max(peak, o['density_micro'])
                levels[o['level']] = levels.get(o['level'], 0) + 1
            elif o['kind'] == 'reset':
                resets.append(o)
    bad = 0
    for x in _jsonl(a.events):
        try:
            take(eng.add(x['src'], x['dst'], x['ts_ms'], x.get('count', 1)))
            last_ts = max(last_ts, x['ts_ms'])
        except (KeyError, TypeError, ValueError):
            bad += 1
    if last_ts:
        take(eng.flush(last_ts + (pol.doc['late_windows'] + 2) * pol.doc['window_ms']))
    if f:
        f.close()
    s = eng.snapshot()
    print(f'{n_win} windows, {s["messages"]} messages, peak density {peak} micro, '
          f'{s["late_dropped"]} late, {bad} bad lines', file=sys.stderr)
    for k in ['normal'] + [x['name'] for x in pol.doc['levels']]:
        if k in levels:
            print(f'  {k:<10} {levels[k]} windows', file=sys.stderr)
    for r in resets:
        print(f'  reset due at window {r["window"]} ({r["mode"]}): {", ".join(r["agents"])}', file=sys.stderr)


def _get(obj, path):
    for k in path.split('.'):
        if not isinstance(obj, dict) or k not in obj:
            return None
        obj = obj[k]
    return obj


def _ts(v):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str):
        if v.isdigit():
            return int(v)
        d = datetime.datetime.fromisoformat(v.replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return int(d.timestamp() * 1000)
    raise ValueError('no timestamp')


def c_ingest_log(a):
    """Envoy (or any) JSON access log -> events. The log format is yours, so the fields are named here."""
    from .client import Reporter
    from .engine import EventError, check_event
    rep = Reporter(a.url, os.environ.get('SMARTWATCH_TOKEN')) if a.url else None
    out = None if a.url else _open_out(a.out)
    agg: dict = {}
    n, skipped = 0, 0

    def emit():
        for (s, d, t), c in sorted(agg.items(), key=lambda kv: (kv[0][2], kv[0][0], kv[0][1])):
            if rep:
                rep.record(s, d, c, t)
            else:
                out.write(json.dumps({'src': s, 'dst': d, 'ts_ms': t, 'count': c}, separators=(',', ':')) + '\n')
        agg.clear()
        if rep:
            rep.flush()
    f = sys.stdin if a.log == '-' else open(a.log, encoding='utf-8', errors='replace')
    with f:
        for line in f:
            if not line.strip():
                continue
            try:
                x = json.loads(line)
                s, d, t = _get(x, a.src_field), _get(x, a.dst_field), _ts(_get(x, a.ts_field))
                check_event(s, d, t, 1)
            except (ValueError, TypeError, EventError, OverflowError):
                skipped += 1
                continue
            key = (s, d, t - t % a.bucket_ms)
            agg[key] = agg.get(key, 0) + 1
            n += 1
            if len(agg) >= 10_000:
                emit()
    emit()
    if out:
        out.close()
    msg = f'{n} log lines as events, {skipped} skipped (missing fields, ids outside [A-Za-z0-9._:@/-]{{1,128}}, bad time)'
    if rep:
        msg += f'; sent {rep.sent}, refused {rep.rejected}, lost {rep.dropped}'
    print(msg, file=sys.stderr)


def c_demo(a):
    from .demo import run
    sys.exit(run())


def c_bench(a):
    from .bench import run
    run(a.events, a.out)


def c_vectors(a):
    from .conformance import run_dir
    d = a.dir
    if d is None:
        from ._bundled import path
        d = str(path('conformance'))
    total, fails = run_dir(d)
    for x in fails:
        print(x)
    print(f'python: {total - len(fails)}/{total} vectors passed' if not fails else f'python: {len(fails)} of {total} failed')
    sys.exit(1 if fails else 0)


def c_audit_verify(a):
    from .audit import verify_file
    ok, idx, msg = verify_file(a.file)
    print(('OK: ' if ok else 'BROKEN: ') + msg)
    sys.exit(0 if ok else 1)


def c_state(a):
    s = _client(a).state()
    lw = s.get('last_window') or {}
    print(_safe(f'environment {s["environment"]}: level {s["level"]}; reset mode {s["reset_mode"]}; '
                f'open proposals {s["open_proposals"]}; pending reset commands {s["pending_resets"]}'))
    if s.get('audit_failed'):
        print(_safe(f'AUDIT LOG FAILED: {s["audit_failed"]}'))
    if lw:
        print(f'last window {lw["window"]}: {lw["messages"]} messages, {lw["agents"]} agents, {lw["pairs"]} pairs, '
              f'density {lw["density_micro"]} micro{"" if lw["exact"] else " (estimate)"}')
    if a.json:
        print(json.dumps(s, indent=2, sort_keys=True))


def c_proposals(a):
    for p in _client(a).proposals(a.status):
        print(_safe(f'{p["proposal_id"]}  {p["status"]:<16} level {p["level"]}, density {p["density_micro"]}, '
                    f'agents {", ".join(p["agents"])}, deadline {p["deadline_ms"]}, on timeout {p["on_timeout"]}'))


def c_decide(a):
    p = _client(a).decide(a.proposal, a.action, a.note or '')
    print(_safe(f'{p["proposal_id"]}: {p["status"]} by {p["decided_by"] or "-"}; resets {", ".join(p["resets"]) or "none"}'))


def c_reset(a):
    r = _client(a).reset(a.agent, a.reason or '', a.idempotency_key)
    print(_safe(f'{r["reset_id"]}: reset of {r["agent_id"]} {r["status"]}{" (repeat of an earlier request)" if r.get("replayed") else ""}'))


def c_token(a):
    from .jwtauth import make_hs256
    sec = os.environ.get('SMARTWATCH_JWT_HS256_SECRET')
    if not sec or len(sec.encode()) < 32:
        raise SystemExit('set SMARTWATCH_JWT_HS256_SECRET (at least 32 bytes) to make a test token')
    now = int(time.time())
    claims = {'sub': a.sub, 'scope': 'reset:agent', 'iat': now, 'exp': now + a.ttl_s}
    if a.issuer:
        claims['iss'] = a.issuer
    if a.audience:
        claims['aud'] = a.audience
    print(make_hs256(sec.encode(), claims))


def main(argv=None):
    ap = argparse.ArgumentParser(prog='sf-smartwatch',
                                 description='Coupling-density monitor for multi-agent systems, with graded alerts and resets.')
    ap.add_argument('--version', action='version', version=f'sf-smartwatch {__version__}')
    sub = ap.add_subparsers(dest='cmd')

    def net(p):
        p.add_argument('--url', required=True, help='monitor URL')
        p.add_argument('--timeout', type=float, default=10.0)

    p = sub.add_parser('serve', help='run the monitor (HTTP)')
    p.add_argument('--policy', help='policy file (default: the uncalibrated default policy)')
    p.add_argument('--audit', required=True, help='audit log file (JSON lines, hash-chained)')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8730)
    p.add_argument('--insecure-dev', action='store_true', help='no credentials; binds 127.0.0.1 only')
    p.set_defaults(fn=c_serve)

    p = sub.add_parser('validate', help='check a policy file')
    p.add_argument('policy')
    p.set_defaults(fn=c_validate)

    p = sub.add_parser('calibrate', help='thresholds from your own traffic (events or windows, JSON lines)')
    p.add_argument('--input', required=True, help='events {"src","dst","ts_ms","count"} or windows from replay/the API; - for stdin')
    p.add_argument('--environment', required=True)
    p.add_argument('--profile', choices=['prod', 'staging'], default='prod',
                   help='prod: p95/p99/p99.9; staging: p90/p95/p99 (permille 950,990,999 / 900,950,990)')
    p.add_argument('--permille', help='own percentiles in permille, comma-separated, e.g. 950,990,999')
    p.add_argument('--names', help='level names, comma-separated (default elevated,high,critical)')
    p.add_argument('--base', help='policy to start from (default: the default policy)')
    p.add_argument('--min-windows', type=int, default=30)
    p.add_argument('--out', default='-', help='policy file to write (not overwritten); - for stdout')
    p.add_argument('--configmap', help='also write a Kubernetes ConfigMap with policy.json')
    p.add_argument('--configmap-name', default='smartwatch-policy')
    p.add_argument('--namespace')
    p.set_defaults(fn=c_calibrate)

    p = sub.add_parser('synth', help='synthetic traffic as events (JSON lines)')
    p.add_argument('--agents', type=int, default=6)
    p.add_argument('--seconds', type=int, default=120)
    p.add_argument('--rate', type=float, default=2.0, help='messages per pair per second')
    p.add_argument('--burst', help='FROM_S,TO_S,HOT_AGENTS,HOT_RATE')
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--start-ms', type=int)
    p.add_argument('--out', default='-')
    p.set_defaults(fn=c_synth)

    p = sub.add_parser('replay', help='run events through the engine offline; summary on stderr')
    p.add_argument('events')
    p.add_argument('--policy')
    p.add_argument('--out', help='write every output (windows, levels, resets) as JSON lines; - for stdout')
    p.set_defaults(fn=c_replay)

    p = sub.add_parser('ingest-log', help='turn a JSON access log (Envoy or other) into events, or send them')
    p.add_argument('log', help='file, or - for stdin')
    p.add_argument('--src-field', required=True, help='field with the calling agent id (dots for nesting)')
    p.add_argument('--dst-field', required=True, help='field with the called agent id')
    p.add_argument('--ts-field', default='start_time', help='milliseconds or ISO 8601 (Envoy %%START_TIME%%)')
    p.add_argument('--bucket-ms', type=int, default=1000)
    p.add_argument('--url', help='send to this monitor (SMARTWATCH_TOKEN = the ingest token) instead of writing')
    p.add_argument('--out', default='-')
    p.set_defaults(fn=c_ingest_log)

    p = sub.add_parser('demo', help='a monitor, five agents, a burst, a proposal, a confirmed reset (about 10 s)')
    p.set_defaults(fn=c_demo)

    p = sub.add_parser('bench', help='time the engine on this machine')
    p.add_argument('--events', type=int, default=200_000)
    p.add_argument('--out')
    p.set_defaults(fn=c_bench)

    p = sub.add_parser('vectors', help='run the shared conformance vectors')
    p.add_argument('dir', nargs='?')
    p.set_defaults(fn=c_vectors)

    p = sub.add_parser('audit', help='check an audit log')
    asub = p.add_subparsers(dest='audit_cmd', required=True)
    q = asub.add_parser('verify')
    q.add_argument('file')
    q.set_defaults(fn=c_audit_verify)

    p = sub.add_parser('state', help='level, last window and counts of a running monitor')
    net(p)
    p.add_argument('--json', action='store_true')
    p.set_defaults(fn=c_state)

    p = sub.add_parser('proposals', help='list reset proposals')
    net(p)
    p.add_argument('--status', help='open, confirmed, cancelled, timed-out-reset, timed-out-cancel')
    p.set_defaults(fn=c_proposals)

    p = sub.add_parser('decide', help='confirm, cancel or escalate a reset proposal')
    net(p)
    p.add_argument('proposal')
    p.add_argument('action', choices=['confirm', 'cancel', 'escalate'])
    p.add_argument('--note')
    p.set_defaults(fn=c_decide)

    p = sub.add_parser('reset', help='reset one agent by hand')
    net(p)
    p.add_argument('agent')
    p.add_argument('--reason')
    p.add_argument('--idempotency-key')
    p.set_defaults(fn=c_reset)

    p = sub.add_parser('token', help='make an HS256 test token with scope reset:agent (from SMARTWATCH_JWT_HS256_SECRET)')
    p.add_argument('--sub', required=True)
    p.add_argument('--ttl-s', type=int, default=900)
    p.add_argument('--issuer')
    p.add_argument('--audience')
    p.set_defaults(fn=c_token)

    a = ap.parse_args(argv)
    if not getattr(a, 'fn', None):
        ap.print_help()
        sys.exit(2)
    try:
        a.fn(a)
    except FileExistsError as e:
        raise SystemExit(f'{e.filename} exists; not overwriting')
    except Exception as e:
        from .client import ClientError
        from .policy import PolicyError
        if isinstance(e, ClientError):
            raise SystemExit(_safe(f'monitor: {e}'))
        if isinstance(e, PolicyError):
            raise SystemExit(f'policy: {e.code}: {e}')
        if isinstance(e, OSError) and not isinstance(e, ConnectionError) and e.filename:
            raise SystemExit(f'{e.filename}: {e.strerror}')
        raise


if __name__ == '__main__':
    main()
