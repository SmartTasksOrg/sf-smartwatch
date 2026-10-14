import base64
import copy
import http.client
import json
import threading
import time

import pytest

from sf_smartwatch.client import Client, ClientError, CommandPoller, Reporter
from sf_smartwatch.jwtauth import JWTError, JWTVerifier, b64e, make_hs256
from sf_smartwatch.policy import DEFAULT_POLICY, Policy
from sf_smartwatch.server import Config, make_server
from sf_smartwatch.service import Watcher

INGEST, OPER = 'ingest-token-0123456789', 'operator-token-0123456789'
SECRET = b'jwt-secret-for-tests-0123456789abcdef'


@pytest.fixture
def mon():
    w = Watcher(Policy())
    cfg = Config(INGEST, OPER, JWTVerifier(hs256_secret=SECRET))
    srv = make_server(w, cfg, '127.0.0.1', 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_address[1]}'
    yield w, url, srv
    srv.shutdown()
    srv.server_close()


def tok(**kw):
    claims = {'sub': 'alice', 'scope': 'reset:agent', 'exp': int(time.time()) + 60}
    claims.update(kw)
    return make_hs256(SECRET, claims)


def raw(url, method, path, body=None, headers=None):
    host, port = url[7:].split(':')
    c = http.client.HTTPConnection(host, int(port), timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def test_roles(mon):
    w, url, _ = mon
    assert Client(url).request('GET', '/healthz')['ok']
    with pytest.raises(ClientError) as e:
        Client(url, INGEST).state()
    assert e.value.status == 401
    assert Client(url, OPER).state()['level'] == 'normal'
    assert Client(url, INGEST).events([{'src': 'a', 'dst': 'b', 'ts_ms': int(time.time() * 1000)}])['accepted'] == 1
    with pytest.raises(ClientError) as e:
        Client(url, OPER).events([{'src': 'a', 'dst': 'b', 'ts_ms': int(time.time() * 1000)}])   # roles are separate
    assert e.value.status == 401
    with pytest.raises(ClientError) as e:
        Client(url, OPER).reset('a')                         # a JWT is configured: the operator token is not enough
    assert e.value.status == 401
    r = Client(url, tok()).reset('team/a', 'test', 'k1')
    assert r['agent_id'] == 'team/a' and r['by'] == 'jwt:alice'
    assert Client(url, INGEST).commands('team/a')[0]['reset_id'] == r['reset_id']
    assert Client(url, INGEST).ack(r['reset_id'], 'team/a')['status'] == 'acked'


@pytest.mark.parametrize('bad', [dict(scope='read'), dict(exp=int(time.time()) - 120), dict(nbf=int(time.time()) + 600)])
def test_bad_jwts(mon, bad):
    _, url, _ = mon
    with pytest.raises(ClientError) as e:
        Client(url, tok(**bad)).reset('a')
    assert e.value.status == 401


def test_jwt_algorithm_none_and_switching_refused():
    v = JWTVerifier(hs256_secret=SECRET)
    h = b64e(json.dumps({'alg': 'none'}).encode())
    p = b64e(json.dumps({'scope': 'reset:agent', 'exp': time.time() + 60}).encode())
    with pytest.raises(JWTError):
        v.verify(f'{h}.{p}.', 'reset:agent')
    with pytest.raises(ValueError):
        JWTVerifier(hs256_secret=b'short')


@pytest.mark.parametrize('kind', ['rsa', 'ec', 'ed25519'])
def test_public_key_jwts(kind):
    crypto = pytest.importorskip('cryptography')  # noqa: F841
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    if kind == 'rsa':
        k, alg = rsa.generate_private_key(65537, 2048), 'RS256'
    elif kind == 'ec':
        k, alg = ec.generate_private_key(ec.SECP256R1()), 'ES256'
    else:
        k, alg = ed25519.Ed25519PrivateKey.generate(), 'EdDSA'
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    v = JWTVerifier(public_key_pem=pem, issuer='idp', audience='smartwatch')
    h = b64e(json.dumps({'alg': alg}).encode())
    p = b64e(json.dumps({'sub': 'x', 'scp': ['reset:agent'], 'exp': int(time.time()) + 60, 'iss': 'idp',
                         'aud': ['smartwatch']}).encode())
    data = f'{h}.{p}'.encode()
    if kind == 'rsa':
        sig = k.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif kind == 'ec':
        r, s = decode_dss_signature(k.sign(data, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    else:
        sig = k.sign(data)
    assert v.verify(f'{h}.{p}.{b64e(sig)}', 'reset:agent')['sub'] == 'x'
    hs = make_hs256(pem, {'scope': 'reset:agent', 'exp': int(time.time()) + 60})    # the public key as an HMAC secret
    with pytest.raises(JWTError):
        v.verify(hs, 'reset:agent')


def test_http_hygiene(mon):
    _, url, _ = mon
    auth = {'Authorization': 'Bearer ' + INGEST}
    assert raw(url, 'GET', '/nope')[0] == 404
    assert raw(url, 'DELETE', '/v1/events', headers=auth)[0] == 405
    js = dict(auth, **{'Content-Type': 'application/json'})
    import socket
    host, port = url[7:].split(':')
    s = socket.create_connection((host, int(port)))
    s.sendall((f'POST /v1/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {INGEST}\r\n'
               f'Content-Type: application/json\r\nContent-Length: {1024 * 1024 + 1}\r\n\r\n').encode())
    assert s.recv(100).split()[1] == b'413'
    s.close()
    assert raw(url, 'POST', '/v1/events', body=b'[]', headers=js)[0] == 400
    assert raw(url, 'POST', '/v1/events', body=b'{"events": [{"src": "a"}]}', headers=js)[0] == 400
    status, _ = raw(url, 'GET', '/ui', headers={'Authorization': 'Basic ' + base64.b64encode(f'x:{OPER}'.encode()).decode()})
    assert status == 200
    s, body = raw(url, 'GET', '/metrics')
    assert s == 200 and b'smartwatch_density_micro' in body


def test_failed_credentials_are_limited_but_valid_ones_pass(mon):
    _, url, _ = mon
    codes = [raw(url, 'GET', '/v1/state', headers={'Authorization': 'Bearer wrong'})[0] for _ in range(25)]
    assert codes[0] == 401 and codes[-1] == 429
    assert raw(url, 'GET', '/v1/state', headers={'Authorization': 'Bearer ' + OPER})[0] == 200


def test_start_refuses_weak_configuration():
    w = Watcher(Policy())
    with pytest.raises(SystemExit):
        make_server(w, Config(None, OPER), '127.0.0.1', 0)
    with pytest.raises(SystemExit):
        make_server(w, Config(OPER, OPER), '127.0.0.1', 0)
    with pytest.raises(SystemExit):
        make_server(w, Config(insecure_dev=True), '0.0.0.0', 0)
    with pytest.raises(SystemExit):
        make_server(w, Config('short', OPER), '127.0.0.1', 0)


def test_reporter_and_poller_end_to_end(mon):
    w, url, _ = mon
    rep = Reporter(url, INGEST, interval_s=0.1)
    for _ in range(50):
        rep.record('x', 'y')
        rep.record('y', 'z', 2)
    assert rep.flush() == 150
    assert w.engine.snapshot()['messages'] == 150
    got = []
    poll = CommandPoller(Client(url, INGEST), 'y', lambda c: got.append(c['reset_id']), interval_s=0.05).start()
    r = Client(url, tok()).reset('y')
    for _ in range(100):
        if got:
            break
        time.sleep(0.02)
    poll.stop()
    assert got == [r['reset_id']] and w.reset_get(r['reset_id'])['status'] == 'acked'


def test_reporter_keeps_events_when_the_monitor_is_down():
    rep = Reporter('http://127.0.0.1:9', 'x')
    rep.record('a', 'b', 3)
    assert rep.flush() == 0 and rep.errors == 1
    assert sum(rep._buf.values()) == 3


def test_reporter_drops_beyond_max_keys():
    rep = Reporter('http://127.0.0.1:9', 'x', max_keys=2)
    for i in range(5):
        rep.record('a', f'b{i}')
    assert rep.dropped == 3
