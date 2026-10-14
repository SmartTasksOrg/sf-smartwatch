import json
import subprocess
import sys

import pytest

from sf_smartwatch.cli import main
from sf_smartwatch.policy import DEFAULT_POLICY, Policy


def run(*args):
    return subprocess.run([sys.executable, '-m', 'sf_smartwatch', *args], capture_output=True, text=True)


def test_version_and_validate(tmp_path):
    assert run('--version').stdout.startswith('sf-smartwatch ')
    p = tmp_path / 'p.json'
    p.write_text(json.dumps(DEFAULT_POLICY))
    r = run('validate', str(p))
    assert r.returncode == 0 and 'valid' in r.stdout
    p.write_text('{}')
    r = run('validate', str(p))
    assert r.returncode == 1 and 'WATCH-BAD-POLICY' in r.stderr


def test_synth_calibrate_replay(tmp_path):
    ev = tmp_path / 'ev.jsonl'
    assert run('synth', '--agents', '6', '--seconds', '120', '--out', str(ev)).returncode == 0
    pol, cm = tmp_path / 'policy.json', tmp_path / 'cm.yaml'
    r = run('calibrate', '--input', str(ev), '--environment', 'staging', '--profile', 'staging', '--out', str(pol),
            '--configmap', str(cm), '--namespace', 'agents')
    assert r.returncode == 0, r.stderr
    doc = Policy.load(str(pol)).doc
    assert doc['environment'] == 'staging' and len(doc['levels']) == 3
    assert 'kind: ConfigMap' in cm.read_text() and 'namespace: agents' in cm.read_text()
    assert run('calibrate', '--input', str(ev), '--environment', 'x', '--out', str(pol)).returncode == 1   # no overwrite
    burst = tmp_path / 'burst.jsonl'
    run('synth', '--agents', '6', '--seconds', '60', '--burst', '20,40,3,80', '--out', str(burst))
    r = run('replay', str(burst), '--policy', str(pol))
    assert r.returncode == 0 and 'reset due' in r.stderr


def test_calibrate_needs_enough_windows(tmp_path):
    ev = tmp_path / 'ev.jsonl'
    run('synth', '--seconds', '10', '--out', str(ev))
    r = run('calibrate', '--input', str(ev), '--environment', 'p')
    assert r.returncode == 1 and 'need 30' in r.stderr


def test_ingest_log(tmp_path):
    log = tmp_path / 'access.jsonl'
    lines = [{'start_time': '2026-10-14T07:00:00.100Z', 'x_agent': 'planner', 'upstream_cluster': 'coder'},
             {'start_time': '2026-10-14T07:00:00.900Z', 'x_agent': 'planner', 'upstream_cluster': 'coder'},
             {'start_time': 1791961201000, 'x_agent': 'coder', 'upstream_cluster': 'tester'},
             {'start_time': 'garbage', 'x_agent': 'a', 'upstream_cluster': 'b'},
             {'x_agent': 'a b', 'upstream_cluster': 'c', 'start_time': 1}]
    log.write_text('\n'.join(json.dumps(x) for x in lines) + '\n')
    r = run('ingest-log', str(log), '--src-field', 'x_agent', '--dst-field', 'upstream_cluster')
    assert r.returncode == 0
    evs = [json.loads(x) for x in r.stdout.splitlines()]
    assert evs[0] == {'src': 'planner', 'dst': 'coder', 'ts_ms': 1791961200000, 'count': 2}
    assert '3 log lines as events, 2 skipped' in r.stderr


def test_audit_verify_and_vectors(tmp_path):
    from sf_smartwatch.audit import AuditLog
    p = tmp_path / 'a.jsonl'
    AuditLog(str(p)).append('x', ts_ms=1)
    assert run('audit', 'verify', str(p)).stdout.startswith('OK')
    r = run('vectors')
    assert r.returncode == 0 and '1472/1472' in r.stdout


def test_token_needs_a_secret(monkeypatch):
    monkeypatch.delenv('SMARTWATCH_JWT_HS256_SECRET', raising=False)
    with pytest.raises(SystemExit):
        main(['token', '--sub', 'x'])


def test_demo():
    from sf_smartwatch.demo import run as demo
    lines = []
    assert demo(lines.append) == 0
    assert lines[-1] == 'demo OK'
