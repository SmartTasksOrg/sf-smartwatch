import filecmp
import os
import subprocess
import sys

from sf_smartwatch._bundled import path
from sf_smartwatch.conformance import FILES, run_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, 'spec', 'conformance')


def test_all_vectors_pass():
    total, fails = run_dir(SPEC)
    assert fails == []
    assert total == 1472


def test_bundled_copies_equal_spec():
    for f in FILES:
        assert filecmp.cmp(os.path.join(SPEC, f), str(path('conformance', f)), shallow=False), f


def test_generator_is_in_sync():
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'spec', 'tools', 'make_vectors.py'), '--check'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_version_matches_pyproject():
    from sf_smartwatch import __version__
    text = open(os.path.join(ROOT, 'pyproject.toml'), encoding='utf-8').read()
    assert f'version = "{__version__}"' in text
