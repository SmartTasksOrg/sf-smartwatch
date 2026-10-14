"""Tamper-evident audit log: every level change, reset proposal, human decision, reset delivery and
manual reset is one JSON line, chained by SHA-256 (spec/SEMANTICS.md, "Audit chain"; vectors:
spec/conformance/audit.json).

record = {"seq": n, "ts_ms": t, "event": "...", ...fields, "prev": <hash of record n-1 or 64 zeros>}
hash   = sha256(canonical_json(record)) as lower-case hex; the line written is record + {"hash": hash}.

Fields must be strings, integers, booleans, null, lists or objects of those (no floats). Editing,
removing or reordering a line breaks every later hash; ``verify`` reports the first bad line. A chain
proves the log is consistent, not that it is complete or who wrote it: whoever controls the file can
truncate it and write a new tail. Keep a copy, or the head hash, somewhere else.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from . import canonical

GENESIS = '0' * 64


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != 'hash'}
    return hashlib.sha256(canonical.encode(body)).hexdigest()


class AuditError(ValueError):
    code = 'WATCH-BAD-AUDIT'


def _read(path: str) -> list:
    out = []
    with open(path, 'rb') as f:
        for i, raw in enumerate(f, 1):
            if not raw.strip():
                continue
            try:
                out.append(json.loads(raw.decode('utf-8')))
            except (ValueError, RecursionError):
                raise AuditError(f'{path}, line {i}: not a JSON record (a write torn by a crash?)') from None
    return out


class AuditLog:
    """Append-only, fsync after every record. Opening an existing file verifies it first and refuses a
    broken one (the file is evidence: it is never repaired here)."""

    def __init__(self, path: str | None = None, clock=now_ms):
        self.path, self.clock = path, clock
        self.records: list[dict] = []
        self._lock = threading.Lock()
        self._prev, self._seq = GENESIS, 0
        if path and os.path.exists(path):
            recs = _read(path)
            ok, i, msg = verify(recs)
            if not ok:
                raise AuditError(f'{path}: {msg}; refusing to append to a broken chain')
            if recs:
                self._prev, self._seq = recs[-1]['hash'], recs[-1]['seq'] + 1

    @property
    def head(self) -> str:
        return self._prev

    def append(self, event: str, ts_ms: int | None = None, **fields) -> dict:
        with self._lock:
            rec = dict(fields)
            rec.update(seq=self._seq, ts_ms=self.clock() if ts_ms is None else ts_ms, event=event, prev=self._prev)
            rec['hash'] = record_hash(rec)
            line = (canonical.dumps(rec) + '\n').encode('utf-8')
            if self.path:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
                try:
                    size = os.fstat(fd).st_size
                    try:
                        view = memoryview(line)
                        while view:                       # a short write (disk nearly full) is continued
                            n = os.write(fd, view)
                            view = view[n:]
                        os.fsync(fd)
                    except OSError as e:
                        try:                              # roll back to the last complete record
                            os.ftruncate(fd, size)
                            os.fsync(fd)
                        except OSError:
                            pass
                        raise AuditError(f'{self.path}: could not append ({e.strerror or e}); '
                                         'the file was cut back to its last complete record') from None
                finally:
                    os.close(fd)
            else:
                self.records.append(rec)
                if len(self.records) > 100000:          # in-memory mode keeps the tail only
                    del self.records[:50000]
            self._prev, self._seq = rec['hash'], self._seq + 1
            return rec


def verify(records) -> tuple:
    """(ok, index of the first bad record or None, message)."""
    prev = GENESIS
    for i, r in enumerate(records):
        seq = r.get('seq') if isinstance(r, dict) else None
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != i:
            return False, i, f'record {i}: seq is not {i}'
        if r.get('prev') != prev:
            return False, i, f'record {i}: prev does not match the hash of record {i - 1}'
        try:
            h = record_hash(r)
        except (TypeError, UnicodeEncodeError, RecursionError):
            return False, i, f'record {i}: has no canonical form'
        if r.get('hash') != h:
            return False, i, f'record {i}: hash does not match its content'
        prev = h
    return True, None, f'{len(records)} records, chain intact, head {prev}'


def verify_file(path: str) -> tuple:
    try:
        return verify(_read(path))
    except AuditError as e:
        return False, None, str(e)
