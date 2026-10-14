"""Canonical JSON: the byte form every SmartWatch engine hashes (audit chain) and compares.

Rules (spec/SEMANTICS.md, "Canonical JSON"):
- objects: keys are ASCII and sorted byte-wise, no whitespace, ``,`` and ``:`` separators;
- strings: UTF-8, escaped only as ``\\"`` ``\\\\`` ``\\b`` ``\\f`` ``\\n`` ``\\r`` ``\\t`` and ``\\u00XX``
  (lower-case hex) for the other characters below U+0020; everything else is written as is;
- numbers: integers only (no floats: their text form differs between languages);
- ``true``, ``false``, ``null``; arrays in order.
"""
from __future__ import annotations

_SHORT = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _str(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def dumps(value) -> str:
    """Return the canonical JSON text of ``value``. Raises TypeError for floats and other types."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _str(value)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(dumps(v) for v in value) + ']'
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str) or not k.isascii():
                raise TypeError('canonical JSON object keys must be ASCII strings')
        return '{' + ','.join(_str(k) + ':' + dumps(value[k]) for k in sorted(value)) + '}'
    raise TypeError(f'canonical JSON does not encode {type(value).__name__} (floats are not allowed)')


def encode(value) -> bytes:
    return dumps(value).encode('utf-8')
