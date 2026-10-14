"""Files shipped inside the wheel (copies of spec/; tests/test_bundled.py fails if a copy differs)."""
from __future__ import annotations

from importlib import resources


def path(*parts: str):
    return resources.files('sf_smartwatch').joinpath('data', *parts)


def read_text(*parts: str) -> str:
    return path(*parts).read_text(encoding='utf-8')
