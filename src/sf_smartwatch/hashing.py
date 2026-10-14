"""Seeded FNV-1a hashes (32 and 64 bit) over UTF-8 text.

    fnv1a32(seed, text) = FNV-1a 32 over  UTF-8(seed) + b"\\x00" + UTF-8(text)
    fnv1a64(seed, text) = FNV-1a 64 over the same bytes
    mix64(h)            = MurmurHash3 fmix64 finalizer (HyperLogLog hashes items with mix64(fnv1a64(...)))

The seed is the council's "pod name + namespace" (``hash_seed`` in the policy): monitors with the same
seed put the same pair in the same bucket. FNV-1a is not a cryptographic hash: anyone who knows the seed
can craft colliding pairs. The bucket counter only ever over-counts (see engine.py), so a collision can
make a pair look hotter, never cooler. Vectors: spec/conformance/hashing.json.
"""
from __future__ import annotations

M32, M64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


def _bytes(seed: str, text: str) -> bytes:
    return seed.encode('utf-8') + b'\x00' + text.encode('utf-8')


def fnv1a32(seed: str, text: str) -> int:
    h = 2166136261
    for b in _bytes(seed, text):
        h = ((h ^ b) * 16777619) & M32
    return h


def mix64(h: int) -> int:
    """MurmurHash3's 64-bit finalizer: spreads FNV's weak high bits (HyperLogLog uses the top 14)."""
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & M64
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & M64
    h ^= h >> 33
    return h


def fnv1a64(seed: str, text: str) -> int:
    h = 14695981039346656037
    for b in _bytes(seed, text):
        h = ((h ^ b) * 1099511628211) & M64
    return h
