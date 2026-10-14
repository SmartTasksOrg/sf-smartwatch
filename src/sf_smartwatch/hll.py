"""HyperLogLog distinct counter, p = 14 (16,384 one-byte registers: 16 KiB; standard error about 0.81 %).

    add(item):  h = mix64(fnv1a64(seed, item)); j = h >> 50 (the top 14 bits);
                w = h & (2^50 - 1); rho = 51 - bit_length(w)  (1 + leading zeros of w in 50 bits; 51 if w = 0)
                M[j] = max(M[j], rho)
    estimate(): Z = sum over v = 51, 50, ..., 0 (in that order) of  count(M[j] == v) * 2^-v   (IEEE double)
                E = alpha * m * m / Z, alpha = 0.7213 / (1 + 1.079 / m), m = 16384
                if E <= 2.5 * m and V > 0 (V = registers equal to 0): E = m * ln(m / V)
                result = min(floor(E + 0.5), 2^53 - 1)
No large-range correction (the hash is 64 bits). The summation order is fixed so that every engine,
using IEEE doubles, gets the same bits. Vectors: spec/conformance/hll.json.
"""
from __future__ import annotations

import hashlib
import math

from .hashing import fnv1a64, mix64

P = 14
M = 1 << P
ALPHA = 0.7213 / (1 + 1.079 / M)
MAXRHO = 64 - P + 1
MAX_INT = 2 ** 53 - 1


class HyperLogLog:
    __slots__ = ('seed', 'reg')

    def __init__(self, seed: str):
        self.seed = seed
        self.reg = bytearray(M)

    def add(self, item: str) -> None:
        h = mix64(fnv1a64(self.seed, item))
        j = h >> (64 - P)
        w = h & ((1 << (64 - P)) - 1)
        rho = MAXRHO - w.bit_length()
        if rho > self.reg[j]:
            self.reg[j] = rho

    def estimate(self) -> int:
        counts = [0] * (MAXRHO + 1)
        for r in self.reg:
            counts[r] += 1
        z = 0.0
        for v in range(MAXRHO, -1, -1):
            if counts[v]:
                z += counts[v] * (2.0 ** -v)
        e = ALPHA * M * M / z
        zeros = counts[0]
        if e <= 2.5 * M and zeros > 0:
            e = M * math.log(M / zeros)
        return min(int(math.floor(e + 0.5)), MAX_INT)

    def digest(self) -> str:
        """sha256 of the registers (the vectors compare it, so every engine updates them the same way)."""
        return hashlib.sha256(bytes(self.reg)).hexdigest()
