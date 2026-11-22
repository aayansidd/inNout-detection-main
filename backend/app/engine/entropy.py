"""Shannon entropy and chi-square uniformity over byte frequencies.

Week 2 link: entropy is frequency analysis, the same idea used to break classical ciphers.
"""

from __future__ import annotations

import math
from collections import Counter


class ByteStats:
    """Accumulates a 256-bin byte histogram across chunks."""

    def __init__(self) -> None:
        self._counts: Counter[int] = Counter()
        self.total = 0

    def update(self, chunk: bytes) -> None:
        self._counts.update(chunk)
        self.total += len(chunk)

    @property
    def counts(self) -> list[int]:
        return [self._counts.get(i, 0) for i in range(256)]

    def entropy(self) -> float:
        return shannon_entropy(self.counts)

    def chi_square(self) -> float:
        return chi_square_uniform(self.counts)


def shannon_entropy(counts: list[int]) -> float:
    """H = -sum p(x) log2 p(x), 0.0 (constant) to 8.0 (uniform). Empty input -> 0.0."""
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def chi_square_uniform(counts: list[int]) -> float:
    """Chi-square statistic vs a uniform byte distribution (255 degrees of freedom).

    Near ~255 means near-uniform (encrypted/random); compressed data usually lands higher.
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    expected = total / 256
    return sum((c - expected) ** 2 / expected for c in counts)


def shannon_entropy_bytes(data: bytes) -> float:
    """Convenience wrapper for in-memory data."""
    stats = ByteStats()
    stats.update(data)
    return stats.entropy()
