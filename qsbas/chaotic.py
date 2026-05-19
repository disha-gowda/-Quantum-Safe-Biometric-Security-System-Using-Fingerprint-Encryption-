"""Module 5: chaotic random generator (logistic map)."""

from __future__ import annotations

from typing import List

from qsbas.quantum_entropy import quantum_initial_value


def logistic_step(x: float, r: float = 3.99) -> float:
    return r * x * (1.0 - x)


def chaotic_bytes(length: int, x0: float | None = None, r: float = 3.99) -> List[int]:
    if length <= 0:
        return []
    x = x0 if x0 is not None else quantum_initial_value()
    x = min(max(x, 1e-6), 1.0 - 1e-6)
    out: List[int] = []
    for _ in range(length):
        x = logistic_step(x, r)
        out.append(int(x * 256) % 256)
    return out


def chaotic_permutation(size: int, x0: float | None = None) -> List[int]:
    """Permute indices 0..size-1 using chaotic sort keys."""
    keys = chaotic_bytes(size, x0=x0)
    indices = list(range(size))
    indices.sort(key=lambda i: keys[i])
    return indices
