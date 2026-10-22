"""Chaotic generators: logistic, tent, and Henon maps for session entropy."""

from __future__ import annotations

from typing import List

from qsbas.quantum_entropy import quantum_initial_value


def logistic_step(x: float, r: float = 3.99) -> float:
    return r * x * (1.0 - x)


def tent_step(x: float, mu: float = 1.99) -> float:
    if x < 0.5:
        return mu * x
    return mu * (1.0 - x)


def henon_step(x: float, y: float, a: float = 1.4, b: float = 0.3) -> tuple[float, float]:
    x_new = 1.0 - a * x * x + y
    y_new = b * x
    x_new = max(-1.5, min(1.5, x_new))
    y_new = max(-1.5, min(1.5, y_new))
    return x_new, y_new


def chaotic_bytes(length: int, x0: float | None = None, r: float = 3.99) -> List[int]:
    """Mixed chaotic stream: logistic + tent + Henon XOR fusion."""
    if length <= 0:
        return []
    x = x0 if x0 is not None else quantum_initial_value()
    x = min(max(x, 1e-6), 1.0 - 1e-6)
    y = (x * 0.6180339887) % 1.0
    if y < 1e-6:
        y = 0.314159
    out: List[int] = []
    for i in range(length):
        x = logistic_step(x, r)
        t = tent_step((x + y) % 1.0)
        x, y = henon_step(x, y)
        fused = int((abs(x) * 127 + t * 89 + abs(y) * 40)) % 256
        out.append((fused ^ int(t * 255)) & 0xFF)
    return out


def chaotic_permutation(size: int, x0: float | None = None) -> List[int]:
    keys = chaotic_bytes(size, x0=x0)
    indices = list(range(size))
    indices.sort(key=lambda i: keys[i])
    return indices
