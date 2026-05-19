"""NPCR and UACI differential attack metrics."""

from __future__ import annotations


def npcr(cipher1: bytes, cipher2: bytes) -> float:
    if len(cipher1) != len(cipher2) or not cipher1:
        return 0.0
    changed = sum(1 for a, b in zip(cipher1, cipher2) if a != b)
    return 100.0 * changed / len(cipher1)


def uaci(cipher1: bytes, cipher2: bytes) -> float:
    if len(cipher1) != len(cipher2) or not cipher1:
        return 0.0
    total = sum(abs(a - b) for a, b in zip(cipher1, cipher2))
    return (100.0 / len(cipher1)) * (total / 255.0)


def entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    import math

    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def histogram_uniformity_score(data: bytes) -> float:
    """Chi-square style uniformity (lower is more uniform); normalized 0–1 score."""
    if not data:
        return 0.0
    expected = len(data) / 256.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    chi = sum((f - expected) ** 2 / expected for f in freq if expected > 0)
    max_chi = len(data) * 255
    return max(0.0, 1.0 - chi / max_chi)
