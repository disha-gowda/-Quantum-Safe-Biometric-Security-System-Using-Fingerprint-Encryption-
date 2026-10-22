"""Module 3: biometric feature hashing."""

from __future__ import annotations

from typing import List

from qsbas.fingerprint import Minutia


def lightweight_hash(x: float, y: float, theta: float) -> int:
    """F_i = H(x_i || y_i || theta_i) — custom 32-bit mix reduced to byte."""
    payload = f"{x:.6f}|{y:.6f}|{theta:.6f}".encode("utf-8")
    state = 0x5A5A5A5A
    for byte in payload:
        state = ((state << 5) ^ state ^ byte) & 0xFFFFFFFF
        state = (state * 0x9E3779B1) & 0xFFFFFFFF
        state ^= state >> 16
        state = (state * 0x85EBCA6B) & 0xFFFFFFFF
        state ^= state >> 13
    return state & 0xFF


def hash_minutiae(minutiae: List[Minutia]) -> List[int]:
    return [lightweight_hash(m.x, m.y, m.theta) for m in minutiae]


def derive_feature_stream(minutiae: List[Minutia], length: int) -> List[int]:
    base = hash_minutiae(minutiae)
    if not base:
        base = [0xA5]
    stream: List[int] = []
    idx = 0
    while len(stream) < length:
        stream.append(base[idx % len(base)])
        idx += 1
        if idx % len(base) == 0 and idx >= len(base):
            mixed = lightweight_hash(
                minutiae[idx % len(minutiae)].x if minutiae else 0.0,
                float(idx),
                stream[-1] / 256.0,
            )
            stream.append(mixed)
    return stream[:length]
