"""GF(2^8) operations for AES-style column mixing (invertible)."""

from __future__ import annotations

from typing import List


def gmul(a: int, b: int) -> int:
    p = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def mix_column(col: List[int]) -> List[int]:
    c0, c1, c2, c3 = (col[i] & 0xFF for i in range(4))
    return [
        gmul(2, c0) ^ gmul(3, c1) ^ c2 ^ c3,
        c0 ^ gmul(2, c1) ^ gmul(3, c2) ^ c3,
        c0 ^ c1 ^ gmul(2, c2) ^ gmul(3, c3),
        gmul(3, c0) ^ c1 ^ c2 ^ gmul(2, c3),
    ]


def inv_mix_column(col: List[int]) -> List[int]:
    c0, c1, c2, c3 = (col[i] & 0xFF for i in range(4))
    return [
        gmul(14, c0) ^ gmul(11, c1) ^ gmul(13, c2) ^ gmul(9, c3),
        gmul(9, c0) ^ gmul(14, c1) ^ gmul(11, c2) ^ gmul(13, c3),
        gmul(13, c0) ^ gmul(9, c1) ^ gmul(14, c2) ^ gmul(11, c3),
        gmul(11, c0) ^ gmul(13, c1) ^ gmul(9, c2) ^ gmul(14, c3),
    ]


def matrix_mix_forward(state: List[int]) -> List[int]:
    n = len(state)
    out = state[:]
    end = n - (n % 4)
    for start in range(0, end, 4):
        mixed = mix_column(out[start : start + 4])
        for j in range(4):
            out[start + j] = mixed[j]
    return out


def matrix_mix_inverse(state: List[int]) -> List[int]:
    n = len(state)
    out = state[:]
    end = n - (n % 4)
    for start in range(0, end, 4):
        mixed = inv_mix_column(out[start : start + 4])
        for j in range(4):
            out[start + j] = mixed[j]
    return out
