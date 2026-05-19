"""Shared byte/bit utilities."""

from __future__ import annotations


def rotl8(value: int, rotation: int) -> int:
    r = rotation % 8
    v = value & 0xFF
    return ((v << r) | (v >> (8 - r))) & 0xFF


def rotr8(value: int, rotation: int) -> int:
    r = rotation % 8
    v = value & 0xFF
    return ((v >> r) | (v << (8 - r))) & 0xFF


def expand_sequence(values: list[int], length: int) -> list[int]:
    if not values:
        values = [0]
    out: list[int] = []
    i = 0
    while len(out) < length:
        out.append(values[i % len(values)] & 0xFF)
        i += 1
    return out


def bytes_to_int_list(data: bytes) -> list[int]:
    return list(data)


def int_list_to_bytes(values: list[int]) -> bytes:
    return bytes(v & 0xFF for v in values)
