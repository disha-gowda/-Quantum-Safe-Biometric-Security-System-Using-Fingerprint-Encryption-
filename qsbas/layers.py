"""
QSBAC-SPN layers (Substitution–Permutation Network).

Pipeline mapping (AES analogue → QSBAC-SPN):
  Key schedule     → K_i = (F_i ⊕ Q_i ⊕ T_s) mod 256
  ShiftRows        → dynamic permutation P_i
  Rotate           → R_i = (F_i ⊕ Q_i ⊕ C_{i-1}) mod 8
  S-box            → S_i = (Q_i ⊕ F_i ⊕ i) mod 256 (bijective dynamic S-box)
  MixColumns       → nonlinear diffusion D_i
  AddRoundKey      → final E_i with P_i, Q_i, C_{i-1}
"""

from __future__ import annotations

from typing import List

from qsbas.chaotic import chaotic_bytes
from qsbas.utils import rotl8, rotr8


def apply_permutation(data: List[int], order: List[int]) -> List[int]:
    n = len(data)
    return [data[order[i] % n] & 0xFF for i in range(n)]


def inverse_permutation(data: List[int], order: List[int]) -> List[int]:
    n = len(data)
    inv = [0] * n
    for i in range(n):
        inv[order[i] % n] = i
    return [data[inv[i] % n] & 0xFF for i in range(n)]


def rotation_factor(features: int, chaotic: int, prev_cipher: int) -> int:
    """R_i = (F_i ⊕ Q_i ⊕ C_{i-1}) mod 8."""
    return (features ^ chaotic ^ (prev_cipher & 0xFF)) & 0x7


def apply_rotation(data: List[int], rotations: List[int]) -> List[int]:
    return [rotl8(b, r) for b, r in zip(data, rotations)]


def inverse_rotation(data: List[int], rotations: List[int]) -> List[int]:
    return [rotr8(b, r) for b, r in zip(data, rotations)]


def _nonlinear_mix(value: int) -> int:
    v = value & 0xFF
    return v ^ (rotl8(v, 3) ^ rotr8(v, 2))


def _invert_nonlinear_mix(value: int) -> int:
    target = value & 0xFF
    for candidate in range(256):
        if _nonlinear_mix(candidate) == target:
            return candidate
    return target


def diffusion_forward(
    rotated: List[int],
    keys: List[int],
    chaotic: List[int],
) -> List[int]:
    out: List[int] = []
    c_prev = 0
    for i in range(len(rotated)):
        t = rotated[i] & 0xFF
        k = keys[i] & 0xFF
        q = chaotic[i] & 0xFF
        d = _nonlinear_mix(((t ^ k) + (c_prev ^ q)) & 0xFF)
        out.append(d)
        c_prev = d
    return out


def diffusion_inverse(
    diffused: List[int],
    keys: List[int],
    chaotic: List[int],
) -> List[int]:
    rotated: List[int] = []
    c_prev = 0
    for i, d in enumerate(diffused):
        d_lin = _invert_nonlinear_mix(d)
        k = keys[i] & 0xFF
        q = chaotic[i] & 0xFF
        t = ((d_lin - (c_prev ^ q)) & 0xFF) ^ k
        rotated.append(t)
        c_prev = diffused[i] & 0xFF
    return rotated


def build_dynamic_sbox(features: List[int], chaotic: List[int], x0: float | None = None) -> List[int]:
    """Bijective S-box: S[i] = (Q_i XOR F_i XOR i) with chaotic position shuffle."""
    keys = chaotic_bytes(256, x0=x0)
    indices = list(range(256))
    indices.sort(
        key=lambda i: (
            keys[i],
            (chaotic[i % len(chaotic)] ^ features[i % len(features)] ^ i) & 0xFF,
            i,
        )
    )
    return indices


def sbox_substitute(data: List[int], sbox: List[int]) -> List[int]:
    return [sbox[b & 0xFF] for b in data]


def inverse_sbox_substitute(data: List[int], sbox: List[int]) -> List[int]:
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v & 0xFF] = i
    return [inv[b & 0xFF] for b in data]
