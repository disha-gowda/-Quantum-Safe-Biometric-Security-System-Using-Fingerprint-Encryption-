"""
QSBAC-SPN v2: 12-round adaptive cipher with SHA-256 S-box, CBC chaining,
key whitening, nonlinear rotations, and matrix-style diffusion.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Tuple

from qsbas.chaotic import chaotic_bytes
from qsbas.constants import QSBAC_IV_BYTES, QSBAC_SPN_ROUNDS
from qsbas.gf256 import matrix_mix_forward, matrix_mix_inverse
from qsbas.spn_v3 import biometric_x0, chaotic_stream, entropy_reinforcement, nonlinear_substitution
from qsbas.layers import (
    apply_permutation,
    apply_rotation,
    diffusion_forward,
    diffusion_inverse,
    inverse_permutation,
    inverse_rotation,
    inverse_sbox_substitute,
    sbox_substitute,
)
from qsbas.utils import rotl8, rotr8


def _seed_digest(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def generate_iv(minutiae_bytes: bytes, timestamp: float, features: List[int], chaotic: List[int]) -> List[int]:
    """IV = SHA256(biometrics || timestamp || session entropy)[:16]."""
    payload = (
        minutiae_bytes
        + struct.pack(">d", timestamp)
        + bytes(features[:32])
        + bytes(chaotic[:32])
    )
    return list(_seed_digest(payload)[:QSBAC_IV_BYTES])


def whitening_keys(keys: List[int], chaotic: List[int], features: List[int], iv: List[int]) -> List[int]:
    digest = _seed_digest(bytes(keys), bytes(chaotic), bytes(features), bytes(iv), b"whiten")
    return list(digest)


def round_keys(
    base_keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    round_idx: int,
    feedback: int,
    length: int,
) -> List[int]:
    """K_{i+1} = SHA256(K || B || C_feedback || round) per byte."""
    seed = _seed_digest(
        bytes(base_keys[:length]),
        bytes(chaotic[: min(32, len(chaotic))]),
        bytes(features[: min(32, len(features))]),
        bytes(iv),
        struct.pack(">HB", round_idx, feedback & 0xFF),
    )
    return [(base_keys[i % len(base_keys)] ^ seed[i % 32] ^ chaotic[i % len(chaotic)]) & 0xFF for i in range(length)]


def sha_permutation_indices(
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    n: int,
    round_idx: int,
    iv: List[int],
) -> List[int]:
    """P(i) = sort by SHA256(K_s XOR i XOR round)."""
    seed = _seed_digest(bytes(iv), struct.pack(">H", round_idx), bytes(keys[: min(n, 64)]))
    order = list(range(n))
    order.sort(
        key=lambda i: (
            seed[i % 32] ^ keys[i % len(keys)] ^ chaotic[i % len(chaotic)] ^ features[i % len(features)],
            seed[(i * 7 + round_idx) % 32],
            i,
        )
    )
    return order


def build_sha256_sbox(
    features: List[int],
    chaotic: List[int],
    round_idx: int,
    iv: List[int],
    x0: float,
    minutiae_digest: bytes,
) -> List[int]:
    """Bijective S-box from SHA256(biometric XOR key XOR index)."""
    base = _seed_digest(minutiae_digest, bytes(features[:32]), bytes(chaotic[:32]), bytes(iv), struct.pack(">H", round_idx))
    extra = chaotic_bytes(256, x0=(x0 + round_idx * 0.013) % 1.0)
    indices = list(range(256))
    indices.sort(
        key=lambda i: (
            base[i % 32] ^ extra[i] ^ (chaotic[i % len(chaotic)] ^ features[i % len(features)] ^ i),
            base[(i * 5 + 11) % 32],
            i,
        )
    )
    return indices


def nonlinear_rotation(features: int, chaotic: int, key: int, msg: int, prev_c: int) -> int:
    """R_i = (K_i XOR M_i XOR S_i XOR C_{i-1}) mod 8."""
    return (features ^ chaotic ^ key ^ msg ^ prev_c) & 0x7


def matrix_diffusion_forward(state: List[int], keys: List[int], chaotic: List[int]) -> List[int]:
    """Dual-pass full-state diffusion (forward-only invertible chain)."""
    state = diffusion_forward(state, keys, chaotic)
    return diffusion_forward(state, keys[::-1], chaotic[::-1])


def matrix_diffusion_inverse(state: List[int], keys: List[int], chaotic: List[int]) -> List[int]:
    state = diffusion_inverse(state, keys[::-1], chaotic[::-1])
    return diffusion_inverse(state, keys, chaotic)


def cbc_forward(state: List[int], iv_byte: int) -> List[int]:
    prev = iv_byte & 0xFF
    out: List[int] = []
    for b in state:
        c = (b ^ prev) & 0xFF
        out.append(c)
        prev = c
    return out


def cbc_inverse(state: List[int], iv_byte: int) -> List[int]:
    prev = iv_byte & 0xFF
    out: List[int] = []
    for c in state:
        p = (c ^ prev) & 0xFF
        out.append(p)
        prev = c
    return out


def minutiae_digest(minutiae: List) -> bytes:
    parts = []
    for m in minutiae:
        parts.append(struct.pack(">fff", float(m.x), float(m.y), float(m.theta)))
    return _seed_digest(b"".join(parts), b"bio")


def spn_encrypt_round(
    state: List[int],
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    round_idx: int,
    x0: float,
    bio_digest: bytes,
    feedback: int,
    chaos: List[int],
) -> Tuple[List[int], List[int]]:
    """One SPN round; returns new state and rotation list for decrypt."""
    n = len(state)
    rk = round_keys(keys, chaotic, features, iv, round_idx, feedback, n)
    key_tag = _seed_digest(bytes(rk), bio_digest, struct.pack(">H", round_idx))

    state = [(state[i] ^ chaos[(round_idx * n + i) % len(chaos)]) & 0xFF for i in range(n)]
    perm = sha_permutation_indices(keys, chaotic, features, n, round_idx, iv)
    state = apply_permutation(state, perm)

    rotations: List[int] = []
    prev = feedback & 0xFF
    for i in range(n):
        r = nonlinear_rotation(features[i % len(features)], chaotic[i % len(chaotic)], rk[i], state[i], prev)
        rotations.append(r)
        prev = state[i]

    state = apply_rotation(state, rotations)
    state = matrix_diffusion_forward(state, rk, chaotic)
    state = matrix_mix_forward(state)
    sbox = build_sha256_sbox(features, chaotic, round_idx, iv, x0, bio_digest)
    state = sbox_substitute(state, sbox)
    state = nonlinear_substitution(state, key_tag, bio_digest)
    state = [(state[i] ^ rk[i]) & 0xFF for i in range(n)]
    state = cbc_forward(state, iv[round_idx % len(iv)])

    return state, rotations


def spn_decrypt_round(
    state: List[int],
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    round_idx: int,
    x0: float,
    bio_digest: bytes,
    feedback: int,
    rotations: List[int],
    chaos: List[int],
) -> List[int]:
    n = len(state)
    rk = round_keys(keys, chaotic, features, iv, round_idx, feedback, n)
    key_tag = _seed_digest(bytes(rk), bio_digest, struct.pack(">H", round_idx))
    sbox = build_sha256_sbox(features, chaotic, round_idx, iv, x0, bio_digest)

    state = cbc_inverse(state, iv[round_idx % len(iv)])
    state = [(state[i] ^ rk[i]) & 0xFF for i in range(n)]
    state = nonlinear_substitution(state, key_tag, bio_digest)
    state = inverse_sbox_substitute(state, sbox)
    state = matrix_mix_inverse(state)
    state = matrix_diffusion_inverse(state, rk, chaotic)
    state = inverse_rotation(state, rotations)
    perm = sha_permutation_indices(keys, chaotic, features, n, round_idx, iv)
    state = inverse_permutation(state, perm)
    state = [(state[i] ^ chaos[(round_idx * n + i) % len(chaos)]) & 0xFF for i in range(n)]
    return state


def encrypt_state_v2(
    data: List[int],
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    x0: float,
    minutiae,
    rounds: int = QSBAC_SPN_ROUNDS,
) -> Tuple[List[int], List[List[int]], List[int], int]:
    bio = minutiae_digest(minutiae)
    bx0 = biometric_x0(minutiae, x0)
    n = len(data)
    chaos = chaotic_stream(n + rounds, bx0)
    w = whitening_keys(keys, chaotic, features, iv)
    state = [(data[i] ^ w[i % 32]) & 0xFF for i in range(n)]

    all_rotations: List[List[int]] = []
    round_feedbacks: List[int] = []
    feedback = iv[0]
    for rnd in range(rounds):
        round_feedbacks.append(feedback)
        state, rots = spn_encrypt_round(
            state, keys, chaotic, features, iv, rnd, bx0, bio, feedback, chaos
        )
        all_rotations.append(rots)
        feedback = state[-1] if state else feedback
    state = [(state[i] ^ w[(i + 17) % 32]) & 0xFF for i in range(n)]
    return state, all_rotations, round_feedbacks, rounds


def decrypt_state_v2(
    data: List[int],
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    x0: float,
    minutiae,
    all_rotations: List[List[int]],
    round_feedbacks: List[int],
    rounds: int,
) -> List[int]:
    bio = minutiae_digest(minutiae)
    bx0 = biometric_x0(minutiae, x0)
    n = len(data)
    chaos = chaotic_stream(n + rounds, bx0)
    w = whitening_keys(keys, chaotic, features, iv)
    state = [(data[i] ^ w[(i + 17) % 32]) & 0xFF for i in range(n)]

    for rnd in range(rounds - 1, -1, -1):
        state = spn_decrypt_round(
            state,
            keys,
            chaotic,
            features,
            iv,
            rnd,
            bx0,
            bio,
            round_feedbacks[rnd],
            all_rotations[rnd],
            chaos,
        )

    state = [(state[i] ^ w[i % 32]) & 0xFF for i in range(n)]
    return state
