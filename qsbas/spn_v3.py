"""
QSBAC-SPN v3: 16-round state-mutating cipher with chaotic injection, cascade diffusion,
GF(2^8) matrix mixing, SHA-256 S-boxes, entropy reinforcement, and adaptive CBC.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import List, Tuple

from qsbas.chaotic import chaotic_bytes, logistic_step
from qsbas.constants import QSBAC_IV_BYTES, QSBAC_SPN_ROUNDS
from qsbas.gf256 import matrix_mix_forward, matrix_mix_inverse
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
from qsbas.quantum_entropy import quantum_initial_value


def _digest(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def generate_iv_v3(
    minutiae_bytes: bytes,
    timestamp: float,
    features: List[int],
    chaotic: List[int],
    x0: float,
) -> List[int]:
    """IV = SHA256(quantum noise + biometrics + timestamp + chaotic seed)."""
    qnoise = os.urandom(16)
    try:
        from qsbas.quantum_entropy import quantum_initial_value

        qf = quantum_initial_value()
        qnoise = _digest(struct.pack(">d", qf), qnoise)
    except Exception:
        pass
    payload = qnoise + minutiae_bytes + struct.pack(">d", timestamp) + bytes(features[:32]) + bytes(chaotic[:32])
    seed = _digest(payload, struct.pack(">d", x0))
    return list(seed[:QSBAC_IV_BYTES])


def minutiae_digest(minutiae: List) -> bytes:
    parts = [struct.pack(">fff", float(m.x), float(m.y), float(m.theta)) for m in minutiae]
    return _digest(b"".join(parts), b"bio-v3")


def biometric_x0(minutiae: List, quantum_x0: float) -> float:
    bio = sum((int(m.x) ^ int(m.y)) & 0xFF for m in minutiae[:32]) % 1000
    x = (bio / 1000.0 + quantum_x0) / 2.0
    return min(max(x, 1e-6), 1.0 - 1e-6)


def chaotic_stream(length: int, x0: float) -> List[int]:
    """Logistic map r=3.99 — chaos[i] = int(x_n * 255)."""
    x = x0
    out: List[int] = []
    for _ in range(length):
        x = logistic_step(x, 3.99)
        out.append(int(x * 255) % 256)
    return out


def mutating_round_key(
    prev_key_digest: bytes,
    ciphertext_byte: int,
    bio_digest: bytes,
    round_idx: int,
    length: int,
    base_keys: List[int],
    chaotic: List[int],
) -> Tuple[List[int], bytes]:
    """K_{i+1} = SHA256(K_i XOR C_i XOR B_i)."""
    new_digest = _digest(prev_key_digest, bytes([ciphertext_byte & 0xFF]), bio_digest, struct.pack(">H", round_idx))
    rk = [
        (base_keys[i % len(base_keys)] ^ new_digest[i % 32] ^ chaotic[i % len(chaotic)] ^ new_digest[(i * 3 + 7) % 32])
        & 0xFF
        for i in range(length)
    ]
    return rk, new_digest


def sha_permutation_v3(
    key_digest: bytes,
    chaotic: List[int],
    features: List[int],
    n: int,
    round_idx: int,
    iv: List[int],
) -> List[int]:
    seed = _digest(key_digest, bytes(iv), struct.pack(">H", round_idx), b"perm-v3")
    order = list(range(n))
    order.sort(
        key=lambda i: (
            seed[i % 32] ^ chaotic[i % len(chaotic)] ^ features[i % len(features)] ^ (i * 13 + round_idx) % 256,
            seed[(i * 7 + round_idx) % 32],
            i,
        )
    )
    return order


def build_sbox_v3(
    key_digest: bytes,
    bio_digest: bytes,
    round_idx: int,
    iv: List[int],
    x0: float,
    chaotic: List[int],
    features: List[int],
) -> List[int]:
    """Bijective SHA-256 + chaotic shuffle S-box."""
    table_seed = _digest(key_digest, bio_digest, bytes(iv), struct.pack(">H", round_idx), b"sbox-v3")
    extra = chaotic_bytes(256, x0=(x0 + round_idx * 0.017) % 1.0)
    indices = list(range(256))
    indices.sort(
        key=lambda i: (
            table_seed[i % 32] ^ extra[i],
            _digest(table_seed, bytes([i]), bio_digest)[0],
            (chaotic[i % len(chaotic)] ^ features[i % len(features)] ^ i),
            i,
        )
    )
    return indices


def nonlinear_substitution(state: List[int], key_digest: bytes, bio_digest: bytes) -> List[int]:
    """Nonlinear layer: state[i] XOR SHA256(i XOR K XOR B)[0] — self-inverse."""
    return [
        (state[i] ^ _digest(key_digest, bio_digest, struct.pack(">H", i))[0]) & 0xFF for i in range(len(state))
    ]


def cascade_diffusion_forward(state: List[int], keys: List[int], chaotic: List[int]) -> List[int]:
    """Triple cascading diffusion (fully invertible)."""
    s = diffusion_forward(state, keys, chaotic)
    s = diffusion_forward(s, chaotic, keys)
    return diffusion_forward(s, keys[::-1], chaotic[::-1])


def cascade_diffusion_inverse(state: List[int], keys: List[int], chaotic: List[int]) -> List[int]:
    s = diffusion_inverse(state, keys[::-1], chaotic[::-1])
    s = diffusion_inverse(s, chaotic, keys)
    return diffusion_inverse(s, keys, chaotic)


def cbc_forward_keyed(state: List[int], iv_byte: int, round_keys: List[int]) -> List[int]:
  prev = iv_byte & 0xFF
  out: List[int] = []
  for i, b in enumerate(state):
    c = (b ^ prev ^ round_keys[i % len(round_keys)]) & 0xFF
    out.append(c)
    prev = c
  return out


def cbc_inverse_keyed(state: List[int], iv_byte: int, round_keys: List[int]) -> List[int]:
  prev = iv_byte & 0xFF
  out: List[int] = []
  for c in state:
    p = (c ^ prev ^ round_keys[len(out) % len(round_keys)]) & 0xFF
    out.append(p)
    prev = c
  return out


def entropy_reinforcement(state: List[int], bio_digest: bytes, round_idx: int) -> List[int]:
    payload = bytes(state) + bio_digest + struct.pack(">H", round_idx)
    mask = _digest(payload, b"reinforce")
    return [(state[i] ^ mask[i % 32]) & 0xFF for i in range(len(state))]


def adaptive_round_count(length: int) -> int:
    """16–20 rounds based on payload size."""
    return min(20, max(16, QSBAC_SPN_ROUNDS + length // 128))


def spn_encrypt_round_v3(
    state: List[int],
    base_keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    round_idx: int,
    x0: float,
    bio_digest: bytes,
    key_digest: bytes,
    feedback: int,
    chaos: List[int],
) -> Tuple[List[int], List[int], bytes]:
    n = len(state)
    rk, key_digest = mutating_round_key(key_digest, feedback, bio_digest, round_idx, n, base_keys, chaotic)

    state = [(state[i] ^ rk[i]) & 0xFF for i in range(n)]
    state = [(state[i] ^ chaos[i % len(chaos)]) & 0xFF for i in range(n)]

    perm = sha_permutation_v3(key_digest, chaotic, features, n, round_idx, iv)
    state = apply_permutation(state, perm)

    rotations: List[int] = []
    prev = feedback & 0xFF
    for i in range(n):
        r = (features[i % len(features)] ^ chaotic[i % len(chaotic)] ^ rk[i] ^ state[i] ^ prev) & 0x7
        rotations.append(r)
        prev = state[i]

    state = apply_rotation(state, rotations)
    state = cascade_diffusion_forward(state, rk, chaotic)
    state = matrix_mix_forward(state)
    state = diffusion_forward(state, rk, chaotic)

    sbox = build_sbox_v3(key_digest, bio_digest, round_idx, iv, x0, chaotic, features)
    state = sbox_substitute(state, sbox)
    state = nonlinear_substitution(state, key_digest, bio_digest)

    state = cbc_forward_keyed(state, iv[round_idx % len(iv)], rk)
    return state, rotations, key_digest


def spn_decrypt_round_v3(
    state: List[int],
    base_keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    round_idx: int,
    x0: float,
    bio_digest: bytes,
    key_digest: bytes,
    feedback: int,
    rotations: List[int],
    chaos: List[int],
) -> List[int]:
    n = len(state)
    rk, _ = mutating_round_key(key_digest, feedback, bio_digest, round_idx, n, base_keys, chaotic)

    state = cbc_inverse_keyed(state, iv[round_idx % len(iv)], rk)
    state = nonlinear_substitution(state, key_digest, bio_digest)

    sbox = build_sbox_v3(key_digest, bio_digest, round_idx, iv, x0, chaotic, features)
    state = inverse_sbox_substitute(state, sbox)

    state = diffusion_inverse(state, rk, chaotic)
    state = matrix_mix_inverse(state)
    state = cascade_diffusion_inverse(state, rk, chaotic)
    state = inverse_rotation(state, rotations)

    perm = sha_permutation_v3(key_digest, chaotic, features, n, round_idx, iv)
    state = inverse_permutation(state, perm)

    state = [(state[i] ^ chaos[i % len(chaos)]) & 0xFF for i in range(n)]
    state = [(state[i] ^ rk[i]) & 0xFF for i in range(n)]
    return state


def whitening_v3(keys: List[int], chaotic: List[int], features: List[int], iv: List[int], bio: bytes) -> List[int]:
    return list(_digest(bytes(keys), bytes(chaotic), bytes(features), bytes(iv), bio, b"w-v3"))


def _key_digest_chain(
    base_keys: List[int],
    chaotic: List[int],
    bio: bytes,
    iv: List[int],
    round_feedbacks: List[int],
    rounds: int,
    length: int,
) -> List[bytes]:
    kd = _digest(bytes(base_keys), bio, bytes(iv), b"init-key-v3")
    starts: List[bytes] = []
    for rnd in range(rounds):
        starts.append(kd)
        _, kd = mutating_round_key(kd, round_feedbacks[rnd], bio, rnd, length, base_keys, chaotic)
    return starts


def encrypt_state_v3(
    data: List[int],
    keys: List[int],
    chaotic: List[int],
    features: List[int],
    iv: List[int],
    x0: float,
    minutiae,
    rounds: int | None = None,
) -> Tuple[List[int], List[List[int]], List[int], int]:
    bio = minutiae_digest(minutiae)
    bx0 = biometric_x0(minutiae, x0)
    n = len(data)
    rnd_count = rounds if rounds is not None else adaptive_round_count(n)
    chaos = chaotic_stream(n + rnd_count, bx0)

    w = whitening_v3(keys, chaotic, features, iv, bio)
    state = [(data[i] ^ w[i % 32]) & 0xFF for i in range(n)]

    all_rotations: List[List[int]] = []
    round_feedbacks: List[int] = []
    key_digest = _digest(bytes(keys), bio, bytes(iv), b"init-key-v3")
    feedback = iv[0]

    for rnd in range(rnd_count):
        round_feedbacks.append(feedback)
        state, rots, key_digest = spn_encrypt_round_v3(
            state, keys, chaotic, features, iv, rnd, bx0, bio, key_digest, feedback, chaos
        )
        all_rotations.append(rots)
        feedback = state[-1] if state else feedback
        if rnd % 2 == 1:
            state = entropy_reinforcement(state, bio, rnd)

    state = [(state[i] ^ w[(i + 11) % 32]) & 0xFF for i in range(n)]
    return state, all_rotations, round_feedbacks, rnd_count


def decrypt_state_v3(
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

    w = whitening_v3(keys, chaotic, features, iv, bio)
    state = [(data[i] ^ w[(i + 11) % 32]) & 0xFF for i in range(n)]

    digest_starts = _key_digest_chain(keys, chaotic, bio, iv, round_feedbacks, rounds, n)

    for rnd in range(rounds - 1, -1, -1):
        if rnd % 2 == 1:
            state = entropy_reinforcement(state, bio, rnd)
        state = spn_decrypt_round_v3(
            state,
            keys,
            chaotic,
            features,
            iv,
            rnd,
            bx0,
            bio,
            digest_starts[rnd],
            round_feedbacks[rnd],
            all_rotations[rnd],
            chaos,
        )

    state = [(state[i] ^ w[i % 32]) & 0xFF for i in range(n)]
    return state
