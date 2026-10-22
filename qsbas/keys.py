"""Module 6: dynamic session key generation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List

from qsbas.chaotic import chaotic_bytes
from qsbas.fingerprint import Minutia
from qsbas.hashing import derive_feature_stream
from qsbas.quantum_entropy import quantum_initial_value


@dataclass
class SessionMaterial:
    timestamp_salt: int
    features: List[int]
    chaotic: List[int]
    keys: List[int]
    perm_indices: List[int]
    rotations: List[int]


def session_timestamp_salt(ts: float | None = None) -> int:
    t = int((ts if ts is not None else time.time()) * 1000)
    return t & 0xFF


def generate_keys(features: List[int], chaotic: List[int], ts: int, length: int) -> List[int]:
    """K_i = (F_i XOR Q_i XOR T_s) mod 256."""
    keys: List[int] = []
    for i in range(length):
        f = features[i % len(features)]
        q = chaotic[i % len(chaotic)]
        keys.append((f ^ q ^ ts) & 0xFF)
    return keys


def permutation_indices(keys: List[int], chaotic: List[int], features: List[int], n: int) -> List[int]:
    """Derive a bijective shuffle from P_i = (K_i + Q_i^2 + F_i * i) mod N used as sort key."""
    order = list(range(n))
    order.sort(
        key=lambda i: (
            (keys[i % len(keys)] + (chaotic[i % len(chaotic)] ** 2) + (features[i % len(features)] * i))
            % n,
            i,
        )
    )
    return order


def build_session_material(
    minutiae: List[Minutia],
    data_length: int,
    timestamp: float | None = None,
    x0: float | None = None,
    features: List[int] | None = None,
    chaotic: List[int] | None = None,
) -> SessionMaterial:
    ts = session_timestamp_salt(timestamp)
    if features is None:
        features = derive_feature_stream(minutiae, data_length)
    if x0 is None:
        x0 = quantum_initial_value()
    if chaotic is None:
        chaotic = chaotic_bytes(data_length, x0=x0)
    keys = generate_keys(features, chaotic, ts, data_length)
    perm = permutation_indices(keys, chaotic, features, data_length)
    return SessionMaterial(
        timestamp_salt=ts,
        features=features,
        chaotic=chaotic,
        keys=keys,
        perm_indices=perm,
        rotations=[],  # filled during encryption
    )
