"""
QSBAC-SPN: Quantum-Safe Biometric Adaptive Cipher (Substitution–Permutation Network).

v2 (default): 12 rounds, SHA-256 S-box, CBC chaining, key whitening, chaotic maps.
v1: legacy single-pass decrypt for sessions encrypted before upgrade.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import List, Tuple

import numpy as np

from qsbas.constants import QSBAC_ENGINE_VERSION, QSBAC_SPN_ROUNDS
from qsbas.fingerprint import Minutia, extract_minutiae, load_fingerprint
from qsbas.keys import SessionMaterial, build_session_material, permutation_indices
from qsbas.layers import (
    apply_permutation,
    apply_rotation,
    build_dynamic_sbox,
    diffusion_forward,
    diffusion_inverse,
    inverse_permutation,
    inverse_rotation,
    inverse_sbox_substitute,
    rotation_factor,
    sbox_substitute,
)
from qsbas.quantum_entropy import quantum_initial_value
from qsbas.spn_v2 import decrypt_state_v2, encrypt_state_v2, generate_iv as generate_iv_v2
from qsbas.spn_v3 import generate_iv_v3
from qsbas.utils import bytes_to_int_list, int_list_to_bytes, rotl8, rotr8


@dataclass
class CipherSession:
    """Session state for QSBAC-SPN decrypt."""

    timestamp: float
    timestamp_salt: int
    minutiae: List[dict]
    features: List[int]
    chaotic: List[int]
    perm_indices: List[int]
    rotations: List[int]
    x0_hint: float
    engine_version: int = QSBAC_ENGINE_VERSION
    iv: List[int] | None = None
    num_rounds: int = QSBAC_SPN_ROUNDS
    round_rotations: List[List[int]] | None = None
    round_feedbacks: List[int] | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "CipherSession":
        data = json.loads(raw)
        if "engine_version" not in data:
            data["engine_version"] = 1
        return cls(**data)


class QSBACSPNCipher:
    """Quantum-Safe Biometric Adaptive Cipher using an SPN structure."""

    def __init__(self, fingerprint_image: np.ndarray | None = None, minutiae: List[Minutia] | None = None):
        if minutiae is not None:
            self.minutiae = minutiae
        elif fingerprint_image is not None:
            from qsbas.constants import MINUTIAE_COUNT

            self.minutiae = extract_minutiae(fingerprint_image, max_points=MINUTIAE_COUNT)
        else:
            raise ValueError("Provide fingerprint image or minutiae list")

    @classmethod
    def from_image_path(cls, path: str) -> "QSBACSPNCipher":
        return cls(fingerprint_image=load_fingerprint(path))

    def _material(self, length: int, timestamp: float | None) -> Tuple[SessionMaterial, float]:
        x0 = quantum_initial_value()
        mat = build_session_material(self.minutiae, length, timestamp=timestamp)
        mat.perm_indices = permutation_indices(mat.keys, mat.chaotic, mat.features, length)
        return mat, x0

    def encrypt(self, plaintext: bytes, timestamp: float | None = None) -> Tuple[bytes, CipherSession]:
        ts = timestamp if timestamp is not None else time.time()
        data = bytes_to_int_list(plaintext)
        n = len(data)
        if n == 0:
            raise ValueError("Plaintext is empty")

        mat, x0 = self._material(n, ts)
        bio_bytes = bytes(
            int(m.x) & 0xFF for m in self.minutiae[:32]
        ) + bytes(int(m.y) & 0xFF for m in self.minutiae[:32])
        iv = generate_iv_v3(bio_bytes, ts, mat.features, mat.chaotic, x0)

        encrypted, round_rots, round_fb, num_rounds = encrypt_state_v2(
            data,
            mat.keys,
            mat.chaotic,
            mat.features,
            iv,
            x0,
            self.minutiae,
        )

        session = CipherSession(
            timestamp=ts,
            timestamp_salt=mat.timestamp_salt,
            minutiae=[{"x": m.x, "y": m.y, "theta": m.theta} for m in self.minutiae],
            features=mat.features,
            chaotic=mat.chaotic,
            perm_indices=mat.perm_indices,
            rotations=[],
            x0_hint=x0,
            engine_version=QSBAC_ENGINE_VERSION,
            iv=iv,
            num_rounds=num_rounds,
            round_rotations=round_rots,
            round_feedbacks=round_fb,
        )
        return int_list_to_bytes(encrypted), session

    def decrypt(self, ciphertext: bytes, session: CipherSession) -> bytes:
        encrypted = bytes_to_int_list(ciphertext)
        n = len(encrypted)
        if n == 0:
            raise ValueError("Ciphertext is empty")

        ver = getattr(session, "engine_version", 1)
        if ver < 2:
            return self._decrypt_v1(encrypted, session)

        minutiae = [Minutia(m["x"], m["y"], m["theta"]) for m in session.minutiae]
        mat = build_session_material(
            minutiae,
            n,
            timestamp=session.timestamp,
            x0=session.x0_hint,
            features=session.features,
            chaotic=session.chaotic,
        )
        iv = session.iv or generate_iv_v2(b"", session.timestamp, session.features, session.chaotic)
        rots = session.round_rotations or []
        fb = session.round_feedbacks or [iv[0]] * (session.num_rounds or QSBAC_SPN_ROUNDS)
        rounds = session.num_rounds or QSBAC_SPN_ROUNDS

        plain = decrypt_state_v2(
            encrypted,
            mat.keys,
            session.chaotic,
            session.features,
            iv,
            session.x0_hint,
            minutiae,
            rots,
            fb,
            rounds=rounds,
        )
        return int_list_to_bytes(plain)

    def _decrypt_v1(self, encrypted: List[int], session: CipherSession) -> bytes:
        """Legacy single-pass decrypt for pre-v2 sessions."""
        n = len(encrypted)
        minutiae = [Minutia(m["x"], m["y"], m["theta"]) for m in session.minutiae]
        mat = build_session_material(
            minutiae,
            n,
            timestamp=session.timestamp,
            x0=session.x0_hint,
            features=session.features,
            chaotic=session.chaotic,
        )
        keys = mat.keys
        chaotic = session.chaotic
        features = session.features
        perm = session.perm_indices
        rotations = session.rotations

        sbox = build_dynamic_sbox(features, chaotic, x0=session.x0_hint)

        after_final: List[int] = []
        prev_c = 0
        for i in range(n):
            e = encrypted[i]
            p = (keys[i] + chaotic[i] ** 2 + features[i] * i) & 0xFF
            r = rotations[i] if i < len(rotations) else 0
            q = chaotic[i]
            s_i = (chaotic[i] ^ features[i] ^ i) & 0xFF
            inner = (e ^ p ^ prev_c) & 0xFF
            inner = rotr8(inner, r)
            inner = (inner - q) & 0xFF
            d = (inner ^ s_i) & 0xFF
            after_final.append(d)
            prev_c = e

        diffused = inverse_sbox_substitute(after_final, sbox)
        rotated = diffusion_inverse(diffused, keys, chaotic)
        permuted = inverse_rotation(rotated, rotations)
        plain = inverse_permutation(permuted, perm)
        return int_list_to_bytes(plain)

    def _encrypt_v1(self, plaintext: bytes, timestamp: float | None = None) -> Tuple[bytes, CipherSession]:
        """Kept for reference; v2 is always used for new encryption."""
        ts = timestamp if timestamp is not None else time.time()
        data = bytes_to_int_list(plaintext)
        n = len(data)
        mat, x0 = self._material(n, ts)
        perm = mat.perm_indices
        keys = mat.keys
        chaotic = mat.chaotic
        features = mat.features

        permuted = apply_permutation(data, perm)
        rotations: List[int] = []
        prev_block = 0
        for i in range(n):
            rotations.append(rotation_factor(features[i], chaotic[i], prev_block))
            prev_block = permuted[i] & 0xFF
        rotated = apply_rotation(permuted, rotations)
        diffused = diffusion_forward(rotated, keys, chaotic)
        sbox = build_dynamic_sbox(features, chaotic, x0=x0)
        diffused = sbox_substitute(diffused, sbox)

        encrypted: List[int] = []
        prev_c = 0
        for i in range(n):
            d = diffused[i]
            s_i = (chaotic[i] ^ features[i] ^ i) & 0xFF
            q = chaotic[i]
            r = rotations[i]
            p = (keys[i] + chaotic[i] ** 2 + features[i] * i) & 0xFF
            inner = rotl8(((d ^ s_i) + q) & 0xFF, r)
            e = (inner ^ p ^ prev_c) & 0xFF
            encrypted.append(e)
            prev_c = e

        session = CipherSession(
            timestamp=ts,
            timestamp_salt=mat.timestamp_salt,
            minutiae=[{"x": m.x, "y": m.y, "theta": m.theta} for m in self.minutiae],
            features=features,
            chaotic=chaotic,
            perm_indices=perm,
            rotations=rotations,
            x0_hint=x0,
            engine_version=1,
        )
        return int_list_to_bytes(encrypted), session


QSBACCipher = QSBACSPNCipher
