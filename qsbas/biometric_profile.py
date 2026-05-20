"""Combined fingerprint + optional iris/face biometric profile."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import List, Optional

import numpy as np

from qsbas.biometric_validation import BiometricValidationError, require_valid_file
from qsbas.constants import (
    BIOMETRIC_AMBIGUITY_GAP,
    BIOMETRIC_DECRYPT_MIN_CIPHER,
    BIOMETRIC_DECRYPT_MIN_HASH,
    BIOMETRIC_DECRYPT_MIN_SPATIAL,
    BIOMETRIC_MATCH_RATIO,
    MINUTIAE_COUNT,
    MINUTIAE_SPATIAL_TOLERANCE,
)
from qsbas.face import extract_face_features
from qsbas.fingerprint import Minutia, extract_minutiae, load_fingerprint
from qsbas.hashing import hash_minutiae, lightweight_hash
from qsbas.iris import extract_iris_features


@dataclass
class BiometricProfile:
    name: str
    fingerprint_minutiae: List[Minutia]
    iris_minutiae: List[Minutia]
    face_minutiae: List[Minutia]
    is_encryptor: bool = False

    @property
    def cipher_minutiae(self) -> List[Minutia]:
        """Exactly 32 minutiae for QSBAC (fingerprint-primary, padded from multimodal)."""
        base = list(self.fingerprint_minutiae[:MINUTIAE_COUNT])
        extras = self.iris_minutiae + self.face_minutiae
        idx = 0
        while len(base) < MINUTIAE_COUNT and idx < len(extras):
            base.append(extras[idx])
            idx += 1
        if len(base) < MINUTIAE_COUNT:
            raise BiometricValidationError(
                "Fingerprint minutiae are insufficient after validation.", "fingerprint"
            )
        return base[:MINUTIAE_COUNT]

    def feature_hash_hex(self) -> str:
        hashes = hash_minutiae(self.cipher_minutiae)
        for m in self.iris_minutiae + self.face_minutiae:
            hashes.append(lightweight_hash(m.x, m.y, m.theta))
        return "".join(f"{h:02x}" for h in hashes[:64])

    def session_feature_hash_hex(self, session_id: int) -> str:
        """Session-bound hash so the same biometrics show a different H per session."""
        import hashlib

        base = self.feature_hash_hex()
        digest = hashlib.sha256(f"qsbas-session:{session_id}:{base}".encode()).hexdigest()
        return digest

    def to_json(self) -> str:
        return json.dumps(
            {
                "name": self.name,
                "is_encryptor": self.is_encryptor,
                "fingerprint_minutiae": [asdict(m) for m in self.fingerprint_minutiae],
                "iris_minutiae": [asdict(m) for m in self.iris_minutiae],
                "face_minutiae": [asdict(m) for m in self.face_minutiae],
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> "BiometricProfile":
        data = json.loads(raw)
        return cls(
            name=data["name"],
            is_encryptor=data.get("is_encryptor", False),
            fingerprint_minutiae=[Minutia(**m) for m in data["fingerprint_minutiae"]],
            iris_minutiae=[Minutia(**m) for m in data.get("iris_minutiae", [])],
            face_minutiae=[Minutia(**m) for m in data.get("face_minutiae", [])],
        )


def build_profile(
    name: str,
    fingerprint_path: str,
    iris_path: Optional[str] = None,
    face_path: Optional[str] = None,
    is_encryptor: bool = False,
) -> BiometricProfile:
    require_valid_file(fingerprint_path, "fingerprint")
    fp_img = load_fingerprint(fingerprint_path)
    fp_minutiae = extract_minutiae(fp_img, max_points=MINUTIAE_COUNT)

    iris_min: List[Minutia] = []
    face_min: List[Minutia] = []
    if iris_path:
        require_valid_file(iris_path, "iris")
        iris_img = load_fingerprint(iris_path)
        _, iris_min = extract_iris_features(iris_img)
        if not iris_min:
            raise BiometricValidationError(
                "Iris image passed checks but feature extraction failed.", "iris"
            )
    if face_path:
        require_valid_file(face_path, "face")
        face_img = load_fingerprint(face_path)
        _, face_min = extract_face_features(face_img)
        if not face_min:
            raise BiometricValidationError(
                "Face image passed checks but feature extraction failed.", "face"
            )

    return BiometricProfile(
        name=name,
        fingerprint_minutiae=fp_minutiae,
        iris_minutiae=iris_min,
        face_minutiae=face_min,
        is_encryptor=is_encryptor,
    )


def _minutiae_spatial_ratio(
    stored: List[Minutia], probe: List[Minutia], tolerance: float = MINUTIAE_SPATIAL_TOLERANCE
) -> float:
    """Share of probe minutiae that align with a stored point (re-scan tolerant)."""
    probe_pts = probe[:MINUTIAE_COUNT]
    stored_pts = stored[:MINUTIAE_COUNT]
    if not probe_pts:
        return 0.0
    hits = 0
    for p in probe_pts:
        for s in stored_pts:
            dist = ((p.x - s.x) ** 2 + (p.y - s.y) ** 2) ** 0.5
            if dist <= tolerance:
                hits += 1
                break
    return hits / len(probe_pts)


def biometric_match_components(
    stored: BiometricProfile, probe: BiometricProfile
) -> tuple[float, float, float | None]:
    """Return (hash_ratio, spatial_ratio, cipher_ratio or None)."""
    stored_fp = stored.fingerprint_minutiae[:MINUTIAE_COUNT]
    probe_fp = probe.fingerprint_minutiae[:MINUTIAE_COUNT]

    stored_h = hash_minutiae(stored_fp)
    probe_h = hash_minutiae(probe_fp)
    hash_ratio = sum(1 for a, b in zip(stored_h, probe_h) if a == b) / max(len(stored_h), 1)
    spatial_ratio = _minutiae_spatial_ratio(stored_fp, probe_fp)

    probe_multimodal = bool(probe.iris_minutiae or probe.face_minutiae)
    stored_multimodal = bool(stored.iris_minutiae or stored.face_minutiae)
    cipher_ratio: float | None = None
    if probe_multimodal and stored_multimodal:
        cipher_stored = hash_minutiae(stored.cipher_minutiae)
        cipher_probe = hash_minutiae(probe.cipher_minutiae)
        cipher_ratio = sum(1 for a, b in zip(cipher_stored, cipher_probe) if a == b) / max(
            len(cipher_stored), 1
        )
    return hash_ratio, spatial_ratio, cipher_ratio


def biometric_match_score(stored: BiometricProfile, probe: BiometricProfile) -> float:
    """Weighted similarity in [0, 1] — both hash and spatial must contribute."""
    hash_ratio, spatial_ratio, cipher_ratio = biometric_match_components(stored, probe)
    if cipher_ratio is not None:
        return 0.30 * hash_ratio + 0.40 * spatial_ratio + 0.30 * cipher_ratio
    return 0.50 * hash_ratio + 0.50 * spatial_ratio


def verify_decrypt_authorization(stored: BiometricProfile, probe: BiometricProfile) -> None:
    """Raise PermissionError unless probe strongly matches one enrolled profile."""
    hash_ratio, spatial_ratio, cipher_ratio = biometric_match_components(stored, probe)
    combined = biometric_match_score(stored, probe)

    if hash_ratio < BIOMETRIC_DECRYPT_MIN_HASH or spatial_ratio < BIOMETRIC_DECRYPT_MIN_SPATIAL:
        raise PermissionError(
            "Fingerprint does not match any authorized profile for this session"
        )
    if cipher_ratio is not None and cipher_ratio < BIOMETRIC_DECRYPT_MIN_CIPHER:
        raise PermissionError(
            "Biometric mismatch: enrolled iris/face does not match your upload"
        )
    if combined < BIOMETRIC_MATCH_RATIO:
        raise PermissionError("Fingerprint not recognized for this session")


def biometric_features_match(stored: BiometricProfile, probe: BiometricProfile) -> bool:
    try:
        verify_decrypt_authorization(stored, probe)
        return True
    except PermissionError:
        return False


def profiles_match(stored: BiometricProfile, probe: BiometricProfile) -> bool:
    if stored.name.strip().lower() != probe.name.strip().lower():
        return False
    return biometric_features_match(stored, probe)


def identify_participant(
    stored_profiles: List[BiometricProfile],
    probe: BiometricProfile,
    *,
    encryptor_only: bool = False,
) -> BiometricProfile:
    """Identify exactly one enrolled user from probe biometrics alone."""
    pool = [p for p in stored_profiles if not encryptor_only or p.is_encryptor]
    if not pool:
        raise PermissionError("Fingerprint not recognized for this session")

    scored = [(p, biometric_match_score(p, probe)) for p in pool]
    scored.sort(key=lambda item: item[1], reverse=True)
    best_profile, best_score = scored[0]

    if best_score < BIOMETRIC_MATCH_RATIO:
        raise PermissionError("Fingerprint not recognized for this session")

    if len(scored) > 1:
        second_score = scored[1][1]
        if second_score >= BIOMETRIC_MATCH_RATIO and (
            best_score - second_score
        ) < BIOMETRIC_AMBIGUITY_GAP:
            raise PermissionError(
                "Fingerprint matches more than one enrolled user; re-enroll with distinct biometrics"
            )

    verify_decrypt_authorization(best_profile, probe)
    return best_profile
