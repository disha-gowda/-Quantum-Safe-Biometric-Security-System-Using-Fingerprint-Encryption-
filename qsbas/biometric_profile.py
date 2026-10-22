"""Combined fingerprint and/or face biometric profile."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from qsbas.biometric_validation import BiometricValidationError, require_valid_file
from qsbas.constants import (
    BIOMETRIC_AMBIGUITY_GAP,
    BIOMETRIC_DECRYPT_MIN_CIPHER,
    BIOMETRIC_DECRYPT_MIN_HASH,
    BIOMETRIC_DECRYPT_MIN_SPATIAL,
    BIOMETRIC_MATCH_RATIO,
    FACE_EMBED_MIN,
    FACE_LANDMARK_COUNT,
    FACE_LANDMARK_TOLERANCE,
    FACE_VERIFY_THRESHOLD,
    FINGERPRINT_VERIFY_THRESHOLD,
    MINUTIAE_COUNT,
    MINUTIAE_SPATIAL_TOLERANCE,
)
from qsbas.face import analyze_face, embedding_similarity, extract_face_features
from qsbas.fingerprint import Minutia, extract_minutiae, load_fingerprint
from qsbas.hashing import hash_minutiae, lightweight_hash


@dataclass
class BiometricProfile:
    name: str
    fingerprint_minutiae: List[Minutia]
    iris_minutiae: List[Minutia]
    face_minutiae: List[Minutia]
    is_encryptor: bool = False
    face_embedding: List[float] = field(default_factory=list)

    @property
    def has_face_template(self) -> bool:
        return len(self.face_minutiae) > 0

    @property
    def has_fingerprint_template(self) -> bool:
        return len(self.fingerprint_minutiae) > 0

    @property
    def cipher_minutiae(self) -> List[Minutia]:
        """Exactly 32 points for QSBAC. Fingerprint enrollment uses fingerprint points only."""
        if self.fingerprint_minutiae:
            base = list(self.fingerprint_minutiae[:MINUTIAE_COUNT])
            if len(base) < MINUTIAE_COUNT:
                raise BiometricValidationError(
                    "Not enough fingerprint features for the cipher.",
                    "fingerprint",
                )
            return base[:MINUTIAE_COUNT]
        face = list(self.face_minutiae[:MINUTIAE_COUNT])
        if len(face) < MINUTIAE_COUNT:
            raise BiometricValidationError(
                "Not enough facial landmarks for the cipher. Provide fingerprint, face, or both.",
                "face",
            )
        return [Minutia(m.x * 255.0, m.y * 255.0, m.theta) for m in face]

    def feature_hash_hex(self) -> str:
        hashes = hash_minutiae(self.cipher_minutiae)
        for m in self.face_minutiae:
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
                "face_embedding": self.face_embedding,
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
            face_embedding=[float(v) for v in data.get("face_embedding", [])],
        )


def build_profile(
    name: str,
    fingerprint_path: Optional[str] = None,
    iris_path: Optional[str] = None,
    face_path: Optional[str] = None,
    is_encryptor: bool = False,
    require_face: bool = False,
    require_fingerprint: bool = False,
) -> BiometricProfile:
    fp_minutiae: List[Minutia] = []
    if fingerprint_path:
        require_valid_file(fingerprint_path, "fingerprint")
        fp_img = load_fingerprint(fingerprint_path)
        fp_minutiae = extract_minutiae(fp_img, max_points=MINUTIAE_COUNT)
    elif require_fingerprint:
        raise BiometricValidationError(
            "A fingerprint image is required.",
            "fingerprint",
        )

    iris_min: List[Minutia] = []
    face_min: List[Minutia] = []
    face_embedding: List[float] = []
    if face_path:
        require_valid_file(face_path, "face")
        face_img = load_fingerprint(face_path)
        analysis = analyze_face(face_img)
        if analysis is None or len(analysis.landmarks) < FACE_LANDMARK_COUNT:
            _, face_min = extract_face_features(face_img)
            if len(face_min) < FACE_LANDMARK_COUNT:
                raise BiometricValidationError(
                    "Face image passed checks but 32 facial landmarks could not be extracted.",
                    "face",
                )
        else:
            face_min = analysis.landmarks[:FACE_LANDMARK_COUNT]
            face_embedding = analysis.embedding
    elif require_face:
        raise BiometricValidationError(
            "A face image is required. Provide one face upload (or live capture where allowed).",
            "face",
        )

    if not fp_minutiae and not face_min:
        raise BiometricValidationError(
            "Provide a fingerprint, a face, or both.",
            "fingerprint",
        )

    return BiometricProfile(
        name=name,
        fingerprint_minutiae=fp_minutiae,
        iris_minutiae=iris_min,
        face_minutiae=face_min,
        is_encryptor=is_encryptor,
        face_embedding=face_embedding,
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


def fingerprint_match_components(
    stored: BiometricProfile, probe: BiometricProfile
) -> tuple[float, float]:
    stored_fp = stored.fingerprint_minutiae[:MINUTIAE_COUNT]
    probe_fp = probe.fingerprint_minutiae[:MINUTIAE_COUNT]
    stored_h = hash_minutiae(stored_fp)
    probe_h = hash_minutiae(probe_fp)
    hash_ratio = sum(1 for a, b in zip(stored_h, probe_h) if a == b) / max(len(stored_h), 1)
    spatial_ratio = _minutiae_spatial_ratio(stored_fp, probe_fp)
    return hash_ratio, spatial_ratio


def fingerprint_match_score(stored: BiometricProfile, probe: BiometricProfile) -> float:
    """Fingerprint-only similarity in [0, 1] from minutiae hash + spatial alignment."""
    if not stored.fingerprint_minutiae or not probe.fingerprint_minutiae:
        return 0.0
    hash_ratio, spatial_ratio = fingerprint_match_components(stored, probe)
    return 0.50 * hash_ratio + 0.50 * spatial_ratio


def fingerprint_verified(stored: BiometricProfile, probe: BiometricProfile) -> bool:
    if not stored.fingerprint_minutiae or not probe.fingerprint_minutiae:
        return False
    hash_ratio, spatial_ratio = fingerprint_match_components(stored, probe)
    score = fingerprint_match_score(stored, probe)
    return (
        hash_ratio >= BIOMETRIC_DECRYPT_MIN_HASH
        and spatial_ratio >= BIOMETRIC_DECRYPT_MIN_SPATIAL
        and score >= FINGERPRINT_VERIFY_THRESHOLD
    )


def face_match_components(
    stored: BiometricProfile, probe: BiometricProfile
) -> tuple[float, float, float]:
    stored_lm = stored.face_minutiae[:FACE_LANDMARK_COUNT]
    probe_lm = probe.face_minutiae[:FACE_LANDMARK_COUNT]
    if not stored_lm or not probe_lm:
        return 0.0, 0.0, 0.0
    hits = 0
    n = min(len(stored_lm), len(probe_lm), FACE_LANDMARK_COUNT)
    for i in range(n):
        p, s = probe_lm[i], stored_lm[i]
        dist = ((p.x - s.x) ** 2 + (p.y - s.y) ** 2) ** 0.5
        if dist <= FACE_LANDMARK_TOLERANCE:
            hits += 1
    spatial = hits / max(n, 1)
    stored_h = hash_minutiae(stored_lm)
    probe_h = hash_minutiae(probe_lm)
    hash_ratio = sum(1 for a, b in zip(stored_h, probe_h) if a == b) / max(len(stored_h), 1)
    embed = embedding_similarity(stored.face_embedding, probe.face_embedding)
    return spatial, hash_ratio, embed


def face_match_score(stored: BiometricProfile, probe: BiometricProfile) -> float:
    """Face similarity in [0, 1] from landmarks + texture embedding (not filename/pixels)."""
    if not stored.face_minutiae or not probe.face_minutiae:
        return 0.0
    spatial, hash_ratio, embed = face_match_components(stored, probe)
    if stored.face_embedding and probe.face_embedding:
        return 0.30 * spatial + 0.15 * hash_ratio + 0.55 * embed
    return 0.60 * spatial + 0.40 * hash_ratio


def face_verified(stored: BiometricProfile, probe: BiometricProfile) -> bool:
    if not stored.has_face_template or not probe.face_minutiae:
        return False
    if len(stored.face_minutiae) < FACE_LANDMARK_COUNT or len(probe.face_minutiae) < FACE_LANDMARK_COUNT:
        return False
    if not stored.face_embedding or not probe.face_embedding:
        return False
    _spatial, _hash_ratio, embed = face_match_components(stored, probe)
    if embed < FACE_EMBED_MIN:
        return False
    return face_match_score(stored, probe) >= FACE_VERIFY_THRESHOLD


def biometric_match_components(
    stored: BiometricProfile, probe: BiometricProfile
) -> tuple[float, float, float | None]:
    """Return (hash_ratio, spatial_ratio, cipher_ratio or None)."""
    hash_ratio, spatial_ratio = fingerprint_match_components(stored, probe)

    probe_multimodal = bool(probe.face_minutiae)
    stored_multimodal = bool(stored.face_minutiae)
    cipher_ratio: float | None = None
    if probe_multimodal and stored_multimodal:
        cipher_stored = hash_minutiae(stored.cipher_minutiae)
        cipher_probe = hash_minutiae(probe.cipher_minutiae)
        cipher_ratio = sum(1 for a, b in zip(cipher_stored, cipher_probe) if a == b) / max(
            len(cipher_stored), 1
        )
    return hash_ratio, spatial_ratio, cipher_ratio


def biometric_match_score(stored: BiometricProfile, probe: BiometricProfile) -> float:
    """Weighted similarity in [0, 1] for the factors that were enrolled."""
    has_fp = stored.has_fingerprint_template
    has_face = stored.has_face_template
    fp = fingerprint_match_score(stored, probe)
    face = face_match_score(stored, probe)
    if has_fp and has_face:
        return 0.50 * fp + 0.50 * face
    if has_face and not has_fp:
        return face
    hash_ratio, spatial_ratio, cipher_ratio = biometric_match_components(stored, probe)
    if cipher_ratio is not None:
        return 0.30 * hash_ratio + 0.40 * spatial_ratio + 0.30 * cipher_ratio
    return fp


def verify_decrypt_authorization(stored: BiometricProfile, probe: BiometricProfile) -> None:
    """Authorize using enrolled factors: fingerprint, face, or both (AND when both enrolled)."""
    has_fp = stored.has_fingerprint_template
    has_face = stored.has_face_template
    if not has_fp and not has_face:
        raise PermissionError("No enrolled biometric template for this user")

    if has_fp and has_face:
        if not probe.fingerprint_minutiae:
            raise PermissionError(
                "This file was enrolled with fingerprint and face. Fingerprint is required."
            )
        if not probe.face_minutiae:
            raise PermissionError(
                "This file was enrolled with fingerprint and face. Face is required."
            )
        fp_ok = fingerprint_verified(stored, probe)
        face_ok = face_verified(stored, probe)
        if fp_ok and face_ok:
            return
        if fp_ok and not face_ok:
            raise PermissionError(
                "Face does not match. Both enrolled factors must verify."
            )
        if face_ok and not fp_ok:
            raise PermissionError(
                "Fingerprint does not match. Both enrolled factors must verify."
            )
        raise PermissionError("Fingerprint and face do not match the enrolled decryptor")

    if has_fp:
        if not probe.fingerprint_minutiae:
            raise PermissionError("Fingerprint input is required for this enrolled profile")
        if not fingerprint_verified(stored, probe):
            raise PermissionError("Fingerprint does not match the enrolled decryptor")
        return

    if not probe.face_minutiae:
        raise PermissionError("Face input is required for this enrolled profile")
    if not face_verified(stored, probe):
        raise PermissionError("Face does not match the enrolled decryptor")


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
    """Identify exactly one enrolled user using that user's enrolled factor(s)."""
    if not probe.fingerprint_minutiae and not probe.face_minutiae:
        raise PermissionError("Provide a fingerprint, a face, or both")

    pool = [p for p in stored_profiles if not encryptor_only or p.is_encryptor]
    if not pool:
        raise PermissionError("Biometrics not recognized for this session")

    dual: list[BiometricProfile] = []
    scored: list[tuple[BiometricProfile, float]] = []
    for profile in pool:
        try:
            verify_decrypt_authorization(profile, probe)
        except PermissionError:
            continue
        dual.append(profile)
        scored.append((profile, biometric_match_score(profile, probe)))

    if not dual:
        raise PermissionError(
            "Biometrics do not match any authorized user for this session"
        )

    scored.sort(key=lambda item: item[1], reverse=True)
    best_profile, best_score = scored[0]
    if len(scored) > 1:
        second_score = scored[1][1]
        if second_score >= min(FINGERPRINT_VERIFY_THRESHOLD, FACE_VERIFY_THRESHOLD) and (
            best_score - second_score
        ) < BIOMETRIC_AMBIGUITY_GAP:
            raise PermissionError(
                "Biometrics match more than one enrolled user; re-enroll with distinct biometrics"
            )

    verify_decrypt_authorization(best_profile, probe)
    return best_profile


def verification_report(stored: BiometricProfile, probe: BiometricProfile) -> dict:
    """Scores and pass/fail flags for UI analysis — never decrypts."""
    fp_score = fingerprint_match_score(stored, probe)
    face_score = (
        face_match_score(stored, probe) if stored.has_face_template or probe.face_minutiae else 0.0
    )
    fp_ok = fingerprint_verified(stored, probe) if stored.has_fingerprint_template else False
    face_ok = face_verified(stored, probe) if stored.has_face_template else False
    try:
        verify_decrypt_authorization(stored, probe)
        allowed = True
    except PermissionError:
        allowed = False
    return {
        "fingerprint_score": round(fp_score * 100.0, 1),
        "fingerprint_threshold": round(FINGERPRINT_VERIFY_THRESHOLD * 100.0, 1),
        "fingerprint_verified": fp_ok,
        "fingerprint_enrolled": stored.has_fingerprint_template,
        "face_score": round(face_score * 100.0, 1),
        "face_threshold": round(FACE_VERIFY_THRESHOLD * 100.0, 1),
        "face_verified": face_ok,
        "face_enrolled": stored.has_face_template,
        "final_allowed": allowed,
    }
