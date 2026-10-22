"""Backend tests: fingerprint only, face only, or both (AND when both enrolled)."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.biometric_profile import (
    BiometricProfile,
    face_verified,
    fingerprint_verified,
    identify_participant,
    verify_decrypt_authorization,
)
from qsbas.constants import FACE_LANDMARK_COUNT, MINUTIAE_COUNT
from qsbas.fingerprint import Minutia
from qsbas.group_cipher import group_decrypt_by_fingerprint, group_encrypt


def _fp(seed: int) -> list[Minutia]:
    return [
        Minutia(float(30 + seed * 45 + i * 5), float(40 + seed * 38 + i * 6), float(seed + i) * 0.2)
        for i in range(MINUTIAE_COUNT)
    ]


def _face(seed: int) -> list[Minutia]:
    return [
        Minutia(
            min(0.95, 0.08 + (i % 8) * 0.10 + seed * 0.22),
            min(0.95, 0.10 + (i // 8) * 0.18),
            0.12 + seed * 0.25 + i * 0.01,
        )
        for i in range(FACE_LANDMARK_COUNT)
    ]


def _embed(seed: int) -> list[float]:
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(352)
    n = float(np.linalg.norm(v)) or 1.0
    return [float(x) / n for x in v]


def make_both(name: str, fp_seed: int, face_seed: int, is_encryptor: bool = False) -> BiometricProfile:
    return BiometricProfile(
        name=name,
        fingerprint_minutiae=_fp(fp_seed),
        iris_minutiae=[],
        face_minutiae=_face(face_seed),
        is_encryptor=is_encryptor,
        face_embedding=_embed(face_seed),
    )


def make_fp_only(name: str, fp_seed: int, is_encryptor: bool = False) -> BiometricProfile:
    return BiometricProfile(
        name=name,
        fingerprint_minutiae=_fp(fp_seed),
        iris_minutiae=[],
        face_minutiae=[],
        is_encryptor=is_encryptor,
        face_embedding=[],
    )


def make_face_only(name: str, face_seed: int, is_encryptor: bool = False) -> BiometricProfile:
    return BiometricProfile(
        name=name,
        fingerprint_minutiae=[],
        iris_minutiae=[],
        face_minutiae=_face(face_seed),
        is_encryptor=is_encryptor,
        face_embedding=_embed(face_seed),
    )


def expect_deny(probe: BiometricProfile, pkg) -> None:
    try:
        group_decrypt_by_fingerprint(pkg, probe)
    except PermissionError:
        return
    raise AssertionError("Expected decryption to be denied")


def main() -> None:
    alice = make_both("Alice", fp_seed=1, face_seed=1, is_encryptor=True)
    pkg = group_encrypt(b"secret-and-gate", [alice])

    correct_both = make_both("_probe_", 1, 1)
    wrong_face = make_both("_probe_", 1, 2)
    wrong_fp = make_both("_probe_", 2, 1)
    both_wrong = make_both("_probe_", 2, 2)
    fp_only = make_fp_only("_probe_", 1)
    face_only = make_face_only("_probe_", 1)

    plain, name = group_decrypt_by_fingerprint(pkg, correct_both)
    assert plain == b"secret-and-gate" and name == "Alice"
    assert fingerprint_verified(alice, correct_both) and face_verified(alice, correct_both)
    print("OK: enrolled both: correct fingerprint + correct face -> allow")

    expect_deny(wrong_face, pkg)
    print("OK: enrolled both: correct fingerprint + wrong face -> deny")
    expect_deny(wrong_fp, pkg)
    print("OK: enrolled both: wrong fingerprint + correct face -> deny")
    expect_deny(fp_only, pkg)
    print("OK: enrolled both: fingerprint only -> deny")
    expect_deny(face_only, pkg)
    print("OK: enrolled both: face only -> deny")
    expect_deny(both_wrong, pkg)
    print("OK: enrolled both: both wrong -> deny")

    bob = make_fp_only("Bob", 3, is_encryptor=True)
    pkg_fp = group_encrypt(b"fp-only-secret", [bob])
    plain, name = group_decrypt_by_fingerprint(pkg_fp, make_fp_only("_probe_", 3))
    assert plain == b"fp-only-secret" and name == "Bob"
    print("OK: enrolled fingerprint only: matching fingerprint -> allow")
    expect_deny(make_fp_only("_probe_", 4), pkg_fp)
    print("OK: enrolled fingerprint only: wrong fingerprint -> deny")
    expect_deny(make_face_only("_probe_", 3), pkg_fp)
    print("OK: enrolled fingerprint only: face cannot decrypt -> deny")

    cara = make_face_only("Cara", 5, is_encryptor=True)
    pkg_face = group_encrypt(b"face-only-secret", [cara])
    plain, name = group_decrypt_by_fingerprint(pkg_face, make_face_only("_probe_", 5))
    assert plain == b"face-only-secret" and name == "Cara"
    print("OK: enrolled face only: matching face -> allow")
    expect_deny(make_face_only("_probe_", 6), pkg_face)
    print("OK: enrolled face only: wrong face -> deny")
    expect_deny(make_fp_only("_probe_", 5), pkg_face)
    print("OK: enrolled face only: fingerprint cannot decrypt -> deny")

    try:
        identify_participant([alice], fp_only)
        raise AssertionError("identify should reject fingerprint-only against dual enrollment")
    except PermissionError:
        pass

    try:
        verify_decrypt_authorization(alice, wrong_face)
        raise AssertionError("verify should reject wrong face")
    except PermissionError:
        pass

    print("ALL MODALITY CASES PASSED")


if __name__ == "__main__":
    main()
