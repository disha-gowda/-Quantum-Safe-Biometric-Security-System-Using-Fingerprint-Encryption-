"""Shared helpers for uploads and dashboard payloads."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from werkzeug.datastructures import FileStorage

from qsbas.biometric_profile import BiometricProfile, build_profile
from qsbas.constants import MAX_AUTHORIZED_USERS, MINUTIAE_COUNT
from qsbas.fingerprint import load_fingerprint
from qsbas.visualization import minutiae_overlay_base64, quality_score

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def save_upload(file: FileStorage, prefix: str) -> str:
    ext = Path(file.filename or "img.png").suffix or ".png"
    name = f"{prefix}_{uuid.uuid4().hex}{ext}"
    path = UPLOAD_DIR / name
    file.save(path)
    return str(path)


def probe_from_fingerprint(
    fp_file: FileStorage,
    iris_file: Optional[FileStorage] = None,
    face_file: Optional[FileStorage] = None,
) -> tuple[BiometricProfile, dict]:
    """Build a biometric probe from uploads only (no declared identity)."""
    return profile_from_form("_probe_", fp_file, iris_file, face_file)


def profile_from_form(
    name: str,
    fp_file: FileStorage,
    iris_file: Optional[FileStorage] = None,
    face_file: Optional[FileStorage] = None,
    is_encryptor: bool = False,
) -> tuple[BiometricProfile, dict]:
    fp_path = save_upload(fp_file, "fp")
    iris_path = save_upload(iris_file, "iris") if iris_file and iris_file.filename else None
    face_path = save_upload(face_file, "face") if face_file and face_file.filename else None
    profile = build_profile(name, fp_path, iris_path, face_path, is_encryptor=is_encryptor)
    meta = {
        "fp_path": fp_path,
        "iris_path": iris_path,
        "face_path": face_path,
        "profile_json": profile.to_json(),
    }
    return profile, meta


def _image_to_b64(path: str | None, max_side: int = 160) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    import cv2

    img = cv2.imread(str(p))
    if img is None:
        return None
    h, w = img.shape[:2]
    scale = min(1.0, max_side / max(h, w))
    if scale < 1.0:
        img = cv2.resize(img, (int(w * scale), int(h * scale)))
    _, buf = cv2.imencode(".png", img)
    import base64

    return base64.b64encode(buf).decode("ascii")


def dashboard_biometric_panel(
    profile: BiometricProfile,
    fp_path: str,
    title: str,
    iris_path: str | None = None,
    face_path: str | None = None,
) -> dict:
    image = load_fingerprint(fp_path)
    minutiae = profile.cipher_minutiae
    return {
        "title": title,
        "name": profile.name,
        "minutiae_count": len(minutiae),
        "quality": round(quality_score(image), 1),
        "hash_hex": profile.feature_hash_hex()[:64] + "...",
        "image_b64": minutiae_overlay_base64(
            image, minutiae, f"{title} - {len(minutiae)} minutiae"
        ),
        "has_iris": len(profile.iris_minutiae) > 0,
        "has_face": len(profile.face_minutiae) > 0,
        "iris_b64": _image_to_b64(iris_path),
        "face_b64": _image_to_b64(face_path),
        "is_encryptor": profile.is_encryptor,
    }
