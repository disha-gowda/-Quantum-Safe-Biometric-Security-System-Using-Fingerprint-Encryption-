"""Shared helpers for uploads and dashboard payloads."""

from __future__ import annotations

import base64
import io
import uuid
from pathlib import Path
from typing import Optional

from flask import Request
from werkzeug.datastructures import FileStorage

from qsbas.biometric_profile import BiometricProfile, build_profile, verification_report
from qsbas.constants import FACE_LANDMARK_COUNT, MINUTIAE_COUNT
from qsbas.face import analyze_face
from qsbas.fingerprint import load_fingerprint
from qsbas.payload import (
    ContentPayload,
    MAX_DOCUMENT_BYTES,
    classify_document,
    pack_payload,
    preview_text,
    unpack_payload,
)
from qsbas.visualization import (
    face_detection_overlay_b64,
    face_landmarks_overlay_b64,
    image_to_b64,
    minutiae_overlay_base64,
    preprocessed_b64,
    quality_score,
)

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOAD_DIR = Path(__file__).resolve().parent.parent / "data" / "downloads"
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


def content_from_encrypt_form(request: Request) -> tuple[bytes, str]:
    mode = (request.form.get("payload_mode") or "text").strip().lower()
    if mode not in {"text", "document", "both"}:
        mode = "text"
    text = (request.form.get("plaintext") or "").strip()
    doc = request.files.get("document")
    file_bytes = None
    filename = None
    mime = None
    if mode in {"document", "both"}:
        if not doc or not doc.filename:
            raise ValueError("Upload a photo, CSV, PDF, or video for document encryption.")
        ok, mime, err = classify_document(doc.filename, doc.mimetype)
        if not ok:
            raise ValueError(err)
        try:
            doc.stream.seek(0)
        except Exception:
            pass
        file_bytes = doc.read()
        if not file_bytes:
            raise ValueError("The uploaded document is empty.")
        if len(file_bytes) > MAX_DOCUMENT_BYTES:
            raise ValueError(
                f"Document is too large ({len(file_bytes)} bytes). Maximum is {MAX_DOCUMENT_BYTES} bytes."
            )
        filename = Path(doc.filename).name
    if mode in {"text", "both"} and not text:
        raise ValueError("Message text is required for this encryption mode.")
    if mode == "document":
        text = ""
    payload = ContentPayload(
        mode=mode,
        text=text,
        filename=filename,
        mime=mime,
        file_bytes=file_bytes,
    )
    return pack_payload(payload), preview_text(payload)


def persist_download(payload: ContentPayload) -> dict:
    view = {
        "mode": payload.mode,
        "text": payload.text,
        "filename": payload.filename,
        "mime": payload.mime,
        "has_file": payload.has_file,
        "has_text": payload.has_text,
        "file_size": len(payload.file_bytes or b""),
        "is_image": bool(payload.mime and payload.mime.startswith("image/")),
        "is_video": bool(payload.mime and payload.mime.startswith("video/")),
        "is_pdf": payload.mime == "application/pdf",
        "token": None,
        "preview": preview_text(payload),
    }
    if payload.has_file and payload.filename:
        token = uuid.uuid4().hex
        safe = Path(payload.filename).name.replace("..", "")
        path = DOWNLOAD_DIR / f"{token}_{safe}"
        path.write_bytes(payload.file_bytes or b"")
        view["token"] = token
        view["path"] = str(path)
    return view


def save_upload(file: FileStorage, prefix: str) -> str:
    ext = Path(file.filename or "img.png").suffix or ".png"
    if ext.lower() not in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}:
        ext = ".png"
    name = f"{prefix}_{uuid.uuid4().hex}{ext}"
    path = UPLOAD_DIR / name
    try:
        file.stream.seek(0)
    except Exception:
        pass
    file.save(path)
    return str(path)


def reject_decryptor_face_live(request: Request, prefix: str) -> None:
    """Decryptor registration: face must be an uploaded image, never live capture."""
    source = (request.form.get(f"{prefix}face_source") or "").strip().lower()
    live_raw = (request.form.get(f"{prefix}face_live") or "").strip()
    if source == "live" or (live_raw and source != "upload"):
        from qsbas.biometric_validation import BiometricValidationError

        raise BiometricValidationError(
            "Decryptor face registration accepts image upload only (live capture is not allowed).",
            "face",
        )


def _file_from_data_url(data_url: str, filename: str) -> Optional[FileStorage]:
    raw = data_url.strip()
    if not raw:
        return None
    if "," in raw and raw.lower().startswith("data:"):
        raw = raw.split(",", 1)[1]
    try:
        payload = base64.b64decode(raw)
    except Exception:
        return None
    if not payload:
        return None
    return FileStorage(stream=io.BytesIO(payload), filename=filename, content_type="image/png")


def resolve_biometric_file(request: Request, field_name: str) -> Optional[FileStorage]:
    """Upload XOR live capture. Explicit source wins; otherwise most recently indicated."""
    source = (request.form.get(f"{field_name}_source") or "").strip().lower()
    live_raw = (request.form.get(f"{field_name}_live") or "").strip()
    uploaded = request.files.get(field_name)
    has_upload = bool(uploaded and uploaded.filename)
    live_file = _file_from_data_url(live_raw, f"{field_name}_live.png") if live_raw else None

    if source == "live" and live_file:
        return live_file
    if source == "upload" and has_upload:
        return uploaded
    if live_file and has_upload:
        return live_file if source != "upload" else uploaded
    return live_file or (uploaded if has_upload else None)


def resolve_prefixed_biometrics(
    request: Request, prefix: str
) -> tuple[Optional[FileStorage], Optional[FileStorage]]:
    fp = resolve_biometric_file(request, f"{prefix}fingerprint")
    face = resolve_biometric_file(request, f"{prefix}face")
    return fp, face


def probe_from_fingerprint(
    fp_file: Optional[FileStorage] = None,
    face_file: Optional[FileStorage] = None,
    require_face: bool = False,
    require_fingerprint: bool = False,
) -> tuple[BiometricProfile, dict]:
    """Build a biometric probe from uploads only (no declared identity)."""
    return profile_from_form(
        "_probe_",
        fp_file,
        face_file,
        require_face=require_face,
        require_fingerprint=require_fingerprint,
    )


def profile_from_form(
    name: str,
    fp_file: Optional[FileStorage] = None,
    face_file: Optional[FileStorage] = None,
    is_encryptor: bool = False,
    require_face: bool = False,
    require_fingerprint: bool = False,
) -> tuple[BiometricProfile, dict]:
    if not fp_file and not face_file:
        from qsbas.biometric_validation import BiometricValidationError

        raise BiometricValidationError("Provide a fingerprint, a face, or both.", "fingerprint")
    fp_path = save_upload(fp_file, "fp") if fp_file else None
    face_path = save_upload(face_file, "face") if face_file else None
    profile = build_profile(
        name,
        fingerprint_path=fp_path,
        face_path=face_path,
        is_encryptor=is_encryptor,
        require_face=require_face,
        require_fingerprint=require_fingerprint,
    )
    meta = {
        "fp_path": fp_path,
        "iris_path": None,
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
    import base64 as b64mod

    return b64mod.b64encode(buf).decode("ascii")


def _fingerprint_analysis_block(fp_path: str | None, profile: BiometricProfile) -> dict | None:
    if not fp_path or not Path(fp_path).is_file():
        return None
    image = load_fingerprint(fp_path)
    minutiae = profile.fingerprint_minutiae[:MINUTIAE_COUNT]
    return {
        "original_b64": image_to_b64(image),
        "preprocessed_b64": preprocessed_b64(image),
        "overlay_b64": minutiae_overlay_base64(image, minutiae, "32 Fingerprint Minutiae"),
        "feature_count": len(minutiae),
        "feature_label": "32 Fingerprint Minutiae Extracted",
        "quality": round(quality_score(image), 1),
    }


def _face_analysis_block(face_path: str | None, profile: BiometricProfile) -> dict | None:
    if not face_path or not Path(face_path).is_file():
        return None
    image = load_fingerprint(face_path)
    analysis = analyze_face(image)
    landmarks = profile.face_minutiae[:FACE_LANDMARK_COUNT]
    bbox = analysis.bbox if analysis else (0, 0, image.shape[1], image.shape[0])
    details = analysis.details if analysis else []
    if not details and landmarks:
        x, y, w, h = bbox
        details = [
            {
                "index": i,
                "label": f"Landmark {i}",
                "x": int(x + m.x * w) if 0.0 <= m.x <= 1.5 else int(m.x),
                "y": int(y + m.y * h) if 0.0 <= m.y <= 1.5 else int(m.y),
                "nx": round(m.x, 4),
                "ny": round(m.y, 4),
            }
            for i, m in enumerate(landmarks, start=1)
        ]
    return {
        "original_b64": image_to_b64(image),
        "detection_b64": face_detection_overlay_b64(image, analysis.bbox if analysis else None),
        "overlay_b64": face_landmarks_overlay_b64(image, bbox, landmarks, "32 Facial Landmarks"),
        "feature_count": len(landmarks),
        "feature_label": "32 Facial Landmarks Extracted",
        "details": details,
    }


def dashboard_biometric_panel(
    profile: BiometricProfile,
    fp_path: str | None,
    title: str,
    iris_path: str | None = None,
    face_path: str | None = None,
    session_id: int | None = None,
) -> dict:
    fp_block = _fingerprint_analysis_block(fp_path, profile)
    face_block = _face_analysis_block(face_path, profile)
    overlay = ""
    quality = 0.0
    if fp_block:
        overlay = fp_block["overlay_b64"]
        quality = fp_block["quality"]
    elif face_block:
        overlay = face_block["overlay_b64"]
    enrolled = []
    if profile.has_fingerprint_template:
        enrolled.append("fingerprint")
    if profile.has_face_template:
        enrolled.append("face")
    return {
        "title": title,
        "name": profile.name,
        "minutiae_count": len(profile.cipher_minutiae),
        "quality": quality,
        "hash_hex": (
            profile.session_feature_hash_hex(session_id) if session_id else profile.feature_hash_hex()
        )[:64],
        "image_b64": overlay,
        "has_iris": False,
        "has_face": len(profile.face_minutiae) > 0,
        "iris_b64": None,
        "face_b64": _image_to_b64(face_path),
        "is_encryptor": profile.is_encryptor,
        "fp_analysis": fp_block,
        "face_analysis": face_block,
        "face_landmark_count": len(profile.face_minutiae),
        "enrolled_factors": " and ".join(enrolled) if enrolled else "none",
    }


def build_auth_analysis(
    stored: BiometricProfile,
    probe: BiometricProfile,
    probe_fp_path: str | None,
    probe_face_path: str | None,
    stored_name: str | None = None,
) -> dict:
    report = verification_report(stored, probe)
    return {
        "matched_name": stored_name or stored.name,
        **report,
        "fingerprint": _fingerprint_analysis_block(probe_fp_path, probe),
        "face": _face_analysis_block(probe_face_path, probe),
        "fingerprint_status": (
            "Verified"
            if report["fingerprint_verified"]
            else ("Skipped" if not report.get("fingerprint_enrolled") else "Failed")
        ),
        "face_status": (
            "Verified"
            if report["face_verified"]
            else ("Skipped" if not report.get("face_enrolled") else "Failed")
        ),
        "final_status": "Verified" if report["final_allowed"] else "Denied",
    }
