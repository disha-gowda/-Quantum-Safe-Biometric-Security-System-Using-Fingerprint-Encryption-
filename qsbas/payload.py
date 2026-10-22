"""Binary envelope so QSBAC can encrypt text, documents, or both."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MAGIC = b"QSBACDOC1"
HEADER_LEN_STRUCT = struct.Struct(">I")

MAX_DOCUMENT_BYTES = 12 * 1024 * 1024

DOCUMENT_EXTENSIONS = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".pdf": "application/pdf",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska",
    ".mpeg": "video/mpeg",
    ".mpg": "video/mpeg",
}

MODES = ("text", "document", "both")


@dataclass
class ContentPayload:
    mode: str
    text: str
    filename: Optional[str] = None
    mime: Optional[str] = None
    file_bytes: Optional[bytes] = None

    @property
    def has_file(self) -> bool:
        return bool(self.file_bytes)

    @property
    def has_text(self) -> bool:
        return bool(self.text and self.text.strip())


def classify_document(filename: str, declared_mime: str | None = None) -> tuple[bool, str, str]:
    ext = Path(filename or "").suffix.lower()
    mime = DOCUMENT_EXTENSIONS.get(ext)
    if not mime:
        return False, "", f"Unsupported document type '{ext}'. Use a photo, CSV, PDF, or video."
    if declared_mime and declared_mime.startswith("image/") and not mime.startswith("image/"):
        return False, mime, "File type does not match the selected photo."
    return True, mime, ""


def preview_text(payload: ContentPayload) -> str:
    if payload.mode == "document":
        name = payload.filename or "document"
        size = len(payload.file_bytes or b"")
        return f"[document] {name} ({size} bytes)"
    if payload.mode == "both":
        name = payload.filename or "document"
        body = payload.text.strip()
        return f"{body}\n[document] {name}" if body else f"[document] {name}"
    return payload.text


def pack_payload(payload: ContentPayload) -> bytes:
    mode = payload.mode if payload.mode in MODES else "text"
    header = {
        "mode": mode,
        "text": payload.text or "",
        "filename": payload.filename or "",
        "mime": payload.mime or "",
        "size": len(payload.file_bytes or b""),
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    blob = MAGIC + HEADER_LEN_STRUCT.pack(len(header_bytes)) + header_bytes
    if payload.file_bytes:
        blob += payload.file_bytes
    return blob


def unpack_payload(raw: bytes) -> ContentPayload:
    if not raw.startswith(MAGIC):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        return ContentPayload(mode="text", text=text)

    offset = len(MAGIC)
    if len(raw) < offset + HEADER_LEN_STRUCT.size:
        raise ValueError("Encrypted document header is truncated")
    (header_len,) = HEADER_LEN_STRUCT.unpack(raw[offset : offset + HEADER_LEN_STRUCT.size])
    offset += HEADER_LEN_STRUCT.size
    header = json.loads(raw[offset : offset + header_len].decode("utf-8"))
    offset += header_len
    file_bytes = raw[offset:]
    expected = int(header.get("size") or 0)
    if expected and len(file_bytes) != expected:
        file_bytes = file_bytes[:expected] if expected <= len(file_bytes) else file_bytes
    mode = header.get("mode") or "text"
    if mode not in MODES:
        mode = "text"
    filename = header.get("filename") or None
    mime = header.get("mime") or None
    if not file_bytes:
        file_bytes = None
        filename = filename if filename else None
    return ContentPayload(
        mode=mode,
        text=header.get("text") or "",
        filename=filename or None,
        mime=mime or None,
        file_bytes=file_bytes,
    )


def replace_text(payload: ContentPayload, new_text: str) -> ContentPayload:
    text = (new_text or "").strip()
    if payload.has_file and text:
        mode = "both"
    elif payload.has_file:
        mode = "document"
    else:
        mode = "text"
        if not text:
            raise ValueError("Message text is required")
    return ContentPayload(
        mode=mode,
        text=text,
        filename=payload.filename,
        mime=payload.mime,
        file_bytes=payload.file_bytes,
    )
