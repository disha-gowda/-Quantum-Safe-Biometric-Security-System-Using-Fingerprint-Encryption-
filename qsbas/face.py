"""Face detection, 32 facial landmark extraction, and face matching features."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import cv2
import numpy as np

from qsbas.constants import FACE_LANDMARK_COUNT
from qsbas.fingerprint import Minutia

# Deterministic 32-point facial layout as fractions of the detected face box.
# Same indices are used at enrollment and verification.
FACE_LANDMARK_FRACTIONS: Tuple[Tuple[float, float], ...] = (
    (0.22, 0.28),
    (0.30, 0.25),
    (0.38, 0.28),
    (0.62, 0.28),
    (0.70, 0.25),
    (0.78, 0.28),
    (0.28, 0.38),
    (0.35, 0.36),
    (0.42, 0.38),
    (0.58, 0.38),
    (0.65, 0.36),
    (0.72, 0.38),
    (0.50, 0.42),
    (0.50, 0.50),
    (0.46, 0.58),
    (0.54, 0.58),
    (0.38, 0.70),
    (0.45, 0.68),
    (0.50, 0.72),
    (0.55, 0.68),
    (0.62, 0.70),
    (0.50, 0.76),
    (0.30, 0.82),
    (0.50, 0.92),
    (0.70, 0.82),
    (0.12, 0.45),
    (0.15, 0.62),
    (0.22, 0.78),
    (0.88, 0.45),
    (0.85, 0.62),
    (0.78, 0.78),
    (0.50, 0.18),
)

FACE_LANDMARK_LABELS: Tuple[str, ...] = (
    "L brow outer",
    "L brow mid",
    "L brow inner",
    "R brow inner",
    "R brow mid",
    "R brow outer",
    "L eye outer",
    "L eye center",
    "L eye inner",
    "R eye inner",
    "R eye center",
    "R eye outer",
    "Nose bridge",
    "Nose tip",
    "Nose L ala",
    "Nose R ala",
    "Mouth L corner",
    "Upper lip L",
    "Upper lip mid",
    "Upper lip R",
    "Mouth R corner",
    "Lower lip mid",
    "Jaw L",
    "Chin",
    "Jaw R",
    "L cheek high",
    "L cheek mid",
    "L jawline",
    "R cheek high",
    "R cheek mid",
    "R jawline",
    "Forehead center",
)


def _cascade() -> cv2.CascadeClassifier:
    return cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")


def _to_gray(image: np.ndarray) -> np.ndarray:
    if len(image.shape) == 2:
        return image
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


@dataclass
class FaceAnalysis:
    roi: np.ndarray
    landmarks: List[Minutia]
    embedding: List[float]
    bbox: Tuple[int, int, int, int]
    details: List[dict] = field(default_factory=list)


def detect_face_bbox(gray: np.ndarray) -> Optional[Tuple[int, int, int, int]]:
    faces = _cascade().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(48, 48))
    if len(faces) == 0:
        return None
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    return int(x), int(y), int(w), int(h)


def _refine_point(gray: np.ndarray, x: int, y: int, window: int = 5) -> Tuple[int, int]:
    h, w = gray.shape
    x0 = max(1, x - window)
    y0 = max(1, y - window)
    x1 = min(w - 1, x + window + 1)
    y1 = min(h - 1, y + window + 1)
    patch = gray[y0:y1, x0:x1]
    if patch.size == 0:
        return x, y
    gx = cv2.Sobel(patch, cv2.CV_64F, 1, 0, ksize=3)
    gy = cv2.Sobel(patch, cv2.CV_64F, 0, 1, ksize=3)
    mag = np.hypot(gx, gy)
    loc = np.unravel_index(int(np.argmax(mag)), mag.shape)
    return x0 + int(loc[1]), y0 + int(loc[0])


def _patch_descriptor(gray: np.ndarray, x: int, y: int, size: int = 8) -> float:
    h, w = gray.shape
    half = size // 2
    x0, y0 = max(0, x - half), max(0, y - half)
    x1, y1 = min(w, x + half), min(h, y + half)
    patch = gray[y0:y1, x0:x1]
    if patch.size == 0:
        return 0.0
    mean = float(np.mean(patch)) / 255.0
    std = float(np.std(patch)) / 128.0
    gx = float(np.mean(np.abs(cv2.Sobel(patch, cv2.CV_64F, 1, 0, ksize=3)))) / 255.0
    packed = (mean * 0.45 + min(std, 1.0) * 0.35 + min(gx, 1.0) * 0.20)
    return float(packed)


def _lbp_histogram(roi: np.ndarray, bins: int = 256) -> List[float]:
    img = cv2.resize(roi, (64, 64), interpolation=cv2.INTER_AREA)
    h, w = img.shape
    lbp = np.zeros((h - 2, w - 2), dtype=np.uint8)
    center = img[1:-1, 1:-1]
    offsets = ((-1, -1), (-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1))
    for i, (dy, dx) in enumerate(offsets):
        neighbor = img[1 + dy : h - 1 + dy, 1 + dx : w - 1 + dx]
        lbp |= ((neighbor >= center).astype(np.uint8) << i)
    hist, _ = np.histogram(lbp.ravel(), bins=bins, range=(0, bins))
    hist = hist.astype(np.float64)
    hist /= hist.sum() + 1e-9
    return [float(v) for v in hist]


def _select_32_landmarks(
    gray: np.ndarray, bbox: Tuple[int, int, int, int]
) -> Tuple[List[Minutia], List[dict]]:
    x, y, w, h = bbox
    landmarks: List[Minutia] = []
    details: List[dict] = []
    for idx, (fx, fy) in enumerate(FACE_LANDMARK_FRACTIONS[:FACE_LANDMARK_COUNT], start=1):
        px = int(x + fx * w)
        py = int(y + fy * h)
        rx, ry = _refine_point(gray, px, py)
        nx = (rx - x) / max(w, 1)
        ny = (ry - y) / max(h, 1)
        desc = _patch_descriptor(gray, rx, ry)
        landmarks.append(Minutia(float(nx), float(ny), float(desc)))
        label = FACE_LANDMARK_LABELS[idx - 1] if idx - 1 < len(FACE_LANDMARK_LABELS) else f"Point {idx}"
        details.append(
            {
                "index": idx,
                "label": label,
                "x": int(rx),
                "y": int(ry),
                "nx": round(nx, 4),
                "ny": round(ny, 4),
                "descriptor": round(desc, 4),
            }
        )
    return landmarks[:FACE_LANDMARK_COUNT], details


def _grid_texture(roi: np.ndarray, cells: int = 8) -> List[float]:
    img = cv2.resize(roi, (cells, cells), interpolation=cv2.INTER_AREA)
    return [float(v) / 255.0 for v in img.astype(np.float64).ravel()]


def analyze_face(image: np.ndarray) -> Optional[FaceAnalysis]:
    gray = _to_gray(image)
    bbox = detect_face_bbox(gray)
    if bbox is None:
        faces = _cascade().detectMultiScale(
            gray, scaleFactor=1.05, minNeighbors=3, minSize=(36, 36)
        )
        if len(faces) == 0:
            return None
        x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
        bbox = (int(x), int(y), int(w), int(h))
    x, y, w, h = bbox
    pad = max(4, w // 8)
    ex = max(0, x - pad)
    ey = max(0, y - pad)
    ew = min(gray.shape[1] - ex, w + 2 * pad)
    eh = min(gray.shape[0] - ey, h + 2 * pad)
    roi = gray[ey : ey + eh, ex : ex + ew]
    if roi.size == 0:
        return None
    roi_resized = cv2.resize(roi, (64, 64), interpolation=cv2.INTER_AREA)
    landmarks, details = _select_32_landmarks(gray, bbox)
    embedding = (
        _lbp_histogram(roi_resized)
        + _grid_texture(roi_resized)
        + [float(m.theta) for m in landmarks[:FACE_LANDMARK_COUNT]]
    )
    return FaceAnalysis(
        roi=roi_resized,
        landmarks=landmarks,
        embedding=embedding,
        bbox=bbox,
        details=details,
    )


def extract_face_features(image: np.ndarray) -> Tuple[Optional[np.ndarray], List[Minutia]]:
    analysis = analyze_face(image)
    if analysis is None:
        return None, []
    return analysis.roi, analysis.landmarks[:FACE_LANDMARK_COUNT]


def embedding_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    va = np.asarray(a, dtype=np.float64)
    vb = np.asarray(b, dtype=np.float64)
    n = min(len(va), len(vb))
    if n == 0:
        return 0.0
    va, vb = va[:n], vb[:n]
    denom = float(np.linalg.norm(va) * np.linalg.norm(vb))
    if denom < 1e-12:
        return 0.0
    return float(np.clip(np.dot(va, vb) / denom, 0.0, 1.0))
