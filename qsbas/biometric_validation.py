"""Reject non-biometric uploads (screenshots, text, random photos)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import cv2
import numpy as np

from qsbas.fingerprint import (
    binarize,
    preprocess_fingerprint,
    thin_binary,
    _crossing_number,
    _neighbors,
)
from qsbas.face import _cascade as face_cascade
from qsbas.iris import _eye_cascade


class BiometricValidationError(ValueError):
    def __init__(self, message: str, modality: str = "fingerprint"):
        self.modality = modality
        super().__init__(message)


@dataclass
class ValidationResult:
    valid: bool
    message: str
    score: float = 0.0


def _to_gray(image: np.ndarray) -> np.ndarray:
    if len(image.shape) == 2:
        return image
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


def count_genuine_minutiae(image: np.ndarray) -> int:
    """Count ridge endings / bifurcations without synthetic padding."""
    processed = preprocess_fingerprint(image)
    skeleton = thin_binary(binarize(processed))
    h, w = skeleton.shape
    step = max(2, min(h, w) // 128)
    count = 0
    for y in range(1, h - 1, step):
        for x in range(1, w - 1, step):
            if skeleton[y, x] == 0:
                continue
            cn = _crossing_number(skeleton, x, y)
            nb = _neighbors(skeleton, x, y)
            if (cn == 1 and nb == 1) or (cn == 3 and nb == 3):
                count += 1
    return count


def _count_letter_components(gray: np.ndarray) -> int:
    """Isolated letter-like blobs typical of text/screenshots."""
    _, bw = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    num, _labels, stats, _ = cv2.connectedComponentsWithStats(bw)
    letters = 0
    for i in range(1, num):
        _x, _y, w, h, area = stats[i]
        if (
            8 <= h <= 120
            and 4 <= w <= 100
            and 0.12 <= w / max(h, 1) <= 1.5
            and 30 <= area <= 2500
        ):
            letters += 1
    return letters


def _text_line_score(gray: np.ndarray) -> float:
    """Morphological horizontal/vertical line density (ridge prints score lower)."""
    h, w = gray.shape
    inv = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 15, 4
    )
    horiz = cv2.morphologyEx(
        inv, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (max(25, w // 20), 1))
    )
    vert = cv2.morphologyEx(
        inv, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (1, max(15, h // 25)))
    )
    area = float(h * w)
    return (cv2.countNonZero(horiz) + cv2.countNonZero(vert)) / max(area, 1.0)


def _flat_region_fraction(gray: np.ndarray, block: int = 32, var_thresh: float = 22.0) -> float:
    """Share of image blocks with near-uniform intensity (app UI / screenshots)."""
    h, w = gray.shape
    if h < block or w < block:
        return 0.0
    flat = 0
    total = 0
    for y in range(0, h - block + 1, block):
        for x in range(0, w - block + 1, block):
            patch = gray[y : y + block, x : x + block]
            total += 1
            if float(np.std(patch)) < var_thresh:
                flat += 1
    return flat / max(total, 1)


def _color_ui_score(image: np.ndarray) -> float:
    """Low unique-color ratio suggests flat UI screenshots, not skin/ridges."""
    if len(image.shape) < 3:
        return 1.0
    small = cv2.resize(image, (96, 96), interpolation=cv2.INTER_AREA)
    pixels = small.reshape(-1, 3)
    packed = pixels.view(np.dtype((np.void, pixels.dtype.itemsize * pixels.shape[1])))
    return len(np.unique(packed)) / max(len(packed), 1)


def _ridge_orientation_coherence(gray: np.ndarray) -> float:
    gx = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
    gy = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
    gxx = cv2.GaussianBlur(gx * gx, (5, 5), 0)
    gyy = cv2.GaussianBlur(gy * gy, (5, 5), 0)
    gxy = cv2.GaussianBlur(gx * gy, (5, 5), 0)
    trace = gxx + gyy + 1e-6
    diff = gxx - gyy
    coherence = np.sqrt(diff * diff + 4.0 * gxy * gxy) / trace
    mask = trace > np.percentile(trace, 40)
    if not np.any(mask):
        return 0.0
    return float(np.mean(coherence[mask]))


def _reject_screenshot_ui(image: np.ndarray, gray: np.ndarray) -> Optional[ValidationResult]:
    """Common checks for app/window screenshots uploaded by mistake."""
    flat_frac = _flat_region_fraction(gray)
    color_score = _color_ui_score(image)
    letter_count = _count_letter_components(gray)

    if letter_count >= 6:
        return ValidationResult(
            False,
            "Screenshot or text detected. Upload a fingerprint scan only.",
            float(letter_count),
        )

    if flat_frac > 0.5 and color_score < 0.2:
        return ValidationResult(
            False,
            "Image looks like a screen capture (flat UI regions), not a fingerprint.",
            flat_frac,
        )

    line_score = _text_line_score(gray)
    if line_score > 0.28 and letter_count >= 5:
        return ValidationResult(
            False,
            "Document or screenshot layout detected. Use a fingerprint image only.",
            line_score,
        )
    if line_score > 0.22 and flat_frac > 0.4 and letter_count >= 3:
        return ValidationResult(
            False,
            "Document or screenshot layout detected. Use a fingerprint image only.",
            line_score,
        )

    return None


def validate_fingerprint(image: np.ndarray) -> ValidationResult:
    gray = _to_gray(image)
    h, w = gray.shape

    if h < 80 or w < 80:
        return ValidationResult(False, "Fingerprint image is too small (minimum 80×80 pixels).", 0.0)

    screenshot = _reject_screenshot_ui(image, gray)
    if screenshot:
        return screenshot

    contrast = float(np.std(gray))
    if contrast < 14.0:
        return ValidationResult(False, "Image has too little contrast for a fingerprint.", 0.0)

    letter_count = _count_letter_components(gray)
    if letter_count >= 8:
        return ValidationResult(
            False,
            "This looks like text or a screenshot, not a fingerprint. Upload a ridge-pattern fingerprint scan.",
            float(letter_count),
        )

    line_score = _text_line_score(gray)
    if line_score > 0.28 and letter_count >= 4:
        return ValidationResult(
            False,
            "Image contains document-like line structures, not a fingerprint.",
            line_score,
        )

    processed = preprocess_fingerprint(gray)
    skeleton = thin_binary(binarize(processed))
    ridge_ratio = cv2.countNonZero(skeleton) / float(h * w)
    if ridge_ratio < 0.008:
        return ValidationResult(
            False,
            "No ridge pattern detected. Please upload a clear fingerprint image.",
            ridge_ratio,
        )
    if ridge_ratio > 0.48:
        return ValidationResult(
            False,
            "Ridge density is abnormal for a fingerprint (image may be noise or corrupted).",
            ridge_ratio,
        )

    coherence = _ridge_orientation_coherence(processed)
    if coherence < 0.22:
        return ValidationResult(
            False,
            "Image lacks oriented ridge flow required for fingerprint biometrics.",
            coherence,
        )

    genuine = count_genuine_minutiae(gray)
    if genuine < 8:
        return ValidationResult(
            False,
            f"Insufficient fingerprint minutiae detected ({genuine} found, need at least 8). "
            "Use a higher-quality fingerprint scan.",
            float(genuine),
        )

    faces = face_cascade().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(72, 72))
    if len(faces) > 0:
        largest = max(faces, key=lambda f: f[2] * f[3])
        face_area = largest[2] * largest[3]
        if face_area > 0.03 * h * w or (ridge_ratio < 0.08 and genuine < 14):
            return ValidationResult(
                False,
                "A face was detected. Use the Face field for face photos, not Fingerprint.",
                0.0,
            )

    eyes = _eye_cascade().detectMultiScale(gray, scaleFactor=1.08, minNeighbors=5, minSize=(24, 24))
    if len(eyes) > 0 and ridge_ratio < 0.05 and genuine < 10:
        return ValidationResult(
            False,
            "An eye/iris region was detected. Use the Iris field for eye photos, not Fingerprint.",
            0.0,
        )

    score = min(1.0, (genuine / 20.0) * 0.4 + coherence * 0.35 + min(ridge_ratio * 8, 0.25))
    return ValidationResult(True, "Valid fingerprint image.", score)


def validate_iris(image: np.ndarray) -> ValidationResult:
    gray = _to_gray(image)
    h, w = gray.shape
    if h < 60 or w < 60:
        return ValidationResult(False, "Iris/eye image is too small.", 0.0)

    screenshot = _reject_screenshot_ui(image, gray)
    if screenshot:
        return ValidationResult(False, screenshot.message.replace("fingerprint", "iris/eye"), screenshot.score)

    eyes = _eye_cascade().detectMultiScale(gray, scaleFactor=1.08, minNeighbors=5, minSize=(20, 20))
    if len(eyes) == 0:
        return ValidationResult(
            False,
            "No eye region detected. Upload a close-up iris or eye photo.",
            0.0,
        )

    largest = max(eyes, key=lambda e: e[2] * e[3])
    x, y, ew, eh = largest
    eye_area = ew * eh
    if eye_area < 0.008 * h * w:
        return ValidationResult(False, "Eyes are too small in the frame. Use a closer iris/eye capture.", 0.0)

    if _count_letter_components(gray) >= 8:
        return ValidationResult(False, "Iris image appears to be a document or screenshot.", 0.0)

    genuine = count_genuine_minutiae(gray)
    if genuine >= 12 and len(eyes) == 0:
        return ValidationResult(
            False,
            "Ridge pattern detected instead of an eye. Use the Fingerprint field for prints.",
            float(genuine),
        )

    return ValidationResult(True, "Valid iris/eye image.", min(1.0, eye_area / (h * w) * 20))


def validate_face(image: np.ndarray) -> ValidationResult:
    gray = _to_gray(image)
    h, w = gray.shape
    if h < 80 or w < 80:
        return ValidationResult(False, "Face image is too small.", 0.0)

    screenshot = _reject_screenshot_ui(image, gray)
    if screenshot:
        return ValidationResult(False, screenshot.message.replace("fingerprint", "face"), screenshot.score)

    faces = face_cascade().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(48, 48))
    if len(faces) == 0:
        return ValidationResult(
            False,
            "No face detected. Upload a clear frontal face photo.",
            0.0,
        )

    x, y, fw, fh = max(faces, key=lambda f: f[2] * f[3])
    face_area = fw * fh
    if face_area < 0.04 * h * w:
        return ValidationResult(False, "Face is too small. Move closer or crop to the face.", 0.0)

    if _count_letter_components(gray) >= 8:
        return ValidationResult(False, "Face image appears to be a document or screenshot.", 0.0)

    processed = preprocess_fingerprint(gray)
    skeleton = thin_binary(binarize(processed))
    ridge_ratio = cv2.countNonZero(skeleton) / float(h * w)
    genuine = count_genuine_minutiae(gray)
    if genuine >= 14 and ridge_ratio > 0.02 and face_area < 0.12 * h * w:
        return ValidationResult(
            False,
            "Fingerprint ridge pattern detected. Use the Fingerprint field for prints.",
            float(genuine),
        )

    return ValidationResult(True, "Valid face image.", min(1.0, face_area / (h * w) * 5))


def validate_modality(image: np.ndarray, modality: str) -> ValidationResult:
    if modality == "fingerprint":
        return validate_fingerprint(image)
    if modality == "iris":
        return validate_iris(image)
    if modality == "face":
        return validate_face(image)
    return ValidationResult(False, f"Unknown modality: {modality}", 0.0)


def validate_file(path: str, modality: str) -> ValidationResult:
    image = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        return ValidationResult(False, f"Could not read image file: {path}", 0.0)
    return validate_modality(image, modality)


def require_valid_file(path: str, modality: str) -> None:
    result = validate_file(path, modality)
    if not result.valid:
        raise BiometricValidationError(f"Invalid input: {result.message}", modality)
