"""Modules 1–2: fingerprint preprocessing and minutiae extraction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import cv2
import numpy as np

from qsbas.constants import MIN_GENUINE_MINUTIAE, MINUTIAE_COUNT


@dataclass
class Minutia:
    x: float
    y: float
    theta: float


def load_fingerprint(path: str) -> np.ndarray:
    image = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise ValueError(f"Could not read fingerprint image: {path}")
    return image


def normalize_image(image: np.ndarray) -> np.ndarray:
    mu = float(np.mean(image))
    sigma = float(np.std(image))
    if sigma < 1e-6:
        sigma = 1.0
    normalized = (image.astype(np.float64) - mu) / sigma
    normalized = np.clip(normalized, -3.0, 3.0)
    normalized = ((normalized + 3.0) / 6.0 * 255.0).astype(np.uint8)
    return normalized


def remove_noise(image: np.ndarray) -> np.ndarray:
    return cv2.GaussianBlur(image, (3, 3), 0)


def enhance_ridges(image: np.ndarray) -> np.ndarray:
    kernel = cv2.getGaussianKernel(9, 3.0)
    kernel2d = kernel @ kernel.T
    enhanced = cv2.filter2D(image, cv2.CV_64F, kernel2d)
    enhanced = cv2.normalize(enhanced, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    return enhanced


def binarize(image: np.ndarray) -> np.ndarray:
    return cv2.adaptiveThreshold(
        image, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2
    )


def thin_binary(binary: np.ndarray) -> np.ndarray:
    skeleton = np.zeros(binary.shape, np.uint8)
    element = cv2.getStructuringElement(cv2.MORPH_CROSS, (3, 3))
    img = binary.copy()
    while True:
        eroded = cv2.erode(img, element)
        temp = cv2.dilate(eroded, element)
        temp = cv2.subtract(img, temp)
        skeleton = cv2.bitwise_or(skeleton, temp)
        img = eroded.copy()
        if cv2.countNonZero(img) == 0:
            break
    return skeleton


def preprocess_fingerprint(image: np.ndarray) -> np.ndarray:
    gray = image if len(image.shape) == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = remove_noise(gray)
    gray = normalize_image(gray)
    gray = enhance_ridges(gray)
    return gray


def _neighbors(skeleton: np.ndarray, x: int, y: int) -> int:
    h, w = skeleton.shape
    count = 0
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            if dx == 0 and dy == 0:
                continue
            ny, nx = y + dy, x + dx
            if 0 <= ny < h and 0 <= nx < w and skeleton[ny, nx] > 0:
                count += 1
    return count


def _crossing_number(skeleton: np.ndarray, x: int, y: int) -> int:
    h, w = skeleton.shape
    pixels = []
    for dy, dx in [(-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1), (-1, -1)]:
        ny, nx = y + dy, x + dx
        if 0 <= ny < h and 0 <= nx < w:
            pixels.append(1 if skeleton[ny, nx] > 0 else 0)
        else:
            pixels.append(0)
    cn = 0
    for i in range(8):
        cn += abs(pixels[i] - pixels[(i + 1) % 8])
    return cn // 2


def _collect_genuine_minutiae(
    processed: np.ndarray, skeleton: np.ndarray, max_scan: int = 128
) -> List[Minutia]:
    minutiae: List[Minutia] = []
    h, w = skeleton.shape
    step = max(2, min(h, w) // 128)
    for y in range(1, h - 1, step):
        for x in range(1, w - 1, step):
            if skeleton[y, x] == 0:
                continue
            cn = _crossing_number(skeleton, x, y)
            neighbors = _neighbors(skeleton, x, y)
            if (cn == 1 and neighbors == 1) or (cn == 3 and neighbors == 3):
                patch = processed[max(0, y - 2) : y + 3, max(0, x - 2) : x + 3]
                gx = cv2.Sobel(patch, cv2.CV_64F, 1, 0, ksize=3)
                gy = cv2.Sobel(patch, cv2.CV_64F, 0, 1, ksize=3)
                theta = float(np.arctan2(gy.mean(), gx.mean()))
                minutiae.append(Minutia(float(x), float(y), theta))
                if len(minutiae) >= max_scan:
                    return minutiae
    return minutiae


def _pad_minutiae_from_genuine(genuine: List[Minutia], max_points: int, w: int, h: int) -> List[Minutia]:
    if not genuine:
        return []
    out = list(genuine)
    idx = 0
    while len(out) < max_points:
        base = genuine[idx % len(genuine)]
        out.append(
            Minutia(
                base.x + (len(out) % 5) * 0.7,
                base.y + (len(out) % 7) * 0.5,
                base.theta,
            )
        )
        idx += 1
    if len(out) > max_points:
        step = len(out) / max_points
        out = [out[int(i * step)] for i in range(max_points)]
    return out[:max_points]


def extract_minutiae(image: np.ndarray, max_points: int = MINUTIAE_COUNT) -> List[Minutia]:
    processed = preprocess_fingerprint(image)
    skeleton = thin_binary(binarize(processed))
    h, w = skeleton.shape
    genuine = _collect_genuine_minutiae(processed, skeleton, max_scan=96)

    if len(genuine) < MIN_GENUINE_MINUTIAE:
        from qsbas.biometric_validation import BiometricValidationError

        raise BiometricValidationError(
            f"Invalid input: Only {len(genuine)} genuine minutiae found; use a clear fingerprint scan.",
            "fingerprint",
        )

    return _pad_minutiae_from_genuine(genuine, max_points, w, h)


def fingerprint_feature_vector(image: np.ndarray) -> Tuple[List[Minutia], np.ndarray]:
    minutiae = extract_minutiae(image)
    return minutiae, preprocess_fingerprint(image)
