"""Iris / eye-region feature extraction."""

from __future__ import annotations

from typing import List, Optional, Tuple

import cv2
import numpy as np

from qsbas.fingerprint import Minutia


def _eye_cascade() -> cv2.CascadeClassifier:
    return cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml")


def extract_iris_features(image: np.ndarray) -> Tuple[Optional[np.ndarray], List[Minutia]]:
    gray = image if len(image.shape) == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    eyes = _eye_cascade().detectMultiScale(gray, scaleFactor=1.08, minNeighbors=6, minSize=(24, 24))
    if len(eyes) == 0:
        return None, []

    regions = sorted(eyes, key=lambda e: e[0])[:2]
    minutiae: List[Minutia] = []
    patches = []
    for x, y, w, h in regions:
        pad = max(2, w // 6)
        ex = max(0, x - pad)
        ey = max(0, y - pad)
        ew = min(gray.shape[1] - ex, w + 2 * pad)
        eh = min(gray.shape[0] - ey, h + 2 * pad)
        roi = gray[ey : ey + eh, ex : ex + ew]
        roi = cv2.resize(roi, (48, 48))
        patches.append(roi)
        cx, cy = ex + ew / 2, ey + eh / 2
        for ring in range(3):
            r = (ring + 1) * ew / 8
            for a in range(4):
                theta = a * 1.57
                minutiae.append(
                    Minutia(cx + r * np.cos(theta), cy + r * np.sin(theta), float(np.mean(roi) / 255))
                )
    combined = patches[0] if patches else None
    return combined, minutiae[:8]
