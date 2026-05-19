"""Face region feature extraction (OpenCV Haar cascade)."""

from __future__ import annotations

from typing import List, Optional, Tuple

import cv2
import numpy as np

from qsbas.fingerprint import Minutia


def _cascade() -> cv2.CascadeClassifier:
    path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    return cv2.CascadeClassifier(path)


def extract_face_features(image: np.ndarray) -> Tuple[Optional[np.ndarray], List[Minutia]]:
    gray = image if len(image.shape) == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    faces = _cascade().detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(48, 48))
    if len(faces) == 0:
        return None, []

    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    roi = gray[y : y + h, x : x + w]
    roi = cv2.resize(roi, (64, 64))

    grid = 4
    minutiae: List[Minutia] = []
    step_x, step_y = w / grid, h / grid
    for gy in range(grid):
        for gx in range(grid):
            cell = roi[gy * 16 : (gy + 1) * 16, gx * 16 : (gx + 1) * 16]
            intensity = float(np.mean(cell))
            angle = float(np.std(cell)) / 128.0
            minutiae.append(
                Minutia(x + gx * step_x + step_x / 2, y + gy * step_y + step_y / 2, angle * 3.14)
            )
    return roi, minutiae[:8]
