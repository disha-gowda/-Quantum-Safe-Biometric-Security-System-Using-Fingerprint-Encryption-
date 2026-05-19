"""Render fingerprint images with minutiae overlays for dashboard UI."""

from __future__ import annotations

import base64
from typing import List

import cv2
import numpy as np

from qsbas.fingerprint import Minutia, preprocess_fingerprint


def minutiae_overlay_base64(image: np.ndarray, minutiae: List[Minutia], title: str = "") -> str:
    if len(image.shape) == 2:
        canvas = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
    else:
        canvas = image.copy()

    processed = preprocess_fingerprint(image)
    canvas = cv2.addWeighted(canvas, 0.35, cv2.cvtColor(processed, cv2.COLOR_GRAY2BGR), 0.65, 0)

    for m in minutiae:
        x, y = int(m.x), int(m.y)
        cv2.circle(canvas, (x, y), 5, (0, 255, 180), 1)
        cv2.circle(canvas, (x, y), 2, (0, 200, 255), -1)
        dx = int(x + 12 * np.cos(m.theta))
        dy = int(y + 12 * np.sin(m.theta))
        cv2.line(canvas, (x, y), (dx, dy), (255, 120, 60), 1)

    if title:
        cv2.putText(canvas, title, (8, 22), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (180, 240, 255), 1)

    _, buf = cv2.imencode(".png", canvas)
    return base64.b64encode(buf).decode("ascii")


def quality_score(image: np.ndarray) -> float:
    gray = image if len(image.shape) == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    contrast = float(np.std(gray))
    return min(99.0, max(40.0, 50.0 + contrast / 4.0))
