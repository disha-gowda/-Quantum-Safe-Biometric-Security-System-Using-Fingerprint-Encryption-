"""Generate a synthetic ridge-pattern fingerprint image for testing."""

from __future__ import annotations

import math
from pathlib import Path

import cv2
import numpy as np


def generate(path: str, size: int = 256) -> None:
    y, x = np.mgrid[0:size, 0:size]
    angle = 0.4
    ridges = np.sin(
        (x * math.cos(angle) + y * math.sin(angle)) * 0.22
        + np.sin(x * 0.03) * 2.0
    )
    image = ((ridges + 1) * 0.5 * 200 + 30).astype(np.uint8)
    noise = np.random.randint(0, 12, (size, size), dtype=np.uint8)
    image = np.clip(image.astype(np.int16) + noise, 0, 255).astype(np.uint8)
    cv2.imwrite(path, image)
    print(f"Wrote sample fingerprint: {path}")


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "sample_fingerprint.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    generate(str(out))
