"""Test biometric validation: sample FP passes, text image fails."""

import sys
from pathlib import Path

import cv2
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.biometric_validation import validate_fingerprint, validate_file

fp = ROOT / "data" / "sample_fingerprint.png"
text_img = ROOT / "data" / "_test_text.png"

if not fp.exists():
    print("Generate sample fingerprint first.")
    sys.exit(1)

canvas = np.ones((400, 600), dtype=np.uint8) * 240
cv2.putText(canvas, "QUANTUM RANDOM", (40, 120), cv2.FONT_HERSHEY_SIMPLEX, 1.2, 0, 2)
cv2.putText(canvas, "NOT A FINGERPRINT", (40, 220), cv2.FONT_HERSHEY_SIMPLEX, 1.0, 0, 2)
cv2.imwrite(str(text_img), canvas)

r1 = validate_file(str(fp), "fingerprint")
r2 = validate_fingerprint(canvas)
print("Sample FP:", r1.valid, r1.message)
print("Text img:", r2.valid, r2.message)
assert r1.valid, "sample fingerprint should pass"
assert not r2.valid, "text screenshot should fail"
print("All validation tests passed.")
