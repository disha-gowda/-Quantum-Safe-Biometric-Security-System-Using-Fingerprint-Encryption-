"""Ensure UI-like screenshots fail fingerprint validation."""

import sys
from pathlib import Path

import cv2
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.biometric_validation import validate_fingerprint, validate_file

fp = ROOT / "data" / "sample_fingerprint.png"
assert fp.exists(), "Run generate_sample_fingerprint.py first"

# Dark UI screenshot similar to the app chat screen
ui = np.zeros((400, 700, 3), dtype=np.uint8)
ui[:] = (20, 28, 48)
cv2.rectangle(ui, (30, 30), (670, 120), (30, 40, 60), -1)
cv2.putText(ui, "secure-chat  #1", (50, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (230, 235, 245), 2)
cv2.putText(ui, "Encryptor: ABC", (50, 160), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (180, 190, 210), 1)
cv2.putText(ui, "Hello", (50, 240), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (255, 255, 255), 2)

r_fp = validate_file(str(fp), "fingerprint")
r_ui = validate_fingerprint(ui)

print("Real fingerprint:", r_fp.valid, r_fp.message)
print("UI screenshot:", r_ui.valid, r_ui.message)
assert r_fp.valid, "sample fingerprint must pass"
assert not r_ui.valid, "UI screenshot must be rejected"
assert "Invalid" in r_ui.message or "screenshot" in r_ui.message.lower() or "screen" in r_ui.message.lower()
print("Screenshot rejection test passed.")
