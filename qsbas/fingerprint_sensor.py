"""Capture a live print from a USB fingerprint sensor — never the face webcam."""

from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional, Tuple

import cv2
import numpy as np

FP_NAME_HINTS = (
    "finger",
    "u.are.u",
    "uareu",
    "digitalpersona",
    "digital persona",
    "futronic",
    "secugen",
    "mantra",
    "morpho",
    "zkteco",
    "zkfinger",
    "fs80",
    "fs88",
    "crossmatch",
    "suprema",
    "nitgen",
    "hamrick",
    "persona",
    "biometric reader",
    "fingerprint",
    "print scanner",
    "optical scanner",
)

WEBCAM_HINTS = (
    "webcam",
    "integrated camera",
    "facetime",
    "rgb camera",
    "ir camera",
    "infrared",
    "laptop camera",
    "front camera",
    "user-facing",
    "facing user",
    "hd camera",
    "hd webcam",
    "studio camera",
    "obs virtual",
)


def _norm(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def _is_webcam_name(name: str) -> bool:
    n = _norm(name)
    if any(h in n for h in FP_NAME_HINTS):
        return False
    return any(h in n for h in WEBCAM_HINTS)


def _is_fingerprint_name(name: str) -> bool:
    n = _norm(name)
    if _is_webcam_name(name):
        return False
    return any(h in n for h in FP_NAME_HINTS)


def _windows_device_names() -> List[str]:
    script = (
        "Get-CimInstance Win32_PnPEntity | "
        "Where-Object { $_.PNPClass -eq 'Camera' -or $_.PNPClass -eq 'Image' "
        "-or $_.Name -match 'Finger|Scan|Camera|Webcam|Persona|Futronic|Mantra' } | "
        "Select-Object -ExpandProperty Name"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except Exception:
        return []
    return [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]


def _open_capture(index: int) -> Optional[cv2.VideoCapture]:
    backends = []
    if os.name == "nt":
        backends = [cv2.CAP_DSHOW, cv2.CAP_MSMF]
    backends.append(cv2.CAP_ANY)
    for backend in backends:
        cap = cv2.VideoCapture(index, backend)
        if cap is not None and cap.isOpened():
            return cap
        if cap is not None:
            cap.release()
    return None


def _grab_frame(cap: cv2.VideoCapture) -> Optional[np.ndarray]:
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 512)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 512)
    frame = None
    for _ in range(10):
        ok, img = cap.read()
        if ok and img is not None and img.size:
            frame = img
    return frame


def find_fingerprint_sensor_index(names: Optional[List[str]] = None) -> Tuple[Optional[int], str]:
    env = os.environ.get("QSBAS_FP_SENSOR_INDEX", "").strip()
    if env.isdigit():
        return int(env), f"Configured sensor index {env}"

    names = names if names is not None else (_windows_device_names() if os.name == "nt" else [])
    for i, name in enumerate(names):
        if _is_fingerprint_name(name):
            return i, name

    # Probe extra indices in case PnP list is shorter than DirectShow list.
    for i in range(max(len(names), 1), 8):
        cap = _open_capture(i)
        if cap is None:
            continue
        cap.release()
        if i < len(names) and _is_webcam_name(names[i]):
            continue
        if i < len(names) and _is_fingerprint_name(names[i]):
            return i, names[i]
    return None, ""


def capture_fingerprint_sensor() -> Tuple[bool, str, Optional[np.ndarray]]:
    """
    Capture one image from a fingerprint sensor.
    Never opens the laptop/face webcam as a fallback.
    """
    names = _windows_device_names() if os.name == "nt" else []
    index, label = find_fingerprint_sensor_index(names)
    if index is None:
        listed = ", ".join(names) if names else "none"
        return (
            False,
            "No fingerprint sensor was found. Connect a USB fingerprint scanner "
            f"(not the face webcam) or upload a fingerprint image. Video devices: {listed}.",
            None,
        )

    if index < len(names) and _is_webcam_name(names[index]):
        return (
            False,
            "Refusing to use the face/webcam device for fingerprint capture. "
            "Connect a fingerprint sensor or upload a fingerprint image.",
            None,
        )

    cap = _open_capture(index)
    if cap is None:
        return False, f"Could not open fingerprint sensor ({label or index}).", None
    try:
        frame = _grab_frame(cap)
    finally:
        cap.release()
    if frame is None:
        return False, "Fingerprint sensor opened but no scan was captured. Place your finger and try again.", None
    return True, label or f"sensor {index}", frame


def frame_to_png_data_url(frame: np.ndarray) -> str:
    if len(frame.shape) == 2:
        bgr = cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
    else:
        bgr = frame
    ok, buf = cv2.imencode(".png", bgr)
    if not ok:
        raise ValueError("Could not encode fingerprint scan")
    import base64

    return "data:image/png;base64," + base64.b64encode(buf).decode("ascii")
