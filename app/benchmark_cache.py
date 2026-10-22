"""In-memory live benchmark cache with history for trend charts."""

from __future__ import annotations

import threading
import time
from typing import Any

from analysis.attack_simulation import simulate_attacks
from analysis.live_benchmark import generate_sbox_matrix, run_live_benchmark
from analysis.research_analysis import generate_research_analysis
from app.database import chat_payload, get_participants, get_session
from qsbas.biometric_profile import BiometricProfile
from qsbas.group_cipher import GroupEncryptedMessage

_MAX_HISTORY = 30
_cache: dict[int, dict[str, Any]] = {}
_lock = threading.Lock()


def _encryptor_profile(session_id: int) -> BiometricProfile | None:
    parts = get_participants(session_id)
    for p in parts:
        if p["is_encryptor"]:
            return BiometricProfile.from_json(p["profile_json"])
    return None


def _session_plaintext(session_id: int) -> bytes:
    row = get_session(session_id)
    if not row:
        return b""
    session = dict(row)
    text = session.get("original_plaintext") or session.get("current_plaintext") or ""
    if text and text not in ("[encrypted]", ""):
        return text.encode("utf-8")
    data = chat_payload(session_id)
    if data:
        pkg = GroupEncryptedMessage.from_json(data["session"]["group_payload"])
        return pkg.message_ciphertext[:256] or b"QSBAC-SESSION-PAYLOAD"
    return b"QSBAC-LIVE-BENCHMARK"


def _session_qsbac_ciphertext(session_id: int) -> bytes | None:
    row = get_session(session_id)
    if not row:
        return None
    try:
        pkg = GroupEncryptedMessage.from_json(dict(row)["group_payload"])
        return pkg.message_ciphertext
    except Exception:
        return None


def run_and_cache(session_id: int, force: bool = False) -> dict[str, Any]:
    """Execute live benchmark and append to session history."""
    with _lock:
        entry = _cache.get(session_id, {"history": [], "last_run": 0.0})
        if not force and entry.get("last_run", 0) > time.time() - 2.0 and entry.get("latest"):
            return entry["latest"]

    plaintext = _session_plaintext(session_id)
    profile = _encryptor_profile(session_id)
    qsbac_ct = _session_qsbac_ciphertext(session_id)

    benchmark = run_live_benchmark(plaintext, profile, session_id, qsbac_ct)
    data = chat_payload(session_id) or {}
    decrypt_count = len(data.get("decrypt_events", []))
    participant_count = len(data.get("participants", []))

    benchmark["attack_simulation"] = simulate_attacks(
        benchmark,
        decrypt_count,
        participant_count,
        bool(profile),
    )
    benchmark["research"] = generate_research_analysis(benchmark)
    benchmark["decrypt_events"] = decrypt_count
    if profile:
        benchmark["sbox"] = generate_sbox_matrix(profile, session_id)
    else:
        benchmark["sbox"] = {"matrix": [], "biometric_entropy": 0}

    labels = benchmark["comparison"]["labels"]
    trend_point = {
        "t": time.time(),
        "stress": benchmark["comparison"]["security_stress"],
        "entropy": benchmark["comparison"]["entropy"],
        "by_algo": {
            lbl: {
                "stress": benchmark["comparison"]["security_stress"][i],
                "intelligence": benchmark["comparison"].get("security_intelligence", [0] * len(labels))[i],
                "entropy": benchmark["comparison"]["entropy"][i],
            }
            for i, lbl in enumerate(labels)
        },
    }

    with _lock:
        entry = _cache.setdefault(session_id, {"history": [], "last_run": 0.0})
        entry["latest"] = benchmark
        entry["last_run"] = time.time()
        entry["history"].append(trend_point)
        entry["history"] = entry["history"][-_MAX_HISTORY:]
        benchmark["history"] = entry["history"]

    return benchmark


def get_cached(session_id: int) -> dict[str, Any]:
    with _lock:
        entry = _cache.get(session_id)
        if entry and entry.get("latest"):
            return entry["latest"]
    return run_and_cache(session_id, force=True)


def invalidate(session_id: int) -> None:
    with _lock:
        _cache.pop(session_id, None)
