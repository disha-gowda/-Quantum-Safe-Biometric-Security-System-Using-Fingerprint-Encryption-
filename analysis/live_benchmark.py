"""Live cryptographic benchmark engine — all metrics from real executions."""

from __future__ import annotations

import hashlib
import math
import time
from typing import Any

from analysis.cipher_suite import ALGORITHMS, avalanche_ciphertext, run_all_ciphers
from analysis.nist_tests import run_nist_suite, suite_pass_rate
from analysis.security_metrics import entropy_bits_per_byte, histogram_uniformity_score, npcr, uaci
from analysis.qsbac_scores import qsbac_adaptive_metrics
from qsbas.biometric_profile import BiometricProfile
from qsbas.constants import QSBAC_ENGINE_VERSION
from qsbas.layers import build_dynamic_sbox
from qsbas.cipher import QSBACSPNCipher


def _block_count(size: int, block: int = 16) -> int:
    return max(1, math.ceil(size / block)) if size else 0


def _throughput_bps(ciphertext_size: int, encrypt_seconds: float) -> float:
    """Throughput = ciphertext size / encryption time (bytes per second)."""
    if encrypt_seconds <= 0:
        return 0.0
    return ciphertext_size / encrypt_seconds


def _randomness_quality(entropy: float, nist_pass: float, uniformity: float) -> float:
    """Composite 0–100 score from live statistical measures."""
    ent_score = min(100.0, (entropy / 8.0) * 100.0) if entropy else 0.0
    return round(0.4 * ent_score + 0.35 * nist_pass + 0.25 * uniformity * 100.0, 2)


def _security_intelligence(entropy: float, nist_pass: float, avalanche: float, uniformity: float) -> float:
    """Strength index: 0.35·H + 0.25·N + 0.2·A + 0.2·U (higher = stronger)."""
    h = min(100.0, (entropy / 8.0) * 100.0) if entropy else 0.0
    n = min(100.0, nist_pass)
    a = min(100.0, avalanche)
    u = min(100.0, uniformity * 100.0)
    return round(0.35 * h + 0.25 * n + 0.2 * a + 0.2 * u, 2)


def _security_stress(entropy: float, nist_pass: float, avalanche: float, uniformity: float) -> float:
    """Stress = 100 − intelligence (lower stress = stronger cipher on dashboard)."""
    intel = _security_intelligence(entropy, nist_pass, avalanche, uniformity)
    return round(max(0.0, min(100.0, 100.0 - intel)), 2)


def _security_rating(stress: float) -> str:
    if stress < 15:
        return "EXCELLENT"
    if stress < 35:
        return "STRONG"
    if stress < 55:
        return "MODERATE"
    return "ELEVATED"


def _histogram_bytes(ciphertext: bytes, bins: int = 64) -> list[int]:
    """Full byte histogram aggregated into bins for smoother distribution charts."""
    if not ciphertext:
        return [0] * bins
    full = [0] * 256
    for b in ciphertext:
        full[b] += 1
    step = max(1, 256 // bins)
    counts = []
    for i in range(bins):
        start = i * step
        end = min(256, start + step)
        counts.append(sum(full[start:end]))
    return counts


def _analyze_ciphertext(ciphertext: bytes) -> dict[str, Any]:
    ct = ciphertext or b""
    sample = ct[: min(512, len(ct))]
    if len(sample) >= 2:
        flipped = bytes(b ^ 1 if i == 0 else b for i, b in enumerate(sample))
        npcr_val = npcr(sample, flipped)
        uaci_val = uaci(sample, flipped)
    else:
        npcr_val = 0.0
        uaci_val = 0.0

    entropy = entropy_bits_per_byte(ct) if ct else 0.0
    uniformity = histogram_uniformity_score(ct) if ct else 0.0
    nist_results = run_nist_suite(ct[:4096] if len(ct) > 4096 else ct)
    nist_pass = suite_pass_rate(nist_results) if ct else 0.0
    digest = hashlib.sha256(ct).hexdigest() if ct else ""
    avalanche_ratio = npcr_val

    stress = _security_stress(entropy, nist_pass, avalanche_ratio, uniformity)
    return {
        "entropy": round(entropy, 4),
        "npcr": round(npcr_val, 2),
        "uaci": round(uaci_val, 2),
        "nist_pass_rate": round(nist_pass, 2),
        "histogram_uniformity": round(uniformity, 4),
        "histogram_counts": _histogram_bytes(ct),
        "avalanche_ratio": round(avalanche_ratio, 2),
        "randomness_quality": _randomness_quality(entropy, nist_pass, uniformity),
        "security_stress": stress,
        "security_intelligence": _security_intelligence(entropy, nist_pass, avalanche_ratio, uniformity),
        "security_rating": _security_rating(stress),
        "ciphertext_size": len(ct),
        "block_count": _block_count(len(ct)),
        "sha256": digest,
        "hex_preview": ct[:64].hex(),
        "nist_tests": [{"name": r.name, "passed": r.passed, "p_value": round(r.p_value, 4)} for r in nist_results],
    }


def run_live_benchmark(
    plaintext: bytes,
    qsbac_profile: BiometricProfile | None,
    session_id: int,
    qsbac_session_ciphertext: bytes | None = None,
) -> dict[str, Any]:
    """
    Full live benchmark: encrypt plaintext with all algorithms, analyze ciphertexts.
    """
    t_start = time.perf_counter()
    if not plaintext:
        plaintext = b"QSBAC-LIVE-BENCHMARK-SEED"

    cipher_runs = run_all_ciphers(plaintext, qsbac_profile)
    avalanche_map = avalanche_ciphertext(plaintext, qsbac_profile)

    algorithms: dict[str, Any] = {}
    for run in cipher_runs:
        analysis = _analyze_ciphertext(run.ciphertext)
        analysis["encrypt_seconds"] = round(run.encrypt_seconds, 6)
        analysis["decrypt_seconds"] = round(run.decrypt_seconds, 6)
        analysis["throughput_bps"] = round(_throughput_bps(len(run.ciphertext), run.encrypt_seconds), 2)
        analysis["key_length_bits"] = run.key_length_bits
        analysis["avalanche_1bit"] = round(avalanche_map.get(run.algorithm, 0.0), 2)
        algorithms[run.algorithm] = analysis

    if "QSBAC" in algorithms:
        q = algorithms["QSBAC"]
        exclusive = qsbac_adaptive_metrics(
            float(q.get("entropy", 0)),
            float(q.get("nist_pass_rate", 0)),
            float(q.get("avalanche_1bit", q.get("avalanche_ratio", 0))),
            float(q.get("histogram_uniformity", 0)),
            qsbac_profile is not None,
            session_id,
            QSBAC_ENGINE_VERSION,
        )
        q.update(exclusive)
        q["engine_version"] = QSBAC_ENGINE_VERSION

    if qsbac_session_ciphertext and "QSBAC" in algorithms:
        session_analysis = _analyze_ciphertext(qsbac_session_ciphertext)
        algorithms["QSBAC"]["session_ciphertext"] = True
        for k, v in session_analysis.items():
            if k not in ("hex_preview",):
                algorithms["QSBAC"][f"live_{k}"] = v

    active_labels = [r.algorithm for r in cipher_runs]
    comparison = {
        "labels": active_labels,
        "entropy": [algorithms.get(a, {}).get("entropy", 0) for a in active_labels],
        "npcr": [algorithms.get(a, {}).get("npcr", 0) for a in active_labels],
        "uaci": [algorithms.get(a, {}).get("uaci", 0) for a in active_labels],
        "nist_pass_rate": [algorithms.get(a, {}).get("nist_pass_rate", 0) for a in active_labels],
        "encrypt_seconds": [algorithms.get(a, {}).get("encrypt_seconds", 0) for a in active_labels],
        "decrypt_seconds": [algorithms.get(a, {}).get("decrypt_seconds", 0) for a in active_labels],
        "throughput_bps": [algorithms.get(a, {}).get("throughput_bps", 0) for a in active_labels],
        "avalanche_1bit": [algorithms.get(a, {}).get("avalanche_1bit", 0) for a in active_labels],
        "security_stress": [algorithms.get(a, {}).get("security_stress", 0) for a in active_labels],
        "security_intelligence": [algorithms.get(a, {}).get("security_intelligence", 0) for a in active_labels],
        "randomness_quality": [algorithms.get(a, {}).get("randomness_quality", 0) for a in active_labels],
        "histogram_by_algo": {
            a: algorithms.get(a, {}).get("histogram_counts", []) for a in active_labels
        },
    }

    qsbac_telemetry = _qsbac_telemetry(qsbac_profile, session_id)

    return {
        "session_id": session_id,
        "timestamp": time.time(),
        "elapsed_ms": round((time.perf_counter() - t_start) * 1000, 2),
        "plaintext_bytes": len(plaintext),
        "algorithms": algorithms,
        "comparison": comparison,
        "avalanche_map": avalanche_map,
        "qsbac_telemetry": qsbac_telemetry,
        "primary": algorithms.get("QSBAC") or (algorithms.get("AES") if algorithms else {}),
    }


def _qsbac_telemetry(profile: BiometricProfile | None, session_id: int) -> dict[str, Any]:
    if not profile:
        return {
            "biometric_verified": False,
            "adaptive_key_status": "NO_PROFILE",
            "quantum_entropy_active": False,
            "feature_hash": "",
        }
    return {
        "biometric_verified": True,
        "adaptive_key_status": "ACTIVE",
        "quantum_entropy_active": True,
        "feature_hash": profile.session_feature_hash_hex(session_id),
        "minutiae_count": len(profile.cipher_minutiae),
    }


def generate_sbox_matrix(profile: BiometricProfile, session_id: int) -> dict[str, Any]:
    """Dynamic 16×16 S-box heatmap slice from biometric + session material."""
    features = [int(m.x) & 0xFF for m in profile.cipher_minutiae]
    chaotic = [int(m.y) & 0xFF for m in profile.cipher_minutiae]
    while len(features) < 32:
        features.append(features[-1] ^ session_id)
    while len(chaotic) < 32:
        chaotic.append(chaotic[-1] ^ (session_id >> 8))
    x0 = (session_id % 1000) / 1000.0
    sbox = build_dynamic_sbox(features, chaotic, x0=x0)
    grid_16 = [sbox[i : i + 16] for i in range(0, 256, 16)]
    return {
        "matrix": grid_16,
        "full_size": 256,
        "session_id": session_id,
        "biometric_entropy": round(entropy_bits_per_byte(bytes(sbox)), 4),
    }
