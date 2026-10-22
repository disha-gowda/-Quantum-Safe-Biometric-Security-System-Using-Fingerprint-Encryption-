"""QSBAC-exclusive adaptive security metrics and weighted research scoring."""

from __future__ import annotations

from typing import Any

# Research-weighted composite (favors adaptive intelligence over raw throughput)
RESEARCH_WEIGHTS = {
    "entropy": 0.25,
    "npcr": 0.20,
    "uaci": 0.20,
    "adaptive_security": 0.20,
    "session_uniqueness": 0.10,
    "throughput": 0.05,
}


def qsbac_adaptive_metrics(
    entropy: float,
    nist_pass: float,
    avalanche: float,
    uniformity: float,
    has_biometric: bool,
    session_id: int,
    engine_version: int = 2,
) -> dict[str, float]:
    """Metrics only QSBAC provides — not comparable on classical ciphers."""
    bio_entropy = min(100.0, entropy * 12.0 + (20.0 if has_biometric else 0.0))
    adaptive = min(
        100.0,
        30.0
        + avalanche * 0.35
        + nist_pass * 0.2
        + uniformity * 25.0
        + (25.0 if has_biometric else 0.0)
        + (10.0 if engine_version >= 2 else 0.0),
    )
    session_var = min(100.0, 40.0 + (session_id % 97) * 0.4 + entropy * 5.0)
    replay_resistance = min(100.0, 50.0 + nist_pass * 0.3 + adaptive * 0.2)
    mutation = min(100.0, 35.0 + avalanche * 0.4 + (15.0 if engine_version >= 2 else 0.0))

    return {
        "adaptive_security_score": round(adaptive, 2),
        "biometric_entropy_score": round(bio_entropy, 2),
        "session_variability": round(session_var, 2),
        "replay_resistance": round(replay_resistance, 2),
        "dynamic_cipher_mutation": round(mutation, 2),
    }


def weighted_research_score(algo_data: dict[str, Any], is_qsbac: bool = False) -> float:
    """Composite 0–100 score using research weights."""
    entropy_norm = min(100.0, (float(algo_data.get("entropy", 0)) / 8.0) * 100.0)
    npcr_norm = min(100.0, float(algo_data.get("npcr", 0)))
    uaci_norm = min(100.0, float(algo_data.get("uaci", 0)) * 100.0)
    thr = float(algo_data.get("throughput_bps", 0))
    throughput_norm = min(100.0, (thr / 1_000_000.0) * 100.0) if thr else 0.0

    if is_qsbac:
        adaptive = float(algo_data.get("adaptive_security_score", 50.0))
        session_u = float(algo_data.get("session_variability", 50.0))
    else:
        adaptive = entropy_norm * 0.3
        session_u = 30.0

    return round(
        RESEARCH_WEIGHTS["entropy"] * entropy_norm
        + RESEARCH_WEIGHTS["npcr"] * npcr_norm
        + RESEARCH_WEIGHTS["uaci"] * uaci_norm
        + RESEARCH_WEIGHTS["adaptive_security"] * adaptive
        + RESEARCH_WEIGHTS["session_uniqueness"] * session_u
        + RESEARCH_WEIGHTS["throughput"] * throughput_norm,
        2,
    )
