"""Dynamic attack resistance simulation derived from live session metrics."""

from __future__ import annotations

from typing import Any


def simulate_attacks(
    benchmark: dict[str, Any],
    decrypt_event_count: int,
    participant_count: int,
    biometric_verified: bool,
) -> dict[str, Any]:
    """Compute attack outcomes from actual entropy, NIST, avalanche, and session state."""
    algos = benchmark.get("algorithms", {})
    qsbac = algos.get("QSBAC", algos.get("AES", {}))
    entropy = float(qsbac.get("entropy", 0))
    nist = float(qsbac.get("nist_pass_rate", 0))
    avalanche = float(qsbac.get("avalanche_1bit", qsbac.get("avalanche_ratio", 0)))
    stress = float(qsbac.get("security_stress", 50))
    key_bits = int(qsbac.get("key_length_bits", 256))

    brute_keyspace = 2 ** min(key_bits, 256)
    brute_success = max(0.0, min(99.99, (1.0 / max(brute_keyspace, 1)) * 1e12 * (stress / 100.0)))
    if entropy > 7.9 and nist > 85:
        brute_success = min(brute_success, 0.001 * (100 - nist))

    replay_base = 5.0 + decrypt_event_count * 2.5
    replay_detection = min(99.0, 40.0 + nist * 0.35 + avalanche * 0.4 + (10 if biometric_verified else 0))
    replay_success = max(0.0, replay_base - replay_detection * 0.45)

    spoof_resistance = min(99.0, 25.0 + avalanche * 0.6 + entropy * 5.0 + (30 if biometric_verified else 0))
    spoof_success = max(0.0, 100.0 - spoof_resistance)

    tamper_detect = min(99.0, 30.0 + avalanche * 0.55 + nist * 0.25)
    tamper_success = max(0.0, (100.0 - tamper_detect) * (stress / 100.0))

    unauthorized_block = min(99.0, 50.0 + participant_count * 8.0 + (25 if biometric_verified else 0))
    unauthorized_success = max(0.0, 15.0 - unauthorized_block * 0.12 + decrypt_event_count * 0.5)

    protection = round(
        (100.0 - brute_success) * 0.25
        + replay_detection * 0.2
        + spoof_resistance * 0.2
        + tamper_detect * 0.2
        + unauthorized_block * 0.15,
        2,
    )
    mitigation = round((protection + (100.0 - stress)) / 2.0, 2)

    attacks = [
        {
            "name": "Brute Force",
            "success_rate": round(brute_success, 4),
            "detection_probability": round(99.0 - brute_success, 2),
            "protection_level": round(100.0 - brute_success, 2),
        },
        {
            "name": "Replay Attack",
            "success_rate": round(replay_success, 2),
            "detection_probability": round(replay_detection, 2),
            "protection_level": round(100.0 - replay_success, 2),
        },
        {
            "name": "Biometric Spoofing",
            "success_rate": round(spoof_success, 2),
            "detection_probability": round(spoof_resistance, 2),
            "protection_level": round(spoof_resistance, 2),
        },
        {
            "name": "Ciphertext Tampering",
            "success_rate": round(tamper_success, 2),
            "detection_probability": round(tamper_detect, 2),
            "protection_level": round(tamper_detect, 2),
        },
        {
            "name": "Unauthorized Decrypt",
            "success_rate": round(unauthorized_success, 2),
            "detection_probability": round(unauthorized_block, 2),
            "protection_level": round(unauthorized_block, 2),
        },
    ]

    return {
        "attacks": attacks,
        "overall_protection": protection,
        "mitigation_score": mitigation,
        "quantum_safe_indicator": round(min(100.0, entropy * 10.0 + nist * 0.2 + avalanche * 0.3), 2),
    }
