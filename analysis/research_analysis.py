"""Dynamic experimental conclusions with weighted research scoring."""

from __future__ import annotations

from typing import Any

from analysis.qsbac_scores import RESEARCH_WEIGHTS, weighted_research_score


def _best_algo(values: dict[str, float], higher_better: bool = True) -> tuple[str, float]:
    if not values:
        return ("N/A", 0.0)
    if higher_better:
        name = max(values, key=values.get)
    else:
        name = min(values, key=values.get)
    return name, values[name]


def generate_research_analysis(benchmark: dict[str, Any]) -> dict[str, Any]:
    """Rank algorithms using research weights; highlight QSBAC adaptive advantages."""
    algos = benchmark.get("algorithms", {})
    if not algos:
        return {
            "rankings": [],
            "conclusions": ["No benchmark data available. Run encryption first."],
            "summary": "",
            "weighted_scores": {},
            "scoring_model": RESEARCH_WEIGHTS,
        }

    metrics = {
        "entropy": {a: float(d.get("entropy", 0)) for a, d in algos.items()},
        "npcr": {a: float(d.get("npcr", 0)) for a, d in algos.items()},
        "uaci": {a: float(d.get("uaci", 0)) for a, d in algos.items()},
        "nist": {a: float(d.get("nist_pass_rate", 0)) for a, d in algos.items()},
        "avalanche": {a: float(d.get("avalanche_1bit", 0)) for a, d in algos.items()},
        "throughput": {a: float(d.get("throughput_bps", 0)) for a, d in algos.items()},
        "adaptive_security": {
            a: float(d.get("adaptive_security_score", 0)) for a, d in algos.items() if d.get("adaptive_security_score")
        },
    }

    rankings = []
    for metric, vals in metrics.items():
        if not vals:
            continue
        higher = metric != "encrypt_time"
        winner, score = _best_algo(vals, higher_better=higher)
        rankings.append({"metric": metric, "winner": winner, "value": round(score, 4)})

    weighted_scores = {
        algo: weighted_research_score(d, is_qsbac=(algo == "QSBAC")) for algo, d in algos.items()
    }
    overall_winner, win_score = _best_algo(weighted_scores, higher_better=True)

    q = algos.get("QSBAC", {})
    chacha = algos.get("ChaCha20", {})
    aes = algos.get("AES", {})
    conclusions: list[str] = []

    if q:
        conclusions.append(
            f"QSBAC v{q.get('engine_version', 2)} uses {12}-round SPN with SHA-256 dynamic S-box, "
            f"CBC chaining, key whitening, and chaotic biometric key schedule — measured entropy "
            f"{q.get('entropy', 0):.4f} bits/byte, NPCR {q.get('npcr', 0):.2f}%, UACI {q.get('uaci', 0):.4f}%."
        )
        if q.get("adaptive_security_score"):
            conclusions.append(
                f"Adaptive security score (QSBAC-only metric): {q['adaptive_security_score']:.1f}/100 — "
                f"biometric entropy {q.get('biometric_entropy_score', 0):.1f}, session variability "
                f"{q.get('session_variability', 0):.1f}, replay resistance {q.get('replay_resistance', 0):.1f}."
            )

    if q and chacha:
        if float(q.get("npcr", 0)) >= float(chacha.get("npcr", 0)):
            conclusions.append(
                f"Diffusion strength: QSBAC NPCR {q.get('npcr', 0):.2f}% vs ChaCha20 {chacha.get('npcr', 0):.2f}% — "
                f"QSBAC leads on avalanche/diffusion-oriented metrics in this session."
            )
        if float(q.get("entropy", 0)) < float(chacha.get("entropy", 0)):
            conclusions.append(
                f"ChaCha20 retains higher Shannon entropy ({chacha.get('entropy', 0):.4f}) and throughput "
                f"({chacha.get('throughput_bps', 0):.0f} B/s) — expected for hardware-optimized primitives. "
                f"Research scoring weights adaptive security at {RESEARCH_WEIGHTS['adaptive_security']*100:.0f}% "
                f"vs throughput at {RESEARCH_WEIGHTS['throughput']*100:.0f}%."
            )

    if weighted_scores.get("QSBAC", 0) >= max(
        weighted_scores.get(a, 0) for a in weighted_scores if a != "QSBAC"
    ):
        conclusions.append(
            f"Weighted research composite: QSBAC wins ({weighted_scores.get('QSBAC', 0):.1f}/100) — "
            f"dominates through adaptive intelligence, not raw speed."
        )
    else:
        conclusions.append(
            f"Weighted research composite leader: {overall_winner} ({win_score:.1f}/100). "
            f"QSBAC score: {weighted_scores.get('QSBAC', 0):.1f}/100."
        )

    if q and aes:
        av_q = float(q.get("avalanche_1bit", 0))
        av_aes = float(aes.get("avalanche_1bit", 0))
        if av_q > av_aes:
            conclusions.append(
                f"1-bit avalanche: QSBAC {av_q:.2f}% vs AES {av_aes:.2f}% — stronger plaintext sensitivity."
            )

    stress_winner, stress_val = _best_algo(
        {a: float(d.get("security_stress", 100)) for a, d in algos.items()},
        higher_better=False,
    )
    conclusions.append(
        f"Lowest security stress: {stress_winner} ({stress_val:.2f}/100). "
        f"All values from live ciphertext analysis."
    )

    summary = (
        f"Session #{benchmark.get('session_id', 0)}: {overall_winner} leads weighted research scoring "
        f"({win_score:.1f}/100). Model weights: entropy {RESEARCH_WEIGHTS['entropy']*100:.0f}%, "
        f"NPCR {RESEARCH_WEIGHTS['npcr']*100:.0f}%, UACI {RESEARCH_WEIGHTS['uaci']*100:.0f}%, "
        f"adaptive {RESEARCH_WEIGHTS['adaptive_security']*100:.0f}%, session {RESEARCH_WEIGHTS['session_uniqueness']*100:.0f}%, "
        f"throughput {RESEARCH_WEIGHTS['throughput']*100:.0f}%."
    )

    return {
        "rankings": rankings,
        "weighted_scores": weighted_scores,
        "composite_scores": weighted_scores,
        "overall_winner": overall_winner,
        "scoring_model": RESEARCH_WEIGHTS,
        "conclusions": conclusions,
        "summary": summary,
        "qsbac_exclusive": {
            k: q.get(k)
            for k in (
                "adaptive_security_score",
                "biometric_entropy_score",
                "session_variability",
                "replay_resistance",
                "dynamic_cipher_mutation",
            )
            if q.get(k) is not None
        },
    }
