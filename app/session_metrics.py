"""Per-session ciphertext security metrics for the analysis dashboard."""

from __future__ import annotations

from analysis.nist_tests import run_nist_suite, suite_pass_rate
from analysis.security_metrics import entropy_bits_per_byte, histogram_uniformity_score, npcr, uaci


def session_ciphertext_bars(ciphertext: bytes, bins: int = 24) -> list[int]:
    """Bar heights (30–100) from byte distribution of this session's ciphertext."""
    if not ciphertext:
        return [30] * bins
    counts = [0] * bins
    for i, byte in enumerate(ciphertext):
        counts[i % bins] += byte
    peak = max(counts) or 1
    return [int(30 + 70 * c / peak) for c in counts]


def session_security_metrics(ciphertext: bytes) -> dict:
    """NPCR/UACI/entropy/NIST computed from this session's QSBAC-SPN ciphertext."""
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

    stress = "LOW"
    if entropy < 7.5 or nist_pass < 80:
        stress = "MEDIUM"
    if entropy < 6.5 or nist_pass < 60:
        stress = "HIGH"

    sample32 = ct[:32]
    return {
        "npcr_val": npcr_val,
        "uaci_val": uaci_val,
        "entropy": entropy,
        "uniformity": uniformity,
        "nist_pass_rate": nist_pass,
        "bar_heights": session_ciphertext_bars(ct),
        "ciphertext_bytes": len(ct),
        "ciphertext_hex_32": sample32.hex(),
        "stress": stress,
    }
