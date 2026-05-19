"""Simplified NIST SP 800-22 style statistical tests."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, List


@dataclass
class TestResult:
    name: str
    passed: bool
    p_value: float
    statistic: float


def _bits_from_bytes(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def frequency_test(bits: List[int]) -> TestResult:
    n = len(bits)
    if n == 0:
        return TestResult("Frequency", False, 0.0, 0.0)
    s = sum(1 if b else -1 for b in bits)
    stat = abs(s) / math.sqrt(n)
    p = math.erfc(stat / math.sqrt(2))
    return TestResult("Frequency", p >= 0.01, p, float(s))


def runs_test(bits: List[int]) -> TestResult:
    n = len(bits)
    if n == 0:
        return TestResult("Runs", False, 0.0, 0.0)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return TestResult("Runs", False, 0.0, 0.0)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    num = abs(runs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    stat = num / den if den else 0.0
    p = math.erfc(stat)
    return TestResult("Runs", p >= 0.01, p, float(runs))


def approximate_entropy_test(bits: List[int], m: int = 2) -> TestResult:
    n = len(bits)
    if n < 2 ** (m + 2):
        return TestResult("Approximate Entropy", False, 0.0, 0.0)

    def phi(block: int) -> float:
        counts = {}
        for i in range(n - block + 1):
            pattern = tuple(bits[i : i + block])
            counts[pattern] = counts.get(pattern, 0) + 1
        total = n - block + 1
        return sum((c / total) * math.log(c / total) for c in counts.values())

    apen = phi(m) - phi(m + 1)
    chi = 2.0 ** (m + 1) * (1 - apen / math.log(2) if apen else 1)
    p = math.exp(-chi) if chi > 0 else 0.5
    return TestResult("Approximate Entropy", p >= 0.01, min(1.0, p), apen)


def serial_test(bits: List[int], m: int = 2) -> TestResult:
    n = len(bits)
    if n < 128:
        return TestResult("Serial", False, 0.0, 0.0)
    psi_m = 0.0
    counts = {}
    for i in range(n - m + 1):
        pattern = tuple(bits[i : i + m])
        counts[pattern] = counts.get(pattern, 0) + 1
    total = n - m + 1
    for c in counts.values():
        psi_m += (c / total) ** 2
    psi_m = (2 ** m / n) * psi_m - 1
    p = math.exp(-psi_m / 2) if psi_m > 0 else 0.5
    return TestResult("Serial", p >= 0.01, min(1.0, p), psi_m)


def fft_spectral_test(bits: List[int]) -> TestResult:
    n = len(bits)
    if n < 32:
        return TestResult("FFT Spectral", False, 0.0, 0.0)
    x = [1.0 if b else -1.0 for b in bits]
    peak = 0.0
    for k in range(1, n // 2):
        real = sum(x[i] * math.cos(2 * math.pi * k * i / n) for i in range(n))
        imag = sum(x[i] * math.sin(2 * math.pi * k * i / n) for i in range(n))
        mag = math.sqrt(real * real + imag * imag)
        peak = max(peak, mag)
    threshold = math.sqrt(n) * 2.576
    stat = peak / threshold if threshold else 0.0
    p = 0.5 if stat <= 1 else 0.001
    return TestResult("FFT Spectral", p >= 0.01, p, stat)


def run_nist_suite(data: bytes) -> List[TestResult]:
    bits = _bits_from_bytes(data)
    tests: List[Callable[[], TestResult]] = [
        lambda: frequency_test(bits),
        lambda: runs_test(bits),
        lambda: approximate_entropy_test(bits),
        lambda: serial_test(bits),
        lambda: fft_spectral_test(bits),
    ]
    return [t() for t in tests]


def suite_pass_rate(results: List[TestResult]) -> float:
    if not results:
        return 0.0
    return 100.0 * sum(1 for r in results if r.passed) / len(results)
