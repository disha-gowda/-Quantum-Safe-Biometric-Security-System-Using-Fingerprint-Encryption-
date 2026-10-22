"""Performance comparison with AES and ChaCha20."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


@dataclass
class BenchmarkResult:
    algorithm: str
    encrypt_seconds: float
    decrypt_seconds: float
    throughput_mbps: float
    adaptive_security: bool
    dynamic_sbox: bool
    biometric_integration: bool


def _throughput_mbps(byte_count: int, seconds: float) -> float:
    if seconds <= 0:
        return 0.0
    return (byte_count / (1024 * 1024)) / seconds


def benchmark_aes(data: bytes, iterations: int = 5) -> BenchmarkResult:
    key = os.urandom(32)
    iv = os.urandom(16)
    enc_time = 0.0
    dec_time = 0.0
    for _ in range(iterations):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        pad = 16 - (len(data) % 16)
        padded = data + bytes([pad] * pad)
        t0 = time.perf_counter()
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        enc_time += time.perf_counter() - t0
        t0 = time.perf_counter()
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        _ = dec.update(ct) + dec.finalize()
        dec_time += time.perf_counter() - t0
    enc_time /= iterations
    dec_time /= iterations
    return BenchmarkResult(
        "AES-256-CBC",
        enc_time,
        dec_time,
        _throughput_mbps(len(data), enc_time),
        False,
        False,
        False,
    )


def benchmark_chacha(data: bytes, iterations: int = 5) -> BenchmarkResult:
    key = os.urandom(32)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    enc_time = 0.0
    dec_time = 0.0
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = aead.encrypt(nonce, data, None)
        enc_time += time.perf_counter() - t0
        t0 = time.perf_counter()
        _ = aead.decrypt(nonce, ct, None)
        dec_time += time.perf_counter() - t0
    enc_time /= iterations
    dec_time /= iterations
    return BenchmarkResult(
        "ChaCha20-Poly1305",
        enc_time,
        dec_time,
        _throughput_mbps(len(data), enc_time),
        False,
        False,
        False,
    )


def benchmark_qsbac(encrypt_fn: Callable[[bytes], bytes], decrypt_fn: Callable[[bytes], bytes], data: bytes, iterations: int = 3) -> BenchmarkResult:
    enc_time = 0.0
    dec_time = 0.0
    ct = encrypt_fn(data)
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = encrypt_fn(data)
        enc_time += time.perf_counter() - t0
        t0 = time.perf_counter()
        _ = decrypt_fn(ct)
        dec_time += time.perf_counter() - t0
    enc_time /= iterations
    dec_time /= iterations
    return BenchmarkResult(
        "QSBAC",
        enc_time,
        dec_time,
        _throughput_mbps(len(data), enc_time),
        True,
        True,
        True,
    )
