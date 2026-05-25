"""Unified encrypt/decrypt for benchmark comparison (AES, DES, Blowfish, ChaCha20, QSBAC)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from Crypto.Cipher import Blowfish, DES
from Crypto.Util.Padding import pad, unpad

from qsbas.biometric_profile import BiometricProfile
from qsbas.cipher import QSBACSPNCipher

ALGORITHMS = ("AES", "DES", "Blowfish", "ChaCha20", "QSBAC")


@dataclass
class CipherRun:
    algorithm: str
    ciphertext: bytes
    encrypt_seconds: float
    decrypt_seconds: float
    key_length_bits: int


def _pad_pkcs7(data: bytes, block: int = 16) -> bytes:
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len] * pad_len)


def _timed_aes(plaintext: bytes, iterations: int = 3) -> CipherRun:
    key = os.urandom(32)
    iv = os.urandom(16)
    enc_total = 0.0
    dec_total = 0.0
    ct = b""
    for _ in range(iterations):
        padded = _pad_pkcs7(plaintext, 16)
        t0 = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
        enc_total += time.perf_counter() - t0
        t0 = time.perf_counter()
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        _ = dec.update(ct) + dec.finalize()
        dec_total += time.perf_counter() - t0
    return CipherRun("AES", ct, enc_total / iterations, dec_total / iterations, 256)


def _timed_des(plaintext: bytes, iterations: int = 3) -> CipherRun:
    key = os.urandom(8)
    iv = os.urandom(8)
    enc_total = 0.0
    dec_total = 0.0
    ct = b""
    for _ in range(iterations):
        padded = pad(plaintext, 8)
        t0 = time.perf_counter()
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(padded)
        enc_total += time.perf_counter() - t0
        t0 = time.perf_counter()
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        _ = unpad(cipher.decrypt(ct), 8)
        dec_total += time.perf_counter() - t0
    return CipherRun("DES", ct, enc_total / iterations, dec_total / iterations, 64)


def _timed_blowfish(plaintext: bytes, iterations: int = 3) -> CipherRun:
    key = os.urandom(16)
    iv = os.urandom(8)
    enc_total = 0.0
    dec_total = 0.0
    ct = b""
    for _ in range(iterations):
        padded = pad(plaintext, 8)
        t0 = time.perf_counter()
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        ct = cipher.encrypt(padded)
        enc_total += time.perf_counter() - t0
        t0 = time.perf_counter()
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        _ = unpad(cipher.decrypt(ct), 8)
        dec_total += time.perf_counter() - t0
    return CipherRun("Blowfish", ct, enc_total / iterations, dec_total / iterations, 128)


def _timed_chacha(plaintext: bytes, iterations: int = 3) -> CipherRun:
    key = os.urandom(32)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    enc_total = 0.0
    dec_total = 0.0
    ct = b""
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = aead.encrypt(nonce, plaintext, None)
        enc_total += time.perf_counter() - t0
        t0 = time.perf_counter()
        _ = aead.decrypt(nonce, ct, None)
        dec_total += time.perf_counter() - t0
    return CipherRun("ChaCha20", ct, enc_total / iterations, dec_total / iterations, 256)


def _timed_qsbac(plaintext: bytes, profile: BiometricProfile, iterations: int = 3) -> CipherRun:
    cipher = QSBACSPNCipher(minutiae=profile.cipher_minutiae)
    enc_total = 0.0
    dec_total = 0.0
    ct = b""
    session_json = ""
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct, sess = cipher.encrypt(plaintext)
        enc_total += time.perf_counter() - t0
        session_json = sess.to_json()
        t0 = time.perf_counter()
        _ = cipher.decrypt(ct, sess)
        dec_total += time.perf_counter() - t0
    _ = session_json
    return CipherRun("QSBAC", ct, enc_total / iterations, dec_total / iterations, 256)


def run_all_ciphers(plaintext: bytes, qsbac_profile: BiometricProfile | None) -> list[CipherRun]:
    """Execute all algorithms on the same plaintext with live timing."""
    runs: list[CipherRun] = []
    if not plaintext:
        return runs
    runs.append(_timed_aes(plaintext))
    runs.append(_timed_des(plaintext))
    runs.append(_timed_blowfish(plaintext))
    runs.append(_timed_chacha(plaintext))
    if qsbac_profile is not None:
        runs.append(_timed_qsbac(plaintext, qsbac_profile))
    return runs


def avalanche_ciphertext(plaintext: bytes, profile: BiometricProfile | None) -> dict[str, float]:
    """1-bit plaintext flip → NPCR-style changed-byte ratio per algorithm."""
    if len(plaintext) < 2:
        return {a: 0.0 for a in ALGORITHMS}
    modified = bytearray(plaintext)
    modified[0] ^= 1
    mod_bytes = bytes(modified)
    out: dict[str, float] = {}
    runs_orig = {r.algorithm: r for r in run_all_ciphers(plaintext, profile)}
    runs_mod = {r.algorithm: r for r in run_all_ciphers(mod_bytes, profile)}
    for algo in ALGORITHMS:
        o = runs_orig.get(algo)
        m = runs_mod.get(algo)
        if not o or not m or not o.ciphertext:
            out[algo] = 0.0
            continue
        c1, c2 = o.ciphertext, m.ciphertext
        n = min(len(c1), len(c2))
        if n == 0:
            out[algo] = 0.0
            continue
        changed = sum(1 for i in range(n) if c1[i] != c2[i])
        out[algo] = 100.0 * changed / n
    return out
