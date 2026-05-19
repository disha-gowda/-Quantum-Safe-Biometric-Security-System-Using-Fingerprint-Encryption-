"""CLI demo: encrypt and decrypt a message with a fingerprint image."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.cipher import QSBACCipher
from analysis.nist_tests import run_nist_suite, suite_pass_rate
from analysis.security_metrics import entropy_bits_per_byte, npcr, uaci


def main() -> None:
    parser = argparse.ArgumentParser(description="QSBAC encrypt/decrypt demo")
    parser.add_argument("--fingerprint", "-f", required=True, help="Path to fingerprint PNG")
    parser.add_argument("--message", "-m", default="Quantum-Safe Biometric Test Message")
    args = parser.parse_args()

    cipher = QSBACCipher.from_image_path(args.fingerprint)
    plaintext = args.message.encode("utf-8")
    ciphertext, session = cipher.encrypt(plaintext)
    recovered = cipher.decrypt(ciphertext, session)

    print("Plaintext: ", plaintext.decode())
    print("Ciphertext length:", len(ciphertext))
    print("Recovered: ", recovered.decode())
    print("Match:", recovered == plaintext)

    modified = bytearray(plaintext)
    modified[0] ^= 1
    ct2, _ = cipher.encrypt(bytes(modified))
    print(f"NPCR: {npcr(ciphertext, ct2):.2f}%")
    print(f"UACI: {uaci(ciphertext, ct2):.2f}%")
    print(f"Entropy: {entropy_bits_per_byte(ciphertext):.4f} bits/byte")
    nist = run_nist_suite(ciphertext)
    print(f"NIST pass rate: {suite_pass_rate(nist):.1f}%")


if __name__ == "__main__":
    main()
