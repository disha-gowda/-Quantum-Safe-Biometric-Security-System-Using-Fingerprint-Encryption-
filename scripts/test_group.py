"""Quick test: group encrypt/decrypt with sample fingerprint."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.biometric_profile import build_profile
from qsbas.constants import MINUTIAE_COUNT
from qsbas.group_cipher import group_decrypt_by_fingerprint, group_encrypt

fp = str(ROOT / "data" / "sample_fingerprint.png")
if not Path(fp).exists():
    print("Run generate_sample_fingerprint.py first")
    sys.exit(1)

alice = build_profile("Alice", fp, is_encryptor=True)
assert len(alice.cipher_minutiae) == MINUTIAE_COUNT

msg = b"Group secret message"
pkg = group_encrypt(msg, [alice])
probe = build_profile("_probe_", fp)
plain, name = group_decrypt_by_fingerprint(pkg, probe)
assert plain == msg and name == "Alice"
print("OK: fingerprint-only decrypt identified", name)
