"""Pack/unpack text, document, and text+document envelopes."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.payload import ContentPayload, pack_payload, preview_text, replace_text, unpack_payload


def main() -> None:
    text = ContentPayload(mode="text", text="hello secret")
    raw = pack_payload(text)
    back = unpack_payload(raw)
    assert back.mode == "text" and back.text == "hello secret" and not back.has_file

    legacy = unpack_payload(b"plain-only")
    assert legacy.mode == "text" and legacy.text == "plain-only"

    csv_bytes = b"a,b\n1,2\n"
    doc = ContentPayload(
        mode="document",
        text="",
        filename="sheet.csv",
        mime="text/csv",
        file_bytes=csv_bytes,
    )
    back = unpack_payload(pack_payload(doc))
    assert back.mode == "document" and back.file_bytes == csv_bytes and back.filename == "sheet.csv"
    assert "[document] sheet.csv" in preview_text(back)

    both = ContentPayload(
        mode="both",
        text="caption",
        filename="clip.mp4",
        mime="video/mp4",
        file_bytes=b"\x00\x01video",
    )
    back = unpack_payload(pack_payload(both))
    assert back.mode == "both" and back.text == "caption" and back.file_bytes == b"\x00\x01video"

    updated = replace_text(back, "new caption")
    assert updated.mode == "both" and updated.file_bytes == back.file_bytes

    import importlib.util

    spec = importlib.util.spec_from_file_location("test_dual_factor", ROOT / "scripts" / "test_dual_factor.py")
    dual = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dual)
    from qsbas.group_cipher import group_decrypt_by_fingerprint, group_encrypt

    blob = pack_payload(doc)
    pkg_face = group_encrypt(blob, [dual.make_face_only("Cara", 5, is_encryptor=True)])
    recovered, name = group_decrypt_by_fingerprint(pkg_face, dual.make_face_only("_probe_", 5))
    assert name == "Cara" and unpack_payload(recovered).file_bytes == csv_bytes

    pkg_fp = group_encrypt(blob, [dual.make_fp_only("Bob", 3, is_encryptor=True)])
    recovered, name = group_decrypt_by_fingerprint(pkg_fp, dual.make_fp_only("_probe_", 3))
    assert name == "Bob" and unpack_payload(recovered).file_bytes == csv_bytes
    print("ALL PAYLOAD CASES PASSED")


if __name__ == "__main__":
    main()
