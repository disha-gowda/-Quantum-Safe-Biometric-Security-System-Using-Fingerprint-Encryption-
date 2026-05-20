"""Multi-user (5) encryption: AES message body + per-user QSBAC key wrapping."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qsbas.biometric_profile import BiometricProfile, identify_participant, profiles_match
from qsbas.cipher import CipherSession, QSBACCipher
from qsbas.constants import MAX_AUTHORIZED_USERS


@dataclass
class UserKeyWrap:
    name: str
    is_encryptor: bool
    profile_json: str
    wrapped_key: str
    wrapper_session_json: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GroupEncryptedMessage:
    message_ciphertext: bytes
    message_nonce: bytes
    user_wraps: List[UserKeyWrap]

    def to_json(self) -> str:
        return json.dumps(
            {
                "message_ciphertext": self.message_ciphertext.hex(),
                "message_nonce": self.message_nonce.hex(),
                "user_wraps": [w.to_dict() for w in self.user_wraps],
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> "GroupEncryptedMessage":
        data = json.loads(raw)
        return cls(
            message_ciphertext=bytes.fromhex(data["message_ciphertext"]),
            message_nonce=bytes.fromhex(data["message_nonce"]),
            user_wraps=[UserKeyWrap(**w) for w in data["user_wraps"]],
        )


def _wrap_key_for_user(master_key: bytes, profile: BiometricProfile) -> Tuple[bytes, CipherSession]:
    cipher = QSBACCipher(minutiae=profile.cipher_minutiae)
    return cipher.encrypt(master_key)


def group_encrypt(plaintext: bytes, participants: List[BiometricProfile]) -> GroupEncryptedMessage:
    if not participants or len(participants) > MAX_AUTHORIZED_USERS:
        raise ValueError(f"Provide 1–{MAX_AUTHORIZED_USERS} participants")

    master_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    msg_ct = AESGCM(master_key).encrypt(nonce, plaintext, None)

    wraps: List[UserKeyWrap] = []
    for profile in participants:
        wrapped, session = _wrap_key_for_user(master_key, profile)
        wraps.append(
            UserKeyWrap(
                name=profile.name,
                is_encryptor=profile.is_encryptor,
                profile_json=profile.to_json(),
                wrapped_key=wrapped.hex(),
                wrapper_session_json=session.to_json(),
            )
        )
    return GroupEncryptedMessage(msg_ct, nonce, wraps)


def _unwrap_and_decrypt(package: GroupEncryptedMessage, wrap: UserKeyWrap) -> bytes:
    stored = BiometricProfile.from_json(wrap.profile_json)
    cipher = QSBACCipher(minutiae=stored.cipher_minutiae)
    session = CipherSession.from_json(wrap.wrapper_session_json)
    master_key = cipher.decrypt(bytes.fromhex(wrap.wrapped_key), session)
    return AESGCM(master_key).decrypt(package.message_nonce, package.message_ciphertext, None)


def group_decrypt(
    package: GroupEncryptedMessage,
    probe: BiometricProfile,
) -> bytes:
    probe_name = probe.name.strip().lower()
    candidates = [
        w for w in package.user_wraps if w.name.strip().lower() == probe_name
    ]
    if not candidates:
        raise PermissionError("Name not authorized for this session")

    matched: UserKeyWrap | None = None
    for wrap in candidates:
        stored = BiometricProfile.from_json(wrap.profile_json)
        if profiles_match(stored, probe):
            matched = wrap
            break
    if not matched:
        raise PermissionError("Fingerprint does not match enrolled profile for this name")

    return _unwrap_and_decrypt(package, matched)


def group_decrypt_by_fingerprint(
    package: GroupEncryptedMessage,
    probe: BiometricProfile,
    *,
    encryptor_only: bool = False,
) -> tuple[bytes, str]:
    """Decrypt by fingerprint only; system identifies the authorized user."""
    stored_profiles = [BiometricProfile.from_json(w.profile_json) for w in package.user_wraps]
    identified = identify_participant(stored_profiles, probe, encryptor_only=encryptor_only)
    wrap = next(w for w in package.user_wraps if w.name.strip().lower() == identified.name.strip().lower())
    return _unwrap_and_decrypt(package, wrap), identified.name
