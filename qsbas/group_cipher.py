"""
Multi-user encryption: QSBAC-SPN full message encryption per authorized participant.

Pipeline: Fingerprint → QSBAC-SPN → Ciphertext
Access: live biometric match + enrolled profile → decrypt participant copy.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import List

from qsbas.biometric_profile import (
    BiometricProfile,
    identify_participant,
    profiles_match,
    verify_decrypt_authorization,
)
from qsbas.cipher import CipherSession, QSBACSPNCipher
from qsbas.constants import MAX_AUTHORIZED_USERS

# 12-byte marker stored in message_nonce (replaces AES-GCM IV field in JSON).
SPN_ENGINE_MARKER = b"QSBAC-SPN\x00"


@dataclass
class UserKeyWrap:
    """Per-user QSBAC-SPN ciphertext and session (JSON field names kept for DB compat)."""

    name: str
    is_encryptor: bool
    profile_json: str
    wrapped_key: str  # hex QSBAC-SPN ciphertext for this participant
    wrapper_session_json: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GroupEncryptedMessage:
    message_ciphertext: bytes  # encryptor canonical ciphertext (metrics / display)
    message_nonce: bytes  # engine marker, not an AES nonce
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


def _spn_encrypt_for_user(plaintext: bytes, profile: BiometricProfile) -> tuple[bytes, CipherSession]:
    cipher = QSBACSPNCipher(minutiae=profile.cipher_minutiae)
    return cipher.encrypt(plaintext)


def _spn_decrypt_for_user(ciphertext_hex: str, session_json: str, profile: BiometricProfile) -> bytes:
    cipher = QSBACSPNCipher(minutiae=profile.cipher_minutiae)
    session = CipherSession.from_json(session_json)
    return cipher.decrypt(bytes.fromhex(ciphertext_hex), session)


def _encryptor_profile(participants: List[BiometricProfile]) -> BiometricProfile:
    for profile in participants:
        if profile.is_encryptor:
            return profile
    return participants[0]


def group_encrypt(plaintext: bytes, participants: List[BiometricProfile]) -> GroupEncryptedMessage:
    if not participants or len(participants) > MAX_AUTHORIZED_USERS:
        raise ValueError(f"Provide 1–{MAX_AUTHORIZED_USERS} participants")

    encryptor = _encryptor_profile(participants)
    primary_ct, _ = _spn_encrypt_for_user(plaintext, encryptor)

    wraps: List[UserKeyWrap] = []
    for profile in participants:
        user_ct, session = _spn_encrypt_for_user(plaintext, profile)
        wraps.append(
            UserKeyWrap(
                name=profile.name,
                is_encryptor=profile.is_encryptor,
                profile_json=profile.to_json(),
                wrapped_key=user_ct.hex(),
                wrapper_session_json=session.to_json(),
            )
        )
    return GroupEncryptedMessage(primary_ct, SPN_ENGINE_MARKER, wraps)


def _decrypt_user_wrap(wrap: UserKeyWrap) -> bytes:
    stored = BiometricProfile.from_json(wrap.profile_json)
    return _spn_decrypt_for_user(wrap.wrapped_key, wrap.wrapper_session_json, stored)


def group_decrypt(
    package: GroupEncryptedMessage,
    probe: BiometricProfile,
) -> bytes:
    probe_name = probe.name.strip().lower()
    candidates = [w for w in package.user_wraps if w.name.strip().lower() == probe_name]
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

    return _decrypt_user_wrap(matched)


def group_decrypt_by_fingerprint(
    package: GroupEncryptedMessage,
    probe: BiometricProfile,
    *,
    encryptor_only: bool = False,
) -> tuple[bytes, str]:
    """Decrypt only when probe matches exactly one enrolled authorized profile."""
    stored_profiles = [BiometricProfile.from_json(w.profile_json) for w in package.user_wraps]
    identified = identify_participant(stored_profiles, probe, encryptor_only=encryptor_only)
    verify_decrypt_authorization(identified, probe)

    wrap = next(
        w
        for w in package.user_wraps
        if w.name.strip().lower() == identified.name.strip().lower()
    )
    try:
        return _decrypt_user_wrap(wrap), identified.name
    except Exception as exc:
        raise PermissionError(
            "Fingerprint does not match any authorized profile for this session"
        ) from exc
