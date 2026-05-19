"""SQLite persistence for group sessions, edits, and decrypt audit."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, List, Optional

from qsbas.constants import EDIT_WINDOW_SECONDS

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "qsbas.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if cols and "group_payload" not in cols:
        conn.execute("ALTER TABLE sessions RENAME TO sessions_legacy")


def init_db() -> None:
    with get_connection() as conn:
        _migrate(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT,
                encryptor_name TEXT NOT NULL,
                current_plaintext TEXT,
                group_payload TEXT NOT NULL,
                fp_encryptor_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                edit_deadline TEXT
            );

            CREATE TABLE IF NOT EXISTS participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                slot INTEGER NOT NULL,
                name TEXT NOT NULL,
                is_encryptor INTEGER DEFAULT 0,
                profile_json TEXT NOT NULL,
                fp_path TEXT,
                iris_path TEXT,
                face_path TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE TABLE IF NOT EXISTS decrypt_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                decryptor_name TEXT NOT NULL,
                decrypted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE TABLE IF NOT EXISTS message_edits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                old_text TEXT NOT NULL,
                new_text TEXT NOT NULL,
                edited_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            """
        )
        conn.commit()


def save_group_session(
    label: str,
    encryptor_name: str,
    plaintext: str,
    group_payload_json: str,
    fp_encryptor_path: str,
    participants: List[dict],
) -> int:
    created = datetime.utcnow()
    deadline = created + timedelta(seconds=EDIT_WINDOW_SECONDS)
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO sessions (
                label, encryptor_name, current_plaintext, group_payload,
                fp_encryptor_path, edit_deadline
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                label,
                encryptor_name,
                plaintext,
                group_payload_json,
                fp_encryptor_path,
                deadline.isoformat(),
            ),
        )
        session_id = int(cur.lastrowid)
        for p in participants:
            conn.execute(
                """
                INSERT INTO participants (
                    session_id, slot, name, is_encryptor, profile_json,
                    fp_path, iris_path, face_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    p["slot"],
                    p["name"],
                    1 if p.get("is_encryptor") else 0,
                    p["profile_json"],
                    p.get("fp_path"),
                    p.get("iris_path"),
                    p.get("face_path"),
                ),
            )
        conn.commit()
        return session_id


def get_session(session_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()


def get_participants(session_id: int) -> List[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM participants WHERE session_id = ? ORDER BY slot",
            (session_id,),
        ).fetchall()


def list_sessions(limit: int = 50):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT s.id, s.label, s.encryptor_name, s.created_at, s.edit_deadline,
                   (SELECT COUNT(*) FROM decrypt_events d WHERE d.session_id = s.id) AS decrypt_count
            FROM sessions s ORDER BY s.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()


def log_decrypt(session_id: int, decryptor_name: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO decrypt_events (session_id, decryptor_name) VALUES (?, ?)",
            (session_id, decryptor_name),
        )
        conn.commit()


def get_decrypt_events(session_id: int) -> List[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT decryptor_name, decrypted_at FROM decrypt_events WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()


def get_message_edits(session_id: int) -> List[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT old_text, new_text, edited_at FROM message_edits WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()


def can_edit(session_id: int) -> bool:
    """True only within the post-encryption window for editing message plaintext."""
    row = get_session(session_id)
    if not row or not row["edit_deadline"]:
        return False
    deadline = datetime.fromisoformat(row["edit_deadline"])
    return datetime.utcnow() <= deadline


def update_message(
    session_id: int,
    old_text: str,
    new_text: str,
    group_payload_json: str,
) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET current_plaintext = ?, group_payload = ? WHERE id = ?",
            (new_text, group_payload_json, session_id),
        )
        conn.execute(
            "INSERT INTO message_edits (session_id, old_text, new_text) VALUES (?, ?, ?)",
            (session_id, old_text, new_text),
        )
        conn.commit()


def chat_payload(session_id: int) -> dict[str, Any]:
    row = get_session(session_id)
    if not row:
        return {}
    participants = get_participants(session_id)
    decrypts = get_decrypt_events(session_id)
    edits = get_message_edits(session_id)
    return {
        "session": dict(row),
        "participants": [dict(p) for p in participants],
        "decrypt_events": [dict(d) for d in decrypts],
        "edits": [dict(e) for e in edits],
    }


def delete_session(session_id: int) -> bool:
    with get_connection() as conn:
        conn.execute("DELETE FROM decrypt_events WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM message_edits WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM participants WHERE session_id = ?", (session_id,))
        cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        return cur.rowcount > 0


def _participant_profiles(session_id: int):
    from qsbas.biometric_profile import BiometricProfile

    rows = get_participants(session_id)
    return [BiometricProfile.from_json(p["profile_json"]) for p in rows]


def reencrypt_session(session_id: int, profiles, group_payload_json: str, plaintext: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET current_plaintext = ?, group_payload = ? WHERE id = ?",
            (plaintext, group_payload_json, session_id),
        )
        conn.commit()


def replace_participants(session_id: int, participant_meta: List[dict]) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM participants WHERE session_id = ?", (session_id,))
        for p in participant_meta:
            conn.execute(
                """
                INSERT INTO participants (
                    session_id, slot, name, is_encryptor, profile_json,
                    fp_path, iris_path, face_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    p["slot"],
                    p["name"],
                    1 if p.get("is_encryptor") else 0,
                    p["profile_json"],
                    p.get("fp_path"),
                    p.get("iris_path"),
                    p.get("face_path"),
                ),
            )
        conn.commit()


def add_session_decryptor(session_id: int, participant_meta: dict) -> None:
    from qsbas.biometric_profile import BiometricProfile
    from qsbas.group_cipher import group_encrypt

    row = get_session(session_id)
    if not row:
        raise ValueError("Session not found")
    participants = get_participants(session_id)
    if len(participants) >= 5:
        raise ValueError("Maximum 5 authorized users per session")
    name_lower = participant_meta["name"].strip().lower()
    if any(p["name"].strip().lower() == name_lower for p in participants):
        raise ValueError("A participant with this name already exists")

    profiles = _participant_profiles(session_id)
    new_profile = BiometricProfile.from_json(participant_meta["profile_json"])
    profiles.append(new_profile)
    plaintext = row["current_plaintext"] or ""
    package = group_encrypt(plaintext.encode("utf-8"), profiles)
    reencrypt_session(session_id, profiles, package.to_json(), plaintext)

    all_meta = [
        {
            "slot": p["slot"],
            "name": p["name"],
            "is_encryptor": bool(p["is_encryptor"]),
            "profile_json": p["profile_json"],
            "fp_path": p["fp_path"],
            "iris_path": p["iris_path"],
            "face_path": p["face_path"],
        }
        for p in participants
    ]
    all_meta.append(
        {
            "slot": len(all_meta),
            "name": participant_meta["name"],
            "is_encryptor": False,
            "profile_json": participant_meta["profile_json"],
            "fp_path": participant_meta.get("fp_path"),
            "iris_path": participant_meta.get("iris_path"),
            "face_path": participant_meta.get("face_path"),
        }
    )
    replace_participants(session_id, all_meta)


def remove_session_decryptor(session_id: int, decryptor_name: str) -> None:
    from qsbas.group_cipher import group_encrypt

    row = get_session(session_id)
    if not row:
        raise ValueError("Session not found")
    participants = get_participants(session_id)
    target = decryptor_name.strip().lower()
    victim = next((p for p in participants if p["name"].strip().lower() == target), None)
    if not victim:
        raise ValueError("Decryptor not found in this session")
    if victim["is_encryptor"]:
        raise ValueError("Cannot remove the encryptor from a session")

    from qsbas.biometric_profile import BiometricProfile

    remaining = [p for p in participants if p["name"].strip().lower() != target]
    profiles = [BiometricProfile.from_json(p["profile_json"]) for p in remaining]
    plaintext = row["current_plaintext"] or ""
    package = group_encrypt(plaintext.encode("utf-8"), profiles)
    reencrypt_session(session_id, profiles, package.to_json(), plaintext)

    meta = [
        {
            "slot": i,
            "name": p["name"],
            "is_encryptor": bool(p["is_encryptor"]),
            "profile_json": p["profile_json"],
            "fp_path": p["fp_path"],
            "iris_path": p["iris_path"],
            "face_path": p["face_path"],
        }
        for i, p in enumerate(remaining)
    ]
    replace_participants(session_id, meta)


def verify_encryptor(session_id: int, encryptor_name: str, fp_path: str) -> bool:
    from qsbas.biometric_profile import BiometricProfile, build_profile, profiles_match

    row = get_session(session_id)
    if not row:
        return False
    if encryptor_name.strip().lower() != row["encryptor_name"].strip().lower():
        return False
    probe = build_profile(encryptor_name, fp_path)
    for p in get_participants(session_id):
        if not p["is_encryptor"]:
            continue
        stored = BiometricProfile.from_json(p["profile_json"])
        if profiles_match(stored, probe):
            return True
    return False
