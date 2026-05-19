"""Clear all sessions from the database and delete stored upload images."""

from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "qsbas.db"
UPLOADS_DIR = ROOT / "data" / "uploads"


def main() -> None:
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        for table in ("decrypt_events", "message_edits", "participants", "sessions"):
            conn.execute(f"DELETE FROM {table}")
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN "
            "('sessions', 'participants', 'decrypt_events', 'message_edits')"
        )
        conn.commit()
        conn.close()
        print(f"Cleared all sessions from {DB_PATH}")
    else:
        print("No database file found.")

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    removed = 0
    for path in UPLOADS_DIR.iterdir():
        if path.is_file():
            path.unlink()
            removed += 1
    print(f"Removed {removed} uploaded image(s) from {UPLOADS_DIR}")


if __name__ == "__main__":
    main()
