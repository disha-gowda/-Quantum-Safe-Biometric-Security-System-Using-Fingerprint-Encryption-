"""Display timestamps in Indian Standard Time (IST)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# IST (UTC+5:30) — fixed offset avoids tzdata dependency on Windows
IST = timezone(timedelta(hours=5, minutes=30))


def parse_db_timestamp(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_ist(value: str | datetime | None, *, fallback: str = "—") -> str:
    dt = parse_db_timestamp(value)
    if dt is None:
        return fallback
    return dt.astimezone(IST).strftime("%d %b %Y, %I:%M:%S %p IST")


def format_ist_list(rows: list[dict], *time_keys: str) -> list[dict]:
    """Return copies of dict rows with UTC timestamp fields converted to IST strings."""
    out: list[dict] = []
    for row in rows:
        item = dict(row)
        for key in time_keys:
            if key in item and item[key]:
                item[key] = format_ist(item[key])
        out.append(item)
    return out
