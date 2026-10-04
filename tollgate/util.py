"""Small shared helpers: UTC ISO timestamps with `Z`, and the console/edge time ranges."""
from datetime import datetime, timezone

RANGES = ("15m", "1h", "today", "all")


def iso_z(t: datetime, timespec: str = "auto") -> str:
    """An aware UTC datetime as ISO 8601 with `Z` (the audit log's timestamp form)."""
    return t.isoformat(timespec=timespec).replace("+00:00", "Z")


def now_z(timespec: str = "auto") -> str:
    return iso_z(datetime.now(timezone.utc), timespec)


def valid_range(r, default: str = "today") -> str:
    return r if r in RANGES else default
