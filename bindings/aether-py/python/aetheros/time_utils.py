"""UTC timestamp helpers.

AetherOS uses RFC3339 timestamps with a `Z` suffix everywhere. Because the Rust core
compares expiry timestamps lexicographically, all timestamps must be normalized to
UTC with the same format so lexical order matches chronological order.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now_rfc3339() -> str:
    """Return the current UTC time as an RFC3339 string with second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rfc3339_in(seconds: float) -> str:
    """Return an RFC3339 string `seconds` from now (UTC), second precision."""
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")
