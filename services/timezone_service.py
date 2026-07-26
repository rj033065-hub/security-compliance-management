"""
services/timezone_service.py
Timezone utility module for handling India Standard Time (Asia/Kolkata / IST).
"""
from datetime import datetime, timezone, timedelta

# Asia/Kolkata Timezone (IST, UTC+05:30) with multi-environment fallback
try:
    from zoneinfo import ZoneInfo
    IST = ZoneInfo("Asia/Kolkata")
except Exception:
    try:
        import pytz
        IST = pytz.timezone("Asia/Kolkata")
    except Exception:
        IST = timezone(timedelta(hours=5, minutes=30), "IST")

DEFAULT_FORMAT = "%d %b %Y, %I:%M:%S %p"


def get_ist_now():
    """Return current timezone-aware datetime in IST (Asia/Kolkata)."""
    return datetime.now(IST)


def to_ist(dt):
    """
    Convert any datetime object (naive or aware) to Asia/Kolkata (IST).
    If naive, assumes the input datetime was stored in UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def format_ist(dt, fmt=DEFAULT_FORMAT, default="N/A"):
    """
    Convert datetime to IST and format as a string.
    Default format: DD Mon YYYY, HH:MM:SS AM/PM (e.g. 26 Jul 2026, 11:58:59 PM).
    """
    if dt is None:
        return default
    ist_dt = to_ist(dt)
    return ist_dt.strftime(fmt)
