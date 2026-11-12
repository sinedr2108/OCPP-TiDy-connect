"""Vrijeme: baza sprema UTC (bez zone), a prikaz i mjesečni obračun su po lokalnoj zoni (CSMS_TIMEZONE)."""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from . import config

TZ = ZoneInfo(config.TIMEZONE)


def to_local(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(TZ)


def local_to_utc(dt: datetime) -> datetime:
    """Lokalno (naivno) vrijeme -> naivni UTC za upite u bazi."""
    return dt.replace(tzinfo=TZ).astimezone(timezone.utc).replace(tzinfo=None)


def fmt(dt: datetime | None, pattern: str = "%d.%m.%Y %H:%M") -> str:
    loc = to_local(dt)
    return loc.strftime(pattern) if loc else ""


def month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    """Početak i kraj lokalnog kalendarskog mjeseca, kao naivni UTC."""
    start = datetime(year, month, 1)
    end = datetime(year + (month == 12), month % 12 + 1, 1)
    return local_to_utc(start), local_to_utc(end)


def current_month() -> tuple[int, int]:
    now = datetime.now(TZ)
    return now.year, now.month
