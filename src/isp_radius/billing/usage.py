"""Exact, non-financial usage deltas from cumulative RADIUS counters.

RADIUS octet counters are cumulative per session. This module converts two
ordered snapshots into a delta without inventing usage for missing counters
or silently accepting counter resets. Pricing and invoice posting belong to
separate billing services.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

_MAX_BIGINT = 0x7FFFFFFFFFFFFFFF


class CounterRegressionError(ValueError):
    """Raised when a cumulative NAS counter moves backwards."""


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    nas_id: str
    session_id: str
    username: str
    event_time: datetime
    input_octets: int | None
    output_octets: int | None
    session_seconds: int | None = None

    def __post_init__(self) -> None:
        for field in ("nas_id", "session_id", "username"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} is required")
        if not isinstance(self.event_time, datetime):
            raise TypeError("event_time must be a datetime")
        if self.event_time.tzinfo is None or self.event_time.utcoffset() is None:
            raise ValueError("event_time must be timezone-aware")
        for field in ("input_octets", "output_octets"):
            value = getattr(self, field)
            if value is not None and (
                type(value) is not int or not 0 <= value <= _MAX_BIGINT
            ):
                raise ValueError(f"{field} must fit a non-negative PostgreSQL BIGINT")
        if self.session_seconds is not None and (
            type(self.session_seconds) is not int or self.session_seconds < 0
        ):
            raise ValueError("session_seconds must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class UsageDelta:
    nas_id: str
    session_id: str
    username: str
    period_start: datetime
    period_end: datetime
    input_bytes: int | None
    output_bytes: int | None
    session_seconds: int | None

    @property
    def total_bytes(self) -> int | None:
        if self.input_bytes is None or self.output_bytes is None:
            return None
        return self.input_bytes + self.output_bytes

    @property
    def total_gib(self) -> Decimal | None:
        total = self.total_bytes
        if total is None:
            return None
        return Decimal(total) / Decimal(1024**3)


def _delta(current: int | None, previous: int | None, field: str) -> int | None:
    if current is None or previous is None:
        return None
    if current < previous:
        raise CounterRegressionError(
            f"{field} decreased from {previous} to {current}; usage cannot be inferred"
        )
    return current - previous


def calculate_usage_delta(
    previous: UsageSnapshot, current: UsageSnapshot
) -> UsageDelta:
    """Calculate bytes and duration between two snapshots of the same session.

    Missing either side of a counter yields None, not a fabricated zero.
    Counter rollback raises an explicit error and requires reconciliation.
    """
    identity = ("nas_id", "session_id", "username")
    if any(getattr(previous, field) != getattr(current, field) for field in identity):
        raise ValueError("usage snapshots must belong to the same NAS session and username")
    if current.event_time <= previous.event_time:
        raise ValueError("current snapshot must be later than previous snapshot")

    return UsageDelta(
        nas_id=current.nas_id,
        session_id=current.session_id,
        username=current.username,
        period_start=previous.event_time,
        period_end=current.event_time,
        input_bytes=_delta(current.input_octets, previous.input_octets, "input_octets"),
        output_bytes=_delta(current.output_octets, previous.output_octets, "output_octets"),
        session_seconds=_delta(
            current.session_seconds, previous.session_seconds, "session_seconds"
        ),
    )
