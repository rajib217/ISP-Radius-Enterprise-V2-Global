"""Validated, vendor-neutral RADIUS accounting event primitives.

This module does not parse UDP packets or write to a database. It defines the
normalized event boundary that protocol adapters and persistence services will use.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class AccountingStatus(StrEnum):
    START = "Start"
    INTERIM_UPDATE = "Interim-Update"
    STOP = "Stop"


_STATUS_CODES = {
    "1": AccountingStatus.START,
    "2": AccountingStatus.STOP,
    "3": AccountingStatus.INTERIM_UPDATE,
}


def _non_negative_int(value: Any, field: str) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return parsed


def _octet_counter(attributes: dict[str, Any], low_name: str, high_name: str) -> int | None:
    low = _non_negative_int(attributes.get(low_name), low_name)
    high = _non_negative_int(attributes.get(high_name), high_name)
    if low is None and high is None:
        return None
    return ((high or 0) << 32) + (low or 0)


def _event_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Event-Timestamp must be a valid Unix timestamp") from exc
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("event_time must be ISO-8601 or Event-Timestamp Unix seconds") from exc
    else:
        raise ValueError("event_time must be ISO-8601 or Event-Timestamp Unix seconds")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("event_time must include a timezone")
    return parsed


@dataclass(frozen=True, slots=True)
class AccountingEvent:
    nas_id: str
    session_id: str
    username: str
    status: AccountingStatus
    event_time: datetime
    input_octets: int | None = None
    output_octets: int | None = None
    session_seconds: int | None = None
    terminate_cause: str | None = None

    def __post_init__(self) -> None:
        if not self.nas_id.strip():
            raise ValueError("nas_id is required")
        if not self.session_id.strip():
            raise ValueError("session_id is required")
        if not self.username.strip():
            raise ValueError("username is required")
        if self.event_time.tzinfo is None or self.event_time.utcoffset() is None:
            raise ValueError("event_time must include a timezone")
        for name in ("input_octets", "output_octets", "session_seconds"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")

    @property
    def idempotency_key(self) -> str:
        """Stable digest for retransmissions, including NASes without Event-Timestamp.

        Event time is intentionally excluded. When a NAS omits Event-Timestamp,
        the server must estimate event time from receipt time; including that
        estimate would make every retransmission look like a new event. An
        identical status/counter snapshot for one NAS session is semantically
        idempotent, even if the NAS sends it again later without counter changes.
        """
        payload = {
            "nas_id": self.nas_id.strip(),
            "session_id": self.session_id.strip(),
            "username": self.username.strip(),
            "status": self.status.value,
            "input_octets": self.input_octets,
            "output_octets": self.output_octets,
            "session_seconds": self.session_seconds,
            "terminate_cause": self.terminate_cause,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_accounting(
    attributes: dict[str, Any], *, received_at: datetime | None = None
) -> AccountingEvent:
    """Normalize decoded RADIUS Accounting-Request attributes.

    The caller must authenticate the packet source and shared secret separately.
    If Event-Timestamp is absent, receipt time minus Acct-Delay-Time is used for
    the projection timestamp. The idempotency digest remains stable regardless.
    """
    raw_status = str(attributes.get("Acct-Status-Type", "")).strip()
    status = _STATUS_CODES.get(raw_status)
    if status is None:
        try:
            status = AccountingStatus(raw_status)
        except ValueError as exc:
            raise ValueError("unsupported or missing Acct-Status-Type") from exc

    nas_id = str(attributes.get("NAS-Identifier") or attributes.get("NAS-IP-Address") or "").strip()
    session_id = str(attributes.get("Acct-Session-Id") or "").strip()
    username = str(attributes.get("User-Name") or "").strip()
    raw_time = attributes.get("Event-Timestamp")
    if raw_time in (None, ""):
        raw_time = attributes.get("event_time")

    if raw_time in (None, ""):
        base_time = received_at or datetime.now(UTC)
        if base_time.tzinfo is None or base_time.utcoffset() is None:
            raise ValueError("received_at must include a timezone")
        delay = _non_negative_int(attributes.get("Acct-Delay-Time"), "Acct-Delay-Time") or 0
        event_time = base_time - timedelta(seconds=delay)
    else:
        event_time = _event_time(raw_time)

    return AccountingEvent(
        nas_id=nas_id,
        session_id=session_id,
        username=username,
        status=status,
        event_time=event_time,
        input_octets=_octet_counter(attributes, "Acct-Input-Octets", "Acct-Input-Gigawords"),
        output_octets=_octet_counter(attributes, "Acct-Output-Octets", "Acct-Output-Gigawords"),
        session_seconds=_non_negative_int(attributes.get("Acct-Session-Time"), "Acct-Session-Time"),
        terminate_cause=(
            str(attributes["Acct-Terminate-Cause"])
            if attributes.get("Acct-Terminate-Cause")
            else None
        ),
    )
