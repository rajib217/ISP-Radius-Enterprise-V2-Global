"""Tenant-scoped, idempotent persistence for calculated usage deltas."""
from __future__ import annotations

from uuid import UUID, uuid4

from isp_radius.billing.usage import UsageDelta
from isp_radius.persistence.accounting_repository import Connection

_INSERT_USAGE_DELTA = """
INSERT INTO subscriber_usage_deltas (
    id, tenant_id, nas_identifier, session_id, username,
    previous_event_id, current_event_id, period_start, period_end,
    input_bytes, output_bytes, session_seconds
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, current_event_id) DO NOTHING
RETURNING id
"""


def persist_usage_delta(
    connection: Connection,
    *,
    tenant_id: str,
    previous_event_id: str,
    current_event_id: str,
    delta: UsageDelta,
) -> bool:
    """Insert a calculated delta; return False if its current event was handled.

    Both source events must exist in the same tenant. Composite foreign keys
    enforce this at the database boundary. The caller owns the transaction.
    """
    try:
        normalized_tenant_id = str(UUID(tenant_id))
        normalized_previous_id = str(UUID(previous_event_id))
        normalized_current_id = str(UUID(current_event_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id and event IDs must be valid UUIDs") from exc

    if normalized_previous_id == normalized_current_id:
        raise ValueError("previous_event_id and current_event_id must differ")

    for field, maximum in (("nas_id", 253), ("session_id", 256), ("username", 128)):
        value = getattr(delta, field)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ValueError(f"{field} must be a non-empty string of at most {maximum} characters")

    if (
        delta.period_start.tzinfo is None
        or delta.period_start.utcoffset() is None
        or delta.period_end.tzinfo is None
        or delta.period_end.utcoffset() is None
        or delta.period_end <= delta.period_start
    ):
        raise ValueError("usage period must have timezone-aware, increasing timestamps")

    for field in ("input_bytes", "output_bytes", "session_seconds"):
        value = getattr(delta, field)
        if value is not None and (type(value) is not int or not 0 <= value <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError(f"{field} must be a non-negative PostgreSQL BIGINT or None")

    cursor = connection.cursor()
    try:
        cursor.execute(
            _INSERT_USAGE_DELTA,
            (
                str(uuid4()), normalized_tenant_id, delta.nas_id, delta.session_id,
                delta.username, normalized_previous_id, normalized_current_id,
                delta.period_start, delta.period_end, delta.input_bytes,
                delta.output_bytes, delta.session_seconds,
            ),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()
