"""Atomic accounting-event ingestion and current-session projection."""
# ruff: noqa: I001
from __future__ import annotations

import logging
from uuid import UUID, uuid4

from isp_radius.aaa.accounting import AccountingEvent, AccountingStatus
from isp_radius.billing.usage import (
    CounterRegressionError,
    UsageSnapshot,
    calculate_usage_delta,
)
from isp_radius.persistence.accounting_repository import (
    Connection,
    insert_accounting_event,
    persist_accounting_event,
)
from isp_radius.persistence.usage_repository import persist_usage_delta

logger = logging.getLogger(__name__)


_UPSERT_SESSION = """
INSERT INTO subscriber_sessions (
    id, tenant_id, nas_identifier, session_id, username, status,
    started_at, last_event_at, stopped_at, input_octets, output_octets,
    session_seconds, terminate_cause
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, nas_identifier, session_id) DO UPDATE SET
    status = CASE WHEN EXCLUDED.status = 'stopped' THEN 'stopped'
                  ELSE subscriber_sessions.status END,
    started_at = COALESCE(subscriber_sessions.started_at, EXCLUDED.started_at),
    last_event_at = GREATEST(subscriber_sessions.last_event_at, EXCLUDED.last_event_at),
    stopped_at = CASE WHEN EXCLUDED.status = 'stopped'
                      THEN EXCLUDED.stopped_at
                      ELSE subscriber_sessions.stopped_at END,
    input_octets = GREATEST(subscriber_sessions.input_octets, EXCLUDED.input_octets),
    output_octets = GREATEST(subscriber_sessions.output_octets, EXCLUDED.output_octets),
    session_seconds = GREATEST(subscriber_sessions.session_seconds, EXCLUDED.session_seconds),
    terminate_cause = COALESCE(EXCLUDED.terminate_cause, subscriber_sessions.terminate_cause),
    updated_at = now()
WHERE subscriber_sessions.status = 'active'
  AND subscriber_sessions.username = EXCLUDED.username
  AND (
      EXCLUDED.last_event_at >= subscriber_sessions.last_event_at
      OR (
          EXCLUDED.status = 'active'
          AND subscriber_sessions.started_at IS NULL
          AND EXCLUDED.started_at IS NOT NULL
      )
  )
RETURNING id
"""

_PREVIOUS_SNAPSHOT = """
SELECT id, event_time, input_octets, output_octets, session_seconds
  FROM accounting_events
 WHERE tenant_id = %s
   AND nas_identifier = %s
   AND session_id = %s
   AND username = %s
   AND event_time < %s
 ORDER BY event_time DESC, received_at DESC, id DESC
 LIMIT 1
"""

_HAS_LATER_EVENT = """
SELECT 1
  FROM accounting_events
 WHERE tenant_id = %s
   AND nas_identifier = %s
   AND session_id = %s
   AND username = %s
   AND event_time > %s
 LIMIT 1
"""


def _fetch_one(connection: Connection, statement: str, parameters: tuple) -> tuple | None:
    cursor = connection.cursor()
    try:
        cursor.execute(statement, parameters)
        return cursor.fetchone()
    finally:
        cursor.close()


def apply_session_projection(
    connection: Connection,
    *,
    tenant_id: str,
    event: AccountingEvent,
) -> bool:
    """Apply a newly inserted event to its current-session projection.

    Older events cannot roll a session backwards. A stopped session is terminal;
    a later event with the same NAS/session key cannot silently reactivate it.
    """
    try:
        normalized_tenant_id = str(UUID(tenant_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id must be a valid UUID") from exc

    is_stop = event.status is AccountingStatus.STOP
    is_start = event.status is AccountingStatus.START
    cursor = connection.cursor()
    try:
        cursor.execute(
            _UPSERT_SESSION,
            (
                str(uuid4()), normalized_tenant_id, event.nas_id, event.session_id,
                event.username, "stopped" if is_stop else "active",
                event.event_time if is_start else None, event.event_time,
                event.event_time if is_stop else None, event.input_octets,
                event.output_octets, event.session_seconds, event.terminate_cause,
            ),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def record_accounting_event(
    connection: Connection,
    *,
    tenant_id: str,
    event: AccountingEvent,
) -> bool:
    """Persist the event and update its projection in the caller's transaction."""
    inserted = persist_accounting_event(connection, tenant_id=tenant_id, event=event)
    if not inserted:
        return False
    apply_session_projection(connection, tenant_id=tenant_id, event=event)
    return True


def record_accounting_event_with_usage(
    connection: Connection,
    *,
    tenant_id: str,
    event: AccountingEvent,
) -> bool:
    """Atomically persist an event, session projection and sequential usage delta.

    A transaction-scoped advisory lock serializes events for the same tenant/NAS/
    session. Late events remain in the immutable event journal but do not create
    overlapping usage intervals. Counter resets are logged for reconciliation;
    they never become negative usage or block Accounting-Response.
    """
    normalized_tenant_id = str(UUID(tenant_id))
    lock_key = f"{normalized_tenant_id}:{event.nas_id}:{event.session_id}"
    _fetch_one(
        connection,
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (lock_key,),
    )

    event_id = insert_accounting_event(
        connection, tenant_id=normalized_tenant_id, event=event
    )
    if event_id is None:
        return False

    apply_session_projection(connection, tenant_id=normalized_tenant_id, event=event)

    identity = (
        normalized_tenant_id, event.nas_id, event.session_id,
        event.username, event.event_time,
    )
    later = _fetch_one(connection, _HAS_LATER_EVENT, identity)
    if later is not None:
        logger.warning(
            "Late RADIUS accounting event retained without usage delta",
            extra={"tenant_id": normalized_tenant_id, "accounting_event_id": event_id},
        )
        return True

    previous = _fetch_one(connection, _PREVIOUS_SNAPSHOT, identity)
    if previous is None:
        return True

    previous_id, previous_time, previous_input, previous_output, previous_seconds = previous
    previous_snapshot = UsageSnapshot(
        nas_id=event.nas_id,
        session_id=event.session_id,
        username=event.username,
        event_time=previous_time,
        input_octets=previous_input,
        output_octets=previous_output,
        session_seconds=previous_seconds,
    )
    current_snapshot = UsageSnapshot(
        nas_id=event.nas_id,
        session_id=event.session_id,
        username=event.username,
        event_time=event.event_time,
        input_octets=event.input_octets,
        output_octets=event.output_octets,
        session_seconds=event.session_seconds,
    )
    try:
        delta = calculate_usage_delta(previous_snapshot, current_snapshot)
    except CounterRegressionError:
        logger.exception(
            "RADIUS cumulative counter regressed; usage delta requires reconciliation",
            extra={"tenant_id": normalized_tenant_id, "accounting_event_id": event_id},
        )
        return True

    persist_usage_delta(
        connection,
        tenant_id=normalized_tenant_id,
        previous_event_id=str(previous_id),
        current_event_id=event_id,
        delta=delta,
    )
    return True
