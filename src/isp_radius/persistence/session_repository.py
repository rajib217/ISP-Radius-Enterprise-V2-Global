"""Atomic accounting-event ingestion and current-session projection."""
from __future__ import annotations

from uuid import UUID, uuid4

from isp_radius.aaa import accounting as aaa_accounting
from isp_radius.persistence import accounting_repository


_UPSERT_SESSION = """
INSERT INTO subscriber_sessions (
    id, tenant_id, nas_identifier, session_id, username, status,
    started_at, last_event_at, stopped_at, input_octets, output_octets,
    session_seconds, terminate_cause
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, nas_identifier, session_id) DO UPDATE SET
    username = EXCLUDED.username,
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
  AND (
      EXCLUDED.last_event_at >= subscriber_sessions.last_event_at
      OR (subscriber_sessions.started_at IS NULL AND EXCLUDED.started_at IS NOT NULL)
  )
RETURNING id
"""


def apply_session_projection(
    connection: accounting_repository.Connection,
    *,
    tenant_id: str,
    event: aaa_accounting.AccountingEvent,
) -> bool:
    """Apply a newly inserted event to its current-session projection.

    Older events cannot roll a session backwards. A stopped session is terminal;
    a later event with the same NAS/session key cannot silently reactivate it.
    """
    try:
        normalized_tenant_id = str(UUID(tenant_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id must be a valid UUID") from exc

    is_stop = event.status is aaa_accounting.AccountingStatus.STOP
    is_start = event.status is aaa_accounting.AccountingStatus.START
    cursor = connection.cursor()
    try:
        cursor.execute(
            _UPSERT_SESSION,
            (
                str(uuid4()),
                normalized_tenant_id,
                event.nas_id,
                event.session_id,
                event.username,
                "stopped" if is_stop else "active",
                event.event_time if is_start else None,
                event.event_time,
                event.event_time if is_stop else None,
                event.input_octets,
                event.output_octets,
                event.session_seconds,
                event.terminate_cause,
            ),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def record_accounting_event(
    connection: accounting_repository.Connection,
    *,
    tenant_id: str,
    event: aaa_accounting.AccountingEvent,
) -> bool:
    """Persist the event and update its projection in the caller's transaction.

    Returns False for an exact duplicate. The caller must commit or roll back
    the transaction; any projection error must roll back the event insert too.
    """
    inserted = accounting_repository.persist_accounting_event(
        connection, tenant_id=tenant_id, event=event
    )
    if not inserted:
        return False
    apply_session_projection(connection, tenant_id=tenant_id, event=event)
    return True
