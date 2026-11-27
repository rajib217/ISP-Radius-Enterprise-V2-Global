"""DB-API repository for normalized RADIUS accounting events.

The caller owns the database transaction and must pass the authenticated tenant ID.
This module deliberately stores no password or raw RADIUS secret attributes.
"""
from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID, uuid4

from isp_radius.aaa.accounting import AccountingEvent


class Cursor(Protocol):
    def execute(self, operation: str, parameters: tuple[Any, ...]) -> Any: ...

    def fetchone(self) -> Any: ...

    def close(self) -> Any: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...


_INSERT_EVENT = """
INSERT INTO accounting_events (
    id, tenant_id, idempotency_key, nas_identifier, session_id, username,
    status, event_time, input_octets, output_octets, session_seconds, terminate_cause
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id
"""


def insert_accounting_event(
    connection: Connection, *, tenant_id: str, event: AccountingEvent
) -> str | None:
    """Insert an event and return its database ID, or None for a duplicate."""
    try:
        normalized_tenant_id = str(UUID(tenant_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id must be a valid UUID") from exc

    cursor = connection.cursor()
    try:
        cursor.execute(
            _INSERT_EVENT,
            (
                str(uuid4()), normalized_tenant_id, event.idempotency_key,
                event.nas_id, event.session_id, event.username, event.status.value,
                event.event_time, event.input_octets, event.output_octets,
                event.session_seconds, event.terminate_cause,
            ),
        )
        row = cursor.fetchone()
        return str(row[0]) if row is not None else None
    finally:
        cursor.close()


def persist_accounting_event(
    connection: Connection, *, tenant_id: str, event: AccountingEvent
) -> bool:
    """Insert one event; return False for an exact duplicate.

    The transaction is intentionally not committed here. The application service
    should persist the event and update its session projection atomically.
    """
    return insert_accounting_event(connection, tenant_id=tenant_id, event=event) is not None
