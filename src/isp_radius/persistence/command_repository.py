"""Tenant-scoped persistence for RADIUS command outbox records."""
from __future__ import annotations

from uuid import UUID, uuid4

from isp_radius.aaa.coa import RadiusCommand


def enqueue_radius_command(connection, *, command: RadiusCommand) -> str | None:
    """Queue a command only for a matching active session and enabled NAS.

    Caller owns the transaction. None means the requested active session/NAS
    target was not found. Duplicate command payloads return the existing ID.
    """
    tenant_id = str(UUID(command.tenant_id))
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT s.id
              FROM subscriber_sessions AS s
              JOIN nas_devices AS n
                ON n.tenant_id = s.tenant_id
               AND n.name = s.nas_identifier
             WHERE s.tenant_id = %s
               AND s.nas_identifier = %s
               AND s.session_id = %s
               AND s.username = %s
               AND s.status = 'active'
               AND n.enabled = TRUE
             FOR UPDATE OF s
            """,
            (tenant_id, command.nas_identifier, command.session_id, command.username),
        )
        if cursor.fetchone() is None:
            return None

        command_id = str(uuid4())
        cursor.execute(
            """
            INSERT INTO radius_command_outbox (
                id, tenant_id, nas_identifier, session_id, username,
                command_type, attributes, idempotency_key, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, 'pending')
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            RETURNING id
            """,
            (
                command_id,
                tenant_id,
                command.nas_identifier,
                command.session_id,
                command.username,
                command.command_type.value,
                __import__("json").dumps(command.attributes, sort_keys=True),
                command.idempotency_key,
            ),
        )
        inserted = cursor.fetchone()
        if inserted is not None:
            return str(inserted[0])

        cursor.execute(
            """
            SELECT id FROM radius_command_outbox
             WHERE tenant_id = %s AND idempotency_key = %s
            """,
            (tenant_id, command.idempotency_key),
        )
        existing = cursor.fetchone()
        return str(existing[0]) if existing else None
    finally:
        cursor.close()
