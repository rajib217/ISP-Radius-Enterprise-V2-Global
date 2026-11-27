"""Tenant-scoped persistence and concurrency-safe leasing for RADIUS commands."""
from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID, uuid4

from isp_radius.aaa.coa import RadiusCommand


@dataclass(frozen=True, slots=True)
class LeasedRadiusCommand:
    id: str
    tenant_id: str
    nas_identifier: str
    session_id: str
    username: str
    command_type: str
    attributes: dict[str, str]
    attempts: int
    lease_token: str


def enqueue_radius_command(connection, *, command: RadiusCommand) -> str | None:
    """Queue only for a matching active session on an enabled NAS."""
    tenant_id = str(UUID(command.tenant_id))
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT s.id FROM subscriber_sessions AS s
            JOIN nas_devices AS n ON n.tenant_id = s.tenant_id AND n.name = s.nas_identifier
            WHERE s.tenant_id = %s AND s.nas_identifier = %s AND s.session_id = %s
              AND s.username = %s AND s.status = 'active' AND n.enabled = TRUE
            FOR UPDATE OF s
            """,
            (tenant_id, command.nas_identifier, command.session_id, command.username),
        )
        if cursor.fetchone() is None:
            return None
        command_id = str(uuid4())
        cursor.execute(
            """
            INSERT INTO radius_command_outbox
              (id, tenant_id, nas_identifier, session_id, username, command_type,
               attributes, idempotency_key, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, 'pending')
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING id
            """,
            (command_id, tenant_id, command.nas_identifier, command.session_id,
             command.username, command.command_type.value,
             json.dumps(command.attributes, sort_keys=True), command.idempotency_key),
        )
        inserted = cursor.fetchone()
        if inserted is not None:
            return str(inserted[0])
        cursor.execute(
            "SELECT id FROM radius_command_outbox WHERE tenant_id = %s AND idempotency_key = %s",
            (tenant_id, command.idempotency_key),
        )
        existing = cursor.fetchone()
        return str(existing[0]) if existing else None
    finally:
        cursor.close()


def lease_pending_commands(connection, *, limit: int = 25, lease_seconds: int = 30):
    """Lease due commands atomically; concurrent workers skip already-locked rows."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    if not 5 <= lease_seconds <= 300:
        raise ValueError("lease_seconds must be between 5 and 300")
    token = str(uuid4())
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH candidates AS (
                SELECT id FROM radius_command_outbox
                WHERE status = 'pending' AND next_attempt_at <= now()
                ORDER BY next_attempt_at, created_at, id
                FOR UPDATE SKIP LOCKED LIMIT %s
            )
            UPDATE radius_command_outbox AS q
            SET status = 'processing', lease_token = %s,
                lease_expires_at = now() + (%s * interval '1 second'),
                attempts = attempts + 1, updated_at = now()
            FROM candidates WHERE q.id = candidates.id
            RETURNING q.id, q.tenant_id, q.nas_identifier, q.session_id,
                      q.username, q.command_type, q.attributes, q.attempts
            """,
            (limit, token, lease_seconds),
        )
        return [
            LeasedRadiusCommand(
                id=str(row[0]), tenant_id=str(row[1]), nas_identifier=row[2],
                session_id=row[3], username=row[4], command_type=row[5],
                attributes=row[6] if isinstance(row[6], dict) else json.loads(row[6]),
                attempts=row[7], lease_token=token,
            )
            for row in cursor.fetchall()
        ]
    finally:
        cursor.close()


def finish_leased_command(
    connection, *, command_id: str, lease_token: str, outcome: str,
    retry_after_seconds: int | None = None, error_code: str | None = None,
) -> bool:
    """Finish only a command still owned by this lease token."""
    try:
        normalized_id, normalized_token = str(UUID(command_id)), str(UUID(lease_token))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("command_id and lease_token must be UUIDs") from exc
    if outcome not in {"acknowledged", "retry", "failed"}:
        raise ValueError("unsupported command outcome")
    if outcome == "retry" and (
        retry_after_seconds is None or not 1 <= retry_after_seconds <= 3600
    ):
        raise ValueError("retry_after_seconds must be between 1 and 3600")
    if error_code is not None and (len(error_code) > 64 or not error_code.isascii()):
        raise ValueError("error_code must be at most 64 ASCII characters")
    new_status = "pending" if outcome == "retry" else outcome
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE radius_command_outbox
            SET status = %s, lease_token = NULL, lease_expires_at = NULL,
                next_attempt_at = CASE WHEN %s = 'retry'
                  THEN now() + (%s * interval '1 second') ELSE next_attempt_at END,
                dispatched_at = CASE WHEN %s IN ('acknowledged','failed')
                  THEN now() ELSE dispatched_at END,
                completed_at = CASE WHEN %s IN ('acknowledged','failed')
                  THEN now() ELSE completed_at END,
                last_error_code = %s, updated_at = now()
            WHERE id = %s AND status = 'processing' AND lease_token = %s
            RETURNING id
            """,
            (new_status, outcome, retry_after_seconds or 0, outcome, outcome,
             error_code, normalized_id, normalized_token),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def requeue_expired_command_leases(connection) -> int:
    """Recover worker crashes; expired lease tokens can no longer complete."""
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE radius_command_outbox
            SET status = 'pending', lease_token = NULL, lease_expires_at = NULL,
                next_attempt_at = now(), last_error_code = 'worker_lease_expired',
                updated_at = now()
            WHERE status = 'processing' AND lease_expires_at < now()
            RETURNING id
            """
        )
        return len(cursor.fetchall())
    finally:
        cursor.close()
