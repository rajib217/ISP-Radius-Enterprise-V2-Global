"""Tenant-scoped leasing and completion for the audited dynamic-authorization outbox."""
from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID, uuid4


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


def lease_pending_commands(
    connection, *, limit: int = 10, lease_seconds: int = 30, max_attempts: int = 8
):
    """Claim due dynamic-authorization requests without blocking peer workers."""
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 5 <= lease_seconds <= 300:
        raise ValueError("lease_seconds must be between 5 and 300")
    if not 1 <= max_attempts <= 50:
        raise ValueError("max_attempts must be between 1 and 50")
    token = str(uuid4())
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH candidates AS (
                SELECT tenant_id, id
                  FROM dynamic_authorization_requests
                 WHERE status = 'pending'
                   AND next_attempt_at <= now()
                   AND attempt_count < LEAST(max_attempts, %s)
                 ORDER BY next_attempt_at, created_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT %s
            )
            UPDATE dynamic_authorization_requests AS q
               SET status = 'processing',
                   lease_token = %s,
                   lease_expires_at = now() + (%s * interval '1 second'),
                   attempt_count = attempt_count + 1,
                   updated_at = now()
              FROM candidates
             WHERE q.tenant_id = candidates.tenant_id
               AND q.id = candidates.id
            RETURNING q.id, q.tenant_id, q.nas_identifier, q.session_id,
                      q.username, q.request_type, q.attributes, q.attempt_count
            """,
            (max_attempts, limit, token, lease_seconds),
        )
        commands = []
        for row in cursor.fetchall():
            request_type = str(row[5])
            command_type = "change_bandwidth" if request_type == "coa" else request_type
            attributes = row[6] if isinstance(row[6], dict) else json.loads(row[6])
            commands.append(
                LeasedRadiusCommand(
                    id=str(row[0]), tenant_id=str(row[1]), nas_identifier=row[2],
                    session_id=row[3], username=row[4], command_type=command_type,
                    attributes=attributes, attempts=row[7], lease_token=token,
                )
            )
        return commands
    finally:
        cursor.close()


def finish_leased_command(
    connection, *, tenant_id: str, command_id: str, lease_token: str,
    outcome: str, retry_after_seconds: int | None = None,
    error_code: str | None = None,
) -> bool:
    """Finish only the tenant-owned request still held by this lease token."""
    try:
        normalized_tenant = str(UUID(tenant_id))
        normalized_id = str(UUID(command_id))
        normalized_token = str(UUID(lease_token))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id, command_id and lease_token must be UUIDs") from exc
    if outcome not in {"acknowledged", "rejected", "retry", "failed"}:
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
            UPDATE dynamic_authorization_requests
               SET status = %s,
                   lease_token = NULL,
                   lease_expires_at = NULL,
                   next_attempt_at = CASE WHEN %s = 'retry'
                     THEN now() + (%s * interval '1 second') ELSE next_attempt_at END,
                   completed_at = CASE WHEN %s IN ('acknowledged','rejected','failed')
                     THEN now() ELSE NULL END,
                   last_error_code = %s,
                   updated_at = now()
             WHERE tenant_id = %s AND id = %s
               AND status = 'processing' AND lease_token = %s
            RETURNING id
            """,
            (
                new_status, outcome, retry_after_seconds or 0, outcome,
                error_code, normalized_tenant, normalized_id, normalized_token,
            ),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def requeue_expired_command_leases(connection, *, max_attempts: int = 8) -> int:
    """Recover abandoned claims and terminally fail requests out of retry budget."""
    if not 1 <= max_attempts <= 50:
        raise ValueError("max_attempts must be between 1 and 50")
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH expired AS (
                SELECT tenant_id, id,
                       attempt_count >= LEAST(max_attempts, %s) AS exhausted
                  FROM dynamic_authorization_requests
                 WHERE status = 'processing' AND lease_expires_at < now()
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE dynamic_authorization_requests AS q
               SET status = CASE WHEN expired.exhausted THEN 'failed' ELSE 'pending' END,
                   lease_token = NULL,
                   lease_expires_at = NULL,
                   next_attempt_at = now(),
                   completed_at = CASE WHEN expired.exhausted THEN now() ELSE NULL END,
                   last_error_code = CASE WHEN expired.exhausted
                                          THEN 'max_attempts_worker_lease_expired'
                                          ELSE 'worker_lease_expired' END,
                   updated_at = now()
              FROM expired
             WHERE q.tenant_id = expired.tenant_id AND q.id = expired.id
            RETURNING q.id
            """,
            (max_attempts,),
        )
        return len(cursor.fetchall())
    finally:
        cursor.close()
