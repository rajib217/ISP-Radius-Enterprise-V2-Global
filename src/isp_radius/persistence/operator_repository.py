"""Persistence operations for operator identities, sessions and audit events."""
from __future__ import annotations

from typing import Any
from uuid import uuid4


def _cursor(connection: Any) -> Any:
    return connection.cursor()


def find_operator_memberships(connection: Any, *, email: str) -> list[tuple[Any, ...]]:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT u.id, u.email, u.password_hash, u.status,
                   m.tenant_id, m.role, m.status
              FROM operator_users AS u
              LEFT JOIN operator_tenant_memberships AS m ON m.user_id = u.id
             WHERE lower(u.email) = %s
             ORDER BY m.tenant_id
            """,
            (email,),
        )
        return cursor.fetchall()
    finally:
        cursor.close()


def create_operator_session(
    connection: Any,
    *,
    user_id: str,
    tenant_id: str,
    token_hash: str,
    csrf_token_hash: str,
    expires_at: Any,
    remote_ip: str | None,
    user_agent: str | None,
) -> str:
    session_id = str(uuid4())
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            INSERT INTO operator_sessions (
                id, tenant_id, user_id, token_hash, csrf_token_hash,
                expires_at, remote_ip, user_agent
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (session_id, tenant_id, user_id, token_hash, csrf_token_hash,
             expires_at, remote_ip, user_agent[:512] if user_agent else None),
        )
    finally:
        cursor.close()
    return session_id


def resolve_operator_session(connection: Any, *, token_hash: str) -> tuple[Any, ...] | None:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT s.id, u.id, u.email, s.tenant_id, m.role, s.csrf_token_hash
              FROM operator_sessions AS s
              JOIN operator_users AS u ON u.id = s.user_id
              JOIN operator_tenant_memberships AS m
                ON m.tenant_id = s.tenant_id AND m.user_id = s.user_id
             WHERE s.token_hash = %s
               AND s.revoked_at IS NULL AND s.expires_at > now()
               AND u.status = 'active' AND m.status = 'active'
             LIMIT 1
            """,
            (token_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        cursor.execute(
            "UPDATE operator_sessions SET last_seen_at = now() WHERE id = %s",
            (row[0],),
        )
        return row
    finally:
        cursor.close()


def revoke_operator_session(connection: Any, *, token_hash: str) -> tuple[Any, ...] | None:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_sessions
               SET revoked_at = now()
             WHERE token_hash = %s AND revoked_at IS NULL
            RETURNING id, tenant_id, user_id
            """,
            (token_hash,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def insert_operator_audit_event(
    connection: Any,
    *,
    tenant_id: str | None,
    actor_user_id: str | None,
    actor_kind: str,
    action: str,
    remote_ip: str | None = None,
    correlation_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    import json

    event_id = str(uuid4())
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            INSERT INTO operator_audit_events (
                id, tenant_id, actor_user_id, actor_kind, action,
                target_type, target_id, correlation_id, remote_ip, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (event_id, tenant_id, actor_user_id, actor_kind, action,
             target_type, target_id, correlation_id, remote_ip,
             json.dumps(metadata or {}, separators=(",", ":"))),
        )
    finally:
        cursor.close()
    return event_id



def operator_login_rate_limited(
    connection: Any, *, email_hash: str, ip_hash: str
) -> bool:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT 1 FROM operator_login_attempts
             WHERE locked_until > now()
               AND ((scope = 'email' AND identifier_hash = %s)
                 OR (scope = 'ip' AND identifier_hash = %s))
             LIMIT 1
            """,
            (email_hash, ip_hash),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def record_operator_login_failure(
    connection: Any, *, email_hash: str, ip_hash: str
) -> None:
    cursor = _cursor(connection)
    try:
        for scope, identifier_hash in (("email", email_hash), ("ip", ip_hash)):
            cursor.execute(
                """
                INSERT INTO operator_login_attempts (
                    scope, identifier_hash, failed_attempts,
                    window_started_at, updated_at
                ) VALUES (%s, %s, 1, now(), now())
                ON CONFLICT (scope, identifier_hash) DO UPDATE SET
                    failed_attempts = CASE
                        WHEN operator_login_attempts.window_started_at < now() - interval '15 minutes'
                        THEN 1 ELSE operator_login_attempts.failed_attempts + 1 END,
                    window_started_at = CASE
                        WHEN operator_login_attempts.window_started_at < now() - interval '15 minutes'
                        THEN now() ELSE operator_login_attempts.window_started_at END,
                    locked_until = CASE
                        WHEN (CASE
                            WHEN operator_login_attempts.window_started_at < now() - interval '15 minutes'
                            THEN 1 ELSE operator_login_attempts.failed_attempts + 1 END) >= 5
                        THEN now() + interval '15 minutes' ELSE NULL END,
                    updated_at = now()
                """,
                (scope, identifier_hash),
            )
    finally:
        cursor.close()


def clear_operator_login_failures(
    connection: Any, *, email_hash: str, ip_hash: str
) -> None:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            DELETE FROM operator_login_attempts
             WHERE (scope = 'email' AND identifier_hash = %s)
                OR (scope = 'ip' AND identifier_hash = %s)
            """,
            (email_hash, ip_hash),
        )
    finally:
        cursor.close()
