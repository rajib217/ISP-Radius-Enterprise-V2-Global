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
               AND s.revoked_at IS NULL AND s.expires_at > now()\n               AND s.last_seen_at > now() - interval '30 minutes'
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



def create_operator_mfa_challenge(
    connection: Any, *, user_id: str, challenge_hash: str, method: str,
    origin: str, rp_id: str, expires_at: Any,
) -> str:
    """Persist only a challenge digest; database limits its lifetime to five minutes."""
    challenge_id = str(uuid4())
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            INSERT INTO operator_mfa_challenges
                (id, user_id, challenge_hash, method, origin, rp_id, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (challenge_id, user_id, challenge_hash, method, origin, rp_id, expires_at),
        )
    finally:
        cursor.close()
    return challenge_id


def consume_operator_mfa_challenge(
    connection: Any, *, challenge_hash: str, method: str, origin: str, rp_id: str,
) -> tuple[Any, ...] | None:
    """Atomically consume a valid challenge once, bound to method and browser origin."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_mfa_challenges
               SET consumed_at = now()
             WHERE challenge_hash = %s AND method = %s AND origin = %s AND rp_id = %s
               AND consumed_at IS NULL AND expires_at > now() AND failed_attempts < 5
            RETURNING id, user_id
            """,
            (challenge_hash, method, origin, rp_id),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def record_operator_mfa_challenge_failure(connection: Any, *, challenge_hash: str) -> bool:
    """Increment bounded challenge failures without extending challenge lifetime."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_mfa_challenges
               SET failed_attempts = failed_attempts + 1
             WHERE challenge_hash = %s AND consumed_at IS NULL
               AND expires_at > now() AND failed_attempts < 5
            RETURNING id
            """,
            (challenge_hash,),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def accept_operator_totp_step(
    connection: Any, *, factor_id: str, user_id: str, time_step: int,
) -> bool:
    """Atomically accept a TOTP time step once; reject replayed or older steps."""
    if time_step < 0:
        raise ValueError("TOTP time step must be non-negative")
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_totp_factors
               SET last_accepted_step = %s, last_used_at = now()
             WHERE id = %s AND user_id = %s AND status = 'active'
               AND last_accepted_step < %s
            RETURNING id
            """,
            (time_step, factor_id, user_id, time_step),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def consume_operator_recovery_code(
    connection: Any, *, user_id: str, code_hash: str,
) -> str | None:
    """Consume one recovery digest atomically and return its batch identifier."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_mfa_recovery_codes
               SET consumed_at = now()
             WHERE user_id = %s AND code_hash = %s AND consumed_at IS NULL
            RETURNING batch_id
            """,
            (user_id, code_hash),
        )
        row = cursor.fetchone()
        return str(row[0]) if row is not None else None
    finally:
        cursor.close()


def revoke_operator_mfa_challenges(connection: Any, *, user_id: str) -> int:
    """Invalidate outstanding MFA challenges after a factor reset."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_mfa_challenges SET consumed_at = now()
             WHERE user_id = %s AND consumed_at IS NULL
            """,
            (user_id,),
        )
        return cursor.rowcount
    finally:
        cursor.close()


def revoke_operator_sessions_for_user(connection: Any, *, user_id: str) -> int:
    """Revoke every active browser session after MFA recovery or factor reset."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_sessions SET revoked_at = now()
             WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user_id,),
        )
        return cursor.rowcount
    finally:
        cursor.close()



def create_operator_webauthn_credential(
    connection: Any, *, user_id: str, credential_id: bytes, public_key: bytes,
    sign_count: int, transports: list[str], backup_eligible: bool, backup_state: bool,
) -> str:
    """Persist a verified credential; authenticator private keys are never stored."""
    if not credential_id or len(credential_id) > 1024:
        raise ValueError("WebAuthn credential ID length is invalid")
    if not public_key or len(public_key) > 8192:
        raise ValueError("WebAuthn public key length is invalid")
    if sign_count < 0 or (backup_state and not backup_eligible):
        raise ValueError("WebAuthn authenticator metadata is invalid")
    credential_row_id = str(uuid4())
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            INSERT INTO operator_webauthn_credentials (
                id, user_id, credential_id, public_key, sign_count, transports,
                backup_eligible, backup_state
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (credential_row_id, user_id, credential_id, public_key, sign_count,
             transports, backup_eligible, backup_state),
        )
    finally:
        cursor.close()
    return credential_row_id


def find_active_operator_webauthn_credential(
    connection: Any, *, credential_id: bytes,
) -> tuple[Any, ...] | None:
    """Fetch public verification material for an active credential ID."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT id, user_id, public_key, sign_count, backup_eligible, backup_state
              FROM operator_webauthn_credentials
             WHERE credential_id = %s AND status = 'active'
             LIMIT 1
            """,
            (credential_id,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def update_operator_webauthn_credential_after_assertion(
    connection: Any, *, credential_row_id: str, user_id: str, new_sign_count: int,
    backup_eligible: bool, backup_state: bool,
) -> bool:
    """Update metadata only after successful assertion verification."""
    if new_sign_count < 0 or (backup_state and not backup_eligible):
        raise ValueError("WebAuthn authenticator metadata is invalid")
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_webauthn_credentials
               SET sign_count = GREATEST(sign_count, %s),
                   backup_eligible = %s, backup_state = %s, last_used_at = now()
             WHERE id = %s AND user_id = %s AND status = 'active'
            RETURNING id
            """,
            (new_sign_count, backup_eligible, backup_state, credential_row_id, user_id),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def revoke_operator_webauthn_credential(
    connection: Any, *, user_id: str, credential_row_id: str,
) -> bool:
    """Revoke one credential owned by the specified operator."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_webauthn_credentials
               SET status = 'revoked', revoked_at = now()
             WHERE id = %s AND user_id = %s AND status = 'active'
            RETURNING id
            """,
            (credential_row_id, user_id),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()
