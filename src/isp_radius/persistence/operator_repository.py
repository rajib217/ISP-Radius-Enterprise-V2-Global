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



def create_operator_login_mfa_challenge(
    connection: Any, *, user_id: str, tenant_id: str, challenge_hash: str,
    origin: str, rp_id: str, expires_at: Any, method: str = "webauthn",
) -> str:
    """Persist a login challenge bound to both operator and selected tenant."""
    challenge_id = str(uuid4())
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            INSERT INTO operator_mfa_challenges
                (id, user_id, tenant_id, challenge_hash, method, origin, rp_id, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (challenge_id, user_id, tenant_id, challenge_hash, method, origin, rp_id, expires_at),
        )
    finally:
        cursor.close()
    return challenge_id


def find_pending_operator_login_mfa_challenge(
    connection: Any, *, challenge_hash: str, origin: str, rp_id: str,
    method: str = "webauthn",
) -> tuple[Any, ...] | None:
    """Fetch an unconsumed login challenge and its server-bound tenant."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT id, user_id, tenant_id
              FROM operator_mfa_challenges
             WHERE challenge_hash = %s AND method = %s
               AND tenant_id IS NOT NULL AND origin = %s AND rp_id = %s
               AND consumed_at IS NULL AND expires_at > now() AND failed_attempts < 5
             LIMIT 1 FOR UPDATE
            """,
            (challenge_hash, method, origin, rp_id),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def consume_operator_login_mfa_challenge(
    connection: Any, *, challenge_hash: str, origin: str, rp_id: str,
    method: str = "webauthn",
) -> tuple[Any, ...] | None:
    """Atomically consume a login challenge and return its bound identity/tenant."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_mfa_challenges
               SET consumed_at = now()
             WHERE challenge_hash = %s AND method = %s AND tenant_id IS NOT NULL
               AND origin = %s AND rp_id = %s AND consumed_at IS NULL
               AND expires_at > now() AND failed_attempts < 5
            RETURNING id, user_id, tenant_id
            """,
            (challenge_hash, method, origin, rp_id),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def find_operator_tenant_membership(
    connection: Any, *, user_id: str, tenant_id: str,
) -> tuple[Any, ...] | None:
    """Resolve an active user and tenant membership after MFA succeeds."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT u.email, m.role
              FROM operator_users AS u
              JOIN operator_tenant_memberships AS m ON m.user_id = u.id
             WHERE u.id = %s AND m.tenant_id = %s
               AND u.status = 'active' AND m.status = 'active'
             LIMIT 1
            """,
            (user_id, tenant_id),
        )
        return cursor.fetchone()
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


def create_operator_totp_factor(
    connection: Any, *, factor_id: str, user_id: str, ciphertext: bytes, nonce: bytes,
    wrapped_data_key: bytes, key_version: str, pending_expires_at: Any,
) -> str:
    """Persist only encrypted TOTP material as a pending factor."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_totp_factors
               SET status = 'revoked', revoked_at = now()
             WHERE user_id = %s AND status = 'pending'
            """,
            (user_id,),
        )
        cursor.execute(
            """
            INSERT INTO operator_totp_factors (
                id, user_id, secret_ciphertext, nonce, wrapped_data_key,
                key_version, status, pending_expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
            """,
            (factor_id, user_id, ciphertext, nonce, wrapped_data_key, key_version, pending_expires_at),
        )
    finally:
        cursor.close()
    return factor_id


def find_pending_operator_totp_factor(
    connection: Any, *, factor_id: str, user_id: str,
) -> tuple[Any, ...] | None:
    """Fetch an unexpired pending factor owned by the operator."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT id, user_id, secret_ciphertext, nonce, wrapped_data_key, key_version
              FROM operator_totp_factors
             WHERE id = %s AND user_id = %s AND status = 'pending'
               AND pending_expires_at > now()
             LIMIT 1
            """,
            (factor_id, user_id),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def find_active_operator_totp_factor(
    connection: Any, *, user_id: str,
) -> tuple[Any, ...] | None:
    """Fetch the single active encrypted TOTP factor for an operator."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT id, user_id, secret_ciphertext, nonce, wrapped_data_key, key_version
              FROM operator_totp_factors
             WHERE user_id = %s AND status = 'active'
             LIMIT 1
            """,
            (user_id,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def record_operator_totp_enrollment_failure(
    connection: Any, *, factor_id: str, user_id: str,
) -> int | None:
    """Bound pending-factor verification attempts and revoke after five failures."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_totp_factors
               SET enrollment_failed_attempts = enrollment_failed_attempts + 1,
                   status = CASE WHEN enrollment_failed_attempts + 1 >= 5
                                 THEN 'revoked' ELSE 'pending' END,
                   revoked_at = CASE WHEN enrollment_failed_attempts + 1 >= 5
                                     THEN now() ELSE NULL END
             WHERE id = %s AND user_id = %s AND status = 'pending'
               AND pending_expires_at > now() AND enrollment_failed_attempts < 5
            RETURNING enrollment_failed_attempts
            """,
            (factor_id, user_id),
        )
        row = cursor.fetchone()
        return int(row[0]) if row is not None else None
    finally:
        cursor.close()


def activate_operator_totp_factor(
    connection: Any, *, factor_id: str, user_id: str, accepted_step: int,
) -> bool:
    """Activate a verified pending factor and consume its enrollment time step."""
    if accepted_step < 0:
        raise ValueError("TOTP time step must be non-negative")
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            UPDATE operator_totp_factors
               SET status = 'active', pending_expires_at = NULL,
                   activated_at = now(), last_accepted_step = %s
             WHERE id = %s AND user_id = %s AND status = 'pending'
               AND pending_expires_at > now()
            RETURNING id
            """,
            (accepted_step, factor_id, user_id),
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
             FOR UPDATE
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


def find_pending_operator_mfa_challenge(
    connection: Any, *, challenge_hash: str, method: str, origin: str, rp_id: str,
) -> tuple[Any, ...] | None:
    """Find an unconsumed, unexpired challenge without consuming it."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT id, user_id
              FROM operator_mfa_challenges
             WHERE challenge_hash = %s AND method = %s AND origin = %s AND rp_id = %s
               AND consumed_at IS NULL AND expires_at > now() AND failed_attempts < 5
             LIMIT 1
            """,
            (challenge_hash, method, origin, rp_id),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def list_active_operator_webauthn_credential_ids(
    connection: Any, *, user_id: str,
) -> tuple[bytes, ...]:
    """Return active credential IDs for exclusion during passkey enrollment."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT credential_id
              FROM operator_webauthn_credentials
             WHERE user_id = %s AND status = 'active'
             ORDER BY created_at, id
            """,
            (user_id,),
        )
        return tuple(row[0] for row in cursor.fetchall())
    finally:
        cursor.close()


def find_operator_password_hash(connection: Any, *, user_id: str) -> tuple[str, str] | None:
    """Fetch active operator password material for a fresh-authentication check."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """
            SELECT password_hash, status
              FROM operator_users
             WHERE id = %s
             LIMIT 1
            """,
            (user_id,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()


def replace_operator_recovery_codes(connection: Any, *, user_id: str, batch_id: str, code_hashes: list[str]) -> None:
    """Replace the current batch and persist only one-way digests."""
    if len(code_hashes) != 10 or any(
        len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)
        for value in code_hashes
    ):
        raise ValueError("exactly ten SHA-256 recovery digests are required")
    cursor = _cursor(connection)
    try:
        cursor.execute(
            "UPDATE operator_mfa_recovery_codes SET consumed_at = now() WHERE user_id = %s AND consumed_at IS NULL",
            (user_id,),
        )
        for digest in code_hashes:
            cursor.execute(
                """INSERT INTO operator_mfa_recovery_codes (id, user_id, batch_id, code_hash)
                   VALUES (%s, %s, %s, %s)""",
                (str(uuid4()), user_id, batch_id, digest),
            )
    finally:
        cursor.close()


def has_available_operator_recovery_codes(connection: Any, *, user_id: str) -> bool:
    cursor = _cursor(connection)
    try:
        cursor.execute(
            "SELECT 1 FROM operator_mfa_recovery_codes WHERE user_id = %s AND consumed_at IS NULL LIMIT 1",
            (user_id,),
        )
        return cursor.fetchone() is not None
    finally:
        cursor.close()


def create_operator_factor_reset_request(
    connection: Any, *, request_id: str, tenant_id: str, target_user_id: str,
    requester_user_id: str, reason: str, expires_at: Any,
) -> bool:
    """Create a request for another active member of the same tenant."""
    if requester_user_id == target_user_id or not reason.strip() or len(reason) > 500:
        return False
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """INSERT INTO operator_mfa_reset_requests
                   (id, tenant_id, target_user_id, requester_user_id, reason, expires_at)
               SELECT %s, %s, %s, %s, %s, %s
                WHERE EXISTS (SELECT 1 FROM operator_tenant_memberships
                    WHERE tenant_id = %s AND user_id = %s AND status = 'active')
               ON CONFLICT DO NOTHING""",
            (request_id, tenant_id, target_user_id, requester_user_id,
             reason.strip(), expires_at, tenant_id, target_user_id),
        )
        return cursor.rowcount == 1
    finally:
        cursor.close()


def approve_operator_factor_reset(
    connection: Any, *, request_id: str, tenant_id: str, approver_user_id: str,
) -> str | None:
    """Execute a dual-control reset atomically in the caller's transaction."""
    cursor = _cursor(connection)
    try:
        cursor.execute(
            """UPDATE operator_mfa_reset_requests AS r
                  SET status = 'approved', approver_user_id = %s, approved_at = now()
                WHERE r.id = %s AND r.tenant_id = %s AND r.status = 'pending'
                  AND r.expires_at > now() AND r.requester_user_id <> %s
                  AND EXISTS (SELECT 1 FROM operator_tenant_memberships AS m
                    WHERE m.tenant_id = r.tenant_id AND m.user_id = %s
                      AND m.status = 'active' AND m.role IN ('owner', 'admin'))
                RETURNING r.target_user_id""",
            (approver_user_id, request_id, tenant_id, approver_user_id, approver_user_id),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        target = str(row[0])
        cursor.execute(
            """UPDATE operator_totp_factors SET status = 'revoked',
                      revoked_at = now(), pending_expires_at = NULL
                WHERE user_id = %s AND status IN ('active', 'pending')""", (target,),
        )
        cursor.execute(
            """UPDATE operator_webauthn_credentials SET status = 'revoked', revoked_at = now()
                WHERE user_id = %s AND status = 'active'""", (target,),
        )
        cursor.execute(
            "UPDATE operator_mfa_recovery_codes SET consumed_at = now() WHERE user_id = %s AND consumed_at IS NULL",
            (target,),
        )
        cursor.execute(
            "UPDATE operator_mfa_challenges SET consumed_at = now() WHERE user_id = %s AND consumed_at IS NULL",
            (target,),
        )
        cursor.execute(
            "UPDATE operator_sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
            (target,),
        )
        cursor.execute(
            "UPDATE operator_mfa_reset_requests SET status = 'completed', completed_at = now() WHERE id = %s AND status = 'approved'",
            (request_id,),
        )
        return target
    finally:
        cursor.close()
