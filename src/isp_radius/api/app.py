"""Private REST endpoint consumed by FreeRADIUS rlm_rest."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from urllib.parse import parse_qs
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from psycopg_pool import ConnectionPool, PoolTimeout
from starlette.concurrency import run_in_threadpool

from isp_radius.aaa.accounting import normalize_accounting
from isp_radius.aaa.authentication import authenticate_subscriber
from isp_radius.aaa.authorization import authorize_subscriber
from isp_radius.persistence.operator_repository import (
    clear_operator_login_failures,
    consume_operator_login_mfa_challenge,
    consume_operator_mfa_challenge,
    create_operator_login_mfa_challenge,
    create_operator_mfa_challenge,
    create_operator_session,
    create_operator_webauthn_credential,
    find_active_operator_webauthn_credential,
    find_operator_memberships,
    find_operator_password_hash,
    find_operator_tenant_membership,
    find_pending_operator_login_mfa_challenge,
    find_pending_operator_mfa_challenge,
    insert_operator_audit_event,
    list_active_operator_webauthn_credential_ids,
    operator_login_rate_limited,
    record_operator_login_failure,
    record_operator_mfa_challenge_failure,
    resolve_operator_session,
    revoke_operator_session,
    update_operator_webauthn_credential_after_assertion,
)
from isp_radius.persistence.session_monitoring_repository import (
    get_subscriber_session_summary,
    list_subscriber_sessions,
)
from isp_radius.persistence.session_repository import record_accounting_event_with_usage
from isp_radius.security.operator_auth import (
    OperatorPrincipal,
    burn_operator_password_verification,
    csrf_matches,
    hash_token,
    issue_session_tokens,
    normalize_operator_email,
    permissions_for_role,
    verify_operator_password,
)
from isp_radius.security.webauthn import (
    WebAuthnVerificationError,
    generate_authentication_options_json,
    generate_registration_options_json,
    generate_webauthn_challenge,
    hash_webauthn_challenge,
    verify_webauthn_authentication,
    verify_webauthn_registration,
)


def _pool_sizes() -> tuple[int, int]:
    """Read bounded pool sizes so environment mistakes cannot exhaust PostgreSQL."""
    try:
        minimum = int(os.environ.get("DB_POOL_MIN_SIZE", "1"))
        maximum = int(os.environ.get("DB_POOL_MAX_SIZE", "10"))
    except ValueError as exc:
        raise RuntimeError("DB_POOL_MIN_SIZE and DB_POOL_MAX_SIZE must be integers") from exc
    if not 1 <= minimum <= maximum <= 100:
        raise RuntimeError("database pool sizes must satisfy 1 <= min <= max <= 100")
    return minimum, maximum


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    database_url = os.environ.get("DATABASE_URL")
    application.state.db_pool = None
    if database_url:
        minimum, maximum = _pool_sizes()
        pool = ConnectionPool(
            conninfo=database_url, min_size=minimum, max_size=maximum,
            timeout=2, open=False, name="isp-radius-api",
        )
        pool.open(wait=True, timeout=5)
        application.state.db_pool = pool
    try:
        yield
    finally:
        if application.state.db_pool is not None:
            application.state.db_pool.close()
            application.state.db_pool = None


app = FastAPI(
    title="ISP RADIUS Authentication API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Apply restrictive headers to API responses without constraining a future UI."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'",
    )
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    if request.url.path.startswith("/operator/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def _database_connection(request: Request) -> Generator[psycopg.Connection, None, None]:
    pool: ConnectionPool | None = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Authentication backend unavailable")
    try:
        with pool.connection(timeout=2) as connection:
            yield connection
    except (psycopg.Error, PoolTimeout) as exc:
        raise HTTPException(
            status_code=503, detail="Authentication backend unavailable"
        ) from exc


_database_dependency = Depends(_database_connection)


def _monitoring_principal(authorization: str | None) -> str:
    """Resolve a read-only tenant principal from SHA-256 bearer-token hashes."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Monitoring authentication required")
    token = authorization[7:].strip()
    if not token or len(token) > 512:
        raise HTTPException(status_code=401, detail="Invalid monitoring credentials")
    try:
        entries = json.loads(os.environ.get("MONITORING_API_KEY_HASHES", ""))
    except (TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=503, detail="Monitoring authentication is unavailable") from None
    if not isinstance(entries, dict) or not entries:
        raise HTTPException(status_code=503, detail="Monitoring authentication is unavailable")
    supplied_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    principal = None
    for key_hash, candidate in entries.items():
        if isinstance(key_hash, str) and hmac.compare_digest(supplied_hash, key_hash.lower()):
            principal = candidate
    if not isinstance(principal, dict):
        raise HTTPException(status_code=401, detail="Invalid monitoring credentials")
    permissions = principal.get("permissions")
    if not isinstance(permissions, list) or "sessions:read" not in permissions:
        raise HTTPException(status_code=403, detail="Monitoring permission denied")
    try:
        from uuid import UUID
        return str(UUID(principal.get("tenant_id")))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=503, detail="Monitoring principal is misconfigured") from None



def _monitoring_tenant_dependency(
    authorization: str | None = Header(default=None),
) -> str:
    """Authenticate monitoring requests before acquiring a database connection."""
    return _monitoring_principal(authorization)



def _operator_origin_guard(request: Request) -> None:
    allowed = {
        item.strip().rstrip("/")
        for item in os.environ.get("OPERATOR_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    origin = request.headers.get("origin", "").rstrip("/")
    if not allowed:
        raise HTTPException(status_code=503, detail="Operator origin policy is not configured")
    if not origin or origin not in allowed:
        raise HTTPException(status_code=403, detail="Request origin is not allowed")


def _operator_cookie_secure() -> bool:
    value = os.environ.get("OPERATOR_COOKIE_SECURE", "true").strip().lower()
    if value not in {"true", "false"}:
        raise HTTPException(status_code=503, detail="Operator cookie policy is invalid")
    if value == "false" and os.environ.get("APP_ENV", "production").lower() not in {
        "development", "test"
    }:
        raise HTTPException(status_code=503, detail="Secure operator cookies are required")
    return value == "true"


def _operator_client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _operator_principal_dependency(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
) -> OperatorPrincipal:
    token = request.cookies.get("operator_session")
    if not token:
        raise HTTPException(status_code=401, detail="Operator authentication required")
    try:
        token_hash = hash_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid operator session") from None
    row = resolve_operator_session(connection, token_hash=token_hash)
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired operator session")
    return OperatorPrincipal(
        session_id=str(row[0]),
        user_id=str(row[1]),
        email=str(row[2]),
        tenant_id=str(row[3]),
        role=str(row[4]),
        csrf_token_hash=str(row[5]),
    )


def require_operator_permission(permission: str):
    """Build a fail-closed dependency for one explicit operator permission."""
    if not permission or ":" not in permission:
        raise ValueError("permission must use the resource:action format")

    def dependency(
        principal: OperatorPrincipal = _operator_principal_dependency_injected,
    ) -> OperatorPrincipal:
        if not principal.allows(permission):
            raise HTTPException(status_code=403, detail="Operator permission denied")
        return principal

    return dependency


_operator_principal_dependency_injected = Depends(_operator_principal_dependency)
_operator_sessions_read_dependency = Depends(
    require_operator_permission("sessions:read")
)


@app.post("/operator/login")
async def operator_login(
    request: Request,
    response: Response,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """Authenticate an operator and issue opaque, tenant-bound browser cookies."""
    _operator_origin_guard(request)
    secure = _operator_cookie_secure()
    raw_body = await request.body()
    if len(raw_body) > 8192:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid login request") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid login request")
    try:
        email = normalize_operator_email(payload.get("email", ""))
    except (AttributeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid login request") from None
    password = payload.get("password")
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise HTTPException(status_code=400, detail="Invalid login request")
    requested_tenant = payload.get("tenant_id")
    if requested_tenant is not None:
        try:
            requested_tenant = str(UUID(requested_tenant))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(status_code=400, detail="Invalid tenant selection") from None

    remote_ip = _operator_client_ip(request)
    ip_hash = hash_token(remote_ip)
    email_hash = hash_token(f"{email}:{ip_hash}")
    login_error: tuple[int, object] | None = None
    session_data: tuple[object, ...] | None = None
    login_mfa_data: tuple[str, dict[str, object]] | None = None

    with connection.transaction():
        if operator_login_rate_limited(
            connection, email_hash=email_hash, ip_hash=ip_hash
        ):
            insert_operator_audit_event(
                connection, tenant_id=None, actor_user_id=None, actor_kind="system",
                action="auth.login.rate_limited", remote_ip=remote_ip,
                metadata={"scope": "rate_limit"},
            )
            login_error = (429, "Too many login attempts. Try again later.")
        else:
            rows = find_operator_memberships(connection, email=email)
            if not rows:
                burn_operator_password_verification(password)
                record_operator_login_failure(
                    connection, email_hash=email_hash, ip_hash=ip_hash
                )
                insert_operator_audit_event(
                    connection, tenant_id=None, actor_user_id=None, actor_kind="system",
                    action="auth.login.failed", remote_ip=remote_ip,
                    metadata={"reason": "invalid_credentials"},
                )
                login_error = (401, "Invalid email or password")
            else:
                user_id, canonical_email, password_hash, user_status = rows[0][:4]
                valid_password = verify_operator_password(password_hash, password)
                active_memberships = [
                    row for row in rows
                    if row[4] is not None and row[6] == "active"
                ]
                if not valid_password or user_status != "active" or not active_memberships:
                    record_operator_login_failure(
                        connection, email_hash=email_hash, ip_hash=ip_hash
                    )
                    insert_operator_audit_event(
                        connection, tenant_id=None, actor_user_id=None, actor_kind="system",
                        action="auth.login.failed", remote_ip=remote_ip,
                        metadata={"reason": "invalid_credentials"},
                    )
                    login_error = (401, "Invalid email or password")
                else:
                    selected = active_memberships
                    if requested_tenant is not None:
                        selected = [row for row in active_memberships if str(row[4]) == requested_tenant]
                        if not selected:
                            login_error = (403, "Tenant membership is not active")
                    elif len(active_memberships) > 1:
                        login_error = (
                            409,
                            {"message": "Tenant selection required",
                             "tenants": [{"tenant_id": str(row[4]), "role": str(row[5])}
                                         for row in active_memberships]},
                        )
                    if login_error is None:
                        membership = selected[0]
                        credential_ids = list_active_operator_webauthn_credential_ids(
                            connection, user_id=str(user_id),
                        )
                        if credential_ids:
                            challenge = generate_webauthn_challenge()
                            origin, rp_id = _operator_webauthn_config(request)
                            try:
                                options = json.loads(generate_authentication_options_json(
                                    rp_id=rp_id, challenge=challenge,
                                    allowed_credential_ids=credential_ids,
                                ))
                                if not isinstance(options, dict) or not isinstance(options.get("challenge"), str):
                                    raise TypeError("Malformed authentication options")
                                returned_challenge = _decode_webauthn_challenge(options["challenge"])
                                if not hmac.compare_digest(returned_challenge, challenge):
                                    raise ValueError("Authentication options challenge mismatch")
                            except (ValueError, TypeError, WebAuthnVerificationError):
                                raise HTTPException(
                                    status_code=503, detail="Unable to start passkey authentication",
                                ) from None
                            create_operator_login_mfa_challenge(
                                connection, user_id=str(user_id), tenant_id=str(membership[4]),
                                challenge_hash=hash_webauthn_challenge(challenge),
                                origin=origin, rp_id=rp_id,
                                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                            )
                            clear_operator_login_failures(
                                connection, email_hash=email_hash, ip_hash=ip_hash,
                            )
                            insert_operator_audit_event(
                                connection, tenant_id=str(membership[4]), actor_user_id=str(user_id),
                                actor_kind="operator", action="auth.login.mfa_challenge_issued",
                                remote_ip=remote_ip, metadata={"method": "webauthn"},
                            )
                            encoded_challenge = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii")
                            login_mfa_data = (encoded_challenge, options)
                        else:
                            # Temporary bootstrap path: accounts without a passkey can enroll.
                            # Production MFA enforcement remains disabled until fallback/recovery exists.
                            tokens = issue_session_tokens()
                            existing_token = request.cookies.get("operator_session")
                            if existing_token:
                                try:
                                    revoke_operator_session(
                                        connection, token_hash=hash_token(existing_token)
                                    )
                                except ValueError:
                                    pass
                            session_id = create_operator_session(
                                connection,
                                user_id=str(user_id),
                                tenant_id=str(membership[4]),
                                token_hash=tokens.session_hash,
                                csrf_token_hash=tokens.csrf_hash,
                                expires_at=tokens.expires_at,
                                remote_ip=remote_ip,
                                user_agent=request.headers.get("user-agent"),
                            )
                            clear_operator_login_failures(
                                connection, email_hash=email_hash, ip_hash=ip_hash
                            )
                            insert_operator_audit_event(
                                connection,
                                tenant_id=str(membership[4]),
                                actor_user_id=str(user_id),
                                actor_kind="operator",
                                action="auth.login.succeeded",
                                remote_ip=remote_ip,
                                target_type="operator_session",
                                target_id=session_id,
                                metadata={"role": str(membership[5])},
                            )
                            session_data = (
                                str(canonical_email), str(membership[4]), str(membership[5]),
                                tokens, session_id,
                            )

    if login_error is not None:
        raise HTTPException(status_code=login_error[0], detail=login_error[1])
    if login_mfa_data is not None:
        challenge, options = login_mfa_data
        return {"mfa_required": True, "method": "webauthn", "challenge": challenge, "publicKey": options}
    if session_data is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    canonical_email, tenant_id, role, tokens, _session_id = session_data
    response.set_cookie(
        "operator_session", tokens.session_token, max_age=43200,
        httponly=True, secure=secure, samesite="lax", path="/",
    )
    response.set_cookie(
        "operator_csrf", tokens.csrf_token, max_age=43200,
        httponly=False, secure=secure, samesite="lax", path="/",
    )
    return {
        "operator": {"email": canonical_email, "tenant_id": tenant_id, "role": role},
        "csrf_token": tokens.csrf_token,
        "expires_at": tokens.expires_at.isoformat(),
    }




def _operator_csrf_guard(
    request: Request, principal: OperatorPrincipal, supplied_token: str | None,
) -> None:
    if not csrf_matches(
        supplied_header=supplied_token,
        csrf_cookie=request.cookies.get("operator_csrf"),
        stored_hash=principal.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _operator_webauthn_config(request: Request) -> tuple[str, str]:
    origin = request.headers.get("origin", "").rstrip("/")
    _operator_origin_guard(request)
    rp_id = os.environ.get("OPERATOR_WEBAUTHN_RP_ID", "").strip().lower().rstrip(".")
    if not rp_id or len(rp_id) > 253 or any(ch.isspace() for ch in rp_id):
        raise HTTPException(status_code=503, detail="WebAuthn relying-party policy is not configured")
    from urllib.parse import urlsplit

    host = (urlsplit(origin).hostname or "").lower().rstrip(".")
    if not host or not (host == rp_id or host.endswith("." + rp_id)):
        raise HTTPException(status_code=503, detail="WebAuthn origin and RP ID do not match")
    return origin, rp_id


def _decode_webauthn_challenge(value: object) -> bytes:
    if not isinstance(value, str) or not 22 <= len(value) <= 128:
        raise HTTPException(status_code=400, detail="Invalid WebAuthn challenge")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid WebAuthn challenge") from None
    if len(decoded) != 32:
        raise HTTPException(status_code=400, detail="Invalid WebAuthn challenge")
    return decoded


@app.post("/operator/login/webauthn/verify")
async def operator_login_webauthn_verify(
    request: Request,
    response: Response,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """Complete password-plus-passkey login before issuing any operator session."""
    _operator_origin_guard(request)
    secure = _operator_cookie_secure()
    origin, rp_id = _operator_webauthn_config(request)
    raw_body = await request.body()
    if len(raw_body) > 16384:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid passkey response") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("credential"), dict):
        raise HTTPException(status_code=400, detail="Invalid passkey response")
    challenge = _decode_webauthn_challenge(payload.get("challenge"))
    challenge_hash = hash_webauthn_challenge(challenge)
    credential = payload["credential"]
    encoded_credential_id = credential.get("rawId") or credential.get("id")
    if not isinstance(encoded_credential_id, str) or not 2 <= len(encoded_credential_id) <= 1400:
        raise HTTPException(status_code=400, detail="Invalid passkey credential ID")
    try:
        raw_id = base64.b64decode(
            encoded_credential_id.encode("ascii")
            + b"=" * (-len(encoded_credential_id) % 4), altchars=b"-_", validate=True,
        )
        encoded_id = credential.get("id")
        decoded_id = (
            base64.b64decode(
                encoded_id.encode("ascii") + b"=" * (-len(encoded_id) % 4),
                altchars=b"-_", validate=True,
            )
            if isinstance(encoded_id, str) else raw_id
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid passkey credential ID") from None
    if not raw_id or len(raw_id) > 1024 or decoded_id != raw_id:
        raise HTTPException(status_code=400, detail="Invalid passkey credential ID")

    login_error: tuple[int, str] | None = None
    session_data: tuple[object, ...] | None = None
    with connection.transaction():
        pending = find_pending_operator_login_mfa_challenge(
            connection, challenge_hash=challenge_hash, origin=origin, rp_id=rp_id,
        )
        if pending is None:
            login_error = (400, "Passkey login challenge is invalid or expired")
        else:
            challenge_id, user_id, tenant_id = pending
            credential_row = find_active_operator_webauthn_credential(
                connection, credential_id=raw_id,
            )
            if credential_row is None or str(credential_row[1]) != str(user_id):
                record_operator_mfa_challenge_failure(connection, challenge_hash=challenge_hash)
                insert_operator_audit_event(
                    connection, tenant_id=str(tenant_id), actor_user_id=str(user_id),
                    actor_kind="operator", action="auth.login.mfa_failed",
                    remote_ip=_operator_client_ip(request), metadata={"method": "webauthn"},
                )
                login_error = (401, "Passkey authentication failed")
            else:
                try:
                    verified = verify_webauthn_authentication(
                        credential=credential,
                        expected_challenge=challenge,
                        expected_origin=origin,
                        rp_id=rp_id,
                        credential_public_key=credential_row[2],
                        credential_current_sign_count=int(credential_row[3]),
                        require_user_verification=True,
                    )
                except (WebAuthnVerificationError, ValueError):
                    record_operator_mfa_challenge_failure(connection, challenge_hash=challenge_hash)
                    insert_operator_audit_event(
                        connection, tenant_id=str(tenant_id), actor_user_id=str(user_id),
                        actor_kind="operator", action="auth.login.mfa_failed",
                        remote_ip=_operator_client_ip(request), metadata={"method": "webauthn"},
                    )
                    login_error = (401, "Passkey authentication failed")
                else:
                    consumed = consume_operator_login_mfa_challenge(
                        connection, challenge_hash=challenge_hash, origin=origin, rp_id=rp_id,
                    )
                    if (
                        consumed is None or str(consumed[0]) != str(challenge_id)
                        or str(consumed[1]) != str(user_id) or str(consumed[2]) != str(tenant_id)
                    ):
                        login_error = (409, "Passkey login challenge was already used")
                    elif not update_operator_webauthn_credential_after_assertion(
                        connection, credential_row_id=str(credential_row[0]),
                        user_id=str(user_id), new_sign_count=verified.new_sign_count,
                        backup_eligible=verified.device_type == "multi_device",
                        backup_state=verified.backed_up,
                    ):
                        login_error = (401, "Passkey credential is no longer active")
                    else:
                        membership = find_operator_tenant_membership(
                            connection, user_id=str(user_id), tenant_id=str(tenant_id),
                        )
                        if membership is None:
                            login_error = (403, "Tenant membership is no longer active")
                        else:
                            canonical_email, role = membership
                            tokens = issue_session_tokens()
                            existing_token = request.cookies.get("operator_session")
                            if existing_token:
                                try:
                                    revoke_operator_session(
                                        connection, token_hash=hash_token(existing_token),
                                    )
                                except ValueError:
                                    pass
                            session_id = create_operator_session(
                                connection, user_id=str(user_id), tenant_id=str(tenant_id),
                                token_hash=tokens.session_hash, csrf_token_hash=tokens.csrf_hash,
                                expires_at=tokens.expires_at, remote_ip=_operator_client_ip(request),
                                user_agent=request.headers.get("user-agent"),
                            )
                            insert_operator_audit_event(
                                connection, tenant_id=str(tenant_id), actor_user_id=str(user_id),
                                actor_kind="operator", action="auth.login.succeeded",
                                remote_ip=_operator_client_ip(request), target_type="operator_session",
                                target_id=session_id,
                                metadata={"role": str(role), "method": "webauthn",
                                          "credential_id_sha256": hashlib.sha256(raw_id).hexdigest()},
                            )
                            session_data = (str(canonical_email), str(tenant_id), str(role), tokens)

    if login_error is not None:
        raise HTTPException(status_code=login_error[0], detail=login_error[1])
    if session_data is None:
        raise HTTPException(status_code=401, detail="Passkey authentication failed")
    canonical_email, tenant_id, role, tokens = session_data
    response.set_cookie(
        "operator_session", tokens.session_token, max_age=43200,
        httponly=True, secure=secure, samesite="lax", path="/",
    )
    response.set_cookie(
        "operator_csrf", tokens.csrf_token, max_age=43200,
        httponly=False, secure=secure, samesite="lax", path="/",
    )
    return {
        "operator": {"email": canonical_email, "tenant_id": tenant_id, "role": role},
        "csrf_token": tokens.csrf_token,
        "expires_at": tokens.expires_at.isoformat(),
    }


@app.post("/operator/webauthn/register/options")
async def operator_webauthn_registration_options(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    principal: OperatorPrincipal = _operator_principal_dependency_injected,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """Create a password-reauthenticated, user-bound passkey registration ceremony."""
    _operator_csrf_guard(request, principal, x_csrf_token)
    origin, rp_id = _operator_webauthn_config(request)
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid enrollment request") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid enrollment request")
    password = payload.get("password")
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise HTTPException(status_code=400, detail="Password re-authentication is required")

    password_row = find_operator_password_hash(connection, user_id=principal.user_id)
    if (
        password_row is None or password_row[1] != "active"
        or not verify_operator_password(password_row[0], password)
    ):
        raise HTTPException(status_code=401, detail="Password re-authentication failed")

    challenge = generate_webauthn_challenge()
    try:
        options_json = generate_registration_options_json(
            rp_id=rp_id,
            rp_name=os.environ.get("OPERATOR_WEBAUTHN_RP_NAME", "ISP RADIUS Operator"),
            user_id=UUID(principal.user_id).bytes,
            user_name=principal.email,
            user_display_name=principal.email,
            challenge=challenge,
            exclude_credential_ids=list_active_operator_webauthn_credential_ids(
                connection, user_id=principal.user_id,
            ),
        )
        options = json.loads(options_json)
        if not isinstance(options, dict) or not isinstance(options.get("challenge"), str):
            raise TypeError("Malformed registration options")
        if not hmac.compare_digest(
            hash_webauthn_challenge(_decode_webauthn_challenge(options["challenge"])),
            hash_webauthn_challenge(challenge),
        ):
            raise ValueError("Registration options challenge mismatch")
    except (ValueError, WebAuthnVerificationError, TypeError):
        raise HTTPException(status_code=503, detail="Unable to start passkey enrollment") from None

    challenge_hash = hash_webauthn_challenge(challenge)
    with connection.transaction():
        create_operator_mfa_challenge(
            connection,
            user_id=principal.user_id,
            challenge_hash=challenge_hash,
            method="webauthn",
            origin=origin,
            rp_id=rp_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        insert_operator_audit_event(
            connection, tenant_id=principal.tenant_id, actor_user_id=principal.user_id,
            actor_kind="operator", action="auth.webauthn.registration.started",
            remote_ip=_operator_client_ip(request), metadata={"method": "webauthn"},
        )
    return {"publicKey": options}


@app.post("/operator/webauthn/register/verify")
async def operator_webauthn_registration_verify(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    principal: OperatorPrincipal = _operator_principal_dependency_injected,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """Verify attestation, then atomically consume its challenge and store public key."""
    _operator_csrf_guard(request, principal, x_csrf_token)
    origin, rp_id = _operator_webauthn_config(request)
    raw_body = await request.body()
    if len(raw_body) > 16384:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid enrollment response") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("credential"), dict):
        raise HTTPException(status_code=400, detail="Invalid enrollment response")
    challenge = _decode_webauthn_challenge(payload.get("challenge"))
    challenge_hash = hash_webauthn_challenge(challenge)
    pending = find_pending_operator_mfa_challenge(
        connection, challenge_hash=challenge_hash, method="webauthn",
        origin=origin, rp_id=rp_id,
    )
    if pending is None or str(pending[1]) != principal.user_id:
        raise HTTPException(status_code=400, detail="Passkey enrollment challenge is invalid or expired")

    credential = payload["credential"]
    response_data = credential.get("response")
    if not isinstance(response_data, dict):
        raise HTTPException(status_code=400, detail="Invalid enrollment response")
    transports = response_data.get("transports", credential.get("transports", []))
    allowed_transports = {"usb", "nfc", "ble", "smart-card", "hybrid", "internal"}
    if (
        not isinstance(transports, list) or len(transports) > 6
        or any(not isinstance(item, str) or item not in allowed_transports for item in transports)
    ):
        raise HTTPException(status_code=400, detail="Invalid authenticator transports")

    try:
        verified = verify_webauthn_registration(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=origin,
            rp_id=rp_id,
            require_user_verification=True,
        )
    except (WebAuthnVerificationError, ValueError):
        record_operator_mfa_challenge_failure(connection, challenge_hash=challenge_hash)
        raise HTTPException(status_code=400, detail="Passkey registration verification failed") from None

    try:
        with connection.transaction():
            consumed = consume_operator_mfa_challenge(
                connection, challenge_hash=challenge_hash, method="webauthn",
                origin=origin, rp_id=rp_id,
            )
            if consumed is None or str(consumed[1]) != principal.user_id:
                raise HTTPException(status_code=409, detail="Passkey enrollment challenge was already used")
            credential_row_id = create_operator_webauthn_credential(
                connection,
                user_id=principal.user_id,
                credential_id=verified.credential_id,
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count,
                transports=transports,
                backup_eligible=verified.device_type == "multi_device",
                backup_state=verified.backed_up,
            )
            insert_operator_audit_event(
                connection, tenant_id=principal.tenant_id, actor_user_id=principal.user_id,
                actor_kind="operator", action="auth.webauthn.registration.succeeded",
                remote_ip=_operator_client_ip(request), target_type="webauthn_credential",
                target_id=credential_row_id,
                metadata={"method": "webauthn", "backup_eligible": verified.device_type == "multi_device"},
            )
    except psycopg.IntegrityError:
        raise HTTPException(status_code=409, detail="This passkey is already registered") from None

    return {"status": "registered", "credential_id": credential_row_id}


@app.get("/operator/session")
def operator_session(
    request: Request,
    principal: OperatorPrincipal = _operator_principal_dependency_injected,
) -> dict[str, object]:
    csrf_cookie = request.cookies.get("operator_csrf")
    if not csrf_cookie:
        raise HTTPException(status_code=401, detail="Operator CSRF cookie is missing")
    try:
        csrf_valid = hmac.compare_digest(
            hash_token(csrf_cookie), principal.csrf_token_hash
        )
    except ValueError:
        csrf_valid = False
    if not csrf_valid:
        raise HTTPException(status_code=401, detail="Operator CSRF cookie is invalid")
    return {
        "operator": {
            "user_id": principal.user_id,
            "email": principal.email,
            "tenant_id": principal.tenant_id,
            "role": principal.role,
        },
        "permissions": sorted(permissions_for_role(principal.role)),
        "csrf_token": csrf_cookie,
    }


@app.post("/operator/logout", status_code=status.HTTP_204_NO_CONTENT)
def operator_logout(
    request: Request,
    response: Response,
    x_csrf_token: str | None = Header(default=None),
    principal: OperatorPrincipal = _operator_principal_dependency_injected,
    connection: psycopg.Connection = _database_dependency,
) -> Response:
    _operator_origin_guard(request)
    csrf_cookie = request.cookies.get("operator_csrf")
    if not csrf_matches(
        supplied_header=x_csrf_token,
        csrf_cookie=csrf_cookie,
        stored_hash=principal.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    session_token = request.cookies.get("operator_session", "")
    with connection.transaction():
        revoked = revoke_operator_session(
            connection, token_hash=hash_token(session_token)
        )
        if revoked is not None:
            insert_operator_audit_event(
                connection,
                tenant_id=principal.tenant_id,
                actor_user_id=principal.user_id,
                actor_kind="operator",
                action="auth.logout",
                remote_ip=_operator_client_ip(request),
                target_type="operator_session",
                target_id=str(revoked[0]),
            )
    secure = _operator_cookie_secure()
    response.delete_cookie("operator_session", path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie("operator_csrf", path="/", secure=secure, httponly=False, samesite="lax")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response



@app.get("/operator/monitoring/sessions")
def operator_monitoring_sessions(
    principal: OperatorPrincipal = _operator_sessions_read_dependency,
    state: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    nas_identifier: str | None = Query(default=None, max_length=253),
    stale_after_seconds: int = Query(default=300, ge=30, le=86400),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """Browser-safe, read-only monitoring BFF scoped to the operator session."""
    try:
        items = list_subscriber_sessions(
            connection,
            tenant_id=principal.tenant_id,
            state=state,
            search=search,
            nas_identifier=nas_identifier,
            stale_after_seconds=stale_after_seconds,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"items": items, "limit": limit, "offset": offset}


@app.get("/operator/monitoring/sessions/summary")
def operator_monitoring_session_summary(
    principal: OperatorPrincipal = _operator_sessions_read_dependency,
    stale_after_seconds: int = Query(default=300, ge=30, le=86400),
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, int]:
    """Return monitoring summary for the tenant bound to the operator session."""
    try:
        return get_subscriber_session_summary(
            connection,
            tenant_id=principal.tenant_id,
            stale_after_seconds=stale_after_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(connection: psycopg.Connection = _database_dependency) -> dict[str, str]:
    connection.execute("SELECT 1")
    return {"status": "ready"}


@app.post("/radius/authenticate", status_code=status.HTTP_204_NO_CONTENT)
async def radius_authenticate(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
) -> Response:
    """Validate one PAP credential request sent over the protected REST channel."""
    raw_body = await request.body()
    if len(raw_body) > 8192:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        username = form["username"][0]
        password = form["password"][0]
        nas_ip = form["nas_ip"][0]
        if any(len(form[key]) != 1 for key in ("username", "password", "nas_ip")):
            raise ValueError("duplicate form field")
    except (UnicodeDecodeError, KeyError, IndexError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid authentication request") from None

    subscriber = await run_in_threadpool(
        authenticate_subscriber, connection, nas_ip=nas_ip, username=username, password=password,
    )
    if subscriber is None:
        raise HTTPException(status_code=401, detail="Invalid subscriber credentials")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/radius/authorize")
async def radius_authorize(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, dict[str, str]]:
    """Return validated Access-Accept reply attributes for an active subscriber."""
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        username = form["username"][0]
        nas_ip = form["nas_ip"][0]
        if any(len(form[key]) != 1 for key in ("username", "nas_ip")):
            raise ValueError("duplicate form field")
    except (UnicodeDecodeError, KeyError, IndexError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid authorization request") from None

    try:
        authorization = await run_in_threadpool(
            authorize_subscriber, connection, nas_ip=nas_ip, username=username,
        )
    except NotImplementedError as exc:
        raise HTTPException(status_code=503, detail="NAS RADIUS profile is unsupported") from exc
    if authorization is None:
        raise HTTPException(status_code=401, detail="Subscriber authorization rejected")
    return {
        attribute: {"op": ":=", "value": value}
        for attribute, value in authorization.attributes.items()
    }


_ACCOUNTING_FORM_FIELDS = {
    "acct_status_type": "Acct-Status-Type",
    "acct_session_id": "Acct-Session-Id",
    "username": "User-Name",
    "event_timestamp": "Event-Timestamp",
    "acct_delay_time": "Acct-Delay-Time",
    "acct_input_octets": "Acct-Input-Octets",
    "acct_input_gigawords": "Acct-Input-Gigawords",
    "acct_output_octets": "Acct-Output-Octets",
    "acct_output_gigawords": "Acct-Output-Gigawords",
    "acct_session_time": "Acct-Session-Time",
    "acct_terminate_cause": "Acct-Terminate-Cause",
}


@app.post("/radius/accounting", status_code=status.HTTP_204_NO_CONTENT)
async def radius_accounting(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
) -> Response:
    """Atomically accept, deduplicate, project and meter a FreeRADIUS accounting event."""
    raw_body = await request.body()
    if len(raw_body) > 8192:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        if any(len(values) != 1 for values in form.values()):
            raise ValueError("duplicate form field")
        nas_ip = str(ip_address(form["nas_ip"][0]))
        attributes = {
            radius_name: form[field_name][0]
            for field_name, radius_name in _ACCOUNTING_FORM_FIELDS.items()
            if field_name in form and form[field_name][0] != ""
        }
        if not attributes.get("Acct-Session-Id") or not attributes.get("User-Name"):
            raise ValueError("required accounting fields are missing")
        if not attributes.get("Acct-Status-Type"):
            raise ValueError("Acct-Status-Type is required")
    except (UnicodeDecodeError, KeyError, IndexError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid accounting request") from None

    try:
        with connection.transaction():
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    SELECT tenant_id, name
                      FROM nas_devices
                     WHERE address = %s AND enabled = TRUE
                    """,
                    (nas_ip,),
                )
                nas_rows = cursor.fetchall()
            finally:
                cursor.close()

            if len(nas_rows) != 1:
                raise HTTPException(status_code=401, detail="Unknown or ambiguous NAS source")

            tenant_id, nas_name = nas_rows[0]
            attributes["NAS-Identifier"] = str(nas_name)
            event = normalize_accounting(attributes)
            await run_in_threadpool(
                record_accounting_event_with_usage,
                connection,
                tenant_id=str(tenant_id),
                event=event,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid accounting attributes") from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/monitoring/sessions")
def monitoring_sessions(
    tenant_id: str = Depends(_monitoring_tenant_dependency),
    state: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    nas_identifier: str | None = Query(default=None, max_length=253),
    stale_after_seconds: int = Query(default=300, ge=30, le=86400),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, object]:
    """List sessions for the authenticated tenant."""
    try:
        items = list_subscriber_sessions(
            connection, tenant_id=tenant_id, state=state, search=search,
            nas_identifier=nas_identifier, stale_after_seconds=stale_after_seconds,
            limit=limit, offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"items": items, "limit": limit, "offset": offset}


@app.get("/monitoring/sessions/summary")
def monitoring_session_summary(
    tenant_id: str = Depends(_monitoring_tenant_dependency),
    stale_after_seconds: int = Query(default=300, ge=30, le=86400),
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, int]:
    """Return tenant-scoped session counts and usage counters."""
    try:
        return get_subscriber_session_summary(
            connection, tenant_id=tenant_id, stale_after_seconds=stale_after_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
