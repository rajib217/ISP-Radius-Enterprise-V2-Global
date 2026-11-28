"""Private REST endpoint consumed by FreeRADIUS rlm_rest."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
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
    create_operator_session,
    find_operator_memberships,
    insert_operator_audit_event,
    operator_login_rate_limited,
    record_operator_login_failure,
    resolve_operator_session,
    revoke_operator_session,
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


_operator_principal_dependency_injected = Depends(_operator_principal_dependency)


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
    email_hash = hash_token(email)
    ip_hash = hash_token(remote_ip)
    login_error: tuple[int, object] | None = None
    session_data: tuple[object, ...] | None = None

    with connection.transaction():
        if operator_login_rate_limited(
            connection, email_hash=email_hash, ip_hash=ip_hash
        ):
            login_error = (429, "Too many login attempts. Try again later.")
        else:
            rows = find_operator_memberships(connection, email=email)
            if not rows:
                burn_operator_password_verification(password)
                record_operator_login_failure(
                    connection, email_hash=email_hash, ip_hash=ip_hash
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
