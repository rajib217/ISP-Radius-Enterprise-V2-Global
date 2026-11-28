from contextlib import nullcontext
from uuid import uuid4

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from isp_radius.api.app import _database_connection, app
from isp_radius.security.operator_auth import hash_token


class FakeConnection:
    def transaction(self):
        return nullcontext()


def _client(monkeypatch, rows):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("OPERATOR_COOKIE_SECURE", "false")
    monkeypatch.setenv("OPERATOR_ALLOWED_ORIGINS", "http://testserver")
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    monkeypatch.setattr("isp_radius.api.app.find_operator_memberships", lambda *_a, **_k: rows)
    monkeypatch.setattr("isp_radius.api.app.operator_login_rate_limited", lambda *_a, **_k: False)
    monkeypatch.setattr("isp_radius.api.app.record_operator_login_failure", lambda *_a, **_k: None)
    monkeypatch.setattr("isp_radius.api.app.clear_operator_login_failures", lambda *_a, **_k: None)
    monkeypatch.setattr("isp_radius.api.app.insert_operator_audit_event", lambda *_a, **_k: "audit-id")
    monkeypatch.setattr("isp_radius.api.app.create_operator_session", lambda *_a, **_k: "session-id")
    return TestClient(app), connection


def test_operator_login_issues_http_only_session_and_csrf_cookies(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("correct-password")
    client, _ = _client(monkeypatch, [(user_id, "operator@example.com", password_hash, "active", tenant_id, "viewer", "active")])
    try:
        response = client.post(
            "/operator/login",
            headers={"Origin": "http://testserver"},
            json={"email": "Operator@Example.com", "password": "correct-password"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["operator"]["tenant_id"] == tenant_id
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(value for value in cookies if value.startswith("operator_session="))
    csrf_cookie = next(value for value in cookies if value.startswith("operator_csrf="))
    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()
    assert "samesite=lax" in csrf_cookie.lower()


def test_operator_login_requires_tenant_selection_for_multi_tenant_user(monkeypatch):
    user_id = str(uuid4())
    tenant_a, tenant_b = str(uuid4()), str(uuid4())
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("correct-password")
    rows = [
        (user_id, "operator@example.com", password_hash, "active", tenant_a, "viewer", "active"),
        (user_id, "operator@example.com", password_hash, "active", tenant_b, "billing", "active"),
    ]
    client, _ = _client(monkeypatch, rows)
    try:
        response = client.post(
            "/operator/login",
            headers={"Origin": "http://testserver"},
            json={"email": "operator@example.com", "password": "correct-password"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    assert {item["tenant_id"] for item in response.json()["detail"]["tenants"]} == {tenant_a, tenant_b}


def test_operator_login_rejects_untrusted_origin(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("correct-password")
    client, _ = _client(monkeypatch, [(user_id, "operator@example.com", password_hash, "active", tenant_id, "viewer", "active")])
    try:
        response = client.post(
            "/operator/login",
            headers={"Origin": "https://attacker.example"},
            json={"email": "operator@example.com", "password": "correct-password"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403


def test_operator_session_and_logout_enforce_csrf_and_revoke(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    csrf = "test-csrf-token-value"
    session_token = "test-session-token-value"
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("correct-password")
    rows = [(user_id, "operator@example.com", password_hash, "active", tenant_id, "viewer", "active")]
    client, _ = _client(monkeypatch, rows)
    monkeypatch.setattr(
        "isp_radius.api.app.resolve_operator_session",
        lambda *_a, **_k: ("session-id", user_id, "operator@example.com", tenant_id, "viewer", hash_token(csrf)),
    )
    revoked = []
    monkeypatch.setattr(
        "isp_radius.api.app.revoke_operator_session",
        lambda *_a, **_k: revoked.append(True) or ("session-id", tenant_id, user_id),
    )
    try:
        client.cookies.set("operator_session", session_token)
        client.cookies.set("operator_csrf", csrf)
        session = client.get("/operator/session")
        bad_logout = client.post(
            "/operator/logout", headers={"Origin": "http://testserver", "X-CSRF-Token": "wrong"}
        )
        logout = client.post(
            "/operator/logout", headers={"Origin": "http://testserver", "X-CSRF-Token": csrf}
        )
    finally:
        app.dependency_overrides.clear()

    assert session.status_code == 200
    assert "sessions:read" in session.json()["permissions"]
    assert bad_logout.status_code == 403
    assert logout.status_code == 204
    assert revoked == [True]


def test_operator_monitoring_bff_derives_tenant_and_checks_read_permission(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    csrf = "bff-csrf-token"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("OPERATOR_COOKIE_SECURE", "false")
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    monkeypatch.setattr(
        "isp_radius.api.app.resolve_operator_session",
        lambda *_a, **_k: ("session-id", user_id, "viewer@example.com", tenant_id, "viewer", hash_token(csrf)),
    )
    observed = {}

    def fake_list(_connection, **kwargs):
        observed.update(kwargs)
        return [{"id": "session-1", "state": "online"}]

    monkeypatch.setattr("isp_radius.api.app.list_subscriber_sessions", fake_list)
    client = TestClient(app)
    try:
        client.cookies.set("operator_session", "valid-session-cookie")
        response = client.get("/operator/monitoring/sessions?state=online&limit=25")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["items"] == [{"id": "session-1", "state": "online"}]
    assert observed["tenant_id"] == tenant_id
    assert observed["state"] == "online"
    assert observed["limit"] == 25


def test_operator_monitoring_bff_denies_role_without_sessions_read(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    monkeypatch.setenv("APP_ENV", "test")
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    monkeypatch.setattr(
        "isp_radius.api.app.resolve_operator_session",
        lambda *_a, **_k: ("session-id", user_id, "billing@example.com", tenant_id, "billing", hash_token("csrf")),
    )
    repository_called = False

    def fake_list(*_a, **_k):
        nonlocal repository_called
        repository_called = True
        return []

    monkeypatch.setattr("isp_radius.api.app.list_subscriber_sessions", fake_list)
    client = TestClient(app)
    try:
        client.cookies.set("operator_session", "valid-session-cookie")
        response = client.get("/operator/monitoring/sessions")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert repository_called is False


def test_operator_monitoring_bff_rejects_missing_session_before_session_lookup(monkeypatch):
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    lookup_called = False

    def fake_resolve(*_a, **_k):
        nonlocal lookup_called
        lookup_called = True

    monkeypatch.setattr("isp_radius.api.app.resolve_operator_session", fake_resolve)
    client = TestClient(app)
    try:
        response = client.get("/operator/monitoring/sessions")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert lookup_called is False



def test_security_headers_are_present_and_hsts_requires_https(monkeypatch):
    http_client = TestClient(app)
    http_response = http_client.get("/health/live")
    assert http_response.status_code == 200
    assert http_response.headers["x-content-type-options"] == "nosniff"
    assert http_response.headers["x-frame-options"] == "DENY"
    assert http_response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in http_response.headers["content-security-policy"]
    assert "strict-transport-security" not in http_response.headers

    https_client = TestClient(app, base_url="https://testserver")
    https_response = https_client.get("/health/live")
    assert https_response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_operator_responses_are_not_cacheable(monkeypatch):
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    client = TestClient(app)
    try:
        response = client.get("/operator/session")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


def test_operator_monitoring_summary_denies_role_without_permission(monkeypatch):
    user_id, tenant_id = str(uuid4()), str(uuid4())
    monkeypatch.setenv("APP_ENV", "test")
    connection = FakeConnection()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    monkeypatch.setattr(
        "isp_radius.api.app.resolve_operator_session",
        lambda *_a, **_k: (
            "session-id", user_id, "billing@example.com", tenant_id, "billing",
            hash_token("csrf"),
        ),
    )
    repository_called = False

    def fake_summary(*_a, **_k):
        nonlocal repository_called
        repository_called = True
        return {}

    monkeypatch.setattr("isp_radius.api.app.get_subscriber_session_summary", fake_summary)
    client = TestClient(app)
    try:
        client.cookies.set("operator_session", "valid-session-cookie")
        response = client.get("/operator/monitoring/sessions/summary")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert repository_called is False



def test_webauthn_registration_options_require_password_reauth_and_return_browser_options(monkeypatch):
    import base64
    import json

    from isp_radius.api.app import _operator_principal_dependency
    from isp_radius.security.operator_auth import OperatorPrincipal

    user_id, tenant_id = str(uuid4()), str(uuid4())
    csrf = "csrf-token-for-webauthn"
    principal = OperatorPrincipal(
        user_id=user_id, email="operator@example.com", tenant_id=tenant_id,
        role="owner", session_id="session-id", csrf_token_hash=hash_token(csrf),
    )
    client, _ = _client(monkeypatch, [])
    app.dependency_overrides[_operator_principal_dependency] = lambda: principal
    monkeypatch.setenv("OPERATOR_ALLOWED_ORIGINS", "http://localhost")
    monkeypatch.setenv("OPERATOR_ALLOWED_ORIGINS", "http://localhost")
    monkeypatch.setenv("OPERATOR_WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr("isp_radius.api.app.find_operator_password_hash", lambda *_a, **_k: ("hashed", "active"))
    monkeypatch.setattr("isp_radius.api.app.verify_operator_password", lambda *_a, **_k: True)
    monkeypatch.setattr("isp_radius.api.app.generate_webauthn_challenge", lambda: b"x" * 32)
    monkeypatch.setattr("isp_radius.api.app.list_active_operator_webauthn_credential_ids", lambda *_a, **_k: ())
    monkeypatch.setattr(
        "isp_radius.api.app.generate_registration_options_json",
        lambda **_k: json.dumps({"challenge": base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")}),
    )
    stored = []
    monkeypatch.setattr("isp_radius.api.app.create_operator_mfa_challenge", lambda *_a, **kw: stored.append(kw) or "challenge-id")
    try:
        client.cookies.set("operator_session", "session-cookie")
        client.cookies.set("operator_csrf", csrf)
        response = client.post(
            "/operator/webauthn/register/options",
            headers={"Origin": "http://localhost", "X-CSRF-Token": csrf},
            json={"password": "current-password"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["publicKey"]["challenge"].startswith("eHh4")
    assert stored[0]["user_id"] == user_id
    assert stored[0]["method"] == "webauthn"
    assert stored[0]["origin"] == "http://localhost"
    assert stored[0]["rp_id"] == "localhost"


def test_webauthn_registration_verification_consumes_challenge_and_persists_public_key(monkeypatch):
    import base64

    from isp_radius.api.app import _operator_principal_dependency
    from isp_radius.security.operator_auth import OperatorPrincipal
    from isp_radius.security.webauthn import VerifiedRegistration

    user_id, tenant_id = str(uuid4()), str(uuid4())
    csrf = "csrf-token-for-webauthn"
    challenge = b"y" * 32
    challenge_text = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
    principal = OperatorPrincipal(
        user_id=user_id, email="operator@example.com", tenant_id=tenant_id,
        role="owner", session_id="session-id", csrf_token_hash=hash_token(csrf),
    )
    client, _ = _client(monkeypatch, [])
    app.dependency_overrides[_operator_principal_dependency] = lambda: principal
    monkeypatch.setenv("OPERATOR_ALLOWED_ORIGINS", "http://localhost")
    monkeypatch.setenv("OPERATOR_WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(
        "isp_radius.api.app.find_pending_operator_mfa_challenge",
        lambda *_a, **_k: ("challenge-id", user_id),
    )
    monkeypatch.setattr(
        "isp_radius.api.app.verify_webauthn_registration",
        lambda **_k: VerifiedRegistration(b"credential-id", b"public-key", 0, "single_device", False),
    )
    monkeypatch.setattr(
        "isp_radius.api.app.consume_operator_mfa_challenge",
        lambda *_a, **_k: ("challenge-id", user_id),
    )
    persisted = []
    monkeypatch.setattr(
        "isp_radius.api.app.create_operator_webauthn_credential",
        lambda *_a, **kw: persisted.append(kw) or "credential-row",
    )
    try:
        client.cookies.set("operator_session", "session-cookie")
        client.cookies.set("operator_csrf", csrf)
        response = client.post(
            "/operator/webauthn/register/verify",
            headers={"Origin": "http://localhost", "X-CSRF-Token": csrf},
            json={
                "challenge": challenge_text,
                "credential": {"id": "browser-id", "response": {"transports": ["internal"]}},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "registered"
    assert persisted[0]["user_id"] == user_id
    assert persisted[0]["credential_id"] == b"credential-id"
    assert persisted[0]["public_key"] == b"public-key"
    assert persisted[0]["transports"] == ["internal"]
