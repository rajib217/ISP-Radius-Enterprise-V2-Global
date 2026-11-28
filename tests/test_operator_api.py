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
