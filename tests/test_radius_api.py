from uuid import uuid4

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from isp_radius.api.app import _database_connection, app


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self.query_cursor = Cursor(rows)

    def cursor(self):
        return self.query_cursor


def test_radius_rest_endpoint_accepts_valid_pap_credentials():
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        "correct-password"
    )
    connection = FakeConnection(
        [(uuid4(), "subscriber-1", password_hash, 20_000_000, 5_000_000)]
    )

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/authenticate",
            data={
                "username": "subscriber-1",
                "password": "correct-password",
                "nas_ip": "192.0.2.10",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 204


def test_radius_rest_endpoint_rejects_invalid_password():
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        "correct-password"
    )
    connection = FakeConnection(
        [(uuid4(), "subscriber-1", password_hash, 20_000_000, 5_000_000)]
    )

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/authenticate",
            data={
                "username": "subscriber-1",
                "password": "wrong-password",
                "nas_ip": "192.0.2.10",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401


def test_monitoring_endpoint_requires_bearer_token_before_database_access():
    database_dependency_called = False

    def override_connection():
        nonlocal database_dependency_called
        database_dependency_called = True
        yield object()

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).get("/monitoring/sessions")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert database_dependency_called is False


def test_monitoring_endpoint_scopes_queries_to_api_key_tenant(monkeypatch):
    import hashlib
    import json

    tenant_id = str(uuid4())
    token = "test-monitoring-token"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv(
        "MONITORING_API_KEY_HASHES",
        json.dumps({token_hash: {"tenant_id": tenant_id, "permissions": ["sessions:read"]}}),
    )

    class MonitoringCursor:
        def execute(self, statement, parameters):
            self.statement = statement
            self.parameters = parameters
        def fetchall(self):
            return []
        def close(self):
            pass

    class MonitoringConnection:
        def __init__(self):
            self.query_cursor = MonitoringCursor()
        def cursor(self):
            return self.query_cursor

    connection = MonitoringConnection()
    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).get(
            "/monitoring/sessions?state=online",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert connection.query_cursor.parameters[1] == tenant_id


def test_monitoring_endpoint_rejects_missing_read_permission(monkeypatch):
    import hashlib
    import json

    token = "no-read-permission"
    monkeypatch.setenv(
        "MONITORING_API_KEY_HASHES",
        json.dumps({
            hashlib.sha256(token.encode()).hexdigest(): {
                "tenant_id": str(uuid4()), "permissions": ["sessions:write"]
            }
        }),
    )
    database_dependency_called = False

    def override_connection():
        nonlocal database_dependency_called
        database_dependency_called = True
        yield object()

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).get(
            "/monitoring/sessions", headers={"Authorization": f"Bearer {token}"}
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert database_dependency_called is False



def test_monitoring_summary_uses_authenticated_tenant_and_stale_threshold(monkeypatch):
    import hashlib
    import json

    tenant_id = str(uuid4())
    token = "summary-monitoring-token"
    monkeypatch.setenv(
        "MONITORING_API_KEY_HASHES",
        json.dumps({
            hashlib.sha256(token.encode()).hexdigest(): {
                "tenant_id": tenant_id, "permissions": ["sessions:read"]
            }
        }),
    )
    observed = {}

    def fake_summary(connection, *, tenant_id, stale_after_seconds):
        observed["connection"] = connection
        observed["tenant_id"] = tenant_id
        observed["stale_after_seconds"] = stale_after_seconds
        return {"online": 3, "stale": 1, "offline": 2}

    monkeypatch.setattr("isp_radius.api.app.get_subscriber_session_summary", fake_summary)
    connection = object()

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).get(
            "/monitoring/sessions/summary?stale_after_seconds=600",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"online": 3, "stale": 1, "offline": 2}
    assert observed == {
        "connection": connection,
        "tenant_id": tenant_id,
        "stale_after_seconds": 600,
    }
