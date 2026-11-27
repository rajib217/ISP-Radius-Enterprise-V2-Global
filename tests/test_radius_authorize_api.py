from uuid import uuid4

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


def test_radius_authorize_returns_mikrotik_rate_limit():
    connection = FakeConnection([("mikrotik", 20_000_000, 5_000_000)])

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/authorize",
            data={"username": "subscriber-1", "nas_ip": "192.0.2.10"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "Mikrotik-Rate-Limit": {"op": ":=", "value": "5000000/20000000"}
    }


def test_radius_authorize_rejects_unknown_subscriber():
    connection = FakeConnection([])

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/authorize",
            data={"username": "missing-user", "nas_ip": "192.0.2.10"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
