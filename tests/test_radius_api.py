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
