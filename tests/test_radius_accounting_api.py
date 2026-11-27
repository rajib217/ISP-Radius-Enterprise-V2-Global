from contextlib import nullcontext
from uuid import uuid4

from fastapi.testclient import TestClient

from isp_radius.api.app import _database_connection, app


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.statement = None
        self.parameters = None
        self.closed = False

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, rows):
        self.query_cursor = Cursor(rows)
        self.transaction_calls = 0

    def cursor(self):
        return self.query_cursor

    def transaction(self):
        self.transaction_calls += 1
        return nullcontext()


def test_radius_accounting_persists_normalized_event_and_acknowledges_duplicate(monkeypatch):
    tenant_id = uuid4()
    connection = FakeConnection([(tenant_id, "trusted-bng-01")])
    recorded = []

    def fake_record(conn, *, tenant_id, event):
        recorded.append((conn, tenant_id, event))
        return False  # Exact retransmission is still acknowledged to FreeRADIUS.

    monkeypatch.setattr("isp_radius.api.app.record_accounting_event", fake_record)

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/accounting",
            data={
                "nas_ip": "192.0.2.55",
                "acct_status_type": "3",
                "acct_session_id": "session-abc",
                "username": "subscriber-01",
                "acct_input_octets": "1",
                "acct_input_gigawords": "1",
                "acct_output_octets": "2048",
                "acct_session_time": "3600",
                "acct_delay_time": "4",
                "nas_identifier": "untrusted-client-value",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 204
    assert connection.transaction_calls == 1
    assert len(recorded) == 1
    _, resolved_tenant, event = recorded[0]
    assert resolved_tenant == str(tenant_id)
    assert event.nas_id == "trusted-bng-01"
    assert event.session_id == "session-abc"
    assert event.input_octets == (1 << 32) + 1
    assert event.output_octets == 2048
    assert event.session_seconds == 3600


def test_radius_accounting_rejects_duplicate_form_fields():
    connection = FakeConnection([])

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/accounting",
            content=(
                "nas_ip=192.0.2.55&acct_status_type=1&acct_status_type=2"
                "&acct_session_id=s1&username=u1"
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert connection.transaction_calls == 0


def test_radius_accounting_rejects_unknown_nas_source():
    connection = FakeConnection([])

    def override_connection():
        yield connection

    app.dependency_overrides[_database_connection] = override_connection
    try:
        response = TestClient(app).post(
            "/radius/accounting",
            data={
                "nas_ip": "192.0.2.55",
                "acct_status_type": "1",
                "acct_session_id": "s1",
                "username": "u1",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert connection.transaction_calls == 1
