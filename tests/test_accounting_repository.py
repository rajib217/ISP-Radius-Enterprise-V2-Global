from datetime import UTC, datetime
from uuid import uuid4

import pytest

from isp_radius.aaa.accounting import AccountingEvent, AccountingStatus
from isp_radius.persistence.accounting_repository import persist_accounting_event


class FakeCursor:
    def __init__(self, returned_row):
        self.returned_row = returned_row
        self.statement = None
        self.parameters = None
        self.closed = False

    def execute(self, operation, parameters):
        self.statement = operation
        self.parameters = parameters

    def fetchone(self):
        return self.returned_row

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def cursor(self):
        return self.fake_cursor


def make_event():
    return AccountingEvent(
        nas_id="bng-01",
        session_id="sess-001",
        username="customer-01",
        status=AccountingStatus.INTERIM_UPDATE,
        event_time=datetime(2026, 11, 27, 10, 0, tzinfo=UTC),
        input_octets=1000,
        output_octets=2000,
        session_seconds=300,
    )


def test_persists_event_and_returns_true_for_new_row():
    cursor = FakeCursor((str(uuid4()),))
    connection = FakeConnection(cursor)
    tenant_id = str(uuid4())

    inserted = persist_accounting_event(connection, tenant_id=tenant_id, event=make_event())

    assert inserted is True
    assert cursor.parameters[1] == tenant_id
    assert cursor.parameters[4] == "sess-001"
    assert cursor.parameters[5] == "customer-01"
    assert "ON CONFLICT (tenant_id, idempotency_key) DO NOTHING" in cursor.statement
    assert cursor.closed is True


def test_duplicate_event_returns_false():
    cursor = FakeCursor(None)
    inserted = persist_accounting_event(
        FakeConnection(cursor), tenant_id=str(uuid4()), event=make_event()
    )
    assert inserted is False
    assert cursor.closed is True


def test_rejects_invalid_tenant_id_before_database_access():
    cursor = FakeCursor(None)
    with pytest.raises(ValueError, match="tenant_id"):
        persist_accounting_event(
            FakeConnection(cursor), tenant_id="not-a-uuid", event=make_event()
        )
    assert cursor.statement is None
    assert cursor.closed is False
