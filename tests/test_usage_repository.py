from datetime import UTC, datetime
from uuid import uuid4

import pytest

from isp_radius.billing.usage import UsageDelta
from isp_radius.persistence.usage_repository import persist_usage_delta


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.statement = None
        self.parameters = None
        self.closed = False

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def cursor(self):
        return self.fake_cursor


def make_delta():
    return UsageDelta(
        nas_id="bng-01", session_id="session-01", username="subscriber-01",
        period_start=datetime(2026, 11, 27, 10, 0, tzinfo=UTC),
        period_end=datetime(2026, 11, 27, 10, 5, tzinfo=UTC),
        input_bytes=1024, output_bytes=2048, session_seconds=300,
    )


def test_persists_usage_delta_with_tenant_and_source_events():
    cursor = FakeCursor((str(uuid4()),))
    tenant_id, previous_id, current_id = str(uuid4()), str(uuid4()), str(uuid4())
    inserted = persist_usage_delta(
        FakeConnection(cursor), tenant_id=tenant_id,
        previous_event_id=previous_id, current_event_id=current_id, delta=make_delta(),
    )
    assert inserted is True
    assert cursor.parameters[1:7] == (
        tenant_id, "bng-01", "session-01", "subscriber-01", previous_id, current_id
    )
    assert cursor.parameters[9:] == (1024, 2048, 300)
    assert "ON CONFLICT (tenant_id, current_event_id) DO NOTHING" in cursor.statement
    assert cursor.closed


def test_duplicate_current_event_returns_false():
    cursor = FakeCursor(None)
    inserted = persist_usage_delta(
        FakeConnection(cursor), tenant_id=str(uuid4()),
        previous_event_id=str(uuid4()), current_event_id=str(uuid4()), delta=make_delta(),
    )
    assert inserted is False
    assert cursor.closed


def test_rejects_same_source_event_ids_before_database_access():
    cursor = FakeCursor(None)
    event_id = str(uuid4())
    with pytest.raises(ValueError, match="must differ"):
        persist_usage_delta(
            FakeConnection(cursor), tenant_id=str(uuid4()),
            previous_event_id=event_id, current_event_id=event_id, delta=make_delta(),
        )
    assert cursor.statement is None


def test_rejects_invalid_tenant_or_event_uuid_before_database_access():
    cursor = FakeCursor(None)
    with pytest.raises(ValueError, match="valid UUIDs"):
        persist_usage_delta(
            FakeConnection(cursor), tenant_id="bad",
            previous_event_id=str(uuid4()), current_event_id=str(uuid4()), delta=make_delta(),
        )
    assert cursor.statement is None


def test_rejects_naive_usage_period():
    cursor = FakeCursor(None)
    delta = make_delta()
    invalid = UsageDelta(
        nas_id=delta.nas_id, session_id=delta.session_id, username=delta.username,
        period_start=datetime(2026, 11, 27, 10, 0), period_end=delta.period_end,
        input_bytes=delta.input_bytes, output_bytes=delta.output_bytes,
        session_seconds=delta.session_seconds,
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        persist_usage_delta(
            FakeConnection(cursor), tenant_id=str(uuid4()),
            previous_event_id=str(uuid4()), current_event_id=str(uuid4()), delta=invalid,
        )
    assert cursor.statement is None
