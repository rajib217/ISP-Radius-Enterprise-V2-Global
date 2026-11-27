from datetime import UTC, datetime
from uuid import uuid4

from isp_radius.aaa.accounting import AccountingEvent, AccountingStatus
from isp_radius.persistence.session_repository import (
    apply_session_projection,
    record_accounting_event,
)


class Cursor:
    def __init__(self, row):
        self.row = row
        self.parameters = None
        self.statement = None
        self.closed = False

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, *cursors):
        self.cursors = list(cursors)

    def cursor(self):
        return self.cursors.pop(0)


def event(status=AccountingStatus.START, at=None):
    return AccountingEvent(
        nas_id="bng-01",
        session_id="session-42",
        username="subscriber-42",
        status=status,
        event_time=at or datetime(2026, 11, 27, 10, 0, tzinfo=UTC),
        input_octets=100,
        output_octets=200,
        session_seconds=30,
        terminate_cause="User-Request" if status is AccountingStatus.STOP else None,
    )


def test_start_creates_active_projection_with_start_time():
    cursor = Cursor((str(uuid4()),))
    assert apply_session_projection(
        Connection(cursor), tenant_id=str(uuid4()), event=event()
    )
    assert cursor.parameters[5] == "active"
    assert cursor.parameters[6] == event().event_time
    assert cursor.parameters[8] is None
    assert "WHERE subscriber_sessions.status = 'active'" in cursor.statement
    assert cursor.closed


def test_stop_projection_is_terminal_and_sets_stop_time():
    stop_event = event(AccountingStatus.STOP)
    cursor = Cursor((str(uuid4()),))
    assert apply_session_projection(
        Connection(cursor), tenant_id=str(uuid4()), event=stop_event
    )
    assert cursor.parameters[5] == "stopped"
    assert cursor.parameters[6] is None
    assert cursor.parameters[8] == stop_event.event_time
    assert cursor.parameters[12] == "User-Request"
    assert cursor.closed


def test_duplicate_event_does_not_attempt_projection():
    event_cursor = Cursor(None)
    connection = Connection(event_cursor)
    assert record_accounting_event(
        connection, tenant_id=str(uuid4()), event=event()
    ) is False
    assert event_cursor.closed
    assert connection.cursors == []


def test_new_event_persists_then_projects_in_same_connection():
    event_cursor = Cursor((str(uuid4()),))
    session_cursor = Cursor((str(uuid4()),))
    connection = Connection(event_cursor, session_cursor)
    assert record_accounting_event(
        connection, tenant_id=str(uuid4()), event=event()
    ) is True
    assert event_cursor.closed
    assert session_cursor.closed
    assert "INSERT INTO accounting_events" in event_cursor.statement
    assert "INSERT INTO subscriber_sessions" in session_cursor.statement
