from datetime import UTC, datetime
from uuid import uuid4

from isp_radius.aaa.accounting import AccountingEvent, AccountingStatus
from isp_radius.persistence.session_repository import (
    apply_session_projection,
    record_accounting_event,
    record_accounting_event_with_usage,
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
        self.executed = []

    def cursor(self):
        cursor = self.cursors.pop(0)
        self.executed.append(cursor)
        return cursor


def event(
    status=AccountingStatus.START,
    at=None,
    input_octets=100,
    output_octets=200,
    session_seconds=30,
):
    return AccountingEvent(
        nas_id="bng-01",
        session_id="session-42",
        username="subscriber-42",
        status=status,
        event_time=at or datetime(2026, 11, 27, 10, 0, tzinfo=UTC),
        input_octets=input_octets,
        output_octets=output_octets,
        session_seconds=session_seconds,
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
    assert "AND subscriber_sessions.username = EXCLUDED.username" in cursor.statement
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


def test_stale_stop_event_cannot_close_a_newer_session_projection():
    cursor = Cursor(None)
    apply_session_projection(
        Connection(cursor),
        tenant_id=str(uuid4()),
        event=event(
            AccountingStatus.STOP,
            at=datetime(2026, 11, 27, 9, 59, tzinfo=UTC),
        ),
    )
    statement = " ".join(cursor.statement.split())
    assert "EXCLUDED.last_event_at >= subscriber_sessions.last_event_at" in statement
    assert "EXCLUDED.status = 'active'" in statement
    assert "subscriber_sessions.started_at IS NULL" in statement
    assert "EXCLUDED.started_at IS NOT NULL" in statement
    assert "EXCLUDED.status = 'stopped' OR" not in statement
    assert cursor.closed


def test_newer_stop_event_can_close_session_projection():
    cursor = Cursor((str(uuid4()),))
    stop_at = datetime(2026, 11, 27, 10, 5, tzinfo=UTC)
    assert apply_session_projection(
        Connection(cursor),
        tenant_id=str(uuid4()),
        event=event(AccountingStatus.STOP, at=stop_at),
    )
    assert cursor.parameters[5] == "stopped"
    assert cursor.parameters[8] == stop_at


def test_accounting_ingestion_persists_delta_in_same_transaction():
    tenant_id = str(uuid4())
    previous_id = str(uuid4())
    inserted_id = str(uuid4())
    previous_time = datetime(2026, 11, 27, 9, 55, tzinfo=UTC)
    current_time = datetime(2026, 11, 27, 10, 0, tzinfo=UTC)
    connection = Connection(
        Cursor((None,)),
        Cursor((inserted_id,)),
        Cursor((str(uuid4()),)),
        Cursor(None),
        Cursor((previous_id, previous_time, 1000, 2000, 300)),
        Cursor((str(uuid4()),)),
    )

    assert record_accounting_event_with_usage(
        connection,
        tenant_id=tenant_id,
        event=event(
            AccountingStatus.INTERIM_UPDATE,
            at=current_time,
            input_octets=1500,
            output_octets=2600,
            session_seconds=330,
        ),
    ) is True

    assert len(connection.executed) == 6
    assert "pg_advisory_xact_lock" in connection.executed[0].statement
    assert "INSERT INTO accounting_events" in connection.executed[1].statement
    assert "INSERT INTO subscriber_sessions" in connection.executed[2].statement
    assert "event_time > %s" in connection.executed[3].statement
    assert "event_time < %s" in connection.executed[4].statement
    usage_cursor = connection.executed[5]
    assert "INSERT INTO subscriber_usage_deltas" in usage_cursor.statement
    assert usage_cursor.parameters[5:7] == (previous_id, inserted_id)
    assert usage_cursor.parameters[9:] == (500, 600, 30)
    assert all(cursor.closed for cursor in connection.executed)


def test_duplicate_accounting_event_stops_before_projection_or_usage():
    connection = Connection(Cursor((None,)), Cursor(None))
    assert record_accounting_event_with_usage(
        connection, tenant_id=str(uuid4()), event=event()
    ) is False
    assert len(connection.executed) == 2
    assert all(cursor.closed for cursor in connection.executed)


def test_late_event_is_kept_but_does_not_create_overlapping_usage():
    connection = Connection(
        Cursor((None,)),
        Cursor((str(uuid4()),)),
        Cursor((str(uuid4()),)),
        Cursor((1,)),
    )
    assert record_accounting_event_with_usage(
        connection,
        tenant_id=str(uuid4()),
        event=event(
            AccountingStatus.INTERIM_UPDATE,
            at=datetime(2026, 11, 27, 9, 58, tzinfo=UTC),
        ),
    ) is True
    assert len(connection.executed) == 4
    assert all(cursor.closed for cursor in connection.executed)


def test_counter_regression_does_not_rollback_accounting_event(caplog):
    connection = Connection(
        Cursor((None,)),
        Cursor((str(uuid4()),)),
        Cursor((str(uuid4()),)),
        Cursor(None),
        Cursor((
            str(uuid4()),
            datetime(2026, 11, 27, 9, 55, tzinfo=UTC),
            5000,
            6000,
            300,
        )),
    )
    assert record_accounting_event_with_usage(
        connection,
        tenant_id=str(uuid4()),
        event=event(
            AccountingStatus.INTERIM_UPDATE,
            at=datetime(2026, 11, 27, 10, 0, tzinfo=UTC),
            input_octets=100,
            output_octets=200,
        ),
    ) is True
    assert "counter regressed" in caplog.text
    assert len(connection.executed) == 5
    assert all(cursor.closed for cursor in connection.executed)
