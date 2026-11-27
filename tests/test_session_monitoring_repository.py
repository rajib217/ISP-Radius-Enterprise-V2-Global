from uuid import uuid4

import pytest

from isp_radius.persistence.session_monitoring_repository import (
    get_subscriber_session_summary,
    list_subscriber_sessions,
)


class Cursor:
    def __init__(self, rows=None, row=None):
        self.rows = rows or []
        self.row = row
        self.statement = None
        self.parameters = None
        self.closed = False

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def cursor(self):
        return self.fake_cursor


def test_lists_sessions_with_tenant_scope_and_derived_state():
    cursor = Cursor(rows=[(
        "session-row-id", "bng-01", "sess-01", "user-01", "active",
        None, "2026-11-28T10:00:00Z", None, 1000, 2000, 300, None,
        "stale", 300,
    )])
    tenant_id = str(uuid4())
    rows = list_subscriber_sessions(
        Connection(cursor), tenant_id=tenant_id, state="stale",
        search="user-01", nas_identifier="bng-01", stale_after_seconds=300,
        limit=25, offset=10,
    )
    assert rows[0]["state"] == "stale"
    assert rows[0]["duration_seconds"] == 300
    assert cursor.parameters == (
        300, tenant_id, "stale", "stale", "%user-01%", "%user-01%",
        "%user-01%", "bng-01", "bng-01", 25, 10,
    )
    assert "WHERE tenant_id = %s" in cursor.statement
    assert "LIMIT %s OFFSET %s" in cursor.statement
    assert cursor.closed


def test_summary_returns_tenant_scoped_counts_and_octets():
    cursor = Cursor(row=(12, 7, 2, 3, 12345, 67890))
    summary = get_subscriber_session_summary(
        Connection(cursor), tenant_id=str(uuid4()), stale_after_seconds=600
    )
    assert summary == {
        "total_sessions": 12, "online": 7, "stale": 2, "offline": 3,
        "input_octets": 12345, "output_octets": 67890,
    }
    assert cursor.parameters[0:2] == (600, 600)
    assert cursor.closed


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"tenant_id": "bad"}, "valid UUID"),
        ({"tenant_id": str(uuid4()), "state": "connected"}, "state must be"),
        ({"tenant_id": str(uuid4()), "limit": 201}, "limit must be"),
        ({"tenant_id": str(uuid4()), "offset": -1}, "offset must be"),
        ({"tenant_id": str(uuid4()), "stale_after_seconds": 10}, "stale_after_seconds"),
        ({"tenant_id": str(uuid4()), "search": "x" * 129}, "search must be"),
    ],
)
def test_list_rejects_invalid_filters_before_database_access(kwargs, message):
    cursor = Cursor()
    with pytest.raises(ValueError, match=message):
        list_subscriber_sessions(Connection(cursor), **kwargs)
    assert cursor.statement is None
    assert not cursor.closed


def test_summary_returns_zeroes_for_empty_result():
    cursor = Cursor(row=None)
    summary = get_subscriber_session_summary(
        Connection(cursor), tenant_id=str(uuid4())
    )
    assert summary["total_sessions"] == 0
    assert summary["online"] == 0
    assert cursor.closed
