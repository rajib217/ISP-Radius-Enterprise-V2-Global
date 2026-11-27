from uuid import uuid4
import pytest
from isp_radius.persistence.command_repository import finish_leased_command, lease_pending_commands

class FakeCursor:
    def __init__(self, rows=None):
        self.rows, self.executed = rows or [], []
    def execute(self, query, params=()):
        self.executed.append((query, params))
    def fetchall(self):
        return self.rows
    def fetchone(self):
        return (uuid4(),)
    def close(self):
        pass

class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor
    def cursor(self):
        return self.fake_cursor


def test_lease_uses_skip_locked():
    cursor = FakeCursor()
    assert lease_pending_commands(FakeConnection(cursor), limit=10, lease_seconds=30) == []
    assert "FOR UPDATE SKIP LOCKED" in cursor.executed[0][0]


@pytest.mark.parametrize("limit,seconds", [(0, 30), (501, 30), (1, 4), (1, 301)])
def test_lease_bounds(limit, seconds):
    with pytest.raises(ValueError):
        lease_pending_commands(FakeConnection(FakeCursor()), limit=limit, lease_seconds=seconds)


def test_finish_rejects_unknown_outcome():
    with pytest.raises(ValueError, match="outcome"):
        finish_leased_command(FakeConnection(FakeCursor()), command_id=str(uuid4()),
                              lease_token=str(uuid4()), outcome="sent")


def test_retry_delay_is_bounded():
    with pytest.raises(ValueError, match="retry_after_seconds"):
        finish_leased_command(FakeConnection(FakeCursor()), command_id=str(uuid4()),
                              lease_token=str(uuid4()), outcome="retry", retry_after_seconds=0)


def test_finish_is_lease_token_guarded():
    cursor = FakeCursor()
    finish_leased_command(FakeConnection(cursor), command_id=str(uuid4()),
                          lease_token=str(uuid4()), outcome="acknowledged")
    sql, _ = cursor.executed[0]
    assert "lease_token = %s" in sql
