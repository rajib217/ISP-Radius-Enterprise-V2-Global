from uuid import uuid4

import pytest

from isp_radius.persistence.command_repository import (
    finish_leased_command,
    lease_pending_commands,
    requeue_expired_command_leases,
)


class FakeCursor:
    def __init__(self, rows=None, one=None):
        self.rows = rows or []
        self.one = one
        self.executed = []

    def execute(self, query, params=()):
        self.executed.append((query, params))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.one

    def close(self):
        pass


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def cursor(self):
        return self.fake_cursor


def test_lease_uses_dynamic_authorization_outbox_and_skip_locked():
    cursor = FakeCursor()
    assert lease_pending_commands(FakeConnection(cursor), limit=10, lease_seconds=30) == []
    sql, params = cursor.executed[0]
    assert "dynamic_authorization_requests" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "attempt_count = attempt_count + 1" in sql
    assert params[0] == 10


def test_lease_maps_coa_to_transport_command_type():
    cursor = FakeCursor(rows=[(
        uuid4(), uuid4(), "nas-1", "sess-1", "user-1", "coa",
        {"Mikrotik-Rate-Limit": "1000/2000"}, 2,
    )])
    leased = lease_pending_commands(FakeConnection(cursor))
    assert leased[0].command_type == "change_bandwidth"
    assert leased[0].attempts == 2
    assert leased[0].attributes == {"Mikrotik-Rate-Limit": "1000/2000"}


@pytest.mark.parametrize("limit,seconds", [(0, 30), (101, 30), (1, 4), (1, 301)])
def test_lease_bounds(limit, seconds):
    with pytest.raises(ValueError):
        lease_pending_commands(FakeConnection(FakeCursor()), limit=limit, lease_seconds=seconds)


def test_finish_rejects_unknown_outcome():
    with pytest.raises(ValueError, match="outcome"):
        finish_leased_command(
            FakeConnection(FakeCursor()), tenant_id=str(uuid4()),
            command_id=str(uuid4()), lease_token=str(uuid4()), outcome="sent",
        )


def test_retry_delay_is_bounded():
    with pytest.raises(ValueError, match="retry_after_seconds"):
        finish_leased_command(
            FakeConnection(FakeCursor()), tenant_id=str(uuid4()),
            command_id=str(uuid4()), lease_token=str(uuid4()),
            outcome="retry", retry_after_seconds=0,
        )


def test_finish_is_tenant_and_lease_token_guarded():
    cursor = FakeCursor(one=(uuid4(),))
    finish_leased_command(
        FakeConnection(cursor), tenant_id=str(uuid4()), command_id=str(uuid4()),
        lease_token=str(uuid4()), outcome="acknowledged",
    )
    sql, _ = cursor.executed[0]
    assert "tenant_id = %s" in sql
    assert "lease_token = %s" in sql


def test_expired_lease_recovery_is_attempt_bounded():
    cursor = FakeCursor(rows=[(uuid4(),), (uuid4(),)])
    assert requeue_expired_command_leases(FakeConnection(cursor)) == 2
    sql, _ = cursor.executed[0]
    assert "attempt_count >= max_attempts" in sql
