from uuid import uuid4

import pytest

from isp_radius.persistence.operator_repository import (
    accept_operator_totp_step,
    consume_operator_mfa_challenge,
    consume_operator_recovery_code,
    record_operator_mfa_challenge_failure,
    revoke_operator_mfa_challenges,
    revoke_operator_sessions_for_user,
)


class FakeCursor:
    def __init__(self, *, row=None, rowcount=0):
        self.row = row
        self.rowcount = rowcount
        self.query = ""
        self.params = None
        self.closed = False

    def execute(self, query, params=None):
        self.query = query
        self.params = params

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


def test_mfa_challenge_consumption_is_atomic_and_origin_bound():
    cursor = FakeCursor(row=("challenge-id", "user-id"))
    result = consume_operator_mfa_challenge(
        FakeConnection(cursor), challenge_hash="a" * 64, method="webauthn",
        origin="https://console.example.com", rp_id="example.com",
    )
    assert result == ("challenge-id", "user-id")
    assert "consumed_at IS NULL" in cursor.query
    assert "expires_at > now()" in cursor.query
    assert "failed_attempts < 5" in cursor.query
    assert "origin = %s" in cursor.query
    assert cursor.params == (
        "a" * 64, "webauthn", "https://console.example.com", "example.com"
    )
    assert cursor.closed


def test_totp_step_replay_is_rejected_by_conditional_update():
    cursor = FakeCursor(row=None)
    accepted = accept_operator_totp_step(
        FakeConnection(cursor), factor_id="factor-id", user_id="user-id", time_step=12345
    )
    assert accepted is False
    assert "last_accepted_step < %s" in cursor.query
    assert cursor.params == (12345, "factor-id", "user-id", 12345)


def test_totp_step_rejects_negative_value_before_database_access():
    cursor = FakeCursor()
    with pytest.raises(ValueError, match="non-negative"):
        accept_operator_totp_step(
            FakeConnection(cursor), factor_id="factor-id", user_id="user-id", time_step=-1
        )
    assert cursor.query == ""


def test_recovery_code_consumption_is_single_use():
    batch_id = str(uuid4())
    cursor = FakeCursor(row=(batch_id,))
    consumed = consume_operator_recovery_code(
        FakeConnection(cursor), user_id="user-id", code_hash="b" * 64
    )
    assert consumed == batch_id
    assert "consumed_at IS NULL" in cursor.query
    assert cursor.params == ("user-id", "b" * 64)


def test_failed_challenge_attempts_are_bounded_and_expiring():
    cursor = FakeCursor(row=("challenge-id",))
    assert record_operator_mfa_challenge_failure(
        FakeConnection(cursor), challenge_hash="c" * 64
    )
    assert "failed_attempts = failed_attempts + 1" in cursor.query
    assert "failed_attempts < 5" in cursor.query
    assert "expires_at > now()" in cursor.query


def test_factor_reset_revokes_challenges_and_all_user_sessions():
    challenge_cursor = FakeCursor(rowcount=3)
    session_cursor = FakeCursor(rowcount=2)
    assert revoke_operator_mfa_challenges(
        FakeConnection(challenge_cursor), user_id="user-id"
    ) == 3
    assert revoke_operator_sessions_for_user(
        FakeConnection(session_cursor), user_id="user-id"
    ) == 2
    assert "consumed_at = now()" in challenge_cursor.query
    assert "revoked_at = now()" in session_cursor.query



def test_webauthn_credential_insert_stores_public_material():
    from isp_radius.persistence.operator_repository import create_operator_webauthn_credential

    cursor = FakeCursor()
    credential_id = create_operator_webauthn_credential(
        FakeConnection(cursor), user_id="user-id", credential_id=b"credential",
        public_key=b"public-key", sign_count=0, transports=["internal"],
        backup_eligible=True, backup_state=True,
    )
    assert credential_id
    assert "public_key" in cursor.query
    assert b"public-key" in cursor.params
    assert b"credential" in cursor.params


def test_webauthn_credential_lookup_is_active_only():
    from isp_radius.persistence.operator_repository import find_active_operator_webauthn_credential

    cursor = FakeCursor(row=("row-id", "user-id", b"key", 4, True, True))
    result = find_active_operator_webauthn_credential(
        FakeConnection(cursor), credential_id=b"credential"
    )
    assert result == ("row-id", "user-id", b"key", 4, True, True)
    assert "status = 'active'" in cursor.query


def test_webauthn_assertion_update_is_owner_bound():
    from isp_radius.persistence.operator_repository import (
        update_operator_webauthn_credential_after_assertion,
    )

    cursor = FakeCursor(row=("row-id",))
    assert update_operator_webauthn_credential_after_assertion(
        FakeConnection(cursor), credential_row_id="row-id", user_id="user-id",
        new_sign_count=5, backup_eligible=True, backup_state=True,
    )
    assert "GREATEST(sign_count, %s)" in cursor.query
    assert "user_id = %s" in cursor.query
    assert cursor.params == (5, True, True, "row-id", "user-id")


def test_webauthn_credential_revocation_is_owner_bound():
    from isp_radius.persistence.operator_repository import revoke_operator_webauthn_credential

    cursor = FakeCursor(row=("row-id",))
    assert revoke_operator_webauthn_credential(
        FakeConnection(cursor), user_id="user-id", credential_row_id="row-id"
    )
    assert "user_id = %s" in cursor.query
    assert "status = 'active'" in cursor.query
