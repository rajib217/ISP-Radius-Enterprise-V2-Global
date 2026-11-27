from uuid import uuid4

from argon2 import PasswordHasher

from isp_radius.aaa.authentication import (
    authenticate_subscriber,
    hash_subscriber_password,
)


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.parameters = None
        self.statement = None
        self.closed = False

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, rows):
        self.query_cursor = Cursor(rows)

    def cursor(self):
        return self.query_cursor


def test_password_hash_is_argon2id_and_not_plaintext():
    encoded = hash_subscriber_password("Correct-Horse-Battery-42")
    assert encoded.startswith("$argon2id$")
    assert encoded != "Correct-Horse-Battery-42"
    assert PasswordHasher().verify(encoded, "Correct-Horse-Battery-42")


def test_active_subscriber_authenticates_with_nas_tenant_mapping():
    tenant_id = uuid4()
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        "correct-password"
    )
    connection = Connection([(tenant_id, "user-100", password_hash, 50_000_000, 10_000_000)])

    result = authenticate_subscriber(
        connection,
        nas_ip="192.0.2.10",
        username="user-100",
        password="correct-password",
    )

    assert result is not None
    assert result.tenant_id == str(tenant_id)
    assert result.download_bps == 50_000_000
    assert result.upload_bps == 10_000_000
    assert connection.query_cursor.parameters == ("192.0.2.10", "user-100")
    assert "s.status = 'active'" in connection.query_cursor.statement
    assert connection.query_cursor.closed


def test_wrong_password_is_rejected():
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        "correct-password"
    )
    connection = Connection([(uuid4(), "user-100", password_hash, 1_000_000, 1_000_000)])

    assert authenticate_subscriber(
        connection,
        nas_ip="192.0.2.10",
        username="user-100",
        password="wrong-password",
    ) is None


def test_unknown_user_and_ambiguous_nas_mapping_fail_closed():
    assert authenticate_subscriber(
        Connection([]),
        nas_ip="192.0.2.10",
        username="unknown",
        password="some-password",
    ) is None

    hash_value = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(
        "correct-password"
    )
    duplicate_rows = [
        (uuid4(), "user-100", hash_value, 1_000_000, 1_000_000),
        (uuid4(), "user-100", hash_value, 1_000_000, 1_000_000),
    ]
    assert authenticate_subscriber(
        Connection(duplicate_rows),
        nas_ip="192.0.2.10",
        username="user-100",
        password="correct-password",
    ) is None


def test_empty_password_fails_without_database_lookup():
    connection = Connection([])
    assert authenticate_subscriber(
        connection, nas_ip="192.0.2.10", username="user-100", password=""
    ) is None
    assert connection.query_cursor.statement is None
