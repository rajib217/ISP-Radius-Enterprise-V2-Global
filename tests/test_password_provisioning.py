from contextlib import contextmanager
from uuid import uuid4

from isp_radius.cli import provision_subscriber


class FakeCursor:
    def __init__(self, found=True):
        self.found = found
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, parameters):
        self.calls.append((statement, parameters))

    def fetchone(self):
        return (1,) if self.found else None


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.fake_cursor


def test_password_cli_rejects_mismatch_without_database(monkeypatch, capsys):
    monkeypatch.setattr(provision_subscriber.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(provision_subscriber.sys.stderr, "isatty", lambda: True)
    prompts = iter(["first-password", "different-password"])
    monkeypatch.setattr(provision_subscriber.getpass, "getpass", lambda _prompt: next(prompts))
    connect = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("DB must not connect"))
    monkeypatch.setattr(provision_subscriber.psycopg, "connect", connect)

    result = provision_subscriber.main(
        ["--tenant-id", str(uuid4()), "--subscriber-id", str(uuid4())]
    )

    assert result == 2
    assert "does not match" in capsys.readouterr().err


def test_password_cli_updates_only_hash_for_tenant_subscriber(monkeypatch, capsys):
    monkeypatch.setattr(provision_subscriber.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(provision_subscriber.sys.stderr, "isatty", lambda: True)
    tenant_id, subscriber_id = str(uuid4()), str(uuid4())
    monkeypatch.setattr(provision_subscriber.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(provision_subscriber.sys.stderr, "isatty", lambda: True)
    prompts = iter(["a-strong-ppp-password", "a-strong-ppp-password"])
    monkeypatch.setattr(provision_subscriber.getpass, "getpass", lambda _prompt: next(prompts))
    monkeypatch.setenv("DATABASE_URL", "postgresql://test")
    cursor = FakeCursor()

    @contextmanager
    def fake_connect(_dsn, connect_timeout):
        assert connect_timeout == 5
        yield FakeConnection(cursor)

    monkeypatch.setattr(provision_subscriber.psycopg, "connect", fake_connect)

    result = provision_subscriber.main(
        ["--tenant-id", tenant_id, "--subscriber-id", subscriber_id]
    )

    assert result == 0
    assert len(cursor.calls) == 2
    assert cursor.calls[0][1] == (tenant_id, subscriber_id)
    stored_hash = cursor.calls[1][1][2]
    assert stored_hash.startswith("$argon2id$")
    assert "a-strong-ppp-password" not in stored_hash
    assert "updated successfully" in capsys.readouterr().out


def test_password_cli_does_not_write_when_subscriber_missing(monkeypatch, capsys):
    prompts = iter(["a-strong-ppp-password", "a-strong-ppp-password"])
    monkeypatch.setattr(provision_subscriber.getpass, "getpass", lambda _prompt: next(prompts))
    monkeypatch.setenv("DATABASE_URL", "postgresql://test")
    cursor = FakeCursor(found=False)

    @contextmanager
    def fake_connect(_dsn, connect_timeout):
        yield FakeConnection(cursor)

    monkeypatch.setattr(provision_subscriber.psycopg, "connect", fake_connect)

    result = provision_subscriber.main(
        ["--tenant-id", str(uuid4()), "--subscriber-id", str(uuid4())]
    )

    assert result == 1
    assert len(cursor.calls) == 1
    assert "not found" in capsys.readouterr().err
