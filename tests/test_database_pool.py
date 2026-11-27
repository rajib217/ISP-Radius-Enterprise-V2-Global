from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from fastapi import Request
from psycopg_pool import PoolTimeout

from isp_radius.api.app import _database_connection, _pool_sizes, app


def _request() -> Request:
    return Request({"type": "http", "app": app, "headers": [], "query_string": b""})


def test_pool_sizes_use_safe_defaults(monkeypatch):
    monkeypatch.delenv("DB_POOL_MIN_SIZE", raising=False)
    monkeypatch.delenv("DB_POOL_MAX_SIZE", raising=False)

    assert _pool_sizes() == (1, 10)


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [("0", "10"), ("2", "1"), ("1", "101"), ("bad", "10")],
)
def test_pool_sizes_reject_invalid_configuration(monkeypatch, minimum, maximum):
    monkeypatch.setenv("DB_POOL_MIN_SIZE", minimum)
    monkeypatch.setenv("DB_POOL_MAX_SIZE", maximum)

    with pytest.raises(RuntimeError):
        _pool_sizes()


def test_database_dependency_fails_closed_without_pool():
    app.state.db_pool = None

    with pytest.raises(HTTPException) as error:
        next(_database_connection(_request()))

    assert error.value.status_code == 503


def test_database_dependency_checks_out_and_returns_connection():
    expected_connection = Mock()

    class FakePool:
        @contextmanager
        def connection(self, timeout):
            assert timeout == 2
            yield expected_connection

    app.state.db_pool = FakePool()
    dependency = _database_connection(_request())

    assert next(dependency) is expected_connection
    with pytest.raises(StopIteration):
        next(dependency)


def test_database_dependency_maps_pool_timeout_to_service_unavailable():
    class TimedOutPool:
        @contextmanager
        def connection(self, timeout):
            raise PoolTimeout("pool exhausted")
            yield  # pragma: no cover

    app.state.db_pool = TimedOutPool()

    with pytest.raises(HTTPException) as error:
        next(_database_connection(_request()))

    assert error.value.status_code == 503
