from types import SimpleNamespace

import pytest

from isp_radius.aaa.coa_transport import (
    RadiusNegativeAcknowledgement,
    RadiusTransportError,
    RadiusTransportTimeout,
)
from isp_radius.worker.command_dispatcher import (
    RadiusCommandWorker,
    WorkerConfig,
    retry_delay,
)


def config(**overrides):
    values = {
        "database_url": "postgresql://example",
        "lease_seconds": 120,
        "transport_timeout": 2,
        "transport_retries": 2,
    }
    values.update(overrides)
    return WorkerConfig(**values)


def command(attempts=1):
    return SimpleNamespace(
        id="cmd-1",
        tenant_id="tenant-1",
        nas_identifier="nas-1",
        session_id="session-1",
        username="subscriber-1",
        command_type="disconnect",
        attributes={},
        lease_token="lease-1",
        attempts=attempts,
    )


class FakePool:
    def __init__(self):
        self.connections = []

    def connection(self):
        connection = FakeConnection()
        self.connections.append(connection)
        return FakeContext(connection)


class FakeConnection:
    def __init__(self):
        self.transactions = 0


class FakeContext:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, *args):
        return False


def worker_with_transport(send, monkeypatch):
    import isp_radius.worker.command_dispatcher as module

    worker = RadiusCommandWorker(
        pool=FakePool(),
        config=config(),
        secret_provider=SimpleNamespace(get_secret=lambda ref: b"x" * 16),
        transport=SimpleNamespace(send=send),
    )
    monkeypatch.setattr(
        module,
        "load_nas_coa_endpoint",
        lambda connection, **kwargs: SimpleNamespace(secret_ref="env:NAS_SECRET"),
    )
    return worker


def test_worker_config_requires_lease_for_full_sequential_batch():
    with pytest.raises(ValueError):
        config(lease_seconds=30, batch_size=10)
    assert config(lease_seconds=120, batch_size=10)


def test_retry_delay_is_exponential_and_bounded():
    assert retry_delay(1, base=5, maximum=900) == 5
    assert retry_delay(2, base=5, maximum=900) == 10
    assert retry_delay(20, base=5, maximum=900) == 900


def test_timeout_schedules_retry(monkeypatch):
    worker = worker_with_transport(
        lambda **kwargs: (_ for _ in ()).throw(RadiusTransportTimeout()),
        monkeypatch,
    )
    finished = []
    worker._finish = lambda cmd, **kwargs: finished.append(kwargs) or True

    worker._dispatch_one(command())

    assert finished == [
        {
            "outcome": "retry",
            "retry_after_seconds": 5,
            "error_code": "nas_timeout",
        }
    ]


def test_nak_is_terminal_failure(monkeypatch):
    worker = worker_with_transport(
        lambda **kwargs: (_ for _ in ()).throw(RadiusNegativeAcknowledgement(503)),
        monkeypatch,
    )
    finished = []
    worker._finish = lambda cmd, **kwargs: finished.append(kwargs) or True

    worker._dispatch_one(command())

    assert finished == [{"outcome": "rejected", "error_code": "radius_nak_503"}]


def test_missing_secret_or_endpoint_fails_without_retry(monkeypatch):
    import isp_radius.worker.command_dispatcher as module

    worker = worker_with_transport(lambda **kwargs: 0, monkeypatch)
    monkeypatch.setattr(
        module,
        "load_nas_coa_endpoint",
        lambda *args, **kwargs: (_ for _ in ()).throw(RadiusTransportError()),
    )
    finished = []
    worker._finish = lambda cmd, **kwargs: finished.append(kwargs) or True

    worker._dispatch_one(command())

    assert finished == [
        {"outcome": "failed", "error_code": "transport_configuration_error"}
    ]


def test_retry_budget_exhaustion_is_terminal():
    worker = RadiusCommandWorker(
        pool=FakePool(),
        config=config(max_attempts=2),
        secret_provider=object(),
        transport=object(),
    )
    finished = []
    worker._finish = lambda cmd, **kwargs: finished.append(kwargs) or True

    worker._retry_or_fail(command(attempts=2), "nas_timeout")

    assert finished == [
        {"outcome": "failed", "error_code": "max_attempts_nas_timeout"}
    ]
