import json
import socket
import urllib.error
import urllib.request
from types import SimpleNamespace

from isp_radius.worker.command_dispatcher import (
    JsonLogFormatter,
    RadiusCommandWorker,
    WorkerConfig,
    start_health_server,
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MetricsCursor:
    def execute(self, query):
        assert "dynamic_authorization_requests" in query

    def fetchone(self):
        return (4, 17, 2, 1, 3)

    def close(self):
        pass


class MetricsConnection:
    def cursor(self):
        return MetricsCursor()


class MetricsContext:
    def __enter__(self):
        return MetricsConnection()

    def __exit__(self, *args):
        return False


class MetricsPool:
    def connection(self, **kwargs):
        assert kwargs == {"timeout": 2}
        return MetricsContext()


def test_worker_health_and_metrics_endpoints():
    port = free_port()
    config = WorkerConfig(
        database_url="postgresql://example",
        health_port=port,
    )
    worker = RadiusCommandWorker(
        pool=MetricsPool(),
        config=config,
        secret_provider=object(),
        transport=object(),
    )
    worker.last_cycle_at = __import__("time").monotonic()
    worker.last_cycle_ok = True
    worker.total_leased = 9
    worker.total_cycle_errors = 2
    server = start_health_server(worker)
    base = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(base + "/health/live") as response:
            assert response.status == 200
            assert json.load(response)["status"] == "alive"
        with urllib.request.urlopen(base + "/health/ready") as response:
            assert response.status == 200
            assert json.load(response)["status"] == "ready"
        with urllib.request.urlopen(base + "/metrics") as response:
            metrics = response.read().decode()
        assert "isp_radius_worker_commands_leased_total 9\\n" in metrics
        assert "isp_radius_worker_queue_pending 4\\n" in metrics
        assert "isp_radius_worker_queue_oldest_pending_seconds 17\\n" in metrics
        assert "isp_radius_worker_commands_failed_last_15m 1\\n" in metrics
        assert "isp_radius_worker_commands_rejected_last_15m 3\\n" in metrics
        try:
            urllib.request.urlopen(base + "/unknown")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("unknown endpoint must return 404")
    finally:
        server.shutdown()
        server.server_close()


def test_readiness_fails_before_first_successful_cycle():
    port = free_port()
    worker = RadiusCommandWorker(
        pool=MetricsPool(),
        config=WorkerConfig(database_url="postgresql://example", health_port=port),
        secret_provider=object(),
        transport=object(),
    )
    server = start_health_server(worker)
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health/ready")
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
            assert json.load(exc) ["status"] == "not_ready"
        else:
            raise AssertionError("worker without a successful cycle must not be ready")
    finally:
        server.shutdown()
        server.server_close()


def test_json_log_formatter_emits_structured_record():
    import logging

    record = logging.LogRecord(
        "isp_radius.worker", logging.WARNING, __file__, 10,
        "command_retry_scheduled command_id=%s", ("safe-id",), None,
    )
    item = json.loads(JsonLogFormatter().format(record))
    assert item["level"] == "WARNING"
    assert item["logger"] == "isp_radius.worker"
    assert item["message"] == "command_retry_scheduled command_id=safe-id"


def test_database_connection_is_released_before_udp_send(monkeypatch):
    import isp_radius.worker.command_dispatcher as module

    class TrackingContext:
        def __init__(self, pool):
            self.pool = pool

        def __enter__(self):
            self.pool.active += 1
            return object()

        def __exit__(self, *args):
            self.pool.active -= 1
            return False

    class TrackingPool:
        active = 0

        def connection(self):
            return TrackingContext(self)

    class SecretProvider:
        def get_secret(self, ref):
            assert ref == "env:NAS_SECRET"
            return b"x" * 16

    class Transport:
        def send(self, **kwargs):
            assert pool.active == 0
            return 41

    pool = TrackingPool()
    worker = RadiusCommandWorker(
        pool=pool,
        config=WorkerConfig(database_url="postgresql://example"),
        secret_provider=SecretProvider(),
        transport=Transport(),
    )
    monkeypatch.setattr(
        module,
        "load_nas_coa_endpoint",
        lambda *args, **kwargs: SimpleNamespace(secret_ref="env:NAS_SECRET"),
    )
    command = SimpleNamespace(
        id="cmd-1", tenant_id="tenant-1", nas_identifier="nas-1",
        session_id="session-1", username="user-1", command_type="disconnect",
        attributes={}, attempts=1, lease_token="lease-1",
    )
    finished = []
    worker._finish = lambda cmd, **kwargs: finished.append(kwargs) or True
    worker._dispatch_one(command)
    assert finished == [{"outcome": "acknowledged"}]
