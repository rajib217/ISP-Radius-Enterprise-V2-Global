"""Reliable background dispatcher for the durable RADIUS command outbox."""
from __future__ import annotations

import logging
import os
import signal
import time
from dataclasses import dataclass
from typing import Callable

import psycopg
from psycopg_pool import ConnectionPool

from isp_radius.aaa.coa_transport import (
    EnvironmentSecretProvider,
    PyradCoaTransport,
    RadiusNegativeAcknowledgement,
    RadiusTransportError,
    RadiusTransportTimeout,
    dispatch_leased_command,
)
from isp_radius.persistence.command_repository import (
    LeasedRadiusCommand,
    finish_leased_command,
    lease_pending_commands,
    requeue_expired_command_leases,
)

logger = logging.getLogger("isp_radius.command_worker")


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    database_url: str
    pool_min_size: int = 1
    pool_max_size: int = 4
    batch_size: int = 10
    poll_interval: float = 1.0
    lease_seconds: int = 120
    transport_timeout: float = 2.0
    transport_retries: int = 2
    max_attempts: int = 8
    retry_base_seconds: int = 5
    retry_max_seconds: int = 900
    recovery_interval: float = 15.0

    def __post_init__(self) -> None:
        if not self.database_url:
            raise ValueError("DATABASE_URL is required")
        if not 1 <= self.pool_min_size <= self.pool_max_size <= 50:
            raise ValueError("pool sizes must satisfy 1 <= min <= max <= 50")
        if not 1 <= self.batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100")
        if not 0.1 <= self.poll_interval <= 60:
            raise ValueError("poll_interval must be between 0.1 and 60 seconds")
        if not 5 <= self.lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 5 and 300 seconds")
        batch_transport_budget = (\n            self.batch_size * self.transport_timeout * (self.transport_retries + 1) + 2\n        )
        if self.lease_seconds <= batch_transport_budget:
            raise ValueError("lease_seconds must cover the full sequential batch transport budget")
        if not 1 <= self.max_attempts <= 50:
            raise ValueError("max_attempts must be between 1 and 50")
        if not 1 <= self.retry_base_seconds <= self.retry_max_seconds <= 3600:
            raise ValueError("retry backoff bounds are invalid")
        if not 1 <= self.recovery_interval <= 300:
            raise ValueError("recovery_interval must be between 1 and 300 seconds")


def config_from_environment() -> WorkerConfig:
    def integer(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise RuntimeError(f"{name} must be an integer") from exc

    def number(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise RuntimeError(f"{name} must be numeric") from exc

    return WorkerConfig(
        database_url=os.environ.get("DATABASE_URL", ""),
        pool_min_size=integer("WORKER_DB_POOL_MIN_SIZE", 1),
        pool_max_size=integer("WORKER_DB_POOL_MAX_SIZE", 4),
        batch_size=integer("RADIUS_WORKER_BATCH_SIZE", 10),
        poll_interval=number("RADIUS_WORKER_POLL_INTERVAL", 1.0),
        lease_seconds=integer("RADIUS_WORKER_LEASE_SECONDS", 120),
        transport_timeout=number("RADIUS_COA_TIMEOUT_SECONDS", 2.0),
        transport_retries=integer("RADIUS_COA_TRANSPORT_RETRIES", 2),
        max_attempts=integer("RADIUS_COMMAND_MAX_ATTEMPTS", 8),
        retry_base_seconds=integer("RADIUS_COMMAND_RETRY_BASE_SECONDS", 5),
        retry_max_seconds=integer("RADIUS_COMMAND_RETRY_MAX_SECONDS", 900),
        recovery_interval=number("RADIUS_WORKER_RECOVERY_INTERVAL", 15.0),
    )


def retry_delay(attempt: int, *, base: int, maximum: int) -> int:
    """Bounded exponential backoff without random jitter, for reproducible recovery."""
    if attempt < 1:
        raise ValueError("attempt must be positive")
    return min(maximum, base * (2 ** min(attempt - 1, 20)))


class RadiusCommandWorker:
    def __init__(
        self,
        *,
        pool: ConnectionPool,
        config: WorkerConfig,
        secret_provider=None,
        transport=None,
    ) -> None:
        self.pool = pool
        self.config = config
        self.secret_provider = secret_provider or EnvironmentSecretProvider()
        self.transport = transport or PyradCoaTransport(
            timeout=config.transport_timeout,
            retries=config.transport_retries,
        )
        self._last_recovery = 0.0

    def _lease_batch(self) -> list[LeasedRadiusCommand]:
        # Commit leases before network I/O so another worker sees the lease.
        with self.pool.connection() as connection:
            with connection.transaction():
                return lease_pending_commands(
                    connection,
                    limit=self.config.batch_size,
                    lease_seconds=self.config.lease_seconds,
                    max_attempts=self.config.max_attempts,
                )

    def _finish(
        self,
        command: LeasedRadiusCommand,
        *,
        outcome: str,
        error_code: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> bool:
        with self.pool.connection() as connection:
            with connection.transaction():
                return finish_leased_command(
                    connection,
                    tenant_id=command.tenant_id,
                    command_id=command.id,
                    lease_token=command.lease_token,
                    outcome=outcome,
                    retry_after_seconds=retry_after_seconds,
                    error_code=error_code,
                )

    def _recover_expired(self, now: float) -> int:
        if now - self._last_recovery < self.config.recovery_interval:
            return 0
        with self.pool.connection() as connection:
            with connection.transaction():
                count = requeue_expired_command_leases(\n                    connection, max_attempts=self.config.max_attempts\n                )
        self._last_recovery = now
        if count:
            logger.warning("recovered_expired_leases count=%d", count)
        return count

    def _dispatch_one(self, command: LeasedRadiusCommand) -> None:
        try:
            with self.pool.connection() as connection:
                dispatch_leased_command(
                    connection,
                    command=command,
                    secret_provider=self.secret_provider,
                    transport=self.transport,
                )
        except RadiusNegativeAcknowledgement as exc:
            cause = str(exc.error_cause) if exc.error_cause is not None else "nas_nak"
            self._finish(command, outcome="rejected", error_code=f"radius_nak_{cause}")
            logger.warning(
                "radius_command_rejected command_id=%s error_cause=%s",
                command.id, cause,
            )
            return
        except RadiusTransportTimeout:
            self._retry_or_fail(command, "nas_timeout")
            return
        except RadiusTransportError:
            # Invalid endpoint, missing secret or unsupported transport is not transient.
            self._finish(command, outcome="failed", error_code="transport_configuration_error")
            logger.error("radius_command_configuration_error command_id=%s", command.id)
            return
        except (psycopg.Error, OSError):
            # The NAS may have received the packet. Retry is safe only because
            # dynamic authorization is scoped to the same session and request.
            self._retry_or_fail(command, "worker_io_error")
            logger.exception("radius_command_io_error command_id=%s", command.id)
            return
        except Exception:
            self._retry_or_fail(command, "worker_unexpected_error")
            logger.exception("radius_command_unexpected_error command_id=%s", command.id)
            return

        updated = self._finish(command, outcome="acknowledged")
        if updated:
            logger.info("radius_command_acknowledged command_id=%s", command.id)
        else:
            logger.warning("radius_command_lease_lost_after_ack command_id=%s", command.id)

    def _retry_or_fail(self, command: LeasedRadiusCommand, error_code: str) -> None:
        if command.attempts >= self.config.max_attempts:
            self._finish(command, outcome="failed", error_code=f"max_attempts_{error_code}")
            logger.error("radius_command_exhausted command_id=%s", command.id)
            return
        delay = retry_delay(
            command.attempts,
            base=self.config.retry_base_seconds,
            maximum=self.config.retry_max_seconds,
        )
        updated = self._finish(
            command,
            outcome="retry",
            retry_after_seconds=delay,
            error_code=error_code,
        )
        if updated:
            logger.warning(
                "radius_command_retry_scheduled command_id=%s attempt=%d delay_seconds=%d",
                command.id, command.attempts, delay,
            )
        else:
            logger.warning("radius_command_lease_lost command_id=%s", command.id)

    def run_once(self) -> int:
        self._recover_expired(time.monotonic())
        commands = self._lease_batch()
        for command in commands:
            self._dispatch_one(command)
        return len(commands)

    def run_forever(self, *, should_stop: Callable[[], bool]) -> None:
        logger.info("radius_command_worker_started")
        while not should_stop():
            started = time.monotonic()
            try:
                processed = self.run_once()
            except (psycopg.Error, OSError):
                logger.exception("radius_command_worker_cycle_failed")
                processed = 0
            if processed == 0:
                remaining = self.config.poll_interval - (time.monotonic() - started)
                if remaining > 0:
                    time.sleep(min(remaining, self.config.poll_interval))
        logger.info("radius_command_worker_stopped")


def main() -> int:
    config = config_from_environment()
    pool = ConnectionPool(
        conninfo=config.database_url,
        min_size=config.pool_min_size,
        max_size=config.pool_max_size,
        timeout=5,
        open=False,
        name="isp-radius-command-worker",
    )
    stop = False

    def request_stop(signum, frame) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    pool.open(wait=True, timeout=10)
    try:
        worker = RadiusCommandWorker(pool=pool, config=config)
        worker.run_forever(should_stop=lambda: stop)
    finally:
        pool.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
