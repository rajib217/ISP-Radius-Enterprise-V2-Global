"""Real PostgreSQL migration and accounting lifecycle tests.

These tests run in CI against PostgreSQL 16. Local runs skip when DATABASE_URL
or psycopg is unavailable.
"""
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

psycopg = pytest.importorskip("psycopg")
DATABASE_URL = os.getenv("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL is not configured")


def _event(status, event_time, input_octets):
    from isp_radius.aaa.accounting import AccountingEvent, AccountingStatus

    return AccountingEvent(
        nas_id="integration-bng",
        session_id="integration-session",
        username="integration-subscriber",
        status=AccountingStatus(status),
        event_time=event_time,
        input_octets=input_octets,
        output_octets=input_octets * 2,
        session_seconds=int((event_time - datetime(2026, 11, 27, 10, 0, tzinfo=UTC)).total_seconds()),
        terminate_cause="User-Request" if status == "Stop" else None,
    )


def test_all_migrations_and_accounting_session_lifecycle():
    from isp_radius.persistence.session_repository import record_accounting_event

    root = Path(__file__).parents[1]
    connection = psycopg.connect(DATABASE_URL)
    try:
        for migration in sorted((root / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))

        tenant_id = str(uuid4())
        connection.execute(
            """
            INSERT INTO tenants (id, name, slug, default_currency, timezone)
            VALUES (%s, %s, %s, 'BDT', 'Asia/Dhaka')
            """,
            (tenant_id, "Integration Tenant", f"it-{tenant_id[:8]}"),
        )
        from isp_radius.aaa.authentication import (
            authenticate_subscriber,
            hash_subscriber_password,
        )

        plan_id = str(uuid4())
        subscriber_id = str(uuid4())
        nas_id = str(uuid4())
        connection.execute(
            """
            INSERT INTO service_plans (
                id, tenant_id, code, name, price, currency,
                billing_period_days, download_bps, upload_bps
            ) VALUES (%s, %s, 'BASIC', 'Basic 50M', 500, 'BDT', 30, 50000000, 10000000)
            """,
            (plan_id, tenant_id),
        )
        connection.execute(
            """
            INSERT INTO subscribers (id, tenant_id, username, full_name, status, service_plan_id)
            VALUES (%s, %s, 'integration-user', 'Integration User', 'active', %s)
            """,
            (subscriber_id, tenant_id, plan_id),
        )
        connection.execute(
            """
            INSERT INTO nas_devices (id, tenant_id, name, role, protocol, address)
            VALUES (%s, %s, 'integration-nas', 'bng', 'radius_udp', '192.0.2.55')
            """,
            (nas_id, tenant_id),
        )
        connection.execute(
            """
            INSERT INTO subscriber_credentials (tenant_id, subscriber_id, password_hash)
            VALUES (%s, %s, %s)
            """,
            (tenant_id, subscriber_id, hash_subscriber_password("integration-secret")),
        )
        auth_result = authenticate_subscriber(
            connection,
            nas_ip="192.0.2.55",
            username="integration-user",
            password="integration-secret",
        )
        assert auth_result is not None
        assert auth_result.tenant_id == tenant_id
        assert auth_result.download_bps == 50_000_000
        assert auth_result.upload_bps == 10_000_000

        base = datetime(2026, 11, 27, 10, 0, tzinfo=UTC)
        interim = _event("Interim-Update", base + timedelta(seconds=20), 250)
        with connection.transaction():
            assert record_accounting_event(connection, tenant_id=tenant_id, event=interim)

        # A delayed Start fills the unknown start time without rewinding counters/time.
        start = _event("Start", base, 100)
        with connection.transaction():
            assert record_accounting_event(connection, tenant_id=tenant_id, event=start)
        with connection.transaction():
            assert not record_accounting_event(connection, tenant_id=tenant_id, event=start)

        stale = _event("Interim-Update", base + timedelta(seconds=10), 175)
        with connection.transaction():
            assert record_accounting_event(connection, tenant_id=tenant_id, event=stale)

        stop = _event("Stop", base + timedelta(seconds=30), 300)
        with connection.transaction():
            assert record_accounting_event(connection, tenant_id=tenant_id, event=stop)

        late_start = _event("Start", base + timedelta(seconds=40), 400)
        with connection.transaction():
            assert record_accounting_event(connection, tenant_id=tenant_id, event=late_start)

        row = connection.execute(
            """
            SELECT status, started_at, last_event_at, stopped_at,
                   input_octets, output_octets, session_seconds, terminate_cause
              FROM subscriber_sessions
             WHERE tenant_id = %s AND nas_identifier = 'integration-bng'
               AND session_id = 'integration-session'
            """,
            (tenant_id,),
        ).fetchone()

        assert row[0] == "stopped"
        assert row[1] == base
        assert row[2] == base + timedelta(seconds=30)
        assert row[3] == base + timedelta(seconds=30)
        assert row[4] == 300
        assert row[5] == 600
        assert row[6] == 30
        assert row[7] == "User-Request"

        counts = connection.execute(
            "SELECT COUNT(*) FROM accounting_events WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
        assert counts[0] == 5
    finally:
        connection.close()
