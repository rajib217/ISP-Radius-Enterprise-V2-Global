from uuid import uuid4

import pytest

from isp_radius.aaa.coa import (
    RadiusCommandType,
    build_bandwidth_coa_command,
    build_disconnect_command,
)
from isp_radius.adapters.radius_attributes import BandwidthPolicy


def test_disconnect_command_targets_one_session():
    command = build_disconnect_command(
        tenant_id=str(uuid4()),
        nas_identifier="nas-01",
        session_id="session-123",
        username="subscriber",
    )
    assert command.command_type is RadiusCommandType.DISCONNECT
    assert command.attributes == {
        "Acct-Session-Id": "session-123",
        "User-Name": "subscriber",
    }


def test_bandwidth_coa_uses_mikrotik_rx_tx_order():
    command = build_bandwidth_coa_command(
        tenant_id=str(uuid4()),
        nas_identifier="nas-01",
        session_id="session-123",
        username="subscriber",
        radius_profile="mikrotik",
        policy=BandwidthPolicy(download_bps=20_000_000, upload_bps=5_000_000),
    )
    assert command.attributes["Mikrotik-Rate-Limit"] == "5000000/20000000"


def test_bandwidth_coa_uses_wispr_profile():
    command = build_bandwidth_coa_command(
        tenant_id=str(uuid4()),
        nas_identifier="nas-01",
        session_id="session-123",
        username="subscriber",
        radius_profile="generic_wispr",
        policy=BandwidthPolicy(download_bps=20_000_000, upload_bps=5_000_000),
    )
    assert command.attributes["WISPr-Bandwidth-Max-Down"] == "20000000"
    assert command.attributes["WISPr-Bandwidth-Max-Up"] == "5000000"


def test_unknown_profile_fails_closed():
    with pytest.raises(NotImplementedError):
        build_bandwidth_coa_command(
            tenant_id=str(uuid4()),
            nas_identifier="nas-01",
            session_id="session-123",
            username="subscriber",
            radius_profile="unknown",
            policy=BandwidthPolicy(download_bps=20, upload_bps=10),
        )


def test_command_idempotency_is_stable_and_payload_sensitive():
    common = {
        "tenant_id": str(uuid4()),
        "nas_identifier": "nas-01",
        "session_id": "session-123",
        "username": "subscriber",
    }
    first = build_disconnect_command(**common)
    second = build_disconnect_command(**common)
    assert first.idempotency_key == second.idempotency_key
    changed = build_bandwidth_coa_command(
        **common,
        radius_profile="mikrotik",
        policy=BandwidthPolicy(download_bps=20, upload_bps=10),
    )
    assert first.idempotency_key != changed.idempotency_key


def test_command_requires_valid_tenant():
    with pytest.raises(ValueError, match="tenant_id"):
        build_disconnect_command(
            tenant_id="not-a-uuid",
            nas_identifier="nas-01",
            session_id="session-123",
            username="subscriber",
        )
