from datetime import datetime, timezone

import pytest

from isp_radius.aaa.accounting import (
    AccountingEvent,
    AccountingStatus,
    normalize_accounting,
)


def sample_attributes():
    return {
        "NAS-Identifier": "edge-bng-01",
        "Acct-Session-Id": "session-0001",
        "User-Name": "subscriber-01",
        "Acct-Status-Type": "3",
        "Event-Timestamp": 1795773600,
        "Acct-Input-Octets": "1024",
        "Acct-Output-Octets": "2048",
        "Acct-Session-Time": "3600",
    }


def test_normalizes_interim_update():
    event = normalize_accounting(sample_attributes())
    assert event.status is AccountingStatus.INTERIM_UPDATE
    assert event.nas_id == "edge-bng-01"
    assert event.input_octets == 1024
    assert event.event_time.utcoffset().total_seconds() == 0


def test_exact_retransmission_has_same_idempotency_key():
    first = normalize_accounting(sample_attributes())
    second = normalize_accounting(sample_attributes())
    assert first.idempotency_key == second.idempotency_key


def test_changed_counter_has_different_idempotency_key():
    first = normalize_accounting(sample_attributes())
    attrs = sample_attributes()
    attrs["Acct-Input-Octets"] = "4096"
    second = normalize_accounting(attrs)
    assert first.idempotency_key != second.idempotency_key


def test_gigawords_extend_32_bit_octet_counters():
    attrs = sample_attributes()
    attrs["Acct-Input-Octets"] = "10"
    attrs["Acct-Input-Gigawords"] = "2"
    event = normalize_accounting(attrs)
    assert event.input_octets == (2 << 32) + 10


def test_nas_ip_is_fallback_identity():
    attrs = sample_attributes()
    attrs.pop("NAS-Identifier")
    attrs["NAS-IP-Address"] = "192.0.2.10"
    assert normalize_accounting(attrs).nas_id == "192.0.2.10"


@pytest.mark.parametrize("bad_value", ["-1", "not-a-number"])
def test_rejects_invalid_octet_counter(bad_value):
    attrs = sample_attributes()
    attrs["Acct-Input-Octets"] = bad_value
    with pytest.raises(ValueError):
        normalize_accounting(attrs)


def test_rejects_timestamp_without_timezone():
    attrs = sample_attributes()
    attrs["Event-Timestamp"] = "2026-11-27T10:00:00"
    with pytest.raises(ValueError, match="timezone"):
        normalize_accounting(attrs)


def test_event_model_rejects_negative_counters():
    with pytest.raises(ValueError, match="non-negative"):
        AccountingEvent(
            nas_id="nas-a",
            session_id="s1",
            username="u1",
            status=AccountingStatus.STOP,
            event_time=datetime.now(timezone.utc),
            input_octets=-1,
        )
