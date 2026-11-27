from datetime import UTC, datetime

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


@pytest.mark.parametrize("bad_value", ["-1", "not-a-number", "4294967296"])
def test_rejects_invalid_octet_counter(bad_value):
    attrs = sample_attributes()
    attrs["Acct-Input-Octets"] = bad_value
    with pytest.raises(ValueError):
        normalize_accounting(attrs)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [("Acct-Input-Octets", "4294967296"), ("Acct-Input-Gigawords", "4294967296")],
)
def test_rejects_octet_counter_components_over_uint32(field, bad_value):
    attrs = sample_attributes()
    attrs[field] = bad_value
    with pytest.raises(ValueError, match="unsigned 32-bit"):
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
            event_time=datetime.now(UTC),
            input_octets=-1,
        )


def test_iso_timestamp_with_z_suffix_is_accepted():
    attrs = sample_attributes()
    attrs["Event-Timestamp"] = "2026-11-27T10:00:00Z"
    event = normalize_accounting(attrs)
    assert event.event_time == datetime(2026, 11, 27, 10, 0, tzinfo=UTC)


def test_missing_event_timestamp_uses_receive_time_and_stable_identity():
    received = datetime(2026, 11, 27, 10, 0, tzinfo=UTC)
    attrs = sample_attributes()
    attrs.pop("Event-Timestamp")
    attrs["Acct-Delay-Time"] = "5"

    first = normalize_accounting(attrs, received_at=received)
    second = normalize_accounting(attrs, received_at=datetime(2026, 11, 27, 10, 1, tzinfo=UTC))

    assert first.event_time == datetime(2026, 11, 27, 9, 59, 55, tzinfo=UTC)
    assert second.event_time != first.event_time
    assert second.idempotency_key == first.idempotency_key



@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("nas_id", "n" * 254, "253"),
        ("session_id", "s" * 257, "256"),
        ("username", "u" * 129, "128"),
        ("session_seconds", 0x1_0000_0000, "unsigned 32-bit"),
        ("input_octets", 0x8000000000000000, "PostgreSQL BIGINT"),
    ],
)
def test_event_model_rejects_values_outside_storage_or_protocol_limits(field, value, message):
    values = {
        "nas_id": "nas-a",
        "session_id": "s1",
        "username": "u1",
        "status": AccountingStatus.STOP,
        "event_time": datetime.now(UTC),
    }
    values[field] = value
    with pytest.raises(ValueError, match=message):
        AccountingEvent(**values)


def test_event_model_rejects_non_integer_session_counters():
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        AccountingEvent(
            nas_id="nas-a",
            session_id="s1",
            username="u1",
            status=AccountingStatus.STOP,
            event_time=datetime.now(UTC),
            session_seconds=1.5,
        )


def test_octet_counter_rejects_values_beyond_postgres_bigint():
    attrs = sample_attributes()
    attrs["Acct-Input-Octets"] = "4294967295"
    attrs["Acct-Input-Gigawords"] = "2147483648"
    with pytest.raises(ValueError, match="BIGINT"):
        normalize_accounting(attrs)
