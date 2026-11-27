from datetime import UTC, datetime
from decimal import Decimal

import pytest

from isp_radius.billing.usage import (
    CounterRegressionError,
    UsageSnapshot,
    calculate_usage_delta,
)


def snapshot(at, *, input_octets=100, output_octets=200, seconds=30, session="s-1"):
    return UsageSnapshot(
        nas_id="bng-01",
        session_id=session,
        username="subscriber-01",
        event_time=at,
        input_octets=input_octets,
        output_octets=output_octets,
        session_seconds=seconds,
    )


def test_calculates_exact_counter_deltas_and_gib():
    previous = snapshot(datetime(2026, 11, 27, 10, 0, tzinfo=UTC))
    current = snapshot(
        datetime(2026, 11, 27, 10, 5, tzinfo=UTC),
        input_octets=1100,
        output_octets=2200,
        seconds=330,
    )

    delta = calculate_usage_delta(previous, current)

    assert delta.input_bytes == 1000
    assert delta.output_bytes == 2000
    assert delta.total_bytes == 3000
    assert delta.session_seconds == 300
    assert delta.total_gib == Decimal(3000) / Decimal(1024**3)


def test_missing_counter_is_unknown_not_zero():
    previous = snapshot(datetime(2026, 11, 27, 10, 0, tzinfo=UTC), input_octets=None)
    current = snapshot(
        datetime(2026, 11, 27, 10, 5, tzinfo=UTC), input_octets=500
    )

    delta = calculate_usage_delta(previous, current)

    assert delta.input_bytes is None
    assert delta.output_bytes == 0
    assert delta.total_bytes is None
    assert delta.total_gib is None


def test_counter_reset_is_rejected_for_reconciliation():
    previous = snapshot(datetime(2026, 11, 27, 10, 0, tzinfo=UTC), input_octets=1000)
    current = snapshot(
        datetime(2026, 11, 27, 10, 5, tzinfo=UTC), input_octets=10
    )

    with pytest.raises(CounterRegressionError, match="decreased"):
        calculate_usage_delta(previous, current)


def test_snapshots_must_match_same_session():
    previous = snapshot(datetime(2026, 11, 27, 10, 0, tzinfo=UTC))
    current = snapshot(
        datetime(2026, 11, 27, 10, 5, tzinfo=UTC), session="different-session"
    )

    with pytest.raises(ValueError, match="same NAS session"):
        calculate_usage_delta(previous, current)


def test_snapshots_must_be_strictly_ordered():
    at = datetime(2026, 11, 27, 10, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="later"):
        calculate_usage_delta(snapshot(at), snapshot(at))


@pytest.mark.parametrize("value", [-1, 1.5, True, 0x8000000000000000])
def test_snapshot_rejects_invalid_counter_values(value):
    with pytest.raises(ValueError):
        snapshot(datetime(2026, 11, 27, 10, 0, tzinfo=UTC), input_octets=value)
