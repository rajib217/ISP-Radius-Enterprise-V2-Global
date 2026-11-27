from uuid import uuid4

import pytest

from isp_radius.aaa.authorization import authorize_subscriber


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.parameters = None

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self.query_cursor = FakeCursor(rows)

    def cursor(self):
        return self.query_cursor


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        (
            "mikrotik",
            {"Mikrotik-Rate-Limit": "5000000/20000000"},
        ),
        (
            "generic_wispr",
            {
                "WISPr-Bandwidth-Max-Down": "20000000",
                "WISPr-Bandwidth-Max-Up": "5000000",
            },
        ),
    ],
)
def test_authorization_maps_plan_bandwidth_to_profile(profile, expected):
    connection = FakeConnection([(profile, 20_000_000, 5_000_000)])

    result = authorize_subscriber(
        connection,
        nas_ip="192.0.2.10",
        username="subscriber-1",
    )

    assert result is not None
    assert result.attributes == expected
    assert connection.query_cursor.parameters == ("192.0.2.10", "subscriber-1")


def test_authorization_fails_closed_for_ambiguous_or_missing_subscriber():
    for rows in ([], [("mikrotik", 20_000_000, 5_000_000)] * 2):
        result = authorize_subscriber(
            FakeConnection(rows),
            nas_ip="192.0.2.10",
            username="subscriber-1",
        )
        assert result is None


def test_authorization_rejects_invalid_nas_ip():
    assert (
        authorize_subscriber(
            FakeConnection([]),
            nas_ip="not-an-ip",
            username="subscriber-1",
        )
        is None
    )


def test_authorization_rejects_unknown_radius_profile():
    with pytest.raises(NotImplementedError):
        authorize_subscriber(
            FakeConnection([("unknown-vendor", 20_000_000, 5_000_000)]),
            nas_ip="192.0.2.10",
            username="subscriber-1",
        )
