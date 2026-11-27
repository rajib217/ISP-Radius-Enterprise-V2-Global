from uuid import uuid4

import pytest

from isp_radius.aaa.dynamic_authorization import (
    DynamicAuthorizationRequest,
    DynamicAuthorizationType,
)
from isp_radius.aaa.dynamic_authorization_service import (
    enqueue_bandwidth_coa,
    enqueue_disconnect,
)


def _request(**overrides):
    values = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "nas_identifier": "edge-bng",
        "session_id": "session-1",
        "username": "subscriber-1",
        "request_type": DynamicAuthorizationType.DISCONNECT,
        "attributes": {},
        "idempotency_key": "command-1",
        "requested_by": "operator-1",
    }
    values.update(overrides)
    return DynamicAuthorizationRequest(**values)


def test_disconnect_request_has_no_policy_attributes():
    request = _request()
    assert request.request_type is DynamicAuthorizationType.DISCONNECT
    assert request.attributes_json() == "{}"


def test_disconnect_rejects_policy_attributes():
    with pytest.raises(ValueError, match="cannot carry"):
        _request(attributes={"Mikrotik-Rate-Limit": "1000/2000"})


def test_coa_requires_supported_attributes():
    with pytest.raises(ValueError, match="at least one"):
        _request(request_type=DynamicAuthorizationType.COA)


def test_coa_rejects_arbitrary_radius_attributes():
    with pytest.raises(ValueError, match="unsupported"):
        _request(
            request_type=DynamicAuthorizationType.COA,
            attributes={"Reply-Message": "arbitrary"},
        )


def test_disconnect_enqueue_uses_active_session_and_tenant_scope():
    class Cursor:
        def __init__(self):
            self.parameters = None

        def execute(self, query, parameters):
            self.query = query
            self.parameters = parameters

        def fetchone(self):
            return ("created-id",)

        def close(self):
            pass

    class Connection:
        def __init__(self):
            self.cursor_instance = Cursor()

        def cursor(self):
            return self.cursor_instance

    connection = Connection()
    result = enqueue_disconnect(
        connection,
        tenant_id=str(uuid4()),
        nas_identifier="edge-bng",
        session_id="session-1",
        username="subscriber-1",
        idempotency_key="disconnect-1",
        requested_by="operator-1",
    )
    assert result.request_type is DynamicAuthorizationType.DISCONNECT
    assert "s.status = 'active'" in connection.cursor_instance.query
    assert "ON CONFLICT (tenant_id, idempotency_key) DO NOTHING" in connection.cursor_instance.query


def test_bandwidth_coa_generates_mikrotik_attribute():
    class Cursor:
        def __init__(self, rows):
            self.rows = rows
            self.calls = []

        def execute(self, query, parameters):
            self.calls.append((query, parameters))

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return ("created-id",)

        def close(self):
            pass

    class Connection:
        def __init__(self):
            self.cursors = [Cursor([("mikrotik",)]), Cursor([])]

        def cursor(self):
            return self.cursors.pop(0)

    result = enqueue_bandwidth_coa(
        Connection(),
        tenant_id=str(uuid4()),
        nas_identifier="edge-bng",
        session_id="session-1",
        username="subscriber-1",
        download_bps=20_000_000,
        upload_bps=5_000_000,
        idempotency_key="coa-1",
        requested_by="operator-1",
    )
    assert result.request_type is DynamicAuthorizationType.COA
    assert result.attributes == {"Mikrotik-Rate-Limit": "5000000/20000000"}


def test_bandwidth_coa_rejects_generic_profile_until_capability_verified():
    class Cursor:
        def execute(self, query, parameters):
            pass

        def fetchall(self):
            return [("generic_wispr",)]

        def close(self):
            pass

    class Connection:
        def cursor(self):
            return Cursor()

    with pytest.raises(NotImplementedError, match="capability must be verified"):
        enqueue_bandwidth_coa(
            Connection(),
            tenant_id=str(uuid4()),
            nas_identifier="edge-bng",
            session_id="session-1",
            username="subscriber-1",
            download_bps=20_000_000,
            upload_bps=5_000_000,
            idempotency_key="coa-2",
            requested_by="operator-1",
        )


def test_coa_rejects_non_positive_bandwidth():
    class Connection:
        def cursor(self):
            raise AssertionError("must validate before querying NAS")

    with pytest.raises(ValueError, match="positive"):
        enqueue_bandwidth_coa(
            Connection(),
            tenant_id=str(uuid4()),
            nas_identifier="edge-bng",
            session_id="session-1",
            username="subscriber-1",
            download_bps=0,
            upload_bps=5_000_000,
            idempotency_key="coa-3",
            requested_by="operator-1",
        )
