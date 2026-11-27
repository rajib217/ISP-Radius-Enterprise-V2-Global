from types import SimpleNamespace

import pytest
from pyrad import packet

from isp_radius.aaa.coa_transport import (
    EnvironmentSecretProvider,
    NasCoaEndpoint,
    PyradCoaTransport,
    RadiusNegativeAcknowledgement,
    RadiusTransportError,
    RadiusTransportTimeout,
)
from isp_radius.persistence.command_repository import LeasedRadiusCommand


def _command(kind="disconnect"):
    return LeasedRadiusCommand(
        id="00000000-0000-0000-0000-000000000001",
        tenant_id="00000000-0000-0000-0000-000000000002",
        nas_identifier="edge-01",
        session_id="session-1",
        username="subscriber-1",
        command_type=kind,
        attributes={"Acct-Session-Id": "session-1", "User-Name": "subscriber-1"},
        attempts=1,
        lease_token="00000000-0000-0000-0000-000000000003",
    )


def test_endpoint_requires_literal_ip_and_udp():
    with pytest.raises(ValueError):
        NasCoaEndpoint("nas.example", 3799, "radius_udp", "env:RADIUS_NAS_EDGE")
    with pytest.raises(ValueError):
        NasCoaEndpoint("192.0.2.1", 3799, "radsec", "env:RADIUS_NAS_EDGE")


def test_environment_secret_provider_rejects_missing_and_short(monkeypatch):
    provider = EnvironmentSecretProvider()
    with pytest.raises(RadiusTransportError):
        provider.get_secret("env:RADIUS_NAS_EDGE")
    monkeypatch.setenv("RADIUS_NAS_EDGE", "short")
    with pytest.raises(RadiusTransportError):
        provider.get_secret("env:RADIUS_NAS_EDGE")
    monkeypatch.setenv("RADIUS_NAS_EDGE", "0123456789abcdef")
    assert provider.get_secret("env:RADIUS_NAS_EDGE") == b"0123456789abcdef"


def test_disconnect_uses_verified_ack(monkeypatch):
    import isp_radius.aaa.coa_transport as module

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["server"] == "192.0.2.10"
            assert kwargs["coaport"] == 3799
            assert kwargs["secret"] == b"0123456789abcdef"

        def CreateCoAPacket(self, **kwargs):
            assert kwargs["code"] == packet.DisconnectRequest
            assert kwargs["message_authenticator"] is True
            return object()

        def SendPacket(self, request):
            return SimpleNamespace(code=packet.DisconnectACK)

    monkeypatch.setattr(module, "Client", FakeClient)
    endpoint = NasCoaEndpoint("192.0.2.10", 3799, "radius_udp", "env:RADIUS_NAS_EDGE")
    assert PyradCoaTransport().send(
        endpoint=endpoint, command=_command(), secret=b"0123456789abcdef"
    ) == packet.DisconnectACK


def test_coa_nak_is_not_reported_as_success(monkeypatch):
    import isp_radius.aaa.coa_transport as module

    class FakeClient:
        def __init__(self, **kwargs): pass
        def CreateCoAPacket(self, **kwargs): return object()
        def SendPacket(self, request):
            return SimpleNamespace(code=packet.CoANAK, **{"get": lambda key, default: [503]})

    monkeypatch.setattr(module, "Client", FakeClient)
    endpoint = NasCoaEndpoint("192.0.2.10", 3799, "radius_udp", "env:RADIUS_NAS_EDGE")
    with pytest.raises(RadiusNegativeAcknowledgement):
        PyradCoaTransport().send(
            endpoint=endpoint, command=_command("change_bandwidth"),
            secret=b"0123456789abcdef",
        )


def test_timeout_is_a_retryable_transport_error(monkeypatch):
    import isp_radius.aaa.coa_transport as module

    class FakeClient:
        def __init__(self, **kwargs): pass
        def CreateCoAPacket(self, **kwargs): return object()
        def SendPacket(self, request): raise module.Timeout()

    monkeypatch.setattr(module, "Client", FakeClient)
    endpoint = NasCoaEndpoint("192.0.2.10", 3799, "radius_udp", "env:RADIUS_NAS_EDGE")
    with pytest.raises(RadiusTransportTimeout):
        PyradCoaTransport().send(
            endpoint=endpoint, command=_command(), secret=b"0123456789abcdef"
        )
