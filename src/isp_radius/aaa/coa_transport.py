"""Authenticated UDP transport for RFC 5176 CoA and Disconnect requests.

Secrets are resolved at dispatch time and are never persisted or logged.
RadSec is deliberately rejected until a TLS transport is implemented.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Protocol

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad import packet

from isp_radius.persistence.command_repository import LeasedRadiusCommand


class RadiusTransportError(RuntimeError):
    """Base class for safe, non-secret-bearing transport errors."""


class RadiusTransportTimeout(RadiusTransportError):
    """No authenticated RADIUS response was received before timeout."""


class RadiusNegativeAcknowledgement(RadiusTransportError):
    """NAS returned a valid NAK; error_cause may contain the RFC 5176 code."""

    def __init__(self, error_cause: int | None):
        self.error_cause = error_cause
        super().__init__("NAS rejected the dynamic authorization request")


class SecretProvider(Protocol):
    def get_secret(self, secret_ref: str) -> bytes: ...


class EnvironmentSecretProvider:
    """Resolve refs like env:RADIUS_NAS_EDGE_01 from the worker environment."""

    _REF = re.compile(r"^env:([A-Z][A-Z0-9_]{2,127})$")

    def get_secret(self, secret_ref: str) -> bytes:
        match = self._REF.fullmatch(secret_ref or "")
        if match is None:
            raise RadiusTransportError("NAS secret reference is invalid or unsupported")
        value = os.environ.get(match.group(1))
        if value is None or len(value.encode("utf-8")) < 16:
            raise RadiusTransportError("NAS shared secret is missing or too short")
        return value.encode("utf-8")


@dataclass(frozen=True, slots=True)
class NasCoaEndpoint:
    address: str
    port: int
    protocol: str
    secret_ref: str

    def __post_init__(self) -> None:
        try:
            normalized = str(ip_address(self.address))
        except ValueError as exc:
            raise ValueError("NAS CoA address must be a literal IP address") from exc
        object.__setattr__(self, "address", normalized)
        if not 1 <= self.port <= 65535:
            raise ValueError("NAS CoA port must be between 1 and 65535")
        if self.protocol != "radius_udp":
            raise ValueError("Only explicitly configured radius_udp endpoints are supported")
        if not self.secret_ref:
            raise ValueError("NAS secret_ref is required")


class PyradCoaTransport:
    """Send one request and accept only a cryptographically verified ACK/NAK."""

    def __init__(self, *, timeout: float = 2.0, retries: int = 2):
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        if not 1 <= retries <= 5:
            raise ValueError("retries must be between 1 and 5")
        self.timeout = timeout
        self.retries = retries

    def send(
        self, *, endpoint: NasCoaEndpoint, command: LeasedRadiusCommand,
        secret: bytes,
    ) -> int:
        if len(secret) < 16:
            raise ValueError("RADIUS shared secret must be at least 16 bytes")
        dictionary = Dictionary(str(Path(__file__).with_name("radius_dictionary")))
        client = Client(
            server=endpoint.address,
            coaport=endpoint.port,
            secret=secret,
            dict=dictionary,
            timeout=self.timeout,
            retries=self.retries,
        )
        attributes = {key.replace("-", "_"): value for key, value in command.attributes.items()}
        attributes.setdefault("User_Name", command.username)
        attributes.setdefault("Acct_Session_Id", command.session_id)
        nas_ip = ip_address(endpoint.address)
        if nas_ip.version == 4:
            attributes["NAS_IP_Address"] = str(nas_ip)
        else:
            attributes["NAS_IPv6_Address"] = str(nas_ip)
        if command.command_type == "disconnect":
            request = client.CreateCoAPacket(
                code=packet.DisconnectRequest, message_authenticator=True, **attributes
            )
            accepted, rejected = packet.DisconnectACK, packet.DisconnectNAK
        elif command.command_type == "change_bandwidth":
            request = client.CreateCoAPacket(message_authenticator=True, **attributes)
            accepted, rejected = packet.CoAACK, packet.CoANAK
        else:
            raise ValueError("Unsupported RADIUS command type")

        try:
            reply = client.SendPacket(request)
        except Timeout as exc:
            raise RadiusTransportTimeout("NAS did not acknowledge the request") from exc

        if reply.code == rejected:
            error_values = reply.get("Error-Cause", [])
            error_cause = int(error_values[0]) if error_values else None
            raise RadiusNegativeAcknowledgement(error_cause)
        if reply.code != accepted:
            raise RadiusTransportError("NAS returned an unexpected RADIUS response code")
        return int(reply.code)


def load_nas_coa_endpoint(connection, *, tenant_id: str, nas_identifier: str) -> NasCoaEndpoint:
    """Resolve the destination and secret reference from the tenant-owned NAS record."""
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT address, coa_port, protocol, secret_ref
              FROM nas_devices
             WHERE tenant_id = %s AND name = %s AND enabled = TRUE
            """,
            (tenant_id, nas_identifier),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    if len(rows) != 1:
        raise RadiusTransportError("NAS endpoint is missing or ambiguous")
    address, port, protocol, secret_ref = rows[0]
    try:
        return NasCoaEndpoint(
            address=str(address), port=int(port), protocol=str(protocol),
            secret_ref=str(secret_ref or ""),
        )
    except (TypeError, ValueError) as exc:
        raise RadiusTransportError("NAS CoA endpoint is not safely configured") from exc


def dispatch_leased_command(
    connection, *, command: LeasedRadiusCommand,
    secret_provider: SecretProvider, transport: PyradCoaTransport,
) -> int:
    """Resolve the NAS from DB, send, and return only after a verified ACK."""
    endpoint = load_nas_coa_endpoint(
        connection, tenant_id=command.tenant_id, nas_identifier=command.nas_identifier
    )
    secret = secret_provider.get_secret(endpoint.secret_ref)
    return transport.send(endpoint=endpoint, command=command, secret=secret)
