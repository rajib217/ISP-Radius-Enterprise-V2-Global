"""Validated RADIUS CoA and Disconnect command primitives.

This module prepares vendor-neutral commands for a durable outbox. It does not
send UDP packets or handle NAS shared secrets; dispatch is a separate trusted
worker responsibility.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from isp_radius.adapters.radius_attributes import (
    BandwidthPolicy,
    get_radius_attribute_adapter,
)


class RadiusCommandType(StrEnum):
    DISCONNECT = "disconnect"
    CHANGE_BANDWIDTH = "change_bandwidth"


class RadiusCommandStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class RadiusCommand:
    tenant_id: str
    nas_identifier: str
    session_id: str
    username: str
    command_type: RadiusCommandType
    attributes: dict[str, str]

    def __post_init__(self) -> None:
        try:
            UUID(self.tenant_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("tenant_id must be a valid UUID") from exc
        for field_name in ("nas_identifier", "session_id", "username"):
            value = getattr(self, field_name)
            if not value or not value.strip():
                raise ValueError(f"{field_name} is required")
            if len(value) > 256:
                raise ValueError(f"{field_name} is too long")
        if any(not isinstance(key, str) or not isinstance(value, str)
               for key, value in self.attributes.items()):
            raise ValueError("RADIUS command attributes must be string pairs")

    @property
    def idempotency_key(self) -> str:
        canonical = json.dumps(
            {
                "tenant_id": str(UUID(self.tenant_id)),
                "nas_identifier": self.nas_identifier.strip(),
                "session_id": self.session_id.strip(),
                "username": self.username.strip(),
                "command_type": self.command_type.value,
                "attributes": self.attributes,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_disconnect_command(
    *, tenant_id: str, nas_identifier: str, session_id: str, username: str
) -> RadiusCommand:
    """Build a Disconnect-Request targetting exactly one active subscriber session."""
    return RadiusCommand(
        tenant_id=tenant_id,
        nas_identifier=nas_identifier,
        session_id=session_id,
        username=username,
        command_type=RadiusCommandType.DISCONNECT,
        attributes={
            "Acct-Session-Id": session_id,
            "User-Name": username,
        },
    )


def build_bandwidth_coa_command(
    *,
    tenant_id: str,
    nas_identifier: str,
    session_id: str,
    username: str,
    radius_profile: str,
    policy: BandwidthPolicy,
) -> RadiusCommand:
    """Build a Change-of-Authorization request using the NAS's declared profile."""
    adapter = get_radius_attribute_adapter(radius_profile)
    attributes = {
        "Acct-Session-Id": session_id,
        "User-Name": username,
        **adapter.access_accept_attributes(policy),
    }
    return RadiusCommand(
        tenant_id=tenant_id,
        nas_identifier=nas_identifier,
        session_id=session_id,
        username=username,
        command_type=RadiusCommandType.CHANGE_BANDWIDTH,
        attributes=attributes,
    )
