"""Validated CoA and Disconnect command domain objects.

This layer creates auditable intent only. A dedicated worker must send RFC 5176
packets using the NAS's protected shared secret and validate the response.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class DynamicAuthorizationType(StrEnum):
    COA = "coa"
    DISCONNECT = "disconnect"


class DynamicAuthorizationStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    FAILED = "failed"


_ALLOWED_COA_ATTRIBUTES = frozenset(
    {
        "Mikrotik-Rate-Limit",
        "WISPr-Bandwidth-Max-Down",
        "WISPr-Bandwidth-Max-Up",
    }
)


@dataclass(frozen=True, slots=True)
class DynamicAuthorizationRequest:
    id: str
    tenant_id: str
    nas_identifier: str
    session_id: str
    username: str
    request_type: DynamicAuthorizationType
    attributes: dict[str, str]
    idempotency_key: str
    requested_by: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.id, "request id"),
            (self.tenant_id, "tenant id"),
        ):
            try:
                UUID(value)
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"{field} must be a valid UUID") from exc
        for value, field in (
            (self.nas_identifier, "nas_identifier"),
            (self.session_id, "session_id"),
            (self.username, "username"),
            (self.idempotency_key, "idempotency_key"),
            (self.requested_by, "requested_by"),
        ):
            if not value or not value.strip():
                raise ValueError(f"{field} is required")
        if len(self.idempotency_key) > 128:
            raise ValueError("idempotency_key must be at most 128 characters")
        if self.request_type is DynamicAuthorizationType.DISCONNECT and self.attributes:
            raise ValueError("Disconnect requests cannot carry policy attributes")
        if self.request_type is DynamicAuthorizationType.COA:
            if not self.attributes:
                raise ValueError("CoA requests require at least one supported policy attribute")
            if set(self.attributes) - _ALLOWED_COA_ATTRIBUTES:
                raise ValueError("CoA request contains an unsupported RADIUS attribute")
            for name, value in self.attributes.items():
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{name} must have a non-empty string value")

    def attributes_json(self) -> str:
        return json.dumps(self.attributes, sort_keys=True, separators=(",", ":"))
