"""Core tenant-scoped ISP domain entities.

These immutable value objects are persistence-agnostic. Database constraints and
tenant authorization must be enforced again at the repository/service boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from ipaddress import ip_address
from uuid import UUID


class SubscriberStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class NasRole(StrEnum):
    BNG = "bng"
    NAS = "nas"
    ROUTER = "router"


class NasProtocol(StrEnum):
    RADIUS_UDP = "radius_udp"
    RADSEC = "radsec"


def _required(value: str, field: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field} is required")


def _uuid(value: str, field: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"{field} must be a valid UUID") from exc


@dataclass(frozen=True, slots=True)
class Tenant:
    id: str
    name: str
    slug: str
    default_currency: str
    timezone: str
    created_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "tenant id")
        _required(self.name, "tenant name")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", self.slug):
            raise ValueError("tenant slug must be lowercase letters, digits and hyphens")
        if not re.fullmatch(r"[A-Z]{3}", self.default_currency):
            raise ValueError("default_currency must be a three-letter uppercase code")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class Subscriber:
    id: str
    tenant_id: str
    username: str
    full_name: str
    status: SubscriberStatus
    service_plan_id: str
    created_at: datetime

    def __post_init__(self) -> None:
        for value, field in (
            (self.id, "subscriber id"),
            (self.tenant_id, "tenant_id"),
            (self.service_plan_id, "service_plan_id"),
        ):
            _uuid(value, field)
        _required(self.username, "username")
        _required(self.full_name, "full_name")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ServicePlan:
    id: str
    tenant_id: str
    code: str
    name: str
    price: Decimal
    currency: str
    billing_period_days: int
    download_bps: int
    upload_bps: int
    enabled: bool = True

    def __post_init__(self) -> None:
        _uuid(self.id, "service plan id")
        _uuid(self.tenant_id, "tenant_id")
        _required(self.code, "plan code")
        _required(self.name, "plan name")
        if not isinstance(self.price, Decimal) or not self.price.is_finite():
            raise ValueError("price must be a finite Decimal")
        if self.price < 0:
            raise ValueError("price must be non-negative")
        if not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("currency must be a three-letter uppercase code")
        if self.billing_period_days <= 0:
            raise ValueError("billing_period_days must be positive")
        if self.download_bps <= 0 or self.upload_bps <= 0:
            raise ValueError("bandwidth limits must be positive bits per second")


@dataclass(frozen=True, slots=True)
class NasDevice:
    id: str
    tenant_id: str
    name: str
    role: NasRole
    protocol: NasProtocol
    address: str
    enabled: bool = True
    description: str | None = None

    def __post_init__(self) -> None:
        _uuid(self.id, "NAS id")
        _uuid(self.tenant_id, "tenant_id")
        _required(self.name, "NAS name")
        try:
            ip_address(self.address)
        except ValueError:
            hostname = self.address[:-1] if self.address.endswith(".") else self.address
            labels = hostname.split(".")
            label_pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
            if (
                not hostname
                or len(hostname) > 253
                or any(not label_pattern.fullmatch(label) for label in labels)
            ):
                raise ValueError("address must be a valid IP address or hostname")
