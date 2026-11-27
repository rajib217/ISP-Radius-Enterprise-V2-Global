"""Stable contracts shared by vendor-specific network adapters.

Concrete drivers must be capability-gated and tested against exact device/firmware versions.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class AdapterFamily(StrEnum):
    BNG = "bng"
    OLT = "olt"
    TRANSPORT = "transport"


class Capability(StrEnum):
    DEVICE_HEALTH_READ = "device.health.read"
    SESSION_LIST = "session.list"
    SESSION_DISCONNECT = "session.disconnect"
    ONU_DISCOVER = "onu.discover"
    ONU_OPTICAL_READ = "onu.optical.read"
    ONU_PROVISION = "onu.provision"


@dataclass(frozen=True, slots=True)
class AdapterMetadata:
    adapter_id: str
    vendor: str
    product_families: tuple[str, ...]
    family: AdapterFamily
    adapter_version: str
    supported_firmware: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AdapterHealth:
    reachable: bool
    observed_at: str
    detail: str | None = None


class NetworkAdapter(Protocol):
    @property
    def metadata(self) -> AdapterMetadata: ...

    @property
    def capabilities(self) -> frozenset[Capability]: ...

    async def health(self) -> AdapterHealth: ...


def require_capability(adapter: NetworkAdapter, capability: Capability) -> None:
    """Fail closed when an adapter has not explicitly declared a capability."""
    if capability not in adapter.capabilities:
        raise NotImplementedError(
            f"Adapter {adapter.metadata.adapter_id!r} does not support {capability.value!r}"
        )
