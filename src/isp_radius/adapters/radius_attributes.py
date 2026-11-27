"""Translate vendor-neutral service policy into supported RADIUS reply attributes."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class RadiusProfile(StrEnum):
    GENERIC_WISPR = "generic_wispr"
    MIKROTIK = "mikrotik"


@dataclass(frozen=True, slots=True)
class BandwidthPolicy:
    """Subscriber bandwidth in bits per second, independent of vendor syntax."""

    download_bps: int
    upload_bps: int

    def __post_init__(self) -> None:
        if self.download_bps <= 0 or self.upload_bps <= 0:
            raise ValueError("download_bps and upload_bps must be positive")


class RadiusAttributeAdapter(Protocol):
    profile: RadiusProfile

    def access_accept_attributes(self, policy: BandwidthPolicy) -> dict[str, str]: ...


@dataclass(frozen=True, slots=True)
class WisprAttributeAdapter:
    """Map policy to WISPr maximum bandwidth attributes."""

    profile: RadiusProfile = RadiusProfile.GENERIC_WISPR

    def access_accept_attributes(self, policy: BandwidthPolicy) -> dict[str, str]:
        return {
            "WISPr-Bandwidth-Max-Down": str(policy.download_bps),
            "WISPr-Bandwidth-Max-Up": str(policy.upload_bps),
        }


@dataclass(frozen=True, slots=True)
class MikrotikAttributeAdapter:
    """Map policy to RouterOS rate-limit syntax.

    RouterOS defines rx as client upload and tx as client download.
    """

    profile: RadiusProfile = RadiusProfile.MIKROTIK

    def access_accept_attributes(self, policy: BandwidthPolicy) -> dict[str, str]:
        return {
            "Mikrotik-Rate-Limit": f"{policy.upload_bps}/{policy.download_bps}"
        }


_ADAPTERS: dict[RadiusProfile, RadiusAttributeAdapter] = {
    RadiusProfile.GENERIC_WISPR: WisprAttributeAdapter(),
    RadiusProfile.MIKROTIK: MikrotikAttributeAdapter(),
}


def get_radius_attribute_adapter(profile: str) -> RadiusAttributeAdapter:
    try:
        return _ADAPTERS[RadiusProfile(profile)]
    except ValueError as exc:
        raise NotImplementedError(f"Unsupported RADIUS profile: {profile}") from exc
