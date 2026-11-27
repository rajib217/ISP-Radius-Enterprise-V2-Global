"""Subscriber authorization and Access-Accept reply policy lookup."""
# ruff: noqa: I001
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

from isp_radius.adapters.radius_attributes import BandwidthPolicy, get_radius_attribute_adapter
from isp_radius.persistence.accounting_repository import Connection


_AUTHORIZATION_QUERY = """
SELECT n.radius_profile, p.download_bps, p.upload_bps
  FROM nas_devices AS n
  JOIN subscribers AS s ON s.tenant_id = n.tenant_id
  JOIN service_plans AS p
    ON p.tenant_id = s.tenant_id AND p.id = s.service_plan_id
 WHERE n.address = %s
   AND n.enabled = TRUE
   AND s.username = %s
   AND s.status = 'active'
   AND p.enabled = TRUE
"""


@dataclass(frozen=True, slots=True)
class SubscriberAuthorization:
    attributes: dict[str, str]


def authorize_subscriber(
    connection: Connection, *, nas_ip: str, username: str
) -> SubscriberAuthorization | None:
    """Resolve active subscriber policy from the authenticated NAS source IP.

    Ambiguous NAS mappings and unknown subscribers fail closed. Vendor-specific
    attributes are generated only by an explicitly configured adapter profile.
    """
    if not nas_ip or not username:
        return None
    try:
        normalized_nas_ip = str(ip_address(nas_ip))
    except ValueError:
        return None

    cursor = connection.cursor()
    try:
        cursor.execute(_AUTHORIZATION_QUERY, (normalized_nas_ip, username))
        rows = cursor.fetchall()
    finally:
        cursor.close()

    if len(rows) != 1:
        return None

    radius_profile, download_bps, upload_bps = rows[0]
    adapter = get_radius_attribute_adapter(str(radius_profile))
    policy = BandwidthPolicy(
        download_bps=int(download_bps),
        upload_bps=int(upload_bps),
    )
    return SubscriberAuthorization(
        attributes=adapter.access_accept_attributes(policy)
    )
