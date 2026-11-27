from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from isp_radius.domain.entities import (
    NasDevice,
    NasProtocol,
    NasRole,
    ServicePlan,
    Subscriber,
    SubscriberStatus,
    Tenant,
)


def uid():
    return str(uuid4())


def test_valid_tenant_and_service_plan():
    tenant_id = uid()
    tenant = Tenant(tenant_id, "Example ISP", "example-isp", "BDT", "Asia/Dhaka", datetime.now(UTC))
    plan = ServicePlan(uid(), tenant_id, "HOME-30", "Home 30 Mbps", Decimal("1000.00"),
                       "BDT", 30, 30_000_000, 10_000_000)
    assert tenant.default_currency == plan.currency
    assert plan.download_bps == 30_000_000


def test_subscriber_is_tenant_scoped_and_requires_uuid_references():
    item = Subscriber(uid(), uid(), "pppoe-user-1", "Customer One", SubscriberStatus.ACTIVE,
                      uid(), datetime.now(UTC))
    assert item.status is SubscriberStatus.ACTIVE
    with pytest.raises(ValueError, match="UUID"):
        Subscriber(uid(), "not-a-uuid", "u1", "Customer", SubscriberStatus.ACTIVE,
                   uid(), datetime.now(UTC))


def test_plan_rejects_float_money_and_nonpositive_bandwidth():
    with pytest.raises(ValueError, match="Decimal"):
        ServicePlan(uid(), uid(), "P1", "Plan 1", 100.0, "BDT", 30, 1, 1)
    with pytest.raises(ValueError, match="bandwidth"):
        ServicePlan(uid(), uid(), "P1", "Plan 1", Decimal(100), "BDT", 30, 0, 1)


def test_nas_accepts_ip_or_hostname_and_rejects_invalid_address():
    nas = NasDevice(uid(), uid(), "BNG-1", NasRole.BNG, NasProtocol.RADIUS_UDP, "192.0.2.1")
    assert nas.address == "192.0.2.1"
    with pytest.raises(ValueError, match="address"):
        NasDevice(uid(), uid(), "BNG-2", NasRole.BNG, NasProtocol.RADIUS_UDP, "bad host name")


def test_plan_rejects_negative_price():
    with pytest.raises(ValueError, match="non-negative"):
        ServicePlan(uid(), uid(), "P1", "Plan 1", Decimal(-1), "BDT", 30, 1, 1)
