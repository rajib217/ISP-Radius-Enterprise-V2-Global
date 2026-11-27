import pytest

from isp_radius.adapters.contracts import (
    AdapterFamily,
    AdapterMetadata,
    Capability,
    require_capability,
)


class FakeAdapter:
    metadata = AdapterMetadata(
        adapter_id="test.fake-bng",
        vendor="Example",
        product_families=("Lab BNG",),
        family=AdapterFamily.BNG,
        adapter_version="0.1.0",
    )
    capabilities = frozenset({Capability.DEVICE_HEALTH_READ})


def test_declared_capability_is_accepted():
    require_capability(FakeAdapter(), Capability.DEVICE_HEALTH_READ)


def test_undeclared_capability_fails_closed():
    with pytest.raises(NotImplementedError):
        require_capability(FakeAdapter(), Capability.SESSION_DISCONNECT)
