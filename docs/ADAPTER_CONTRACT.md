# Vendor Adapter Contract

## Adapter families
- **BNG/NAS adapters:** NAS identity, health, session query, CoA/disconnect support, vendor-specific authorization attributes and optional operational telemetry.
- **OLT/access adapters:** chassis/slot/port inventory, PON topology, ONU discovery, optical metrics, ONU state and supported provisioning operations.
- **Transport adapters:** SNMP, SSH/CLI, NETCONF, REST or vendor SDK clients. Transport is not itself proof of device capability.

## Required metadata
Every adapter declares stable ID, vendor, product families, supported firmware ranges, adapter version, transport requirements, credential scope and capability list.

## Capability rules
Capabilities are explicit and independently testable. Examples: `session.list`, `session.disconnect`, `onu.discover`, `onu.optical.read`, `onu.provision`, `device.health.read`. Unsupported operations return a typed unsupported result. Never infer support from a vendor label.

## Safety
Read operations should be the default. Mutating operations require validated input, audit correlation, timeouts, bounded retries and an explicit impact classification. Destructive or service-affecting operations require a caller-side approval policy. Credentials are retrieved from a secret provider and must never be logged.

## Initial Python interface
The initial scaffold defines metadata and capabilities in `src/isp_radius/adapters/contracts.py`. Concrete drivers are not included yet. Each driver must include unit tests with mocked transports and integration evidence from a hardware or vendor simulator lab.
