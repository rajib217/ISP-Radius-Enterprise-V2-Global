# Architecture Decision Log

## ADR-0001: Separate V2 repository
**Decision:** V2 is developed in ISP-Radius-Enterprise-V2-Global. V1 remains unchanged and is used as a reference and migration source.
**Reason:** Protect existing deployments and allow a clean architecture evolution.

## ADR-0002: Separate BNG AAA and OLT management
**Decision:** Subscriber RADIUS authentication is modeled around NAS/BNG clients. OLT/ONU management is a separate adapter domain.
**Reason:** OLTs are commonly access/management devices, while PPPoE/IPoE subscriber AAA is handled by a BNG/NAS. Device roles vary and must be configured explicitly.

## ADR-0003: Capability-based vendor support
**Decision:** Integrations advertise individually verified capabilities with device and firmware compatibility evidence.
**Reason:** Vendor names alone do not establish protocol or feature compatibility.

## ADR-0004: Incremental platform choices
**Decision:** Start with Python domain services and FreeRADIUS; select database, queue and frontend implementation after V1 audit and AAA data-model validation.
**Reason:** Avoid premature infrastructure and risky rewrites.
