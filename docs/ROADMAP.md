# Roadmap

## Phase 0: Foundation and V1 audit
- Establish V2 repository, architecture rules, coding standards and CI.
- Inspect V1 source, schema, RADIUS configuration, NAS/OLT modules, installer and tests.
- Build a feature map and migration compatibility matrix.

## Phase 1: Domain and data foundation
- Tenant, user, subscriber, service-plan, NAS and policy domain models.
- Versioned database migrations and repository layer.
- API authentication, RBAC, audit and OpenAPI baseline.

## Phase 2: AAA core
- FreeRADIUS SQL integration and authorization policy.
- Authentication test harness for PAP/CHAP/MS-CHAPv2 as supported by selected configuration.
- Accounting Start/Interim/Stop idempotency, session reconciliation and stale-session policy.
- CoA/Disconnect with correlation, response handling and audit.

## Phase 3: Vendor adapters
- MikroTik RouterOS BNG/NAS adapter and compatibility test matrix.
- Juniper MX BNG adapter based on documented supported RADIUS and management interfaces.
- OLT adapter SDK, then separate vendor drivers for Huawei, ZTE, FiberHome, VSOL, C-DATA, BDCOM and others based on verified APIs/MIBs/firmware.

## Phase 4: Operations and commercial readiness
- HA/failover profiles, observability, backup/restore and upgrade/rollback.
- Billing integrations, webhooks, customer/staff portals and reporting.
- Licensing, tenant packaging, white-label/OEM and on-prem deployment profiles.

## Release gates
No phase is complete from documentation alone. Each phase requires code, automated tests, security review, deployment instructions and demonstrated recovery behavior.
