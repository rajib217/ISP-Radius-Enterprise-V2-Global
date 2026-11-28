# Roadmap

## Phase 0: Foundation and V1 audit
- [x] Establish V2 repository, architecture rules, coding standards and CI.
- [x] Inspect V1 source, schema, RADIUS configuration, NAS/OLT modules, installer and tests.
- [x] Build an initial feature map and migration compatibility matrix.

## Phase 1: Domain and data foundation
- [x] Tenant, subscriber, service-plan and NAS domain foundations.
- [x] Versioned database migrations and repository layer for current implemented domains.
- [x] Private API baseline and monitoring service-token authentication.
- [ ] Human operator identity, secure login/session lifecycle, tenant membership and RBAC.
- [ ] Centralized audit identity and privileged-action audit coverage.

## Phase 2: AAA core
- [x] Idempotent accounting ingestion and transactional session projection.
- [x] Usage-delta metering evidence.
- [x] CoA/Disconnect command outbox, worker leasing/retry and RFC 5176 UDP transport.
- [x] Read-only tenant-scoped subscriber session monitoring API.
- [ ] CHAP/MS-CHAPv2/EAP support according to the selected deployment and security model.
- [ ] API rate limiting and operational abuse controls.
- [ ] FreeRADIUS configuration validation on target distributions and live NAS interoperability tests.

## Phase 3: Operator console foundation
- [ ] Implement server-side operator authentication and authorization before browser access to tenant data.
- [ ] Add a server-side backend-for-frontend (BFF); service credentials remain server-side and are never bundled into JavaScript.
- [ ] Add secure cookies, CSRF protection, session rotation/expiry, logout and login abuse controls.
- [ ] Build the subscriber session dashboard: summary KPIs, online/stale/offline filters, search, NAS filter, pagination, refresh and explicit data freshness.
- [ ] Add loading, empty, error, permission-denied and responsive states; test keyboard access and WCAG 2.2 AA core flows.
- [ ] Add component and API integration tests with tenant-isolation coverage.

## Phase 4: Vendor adapters
- [ ] MikroTik RouterOS BNG/NAS adapter and compatibility test matrix.
- [ ] Juniper MX BNG adapter based on documented supported RADIUS and management interfaces.
- [ ] OLT adapter SDK, then separate vendor drivers based on verified APIs/MIBs/firmware.

## Phase 5: Billing, operations and commercial readiness
- [ ] Complete invoice, payment allocation, receipt, refund and financial posting workflows with double-entry controls.
- [ ] HA/failover profiles, observability, backup/restore and upgrade/rollback.
- [ ] Customer/staff portals, integrations and reporting.
- [ ] Licensing, tenant packaging, white-label/OEM and on-prem deployment profiles.

## Release gates
No phase is complete from documentation alone. Each phase requires code, automated tests, security review, deployment instructions and demonstrated recovery behavior. Never expose service credentials in browser bundles. Never represent an enqueued CoA/Disconnect command as a completed NAS operation until a verified response is recorded.
