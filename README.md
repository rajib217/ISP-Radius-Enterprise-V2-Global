# ISP RADIUS Enterprise V2 Global

Vendor-neutral AAA and ISP network operations platform. This is a separate V2 codebase; V1 remains unchanged: https://github.com/rajib217/ISP-Radius-Enterprise

**Status:** early implementation. Includes normalized and idempotent RADIUS accounting ingestion, transactional PostgreSQL session projection and usage metering, Argon2id subscriber authentication, a private REST API, interactive Argon2id password provisioning, explicit RADIUS reply profiles, and FreeRADIUS 3.2 PAP authentication, authorization and accounting templates. A tenant-scoped CoA/Disconnect outbox, RFC 5176 UDP transport, leased retry worker, and read-only tenant-scoped session monitoring API are implemented. Monitoring API access currently uses configured SHA-256 bearer-token hashes with the `sessions:read` permission. An initial human operator login/session API is also implemented with Argon2id verification, tenant membership selection, opaque hashed session tokens, HttpOnly cookies, CSRF/origin checks, persistent login throttling, audit events, and role-to-permission mapping. The monitoring API remains service-level API-key authentication.

**Not production-ready:** CHAP/MS-CHAP/EAP, RADIUS API rate limiting, per-route RBAC enforcement for future write operations beyond the initial read-only monitoring BFF, MFA/password recovery, full HA, load testing, target-distribution FreeRADIUS validation, and live NAS interoperability remain incomplete. The operator dashboard must not embed monitoring API keys in browser code. Build and test the BFF before exposing monitoring data in a browser console. Production validation and security review are required before deployment.

## Product goals
- RADIUS AAA: authentication, authorization, accounting, session lifecycle, CoA and disconnect.
- PPPoE/IPoE and IPv4/IPv6 service policy.
- Multi-tenant subscriber, service, NAS and network inventory.
- Vendor adapters for BNGs/routers and separate OLT/ONU management.
- Billing/payment integration through versioned APIs and events.
- RBAC, audit, secret management, HA, observability and recoverable backups.
- On-premises deployment first, with architecture that can support managed/SaaS deployments.

## Architecture rules
1. Keep the AAA domain independent of vendor-specific code.
2. Treat BNG/NAS subscriber authentication separately from OLT access-network management. OLTs are not presumed to authenticate subscriber PPP sessions.
3. Expose verified adapter capabilities, not broad vendor compatibility promises.
4. Make accounting ingestion idempotent and update the current-session projection in the same transaction.
5. Keep secrets and customer data out of source control.
6. Make schema changes through versioned migrations.
7. Preserve V1 as a reference and migration source, never as a write target.
8. Derive tenant scope from authenticated server-side identity; never trust a browser-supplied tenant ID.
9. Never ship service API keys or database credentials to browser clients.

## Initial repository layout
- `src/isp_radius/aaa/`: normalized accounting, Argon2id authentication, and CoA/Disconnect command domain
- `src/isp_radius/api/`: private REST authentication, authorization, accounting and monitoring API
- `deploy/freeradius/3.2/`: FreeRADIUS integration templates
- `src/isp_radius/domain/`: tenant, subscriber, service-plan and NAS value objects
- `src/isp_radius/finance/`: currency-safe journal and reversal primitives
- `src/isp_radius/persistence/`: tenant-scoped accounting event, usage and session repositories
- `src/isp_radius/worker/`: durable CoA/Disconnect command dispatcher
- `docs/UI_UX_DESIGN_SYSTEM.md`: operator-focused interface and charting standards
- `docs/BILLING_FINANCIAL_CONTROLS.md`: double-entry accounting and financial control requirements
- `docs/`: architecture, scope, adapter contract, security, roadmap and decisions
- `tests/`: automated tests
- `pyproject.toml`: Python package and test configuration

Operator identity storage (migration 0013) is now present; login/session enforcement and RBAC remain pending. See [Operator Console Security](docs/OPERATOR_CONSOLE_SECURITY.md) for the required security boundary.\n\nSee [Architecture](docs/ARCHITECTURE.md), [Product scope](docs/PRODUCT_SCOPE.md), [Roadmap](docs/ROADMAP.md), [V1 audit](docs/V1_AUDIT.md), [operator console security](docs/OPERATOR_CONSOLE_SECURITY.md), and [database migration notes](migrations/README.md).

## Development
Requires Python 3.12+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check src tests
```

## Read-only subscriber session monitoring

Endpoints: `GET /monitoring/sessions` and `GET /monitoring/sessions/summary`.

Configure `MONITORING_API_KEY_HASHES` as a JSON object keyed by lowercase SHA-256 bearer-token hashes. Each value must contain `tenant_id` and a `permissions` array including `sessions:read`. Generate a token and digest:

```bash
python -c 'import hashlib,secrets; key=secrets.token_urlsafe(32); print("API_KEY="+key); print("SHA256="+hashlib.sha256(key.encode()).hexdigest())'
```

Keep the API key secret and store only its digest in deployment configuration. Use TLS, restrict network access, rotate keys, and keep configuration in a deployment secret store. These credentials are intended for trusted service-to-service access, not direct browser delivery. A stale session means accounting updates are overdue, not that disconnection is confirmed.

## License
Apache License 2.0. See `LICENSE`.
