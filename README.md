# ISP RADIUS Enterprise V2 Global

Vendor-neutral AAA and ISP network operations platform. This is a separate V2 codebase; V1 remains unchanged: https://github.com/rajib217/ISP-Radius-Enterprise

**Status:** foundation scaffold. No production AAA or vendor integration is claimed until implemented and tested against real protocol/device labs.

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
4. Use durable accounting and idempotent event processing.
5. Keep secrets and customer data out of source control.
6. Make schema changes through versioned migrations.
7. Preserve V1 as a reference and migration source, never as a write target.

## Initial repository layout
- `src/isp_radius/`: application and domain packages
- `docs/`: architecture, scope, adapter contract, security, roadmap and decisions
- `tests/`: automated tests
- `pyproject.toml`: Python package and test configuration

See [Architecture](docs/ARCHITECTURE.md), [Product scope](docs/PRODUCT_SCOPE.md), [Roadmap](docs/ROADMAP.md), and [V1 audit](docs/V1_AUDIT.md).

## Development
Requires Python 3.12+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check src tests
```

## License
Apache License 2.0. See [LICENSE](LICENSE).
