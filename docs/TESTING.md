# Testing Strategy

## Required test layers
- **Unit:** domain rules, validation, adapter capability gates and policy evaluation.
- **Contract:** stable adapter interface, API schemas, RADIUS attribute mapping and event schemas.
- **Integration:** database migrations, FreeRADIUS SQL queries, accounting lifecycle, CoA request/response and outbox processing.
- **Protocol:** packet-level tests for Access-Request/Accept/Reject, Accounting-Request and Dynamic Authorization.
- **Device lab:** exact vendor, product, firmware and enabled feature set for every adapter capability claim.
- **Operational:** backup/restore, node failure, queue replay, upgrade/rollback and tenant-isolation tests.

## CI baseline
GitHub Actions runs pytest and Ruff on pushes to main and pull requests. CI is a guardrail, not a substitute for RADIUS protocol or physical-device lab validation.

## Test data safety
Use synthetic subscriber records and generated test secrets. Never import live customer data, production credentials or packet captures containing sensitive attributes into CI.
