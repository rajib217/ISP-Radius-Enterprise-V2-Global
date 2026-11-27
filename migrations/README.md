# Database migrations

## Baseline

- Target: PostgreSQL 16 or newer.
- `0001_core.sql` is the initial schema for an empty database.
- Take and verify a backup before applying migrations to any non-empty environment.
- Apply each migration once, in filename order, using a database role limited to schema changes.
- The application role should not own tables or have permission to bypass tenant-scoped service access.

## Tenant isolation

Every tenant-owned record includes `tenant_id`. Composite primary/foreign keys prevent a subscriber, service plan, NAS, account, journal, or journal line from referencing another tenant's record. Application queries must still include the authenticated tenant ID. Do not trust a tenant ID supplied by a browser/client.

## Accounting invariants

Money uses `NUMERIC(19,4)`, never floating point. A posted journal is checked at transaction commit for at least two lines, one currency, and equal debit/credit totals. Lines become immutable once the journal is posted or reversed. Corrections use a separate linked reversal.

Post in one database transaction: insert draft header, insert all lines, update status to `posted`, then commit. A failure rolls back the entire transaction. A reversal workflow must also lock and verify the original journal, ensure it has not already been reversed, insert the reversing draft, and update the original state atomically.

## Important scope

This is a foundational schema, not a complete billing or statutory accounting implementation. It does not yet include invoices, payment allocation, taxes, fiscal-period close, audit actor records, RADIUS accounting-event storage, or a migration runner. Migration 0002 adds normalized accounting event persistence with tenant-scoped idempotency. The repository adapter leaves commit/rollback to the caller so event insertion can be combined atomically with session projection updates. Production deployment still requires integration tests against PostgreSQL and a supported DB-API driver. Validate the SQL against the exact PostgreSQL version in staging before production use.
