# Database migrations

## Baseline

- Target: PostgreSQL 16 or newer.
- Apply every numbered migration from `0001_core.sql` through `0011_dynamic_authorization_worker_leases.sql` in filename order.
- These migrations assume an empty database for the baseline.
- Take and verify a backup before applying migrations to any non-empty environment.
- Apply each migration once, in filename order, using a database role limited to schema changes.
- The application role should not own tables or have permission to bypass tenant-scoped service access.

## Tenant isolation

Every tenant-owned record includes `tenant_id`. Composite primary/foreign keys prevent a subscriber, service plan, NAS, account, journal, or journal line from referencing another tenant's record. Application queries must still include the authenticated tenant ID. Do not trust a tenant ID supplied by a browser/client.

## Accounting invariants

Money uses `NUMERIC(19,4)`, never floating point. A posted journal is checked at transaction commit for at least two lines, one currency, and equal debit/credit totals. Lines become immutable once the journal is posted or reversed. Corrections use a separate linked reversal.

Post in one database transaction: insert draft header, insert all lines, update status to `posted`, then commit. A failure rolls back the entire transaction. A reversal workflow must also lock and verify the original journal, ensure it has not already been reversed, insert the reversing draft, and update the original state atomically.

## Accounting event and session lifecycle

Migration 0002 stores normalized accounting events with tenant-scoped idempotency. Migration 0003 adds the current subscriber-session projection, keyed by tenant, NAS identifier, and RADIUS session ID. Start, Interim-Update, and Stop events are applied in the same caller-owned transaction as the event insert. Older events cannot move the projection backwards, and a stopped session is terminal for that session key. Interim-Update received before Start can create an active projection with an unknown start time.

The repository adapter leaves commit/rollback to the caller. If projection update fails, the caller must roll back the transaction so the event insert is not committed alone.

## Subscriber authentication and authorization

Migration 0004 adds one Argon2id password hash per tenant-scoped subscriber. Migration 0005 indexes enabled NAS source addresses for authentication lookup. Migration 0006 assigns each NAS an explicit RADIUS reply profile (`generic_wispr` or `mikrotik`) so vendor-specific attributes are selected deliberately. The authentication service resolves the tenant from the authenticated NAS packet source IP, requires the NAS, subscriber, and service plan to be enabled, and verifies the password hash in application memory. No plaintext password is stored. The initial FreeRADIUS integration is PAP-only over a protected REST/HTTPS channel.

## CoA and Disconnect outbox

Migration 0007 adds an immutable-intent, tenant-scoped outbox for CoA and Disconnect requests. New commands can only be enqueued for a matching active subscriber session and enabled NAS. An idempotency key prevents duplicate operator actions. The outbox stores no RADIUS shared secret. Command intent and terminal audit records cannot be edited or deleted by ordinary application updates.

Migration 0011 adds fenced leases, retry budgets, and crash recovery to the same audited outbox populated by the application service. The background worker sends RFC 5176 requests over authenticated RADIUS/UDP and records ACK, NAK, timeout, or terminal failure. Operator API authentication/RBAC, RadSec, and live NAS tests remain pending. Do not represent an enqueued command as a completed disconnect or applied policy change.

## Important scope

This is a foundational schema, not a complete billing or statutory accounting implementation. It does not yet include invoices, payment allocation, taxes, fiscal-period close, production user/actor identity tables, a production RADIUS listener, or a migration runner. Validate SQL, locking behavior, and concurrent event ingestion against the exact PostgreSQL version in staging before production use.
