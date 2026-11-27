# Architecture

## Logical layers
1. **API and administration:** versioned REST API, web console, authentication, RBAC and tenant context.
2. **Domain services:** subscribers, service plans, policy, NAS inventory, sessions, billing integration and audit.
3. **AAA runtime:** FreeRADIUS integration, SQL-backed authorization/accounting, policy lookup and dynamic authorization workflows.
4. **Integration adapters:** vendor-neutral contracts with separate BNG/router and OLT/ONU adapter families.
5. **Data and events:** transactional relational database, durable event/outbox processing, cache only for rebuildable/ephemeral state.
6. **Operations:** metrics, logs, traces, backups, health checks and deployment automation.

## Initial technology direction
FreeRADIUS is the AAA protocol engine. Python 3.12+ is the initial backend language for domain services and adapters. PostgreSQL is the preferred platform database for new V2 data, subject to an explicit schema and FreeRADIUS SQL integration decision. Redis is optional for ephemeral coordination, not the source of truth. A durable queue is introduced only when asynchronous workloads require it.

## Core invariants
- Accounting events are persisted idempotently and can be replayed safely.
- Session identity uses NAS identity plus Acct-Session-Id and appropriate uniqueness constraints.
- Disconnect/CoA requests are authorized, rate-limited, correlated and audited.
- Every tenant-owned record is scoped by tenant ID at the data-access boundary.
- Vendor adapter errors never silently become success.
- A device operation declares impact and requires policy/approval when disruptive.
- API changes are versioned and backward compatibility is tested.

## Deployment evolution
Start with a documented single-node deployment with clear service boundaries. Add database replication, multiple RADIUS nodes, load balancing and queue redundancy as separately testable HA profiles. Do not make a distributed deployment the default before failure modes and recovery procedures are validated.
