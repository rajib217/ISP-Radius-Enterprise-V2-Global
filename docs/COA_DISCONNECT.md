# RADIUS CoA and Disconnect

## Implemented
- Validated Disconnect-Request and Change-of-Authorization command models.
- MikroTik and generic WISPr bandwidth attribute mapping.
- Tenant-scoped durable outbox restricted to matching active sessions and enabled NAS inventory.
- Stable command idempotency keys.
- Concurrent worker leasing with PostgreSQL `FOR UPDATE SKIP LOCKED`.
- Lease-token guarded completion, bounded retry scheduling and expired-lease recovery.

## Dispatcher boundary
The queue is ready for a transport adapter, but V2 does **not yet send** RADIUS
CoA/Disconnect UDP packets. A production dispatcher must resolve NAS address
and secret from trusted inventory/secret storage, construct RFC-compliant
CoA-Request or Disconnect-Request packets, include and verify Message-Authenticator,
validate response source, identifier and Response Authenticator, and distinguish
ACK, NAK, timeout and malformed response.

A timeout is not proof that the NAS did not apply a command. Retry policy must
preserve command identity and avoid unsafe repeated actions. Record operator,
reason, response code, attempts and timestamps in immutable audit, with RBAC
and maker-checker controls. Never report success until a verified NAS ACK.

Live MikroTik and other BNG/BRAS interoperability tests remain required.
