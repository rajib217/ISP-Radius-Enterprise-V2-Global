# RADIUS CoA and Disconnect

## Current implementation boundary

V2 now defines validated Disconnect-Request and Change-of-Authorization command
objects and persists them through a tenant-scoped durable outbox. Commands can
only be queued for a matching active session on an enabled NAS. Exact duplicate
commands are idempotent.

The outbox does **not** send UDP packets. A separate dispatcher is required to
send Disconnect-Request / CoA-Request packets to NAS UDP/3799, validate response
codes and authenticators, apply bounded retries, and update command status.
Do not mark a command successful merely because it was queued.

## Supported attribute mapping

- MikroTik: `Mikrotik-Rate-Limit`, formatted as client upload/client download.
- Generic WISPr: `WISPr-Bandwidth-Max-Down` and `WISPr-Bandwidth-Max-Up`.
- Disconnect: `Acct-Session-Id` and `User-Name` identify the target session.

Unknown NAS profiles fail closed. A vendor name alone is not evidence that a
specific firmware supports a given CoA attribute.

## Security requirements for the dispatcher

- Resolve the NAS only from the tenant-scoped NAS inventory.
- Obtain the NAS shared secret from a dedicated secret manager or encrypted
  secret store. Never store plaintext shared secrets in the outbox.
- Send only to the configured NAS address and UDP/3799; do not accept a caller
  supplied destination address.
- Require Message-Authenticator and verify response authenticators.
- Use a bounded timeout/retry policy and an idempotent command ID.
- Record actor, reason, request/response code, attempts and timestamps in audit.
- Restrict command creation to authenticated, authorized operator workflows
  with RBAC and maker-checker controls for sensitive actions.

## Deployment status

The command model, SQL migration and outbox repository are present. The
network dispatcher, operator API/UI, NAS secret management, CoA ACK/NAK
handling, and live RouterOS/BNG interoperability tests remain future work.
