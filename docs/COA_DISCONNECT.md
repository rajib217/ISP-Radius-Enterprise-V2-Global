# CoA and Disconnect transport

The dispatcher now has an RFC 5176 UDP transport using pyrad. It creates
Disconnect-Request (40) or CoA-Request (43), validates the response using the
NAS shared secret, and treats only Disconnect-ACK (41) or CoA-ACK (44) as
success. A valid NAK is a rejection, not a successful disconnect/change.

## NAS configuration

Migration `0009_nas_coa_endpoint.sql` adds `coa_port` (default 3799) and
`secret_ref`. The secret itself is never stored in PostgreSQL. The initial
provider accepts references such as `env:RADIUS_NAS_EDGE_01`; inject a
minimum 16-byte secret into the worker environment using the deployment's
secret manager. Never commit secrets to source control or log them.

Only a literal IP address and `radius_udp` are currently accepted. DNS names,
CIDR values, RadSec, and unconfigured secrets fail closed. RadSec needs a
separate TLS transport and certificate-validation implementation.

## Worker integration

The worker consumes the same `dynamic_authorization_requests` outbox populated by the application service. It maps `coa` and `disconnect` requests to transport command types and supplies the session selectors required by RFC 5176. It calls `dispatch_leased_command` for each leased item. On a verified ACK,
finish the lease as `acknowledged`. On `RadiusTransportTimeout`, schedule a
bounded retry with `finish_leased_command(..., outcome="retry", ...)`. A
`RadiusNegativeAcknowledgement` is a definitive NAS rejection and should be
recorded as `rejected` with its RFC 5176 Error-Cause code. Do not mark a command
successful merely because a UDP datagram was sent.

The transport has bounded timeout/retries. The lease must cover the configured batch size multiplied by the maximum per-command transport duration, plus scheduling margin. The worker validates this at startup. Keep the batch and database pool sized for the NAS fleet.

## Compatibility and security limits

The dictionary covers only attributes currently emitted by this application:
User-Name, Acct-Session-Id, WISPr bandwidth values, and MikroTik rate-limit.
NAS firmware, vendor-specific CoA acceptance, and exact attribute direction
must be validated against each model/firmware in a lab before production.
The worker is implemented, but RadSec and live hardware interoperability tests
remain outstanding.


## Background worker

Install the package and run `isp-radius-command-worker` under systemd, a
container supervisor, or another process manager. Apply migrations through
`0011_dynamic_authorization_worker_leases.sql` first. The worker leases rows in a
short committed transaction, performs UDP I/O outside that transaction, and
then finalizes the row using its lease token.

Environment settings:

- `DATABASE_URL` (required)
- `RADIUS_NAS_<NAME>` secret variables referenced as `env:RADIUS_NAS_<NAME>`
- `RADIUS_WORKER_BATCH_SIZE` (default 10)
- `RADIUS_WORKER_POLL_INTERVAL` (default 1 second)
- `RADIUS_WORKER_LEASE_SECONDS` (default 120)
- `RADIUS_COA_TIMEOUT_SECONDS` (default 2)
- `RADIUS_COA_TRANSPORT_RETRIES` (default 2)
- `RADIUS_COMMAND_MAX_ATTEMPTS` (default 8)
- `RADIUS_COMMAND_RETRY_BASE_SECONDS` (default 5)
- `RADIUS_COMMAND_RETRY_MAX_SECONDS` (default 900)

A NAS NAK is recorded as `rejected`; invalid endpoint/secret configuration is recorded as `failed`.
Timeouts and transient I/O errors use bounded exponential backoff. Expired
leases are recovered after worker crashes. Shutdown responds to SIGTERM/SIGINT.
The outbox records the final state and a safe error code, never a shared secret.

The worker is at-least-once: a worker can crash after the NAS processes a
request but before the database records its ACK. Therefore a retry may send a
duplicate request. Commands target the same username/session tuple; validate
vendor behavior and operational idempotency in a lab. The lease duration must
exceed the configured transport timeout/retry budget.
