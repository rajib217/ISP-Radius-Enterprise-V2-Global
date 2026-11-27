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

Call `dispatch_leased_command` for a leased outbox item. On a verified ACK,
finish the lease as `acknowledged`. On `RadiusTransportTimeout`, schedule a
bounded retry with `finish_leased_command(..., outcome="retry", ...)`. A
`RadiusNegativeAcknowledgement` is a definitive NAS rejection and should be
recorded as failed with its RFC 5176 Error-Cause code. Do not mark a command
successful merely because a UDP datagram was sent.

The transport has bounded timeout/retries. The outbox lease must exceed the
maximum transport duration plus scheduling margin. Use one dispatcher process
pool sized to the network and database capacity.

## Compatibility and security limits

The dictionary covers only attributes currently emitted by this application:
User-Name, Acct-Session-Id, WISPr bandwidth values, and MikroTik rate-limit.
NAS firmware, vendor-specific CoA acceptance, and exact attribute direction
must be validated against each model/firmware in a lab before production.
This code does not yet include a long-running worker service, RadSec, or live
hardware interoperability tests.
