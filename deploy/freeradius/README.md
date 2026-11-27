# FreeRADIUS 3.2.x integration

This integration supports **PPPoE/PAP authentication, subscriber bandwidth authorization, and RADIUS accounting event forwarding through rlm_rest**. It does not yet implement CHAP, MS-CHAP, EAP, CoA/Disconnect, or proxy/NAT identity mapping.

## Flow

1. FreeRADIUS validates the RADIUS client using its configured per-NAS shared secret.
2. The authorize call sends only the username and packet source IP. The API resolves the NAS, active subscriber, service plan and configured reply profile, then returns RADIUS reply attributes as JSON.
3. The authenticate call sends the username, PAP password and packet source IP over HTTPS. The API verifies the Argon2id password hash.
4. The accounting section forwards Start, Interim-Update and Stop attributes to the private API. The API resolves the tenant and canonical NAS name from the packet source IP, normalizes the counters and persists the event plus current-session projection in one PostgreSQL transaction.
5. HTTP 200 from authorize means a policy was found; HTTP 401 rejects unknown or inactive subscribers. HTTP 204 from authenticate means Access-Accept; HTTP 401 means Access-Reject. Accounting returns HTTP 204 for both new and duplicate events so FreeRADIUS does not retry an already accepted event. Backend errors return 5xx and must fail closed.
6. The cleartext PAP password is never stored. It exists only in the protected request and authentication process, so request bodies and credentials must never be logged.

The API uses the RADIUS packet source IP rather than the client-supplied NAS-IP-Address or NAS-Identifier for tenant/NAS lookup. Configure the exact source IP in `nas_devices.address`. This direct-NAS mode does not support a RADIUS proxy or NAT layer that changes the source IP.

## Accounting event identity

The event fingerprint uses canonical NAS name, Acct-Session-Id, username, status, counters, session duration and terminate cause. Event time is deliberately excluded. This makes retransmissions idempotent even when the NAS omits Event-Timestamp and the API estimates event time from receipt time minus Acct-Delay-Time. Repeated identical interim snapshots are treated as the same event, because they carry no new accounting state. NAS devices should provide unique Acct-Session-Id values for each subscriber session.

If Event-Timestamp is present, it is used for session ordering. If it is absent, the API uses its UTC receive time minus Acct-Delay-Time. Delayed Stop events remain terminal in the session projection.

## Install

On Debian/Ubuntu, install FreeRADIUS 3.2 and its REST module using the distribution package manager. Confirm that `rlm_rest` is available.

1. Apply migrations `0001_core.sql` through `0006_nas_radius_profile.sql` in filename order.
2. Install V2 API dependencies: `pip install -e .`.
3. Set `DATABASE_URL` in a protected service environment. The API role needs read access to NAS, subscriber, service-plan and credential tables, and write access to accounting event/session tables. Use a separate restricted role for administrative provisioning.
4. Optionally set `DB_POOL_MIN_SIZE` (default 1) and `DB_POOL_MAX_SIZE` (default 10). Values must satisfy `1 <= min <= max <= 100`. Each API worker owns its own pool, so size the aggregate across all workers against PostgreSQL's connection limit.
5. Set each NAS `radius_profile` to `mikrotik` for RouterOS or `generic_wispr` for WISPr bandwidth reply attributes. The migration default is `generic_wispr`; choose deliberately and confirm the NAS supports the selected attributes.
6. Run the password provisioning command from a trusted interactive terminal:

   ```bash
   isp-radius-set-password --tenant-id TENANT-UUID --subscriber-id SUBSCRIBER-UUID
   ```

   It prompts twice with terminal echo disabled and stores only an Argon2id hash. Do not pass a password in shell arguments or insert cleartext into PostgreSQL.
7. Run the API behind a TLS reverse proxy. Bind the application server to loopback or a private interface only. Do not expose the HTTP backend publicly.
8. Install `mods-available/rest_isp_radius` into FreeRADIUS `mods-available` and enable it with:

   ```bash
   ln -s ../mods-available/rest_isp_radius /etc/freeradius/3.0/mods-enabled/rest_isp_radius
   ```

9. Copy the authentication and accounting fragments from `sites-available/isp-radius-auth` into the existing `sites-enabled/default` virtual server's authorize, authenticate and accounting sections. Do not replace the complete default server with this fragment.
10. Add each BNG/NAS separately to `clients.conf`. Generate a unique high-entropy shared secret per device. Never use the example secret.
11. Store the API CA certificate at the configured path and verify the API certificate hostname.
12. Confirm the FreeRADIUS dictionaries include `Mikrotik-Rate-Limit` and/or `WISPr-Bandwidth-Max-Up/Down` as required by the selected profile.

## Validate

Run the config parser before restarting:

```bash
freeradius -XC
# Debian/Ubuntu alternative:
freeradius -XC -d /etc/freeradius/3.0
```

Then test in a maintenance window with debug logging on a staging NAS:

```bash
freeradius -X
radtest test-subscriber 'test-password' 127.0.0.1 0 'LOCAL_TEST_CLIENT_SECRET'
```

Do not enable production debug logging. Ensure access logs, reverse-proxy logs, tracing, and error reporting never record request bodies, Authorization headers, or subscriber passwords. Restrict API access to the FreeRADIUS host using firewall rules or mTLS at the reverse proxy.

## Current limitations

- PAP only. The site fragment rejects requests without User-Password; do not enable CHAP/MS-CHAP/EAP until a compatible verifier is implemented and tested.
- Bandwidth reply attributes are implemented for explicit `generic_wispr` and `mikrotik` NAS profiles. MikroTik uses `Mikrotik-Rate-Limit` with client upload as RouterOS rx and download as tx. Framed IP, VLAN, IPv6 pools and per-device capability discovery remain pending.
- Accounting REST forwarding and the transactional PostgreSQL event/session repositories are implemented and covered by unit and PostgreSQL integration tests. The FreeRADIUS config itself has not yet been validated against your exact package build or a live NAS.
- NAS source-IP mapping assumes direct RADIUS packets and globally unambiguous tenant mapping. Proxy support needs trusted proxy identity and explicit tenant/NAS mapping.
- The API uses a bounded per-worker PostgreSQL connection pool. Pool sizing must account for worker count and the PostgreSQL connection budget. Rate limiting, request metrics, and load tests remain required before high-volume production use.

## References

- [FreeRADIUS REST module configuration](https://www.freeradius.org/documentation/freeradius-server/4.0.0/howto/modules/rest/configuration.html)
- [FreeRADIUS REST response-code behavior](https://github.com/FreeRADIUS/freeradius-server/blob/master/src/modules/rlm_rest/rlm_rest.c)
- [MikroTik RADIUS attributes and rate-limit direction](https://help.mikrotik.com/docs/spaces/ROS/pages/328097/RADIUS)
