# FreeRADIUS 3.2.x integration

This is the first supported integration slice: **PPPoE/PAP authentication and subscriber bandwidth authorization through rlm_rest**. It does not yet implement CHAP, MS-CHAP, EAP, CoA/Disconnect, or forwarding accounting packets to the V2 accounting endpoint.

## Flow

1. FreeRADIUS validates the RADIUS client using its configured per-NAS shared secret.
2. The rest_isp_radius module sends a URL-encoded POST over HTTPS to the V2 API.
3. The API resolves the tenant from the packet source IP, checks that the NAS, subscriber, and service plan are enabled, then verifies the Argon2id password hash.
4. The authorize call returns JSON reply attributes for the NAS profile. HTTP 200 means authorization policy was found; HTTP 401 rejects unknown/inactive subscribers. The authenticate call uses HTTP 204 for Access-Accept and HTTP 401 for Access-Reject. Backend errors return 5xx and must fail closed.
5. No cleartext subscriber password is stored in PostgreSQL.

The API uses the RADIUS packet source IP rather than the client-supplied NAS-IP-Address attribute for tenant/NAS lookup. Configure the exact source IP in nas_devices.address. This initial direct-NAS mode does not support a RADIUS proxy or NAT layer that changes the source IP.

## Install

On Debian/Ubuntu, install FreeRADIUS 3.2 and its REST module using the distribution package manager. Confirm that rlm_rest is available.

1. Apply migrations 0001 through 0006 in order.
2. Install V2 API dependencies: `pip install -e .`.
3. Set `DATABASE_URL` in a protected service environment. Use a dedicated PostgreSQL application role with only the required SELECT permissions for authentication tables.
4. Optionally set `DB_POOL_MIN_SIZE` (default 1) and `DB_POOL_MAX_SIZE` (default 10). Values must be integers satisfying `1 <= min <= max <= 100`. Each API worker owns its own pool, so size the aggregate across all workers against PostgreSQL's connection limit.
5. Run the API behind a TLS reverse proxy. Bind the application server to loopback or a private interface only. Do not expose the HTTP backend publicly.
6. Install mods-available/rest_isp_radius into FreeRADIUS mods-available and enable it with: `ln -s ../mods-available/rest_isp_radius /etc/freeradius/3.0/mods-enabled/rest_isp_radius`.
7. Copy the authentication fragment from sites-available/isp-radius-auth into the existing sites-enabled/default virtual server authorize and authenticate sections. Do not replace the complete default server with this fragment.
8. Add each BNG/NAS separately to clients.conf. Generate a unique high-entropy shared secret per device. Never use the example secret.
9. Store the API CA certificate at the configured path and verify the API certificate hostname.
10. Configure each subscriber with an Argon2id hash in subscriber_credentials; never insert a cleartext password.

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
- No RADIUS Accounting-Request integration is wired to this API yet. Keep the existing accounting path until the accounting REST/SQL integration is implemented and validated.
- NAS source-IP mapping assumes direct RADIUS packets and globally unambiguous tenant mapping. Proxy support needs trusted proxy identity and explicit tenant/NAS mapping.
- The API uses a bounded per-worker PostgreSQL connection pool. Pool sizing must account for worker count and the PostgreSQL connection budget. Rate limiting, request metrics, and load tests remain required before high-volume production use.
- FreeRADIUS config has not yet been validated against your exact package build or NAS firmware. Run freeradius -XC and end-to-end radtest/real NAS tests before production.

## Reference

- [FreeRADIUS REST module configuration](https://www.freeradius.org/documentation/freeradius-server/4.0.0/howto/modules/rest/configuration.html)
- [FreeRADIUS REST response-code behavior](https://github.com/FreeRADIUS/freeradius-server/blob/master/src/modules/rlm_rest/rlm_rest.c)
