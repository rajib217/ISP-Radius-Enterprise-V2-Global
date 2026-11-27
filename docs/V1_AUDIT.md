# V1 Repository Audit (Initial)

Source reviewed: https://github.com/rajib217/ISP-Radius-Enterprise

## Confirmed from source and design documentation
- V1 is a Flask application with a custom route registry, raw PyMySQL SQL access and Jinja2 server-rendered templates. It is not a Flask-Blueprint/SQLAlchemy application.
- V1 contains subscriber, plan, reseller/staff, payments, accounting, ticketing, messaging, inventory, NAS, OLT/ONU monitoring, reporting, portal and backup features.
- V1 uses FreeRADIUS standard tables including radcheck, radreply, radgroupcheck, radgroupreply, radusergroup, radacct, radpostauth and nas.
- RADIUS policy synchronization is implemented in `panel/radius.py`; CoA workflows are represented in `panel/mod_coa.py`.
- OLT/ONU functionality is implemented separately in `panel/mod_olt.py`, `panel/oltsync.py` and SNMP helpers.
- V1 OLT code exposes editable OID settings and SNMP v2c/v1-style community configuration. The shown defaults include community `public`; production deployments must not retain default community strings.
- The visible OLT preset map contains Huawei and ZTE table presets. BDCOM, VSOL and C-Data appear in the vendor selection list, but that alone is not evidence of tested OID profiles or full provisioning support.
- V1's OLT synchronization comments explicitly describe vendor presets as starting points that operators must confirm with SNMP walk. Treat all such presets as unverified until tested against exact model and firmware.
- V1 schema uses MariaDB and an additive, re-runnable schema approach. V2 should use explicit versioned migrations.
- V1 has an Apache License 2.0 file. V2 repository also contains an Apache License 2.0 file.

## Migration preservation requirements
Preserve concepts and workflows for subscriber lifecycle, package policy, resellers/downline scoping, accounting, payments, online sessions, disconnect, portal, notifications, tickets, inventory, OLT/ONU inventory and backups. Do not blindly copy V1 tables or assume semantics are portable.

## Security and correctness review items
- V1 CoA request history is a useful operational workflow. Its comments also describe temporarily retaining attempted passwords for unknown usernames. V2 must never persist attempted subscriber passwords in logs or audit records.
- Review NAS source validation, RADIUS shared-secret handling, Message-Authenticator requirements, CoA response correlation and replay protections before implementing AAA.
- Review payment callback amount/state verification and idempotency before migrating payment integrations.
- Review secret encryption/key backup behavior and access control before migrating integrations.
- Review OLT SNMP transport, credential handling, OID correctness and mutation safety. Read-only discovery must be separated from provisioning.

## Audit limitations
This is an initial documentation and selected source-file review, not a complete security or correctness audit. Remaining work: inspect all FreeRADIUS deployment configuration and SQL queries, complete schema migrations, authorization/accounting edge cases, CoA packet handling, all OID mappings, payment callback verification, authentication/session security, installer and update/rollback scripts, and all tests. No production data or secrets were accessed.
