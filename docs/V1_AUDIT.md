# V1 Repository Audit (Initial)

Source reviewed: https://github.com/rajib217/ISP-Radius-Enterprise

## Confirmed from source and design documentation
- V1 is a Flask application with a custom route registry, raw PyMySQL SQL access and Jinja2 server-rendered templates. It is not a Flask-Blueprint/SQLAlchemy application.
- V1 contains subscriber, plan, reseller/staff, payments, accounting, ticketing, messaging, inventory, NAS, OLT/ONU monitoring, reporting, portal and backup features.
- V1 uses FreeRADIUS standard tables including radcheck, radreply, radgroupcheck, radgroupreply, radusergroup, radacct, radpostauth and nas.
- RADIUS policy synchronization is implemented in `panel/radius.py`; CoA workflows are represented in `panel/mod_coa.py`.
- OLT/ONU functionality is implemented separately in `panel/mod_olt.py`, `panel/oltsync.py` and SNMP helpers. The exact device/firmware support still needs per-driver review.
- V1 schema uses MariaDB and an additive, re-runnable schema approach. V2 should use explicit versioned migrations.

## Migration preservation requirements
Preserve concepts and workflows for subscriber lifecycle, package policy, resellers/downline scoping, accounting, payments, online sessions, disconnect, portal, notifications, tickets, inventory, OLT/ONU inventory and backups. Do not blindly copy V1 tables or assume semantics are portable.

## Audit limitations
This is an initial documentation and source-file review, not a complete security or correctness audit. Remaining work: inspect FreeRADIUS deployment configuration, every schema migration, authorization and accounting SQL, CoA packet handling, OLT OID mappings, payment callback verification, auth/session security, installer and update/rollback scripts. No production data or secrets were accessed.
