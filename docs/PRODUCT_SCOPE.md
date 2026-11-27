# Product Scope

## Intended customers
Regional and national ISPs, fiber operators, WISPs, wholesale providers and managed network operators. The product must support both single-operator deployments and tenant-isolated managed deployments.

## Functional domains
- Identity and subscriber lifecycle
- Service catalog, plans, policy and entitlement
- AAA and RADIUS integration
- NAS/BNG inventory and session control
- Access network inventory, OLT/ONU telemetry and provisioning
- Billing/payment integrations
- Staff, roles, audit and tenant administration
- Monitoring, alerting, backup and operations

## Protocol boundaries
RADIUS is the AAA protocol for NAS/BNG subscriber authentication and accounting. CoA and Disconnect-Request are NAS-directed dynamic authorization operations. OLT management is a distinct integration domain using device-supported interfaces such as SNMP, SSH/CLI, NETCONF, REST or vendor APIs. A device adapter must document which operations are read-only, reversible, disruptive or unsupported.

## Non-goals for the first release
- Replacing every vendor's EMS/NMS.
- Automatically pushing arbitrary CLI to production devices.
- Claiming full interoperability based only on vendor name.
- Kubernetes as a mandatory deployment dependency.
- Rewriting V1 in place.

## Release acceptance
A feature is released only with domain tests, API contract tests, security review, operational documentation and a compatibility record describing exact device family, firmware and tested capabilities.
