# Enterprise UI/UX Design System

## Product experience principles
- Optimize for operator clarity, safe action and fast diagnosis, not visual novelty.
- Use progressive disclosure: summary first, operational detail on demand.
- Keep high-frequency workflows keyboard-friendly and low-friction.
- Make destructive, financial and network-disruptive actions explicit, reviewable and auditable.
- Every chart must answer a decision question and link to the records behind its aggregate.
- Never communicate health using color alone; pair status colors with labels and icons.
- Support desktop operations first while remaining usable on tablets and mobile.

## Information architecture
1. **Overview:** organization health, subscriber trends, revenue, collection, active sessions and critical alerts.
2. **Subscribers:** directory, profile, credentials lifecycle, services, invoices, payments, sessions and support history.
3. **AAA & Sessions:** NAS/BNG inventory, authentication outcomes, accounting events, live sessions, CoA and disconnect operations.
4. **Network:** sites, routers/BNGs, OLTs, PON ports, ONUs/ONTs, topology, telemetry and device tasks.
5. **Billing & Finance:** products/plans, invoices, receipts, payment allocation, credit notes, refunds, ledger, reconciliation, receivables, payables and reports.
6. **Support:** tickets, outages, customer communication and work queues.
7. **Analytics:** network, subscriber, service quality and financial analysis.
8. **Administration:** tenants, staff, roles, audit, integrations, automation and system settings.

## Visual system
- Use a restrained neutral foundation with one primary brand color and semantic status colors.
- Establish consistent spacing, typography, elevation, border, radius and focus tokens as code before building screens.
- Use tabular numerals for currency, counters, IDs and measurements.
- Use consistent currency, timezone, date and number formatting per tenant.
- Tables need saved filters, sorting, pagination, column controls, export permissions and clear empty/error/loading states.
- Forms need inline validation, server-error mapping, unsaved-change protection and accessible labels.
- Dashboards must offer date range, comparison period, timezone and filter context.

## Chart and analytics standards
- Select chart type based on the question: line for time trends, bar for category comparisons, stacked bar only for composition over time, histogram for distributions, cohort/retention views for churn, and tables for exact financial reconciliation.
- Show units, time window, aggregation, timezone, source freshness and missing-data gaps.
- Do not use 3D charts, misleading truncated axes or dual axes without a clear reason.
- Provide accessible legends, data tables and drill-down paths.
- Revenue charts must distinguish invoiced, collected, recognized and outstanding amounts.
- Bandwidth charts must distinguish bits/s from bytes/s and clearly state interface/direction and sampling interval.
- Avoid aggregating incomparable currencies or timezones.

## Operational safety
- CoA, disconnect, ONU disable, port shutdown, bulk changes and credential resets require permission checks and a confirmation preview.
- Preview target count, expected impact, selected device and rollback/compensation path where available.
- Use idempotency keys for retryable commands and show request/response correlation IDs.
- Display unsupported capability as unsupported, never as success.
- Audit actor, tenant, timestamp, target, before/after state, reason and result for privileged actions.

## Accessibility and quality gates
- Target WCAG 2.2 AA for core workflows.
- Full keyboard navigation, visible focus, semantic headings and screen-reader labels.
- Responsive behavior must preserve essential information and safe action controls.
- Each screen requires design review, empty/loading/error/permission-denied states and automated component tests.
- Use realistic data fixtures and verify currency rounding, large counters, long names and timezone boundaries.
