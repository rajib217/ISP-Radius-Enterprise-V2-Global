# Billing and Financial Control Requirements

## Accounting model
The billing domain must maintain an auditable, balanced accounting model. Financial postings use a double-entry general ledger with immutable posted journal entries. Corrections are made through reversal and replacement entries, never by silently editing posted history.

## Core records
- Chart of accounts with account type, normal balance, code, parent and posting restrictions.
- Fiscal periods with open, soft-close and closed states.
- Journal entry and journal lines with debit, credit, currency, effective date, posting date, source, reference and audit metadata.
- Customer account, invoice, invoice line, credit note, receipt, payment, refund and allocation.
- Supplier, bill, payable and payment records where accounts payable is enabled.
- Tax code, tax jurisdiction, inclusive/exclusive pricing and tax rounding policy.
- Payment gateway settlement, bank/cash reconciliation and discrepancy records.

## Non-negotiable invariants
- Every posted journal entry balances per currency: total debits equal total credits.
- Posted entries are immutable; corrections use linked reversals.
- Draft, approved, posted, voided and reversed states are distinct and permission-controlled.
- Invoice numbering is unique within its configured legal/tenant scope and must not be reused after issue.
- Payment receipt and allocation are separate. Partial, excess, unapplied and split allocations are supported.
- Refunds must reference an original payment or approved credit balance and require authorization.
- No floating-point arithmetic for money. Use fixed-precision decimal values and explicit currency minor-unit/rounding rules.
- Store transaction currency and, when multi-currency is supported, functional/reporting currency, exchange rate, rate source and conversion date.
- Tenant boundaries apply to every financial record and report.
- Every financial mutation records actor, timestamp, reason, source and correlation ID.

## ISP billing workflows
- Recurring subscriptions, prorations, one-time charges, discounts and plan changes.
- Invoice generation with preview, tax calculation, approval and issue.
- Payment capture/import, gateway callback verification, receipt generation and allocation.
- Dunning and overdue aging with configurable grace periods and service restriction policy.
- Credit note, refund, chargeback and failed-payment handling.
- Reseller/agent commissions as separately calculated liabilities, not hidden invoice discounts.
- General ledger posting for invoices, receipts, refunds, taxes, discounts, write-offs and gateway fees.
- Reconciliation of gateway settlements and bank/cash statements against receipts and ledger postings.

## Financial reports and analysis
- Accounts receivable aging by current, 1-30, 31-60, 61-90 and over-90-day buckets, configurable by tenant.
- Invoice value, collected cash, recognized revenue, deferred revenue and outstanding balance shown as separate measures.
- Daily collection, collection efficiency, bad debt/write-off, refunds and payment-channel mix.
- Revenue by service plan, region, reseller, customer segment and tax category.
- ARPU must state its subscriber denominator and period; active, billed and paying subscribers are not interchangeable.
- Cash flow and bank reconciliation status.
- Trial balance, general ledger, profit and loss, balance sheet and tax reports.
- Every report exposes filters, period, currency, timezone, generation timestamp and drill-down to source records.

## Authorization and segregation of duties
- Separate permissions for create, approve, post, reverse, refund, write-off, export and close-period actions.
- Enforce maker-checker approval for configurable high-value transactions and sensitive adjustments.
- A user must not approve their own transaction where maker-checker is required.
- Closed periods reject backdated postings unless an authorized period reopen workflow is completed and audited.

## Compliance boundary
Tax rules, invoice legal requirements, retention periods and statutory reports vary by jurisdiction. Implement configurable tax and document policies and validate each deployment against its operating jurisdiction before claiming legal or tax compliance. This document defines product controls, not a substitute for local professional accounting or tax review.
