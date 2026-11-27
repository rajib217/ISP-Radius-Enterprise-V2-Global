-- PostgreSQL 16+ baseline schema. Apply once to an empty database.
-- All tenant-owned tables carry tenant_id and use composite foreign keys.
BEGIN;

CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    slug VARCHAR(63) NOT NULL UNIQUE,
    default_currency CHAR(3) NOT NULL CHECK (default_currency ~ '^[A-Z]{3}$'),
    timezone VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE service_plans (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(160) NOT NULL,
    price NUMERIC(19,4) NOT NULL CHECK (price >= 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    billing_period_days INTEGER NOT NULL CHECK (billing_period_days > 0),
    download_bps BIGINT NOT NULL CHECK (download_bps > 0),
    upload_bps BIGINT NOT NULL CHECK (upload_bps > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, code)
);

CREATE TABLE subscribers (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    username VARCHAR(128) NOT NULL,
    full_name VARCHAR(160) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('pending','active','suspended','terminated')),
    service_plan_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, username),
    FOREIGN KEY (tenant_id, service_plan_id)
        REFERENCES service_plans(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX subscribers_status_idx ON subscribers (tenant_id, status);

CREATE TABLE nas_devices (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name VARCHAR(160) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('bng','nas','router')),
    protocol VARCHAR(16) NOT NULL CHECK (protocol IN ('radius_udp','radsec')),
    address VARCHAR(253) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE chart_of_accounts (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    code VARCHAR(32) NOT NULL,
    name VARCHAR(160) NOT NULL,
    account_type VARCHAR(16) NOT NULL CHECK
        (account_type IN ('asset','liability','equity','revenue','expense')),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    is_control_account BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, code)
);

CREATE TABLE journal_entries (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    reference VARCHAR(96) NOT NULL,
    description TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status VARCHAR(16) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','posted','reversed')),
    reversal_of UUID,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, reference),
    UNIQUE (tenant_id, reversal_of),
    FOREIGN KEY (tenant_id, reversal_of)
        REFERENCES journal_entries(tenant_id, id) ON DELETE RESTRICT,
    CHECK (reversal_of IS NULL OR reversal_of <> id)
);

CREATE TABLE journal_lines (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    journal_entry_id UUID NOT NULL,
    account_id UUID NOT NULL,
    line_number SMALLINT NOT NULL CHECK (line_number > 0),
    side VARCHAR(6) NOT NULL CHECK (side IN ('debit','credit')),
    amount NUMERIC(19,4) NOT NULL CHECK (amount > 0),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    memo TEXT,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, journal_entry_id, line_number),
    FOREIGN KEY (tenant_id, journal_entry_id)
        REFERENCES journal_entries(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, account_id)
        REFERENCES chart_of_accounts(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX journal_lines_account_idx ON journal_lines (tenant_id, account_id);

-- A posted journal must balance in exactly one currency. Deferred validation
-- permits inserting the header and all lines in one transaction before posting.
CREATE FUNCTION assert_posted_journal_balanced() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    entry_tenant UUID;
    entry_id UUID;
    debit_total NUMERIC(19,4);
    credit_total NUMERIC(19,4);
    currency_count BIGINT;
    line_count BIGINT;
BEGIN
    entry_tenant := NEW.tenant_id;
    entry_id := NEW.id;
    IF NEW.status <> 'posted' THEN
        RETURN NEW;
    END IF;

    SELECT COUNT(*), COUNT(DISTINCT currency),
           COALESCE(SUM(amount) FILTER (WHERE side = 'debit'), 0),
           COALESCE(SUM(amount) FILTER (WHERE side = 'credit'), 0)
      INTO line_count, currency_count, debit_total, credit_total
      FROM journal_lines
     WHERE tenant_id = entry_tenant AND journal_entry_id = entry_id;

    IF line_count < 2 OR currency_count <> 1 OR debit_total <> credit_total THEN
        RAISE EXCEPTION 'Posted journal % must have at least two lines, one currency, and balanced debits/credits', entry_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER journal_posting_balance_check
AFTER INSERT OR UPDATE ON journal_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_posted_journal_balanced();

-- Posted journals are immutable. Corrections must use a linked reversal.
CREATE FUNCTION prevent_posted_journal_line_mutation() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    target_tenant UUID;
    target_entry UUID;
    current_status VARCHAR(16);
BEGIN
    target_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
    target_entry := COALESCE(NEW.journal_entry_id, OLD.journal_entry_id);
    SELECT status INTO current_status
      FROM journal_entries
     WHERE tenant_id = target_tenant AND id = target_entry;
    IF current_status IN ('posted','reversed') THEN
        RAISE EXCEPTION 'Lines of a posted or reversed journal are immutable';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER journal_lines_immutable_after_post
BEFORE INSERT OR UPDATE OR DELETE ON journal_lines
FOR EACH ROW EXECUTE FUNCTION prevent_posted_journal_line_mutation();

COMMIT;
