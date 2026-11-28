-- One-time recovery and dual-control administrative MFA reset workflow.
BEGIN;
CREATE TABLE operator_mfa_reset_requests (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    target_user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    requester_user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    approver_user_id UUID REFERENCES operator_users(id) ON DELETE RESTRICT,
    reason VARCHAR(500) NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'completed', 'rejected', 'expired')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CHECK (requester_user_id <> target_user_id),
    CHECK (approver_user_id IS NULL OR approver_user_id <> requester_user_id),
    CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '24 hours'),
    CHECK ((status IN ('approved', 'completed')) = (approved_at IS NOT NULL)),
    CHECK ((status = 'completed') = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX operator_mfa_one_pending_reset_per_target_idx
    ON operator_mfa_reset_requests (tenant_id, target_user_id) WHERE status = 'pending';
CREATE INDEX operator_mfa_reset_request_expiry_idx
    ON operator_mfa_reset_requests (expires_at) WHERE status = 'pending';
COMMIT;
