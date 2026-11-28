-- Bind login MFA challenges to the tenant selected during password authentication.
BEGIN;
ALTER TABLE operator_mfa_challenges
    ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE RESTRICT;
CREATE INDEX operator_mfa_login_challenge_idx
    ON operator_mfa_challenges (tenant_id, user_id, expires_at)
    WHERE tenant_id IS NOT NULL AND consumed_at IS NULL;
COMMIT;
