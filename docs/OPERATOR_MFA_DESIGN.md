# Operator MFA design

## Decision

The operator console will use **WebAuthn/passkeys as the preferred MFA method**, with **TOTP authenticator apps as a controlled fallback**. SMS, voice calls, and email codes are not accepted as MFA factors. Email remains an account identifier and notification channel, not an authentication factor.

MFA is a release requirement for every human operator account before the browser console is exposed to production. Owner and admin roles must never be allowed to bypass MFA. A password-only login may create a short-lived, restricted MFA challenge, but it must not create an operator session or authorize any BFF request.

## Factor policy

### WebAuthn / passkeys (preferred)

- Validate the challenge, origin, RP ID, credential ID, signature, user-presence and user-verification flags server-side.
- Require user verification for privileged operator accounts.
- Store credential public keys and metadata only. Never store authenticator private keys.
- Enforce a one-time, short-lived challenge bound to the login attempt, user and browser origin.
- Validate the exact configured HTTPS origins and RP ID. Never derive trusted origins from an untrusted Host header.
- Handle authenticator counter behavior according to WebAuthn guidance. A zero or non-increasing counter is not, by itself, proof of compromise for synced passkeys, but suspicious credential behavior must be audited and risk-reviewed.
- Allow multiple registered credentials so an operator can enroll a backup authenticator.

### TOTP fallback

- Use RFC 6238 with a 30-second time step and a narrow clock-skew window (at most one step either side).
- Generate secrets with a cryptographically secure random source and display the provisioning URI/QR only during enrollment.
- Encrypt TOTP secrets at rest using envelope encryption backed by a deployment-managed KMS or secret-management system. Store the encryption key version with the ciphertext. Do not use a hard-coded application key or plain environment variable as a long-term substitute for a KMS.
- Persist the last accepted time step and reject reuse to prevent replay.
- Require password re-authentication to enroll, replace, or disable a factor.
- TOTP is a fallback, not equivalent to phishing-resistant WebAuthn. Audit its use.

## Login state machine

1. Verify the password using the existing Argon2id path and existing login throttling.
2. If no MFA factor is enrolled, deny production login and direct the account through a controlled enrollment/provisioning workflow. Do not silently downgrade to password-only.
3. If MFA is enrolled, issue a random, opaque, single-use MFA challenge with a maximum five-minute lifetime. Persist only its digest.
4. Verify WebAuthn or TOTP against the challenge, user, origin and factor record. Consume the challenge atomically.
5. Only after successful MFA, create the normal tenant-bound operator session and CSRF token.
6. Record factor type, credential identifier (non-secret), outcome and correlation ID in the append-only audit log. Never log passwords, OTP values, recovery codes, challenge tokens, cookies, or TOTP secrets.

A challenge must be bound to the user and login attempt, must not be accepted as a normal session credential, and must not be reusable across tenants or origins. A failed or expired challenge must not produce a session.

## Recovery policy

- Issue ten single-use recovery codes after MFA enrollment or reset.
- Each code must contain at least 128 bits of cryptographically random entropy. Show the codes once and require the operator to acknowledge secure storage.
- Store only one-way hashes of recovery codes. Consume a code atomically on successful use. Never return existing codes from an API.
- Recovery codes are emergency access, not a routine second factor. Their use must generate a high-severity audit event and trigger notification.
- Regenerate the full set only after fresh MFA verification; invalidate every prior code in the same transaction.
- Lost-factor recovery requires an administrator-assisted, documented identity-verification process. For owner/admin accounts, require two-person approval and out-of-band verification. Support staff must not be able to reset an owner/admin factor unilaterally.
- A factor reset revokes all active sessions and outstanding MFA challenges. It must not change tenant membership or role.
- Never use email-only reset links or support chat identity claims as sufficient proof.

## Data model requirements before implementation

Migration 0015 introduces separate, tenant-independent user factor records because operator identity is global across tenant memberships:

- WebAuthn credential: user ID, credential ID (unique), public key, signature counter, transports, AAGUID, created/last-used/revoked timestamps.
- TOTP factor: user ID, encrypted secret, encryption key version, pending/active/revoked state, enrollment expiry, last accepted time step.
- MFA challenge: user ID, challenge digest, allowed factor method, origin/RP binding, expiry, consumed timestamp, attempt count.
- Recovery code: user ID, one-way digest, created/consumed timestamps and batch identifier.

Migration 0015 adds foreign keys to operator_users, uniqueness constraints for credential IDs and challenge digests, bounded challenge attempt counters, expiry indexes, TOTP ciphertext storage and recovery-code digest storage. Repository operations provide conditional one-time challenge consumption, TOTP time-step replay protection, recovery-code consumption, and session/challenge revocation after factor reset. Factor secrets and recovery material must never be placed in audit metadata.

Do not add plaintext TOTP secrets, raw challenges, raw recovery codes, or reversible recovery-code storage to PostgreSQL. Do not make MFA enrollment active until the user completes a valid factor challenge.

## Operational controls

- Use the same or stricter distributed rate limits for MFA verification and recovery as for password login. Lockouts must not create an easy permanent denial-of-service vector against privileged accounts.
- Keep system clocks synchronized. Alert on excessive clock drift because it can affect TOTP and WebAuthn challenge validation.
- Rotate KMS keys using key-version metadata and a documented re-encryption procedure.
- Audit factor enrollment, removal, recovery-code use, failed verification, factor reset, and credential revocation.
- Require re-authentication with MFA before changing password, tenant access, role, MFA factors, or recovery methods.
- Test concurrent challenge redemption and recovery-code reuse against PostgreSQL transactions, not only mocked repository calls.

## Delivery order

1. Add schema and repository operations for factors, challenges and recovery codes.
2. Implement and test WebAuthn challenge/attestation/assertion verification with a maintained library.
3. Implement TOTP fallback with encryption-provider abstraction and replay protection.
4. Integrate the login state machine so password-only authentication cannot issue a full session.
5. Add recovery workflow, dual-control administrative reset, audit events and notification hooks.
6. Add integration tests for replay, expired challenges, cross-origin rejection, concurrent redemption, recovery-code reuse, factor reset and session revocation.
7. Only then enable MFA enforcement and proceed to the production operator dashboard.

## WebAuthn implementation status

The WebAuthn verification adapter uses the maintained `webauthn` (py_webauthn) library for attestation and assertion verification. It validates configured origin shape, passes the exact challenge, origin and RP ID to the library, requires user verification by default, and returns only public credential material and authenticator metadata. Repository primitives persist verified credentials, fetch active public keys, update counters and backup state after successful assertions, and revoke credentials with an owner check. Challenge generation uses 32 random bytes; only its SHA-256 digest belongs in the challenge table.

Password-reauthenticated WebAuthn registration option and verification endpoints bind enrollment challenges to the authenticated user, exact allowed origin and configured RP ID. The login path now detects registered passkeys and returns a restricted, tenant-bound WebAuthn challenge instead of issuing a session. The assertion endpoint verifies the signature, challenge, origin, RP ID, credential ownership and required user verification, then atomically consumes the challenge, updates authenticator metadata and creates the tenant-bound session. Accounts without any enrolled factor still use the temporary password-only bootstrap path so they can enroll; this is not acceptable for production exposure. Recovery-code issuance and redemption, administrative reset approvals, notification wiring, complete enrollment/bootstrap controls and PostgreSQL concurrency tests remain **not implemented**. MFA is **not enforced**.


## TOTP and AWS KMS implementation status

TOTP enrollment and login fallback use RFC 6238 six-digit SHA-1 codes with a 30-second period and at most one adjacent time step. TOTP secrets are encrypted with AES-256-GCM using per-factor data keys generated by AWS KMS. The database stores ciphertext, nonce, KMS-wrapped data key and KMS key ID only. AES-GCM additional authenticated data binds the ciphertext to the operator and factor. The optional `aws-kms` dependency is installed with `pip install .[aws-kms]`; configure `OPERATOR_TOTP_KMS_KEY_ID` and the standard AWS credential/region environment. The runtime role needs only `kms:GenerateDataKey` and `kms:Decrypt` on that key. If KMS is unavailable or unconfigured, TOTP enrollment and verification fail closed.

Pending TOTP enrollment expires after ten minutes. The enrollment code's time step is stored at activation, preventing that same code from being replayed for login. Login challenges are tenant-bound, method-bound, origin-bound, expire after five minutes and allow at most five failures. TOTP verification updates the accepted time step atomically to prevent replay.

Recovery-code issuance/rotation, recovery login, administrative reset approvals, notification delivery and production MFA enforcement remain pending. Accounts without an enrolled factor retain the temporary bootstrap path and must not be exposed in production.


The TOTP fallback now has password-reauthenticated enrollment, encrypted pending-factor storage, authenticator-code activation, tenant-bound login challenges, atomic time-step replay protection and a login fallback alongside passkeys. AWS KMS is the supported envelope-encryption provider. Install `.[aws-kms]` and configure `OPERATOR_TOTP_KMS_KEY_ID`, AWS region and a least-privilege runtime role before enabling it. Failed enrollment verification is capped at five attempts and revokes the pending factor. The login flow invalidates other outstanding MFA challenges after successful factor verification.
