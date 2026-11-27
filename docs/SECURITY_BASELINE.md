# Security Baseline

- Enforce tenant isolation at every service and persistence boundary; deny by default.
- Store passwords with a modern adaptive password hash. Store device, RADIUS, payment and API secrets in a secret manager or encrypted secret store with key rotation.
- Never log passwords, shared secrets, tokens, payment credentials or full sensitive RADIUS attributes.
- Restrict RADIUS UDP 1812/1813 and dynamic authorization ports to known NAS addresses. Prefer RadSec/TLS where both ends support it and certificate lifecycle is operationally managed.
- Use TLS for all administrative/API traffic. Secure cookies, CSRF protection for browser sessions, rate limiting and MFA for privileged roles.
- Validate NAS source identity and shared-secret mapping. Support Message-Authenticator requirements according to RADIUS client/server compatibility.
- Use least-privilege database accounts and separate runtime identities.
- Maintain append-only audit events for privileged changes and device operations.
- Backups must be encrypted, access-controlled and restore-tested.
- Include dependency scanning, static analysis, secret scanning and security tests in CI.
- Define retention and deletion policies for accounting, authentication logs and personal data.
