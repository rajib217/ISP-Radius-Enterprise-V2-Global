# Operator Console Security Boundary

## Status
Initial operator authentication is implemented at `/operator/login`, `/operator/session` and `/operator/logout`. It verifies Argon2id credentials, resolves active tenant memberships, requires tenant selection for multi-tenant users, issues opaque HttpOnly session cookies, validates CSRF and Origin on logout, throttles login failures, and writes audit events. The `/monitoring/*` bearer-token mechanism remains service-to-service only. The browser BFF and per-route permission enforcement are not yet implemented.

## Required request path

```text
Browser
  -> HTTPS operator session (HttpOnly cookie)
  -> authenticated server-side BFF
  -> private monitoring API (server-held service credential)
  -> tenant-scoped repository
  -> PostgreSQL
```

The browser must never receive `MONITORING_API_KEY_HASHES`, a raw monitoring bearer token, a database URL, or any other service secret. Do not place these values in Vite/React public environment variables, HTML, local storage, session storage, source maps, or browser-readable configuration.

## Identity and authorization requirements
1. Authenticate a human operator against a versioned identity store. Passwords, if used, must be stored using a modern password hashing scheme such as Argon2id.
2. Resolve the operator's active tenant membership and permissions on the server for every protected request.
3. Derive tenant scope from the authenticated server-side principal. Reject client-supplied tenant overrides unless a separately authorized tenant-switch workflow validates them.
4. Define explicit permissions for read-only monitoring and each future privileged action. A monitoring viewer must not inherit CoA, disconnect, subscriber edit, or finance permissions.
5. Fail closed when identity, tenant membership, permission data, or the authorization service is unavailable.

## Browser session controls
- HTTPS only; cookies must be Secure, HttpOnly and SameSite=Lax or stricter where compatible.
- Protect state-changing requests with CSRF tokens and origin checks.
- Rotate session identifiers after login and privilege changes; enforce idle and absolute expiry.
- Provide server-side logout/revocation and prevent session fixation.
- Rate-limit login and recovery endpoints; avoid account enumeration.
- Use generic authentication failures and security audit events without logging passwords, cookies, tokens, or secrets.
- Apply a restrictive Content Security Policy and appropriate security headers.

## BFF requirements
- The BFF authenticates the browser session, checks the operator's permission and derives tenant identity before calling the private monitoring API.
- The service credential is loaded from server-side secret configuration only.
- The BFF forwards only allowlisted query parameters, validates bounds, and does not accept a tenant ID from the browser as authoritative.
- Do not create an unrestricted generic proxy. Expose narrowly scoped application routes.
- Use request timeouts, bounded response sizes, safe error mapping and correlation IDs.
- Keep API and browser origins constrained by deployment configuration.

## Monitoring dashboard data contract
The initial dashboard is read-only:
- Summary: online, stale and offline counts plus the usage counters returned by the monitoring API.
- Session list: subscriber username, NAS, session identity, start/last-update information, duration and usage counters where available.
- Filters: state, username/session search, NAS identifier, stale threshold and bounded pagination.
- Refresh must not imply that a stale session is disconnected. Show last refresh time and explain that stale means accounting updates are overdue.
- Do not add disconnect, CoA, credential reset, or billing actions to the first dashboard release.

## Delivery gates
Before browser release:
- Identity, tenant membership, login/session lifecycle, CSRF/origin checks, login throttling, role mapping and audit storage are implemented and migrated.
- Automated tests prove login, tenant selection, session lookup, CSRF rejection and logout revocation. BFF-specific unauthenticated, unauthorized and cross-tenant tests remain required.
- Cross-tenant access tests cover every BFF route and repository query.
- Browser bundles and source maps are scanned to confirm no service secrets are present.
- CSRF, 30-minute idle expiry, 12-hour absolute expiry, revocation and login throttling are tested. Security headers and MFA remain outstanding.
- UI includes loading, empty, stale-data, API-error and permission-denied states.
- A security review and deployment runbook are completed.

## Current API configuration

- `OPERATOR_ALLOWED_ORIGINS`: comma-separated exact browser origins. Required for login/logout; missing configuration fails closed.
- `OPERATOR_COOKIE_SECURE`: defaults to `true`. Setting it to `false` is permitted only when `APP_ENV` is `development` or `test`.
- Session lifetime: 12-hour absolute expiry and 30-minute idle timeout.
- Login throttling: five failures per email/IP pair or IP in a 15-minute window trigger a 15-minute lock.
- Apply migrations through `0014_operator_login_throttling.sql` before enabling operator login.

## Explicit non-goals for the first release
No browser-stored service bearer token, no tenant selection by arbitrary request parameter, no write operations, no claim that a stale session is offline, and no automatic cleanup or billing based on monitoring state.
