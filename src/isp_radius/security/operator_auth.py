"""Security primitives for human operator sessions and RBAC."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_SESSION_TTL = timedelta(hours=12)
_PASSWORD_HASHER = PasswordHasher()

_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": frozenset({"*"}),
    "admin": frozenset({"*"}),
    "operations": frozenset({"sessions:read", "sessions:disconnect", "nas:read", "nas:write"}),
    "billing": frozenset({"billing:read", "billing:write", "invoices:read", "payments:write"}),
    "support": frozenset({"sessions:read", "subscribers:read", "tickets:write"}),
    "viewer": frozenset({"sessions:read", "subscribers:read", "billing:read"}),
}


@dataclass(frozen=True, slots=True)
class SessionTokens:
    session_token: str
    csrf_token: str
    session_hash: str
    csrf_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class OperatorPrincipal:
    user_id: str
    email: str
    tenant_id: str
    role: str
    session_id: str
    csrf_token_hash: str

    @property
    def permissions(self) -> frozenset[str]:
        return _ROLE_PERMISSIONS.get(self.role, frozenset())

    def allows(self, permission: str) -> bool:
        permissions = self.permissions
        return "*" in permissions or permission in permissions


def normalize_operator_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 254 or normalized.count("@") != 1:
        raise ValueError("invalid operator email")
    local, domain = normalized.split("@")
    if not local or not domain or "." not in domain or any(ch.isspace() for ch in normalized):
        raise ValueError("invalid operator email")
    return normalized


def hash_token(token: str) -> str:
    if not token or len(token) > 512:
        raise ValueError("token must contain 1 to 512 characters")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session_tokens(*, now: datetime | None = None) -> SessionTokens:
    issued_at = now or datetime.now(UTC)
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    return SessionTokens(
        session_token=session_token,
        csrf_token=csrf_token,
        session_hash=hash_token(session_token),
        csrf_hash=hash_token(csrf_token),
        expires_at=issued_at + _SESSION_TTL,
    )


def verify_operator_password(password_hash: str, password: str) -> bool:
    if not password or len(password) > 1024 or not password_hash.startswith("$argon2id$"):
        return False
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False


def permissions_for_role(role: str) -> frozenset[str]:
    return _ROLE_PERMISSIONS.get(role, frozenset())


def csrf_matches(*, supplied_header: str | None, csrf_cookie: str | None, stored_hash: str) -> bool:
    if not supplied_header or not csrf_cookie or len(supplied_header) > 512:
        return False
    if not hmac.compare_digest(supplied_header, csrf_cookie):
        return False
    try:
        return hmac.compare_digest(hash_token(supplied_header), stored_hash)
    except ValueError:
        return False


def session_expiry(now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) + _SESSION_TTL
