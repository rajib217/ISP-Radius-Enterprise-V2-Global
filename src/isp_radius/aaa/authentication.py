"""Subscriber authentication with Argon2id and tenant resolution via NAS IP."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from isp_radius.persistence.accounting_repository import Connection


_AUTH_QUERY = """
SELECT s.tenant_id, s.username, c.password_hash,
       p.download_bps, p.upload_bps
  FROM nas_devices AS n
  JOIN subscribers AS s ON s.tenant_id = n.tenant_id
  JOIN subscriber_credentials AS c
    ON c.tenant_id = s.tenant_id AND c.subscriber_id = s.id
  JOIN service_plans AS p
    ON p.tenant_id = s.tenant_id AND p.id = s.service_plan_id
 WHERE n.address = %s
   AND n.enabled = TRUE
   AND s.username = %s
   AND s.status = 'active'
   AND p.enabled = TRUE
"""

_PASSWORD_HASHER = PasswordHasher()
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash("not-a-real-subscriber-password")


@dataclass(frozen=True, slots=True)
class AuthenticatedSubscriber:
    tenant_id: str
    username: str
    download_bps: int
    upload_bps: int


def hash_subscriber_password(password: str) -> str:
    """Create a one-way Argon2id password hash; never persist the raw password."""
    if not password or len(password) > 1024:
        raise ValueError("password must contain 1 to 1024 characters")
    return _PASSWORD_HASHER.hash(password)


def authenticate_subscriber(
    connection: Connection,
    *,
    nas_ip: str,
    username: str,
    password: str,
) -> AuthenticatedSubscriber | None:
    """Authenticate an active subscriber against the tenant owning the NAS IP.

    Ambiguous NAS IP mappings fail closed. Passwords are verified in-process;
    only the Argon2id hash is read from the database.
    """
    if not nas_ip or not username or not password or len(password) > 1024:
        return None
    try:
        normalized_nas_ip = str(ip_address(nas_ip))
    except ValueError:
        return None

    cursor = connection.cursor()
    try:
        cursor.execute(_AUTH_QUERY, (normalized_nas_ip, username))
        rows = cursor.fetchall()
    finally:
        cursor.close()

    if len(rows) != 1:
        try:
            _PASSWORD_HASHER.verify(_DUMMY_PASSWORD_HASH, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        return None

    tenant_id, canonical_username, password_hash, download_bps, upload_bps = rows[0]
    try:
        valid = _PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        valid = False

    if not valid:
        return None

    return AuthenticatedSubscriber(
        tenant_id=str(tenant_id),
        username=str(canonical_username),
        download_bps=int(download_bps),
        upload_bps=int(upload_bps),
    )
