"""Cryptographic primitives for operator TOTP enrollment and verification.

KMS integration is supplied by a deployment-specific DataKeyProvider. Plaintext
data keys exist only in process memory and are never persisted or logged.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6
_TOTP_SECRET_BYTES = 20
_AES_KEY_BYTES = 32
_GCM_NONCE_BYTES = 12
_MAX_CLOCK_SKEW_STEPS = 1


class DataKeyProvider(Protocol):
    """Adapter to a KMS that creates and unwraps short-lived AES-256 data keys."""

    def generate_data_key(self) -> tuple[bytes, bytes, str]:
        """Return (plaintext AES-256 key, KMS-wrapped key, KMS key version."""

    def decrypt_data_key(self, *, wrapped_key: bytes, key_version: str) -> bytes:
        """Unwrap a data key using the named KMS key version."""


@dataclass(frozen=True, slots=True)
class EncryptedTOTPSecret:
    ciphertext: bytes
    nonce: bytes
    wrapped_data_key: bytes
    key_version: str


def generate_totp_secret() -> str:
    """Generate a 160-bit RFC 4226/6238 secret encoded as unpadded Base32."""
    return base64.b32encode(secrets.token_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    if not isinstance(secret, str) or not 16 <= len(secret) <= 128:
        raise ValueError("invalid TOTP secret")
    normalized = secret.strip().upper()
    if not normalized or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for ch in normalized):
        raise ValueError("invalid TOTP secret")
    try:
        decoded = base64.b32decode(
            normalized + "=" * (-len(normalized) % 8), casefold=False
        )
    except (ValueError, binascii.Error):
        raise ValueError("invalid TOTP secret") from None
    if len(decoded) < 10:
        raise ValueError("invalid TOTP secret")
    return decoded


def _totp_at_step(secret: bytes, step: int, *, digits: int = _TOTP_DIGITS) -> str:
    if step < 0 or digits not in (6, 8):
        raise ValueError("invalid TOTP parameters")
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def verify_totp(
    secret: str,
    code: str,
    *,
    now: datetime | None = None,
    allowed_skew_steps: int = _MAX_CLOCK_SKEW_STEPS,
) -> int | None:
    """Return the matching time-step, or None; callers must persist it atomically.

    The returned step must be passed to accept_operator_totp_step before granting
    access. This function intentionally does not implement replay persistence.
    """
    if allowed_skew_steps not in (0, 1):
        raise ValueError("TOTP clock skew must be zero or one step")
    if (
        not isinstance(code, str)
        or len(code) != _TOTP_DIGITS
        or not code.isascii()
        or not code.isdigit()
    ):
        return None
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("TOTP verification time must be timezone-aware")
    timestamp = int(instant.timestamp())
    if timestamp < 0:
        return None
    current_step = timestamp // _TOTP_PERIOD_SECONDS
    key = _decode_secret(secret)
    matched_step: int | None = None
    for offset in range(-allowed_skew_steps, allowed_skew_steps + 1):
        candidate_step = current_step + offset
        if candidate_step < 0:
            continue
        if hmac.compare_digest(_totp_at_step(key, candidate_step), code):
            matched_step = candidate_step
    return matched_step


def totp_provisioning_uri(
    secret: str, *, account_name: str, issuer: str
) -> str:
    """Build an authenticator-compatible otpauth URI for one-time enrollment display."""
    _decode_secret(secret)
    if not account_name or len(account_name) > 254 or not issuer or len(issuer) > 64:
        raise ValueError("invalid TOTP account metadata")
    label = quote(f"{issuer}:{account_name}", safe="")
    return (
        f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={_TOTP_DIGITS}&period={_TOTP_PERIOD_SECONDS}"
    )


def encrypt_totp_secret(
    secret: str,
    *,
    user_id: str,
    factor_id: str,
    key_provider: DataKeyProvider,
) -> EncryptedTOTPSecret:
    """Encrypt a TOTP secret with AES-256-GCM and a KMS-wrapped data key."""
    plaintext_secret = _decode_secret(secret)
    if not user_id or not factor_id:
        raise ValueError("user and factor identifiers are required")
    data_key, wrapped_key, key_version = key_provider.generate_data_key()
    if len(data_key) != _AES_KEY_BYTES:
        raise ValueError("KMS data key must be 256 bits")
    if not 1 <= len(wrapped_key) <= 4096 or not 1 <= len(key_version) <= 128:
        raise ValueError("invalid KMS wrapped key metadata")
    nonce = secrets.token_bytes(_GCM_NONCE_BYTES)
    aad = f"isp-radius:operator-totp:v1:{user_id}:{factor_id}:{key_version}".encode()
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext_secret, aad)
    return EncryptedTOTPSecret(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_data_key=wrapped_key,
        key_version=key_version,
    )


def decrypt_totp_secret(
    encrypted: EncryptedTOTPSecret,
    *,
    user_id: str,
    factor_id: str,
    key_provider: DataKeyProvider,
) -> str:
    """Decrypt only when the factor identity and KMS key version match."""
    if len(encrypted.nonce) != _GCM_NONCE_BYTES:
        raise ValueError("invalid TOTP nonce")
    data_key = key_provider.decrypt_data_key(
        wrapped_key=encrypted.wrapped_data_key,
        key_version=encrypted.key_version,
    )
    if len(data_key) != _AES_KEY_BYTES:
        raise ValueError("KMS data key must be 256 bits")
    aad = (
        f"isp-radius:operator-totp:v1:{user_id}:{factor_id}:{encrypted.key_version}"
    ).encode()
    try:
        plaintext = AESGCM(data_key).decrypt(encrypted.nonce, encrypted.ciphertext, aad)
    except InvalidTag:
        raise ValueError("TOTP secret authentication failed") from None
    return base64.b32encode(plaintext).decode("ascii").rstrip("=")


def generate_recovery_codes(*, count: int = 10) -> tuple[str, ...]:
    """Generate ten unique 144-bit codes for one-time offline storage."""
    import secrets

    if count != 10:
        raise ValueError("recovery code batches must contain exactly ten codes")
    return tuple(
        "-".join(
            secrets.token_hex(18).upper()[i:i + 6]
            for i in range(0, 36, 6)
        )
        for _ in range(count)
    )


def normalize_recovery_code(code: str) -> str:
    """Normalize a code while rejecting all characters outside its alphabet."""
    if not isinstance(code, str):
        raise TypeError("invalid recovery code type")
    value = code.replace("-", "").replace(" ", "").upper()
    if len(value) != 36 or any(ch not in "0123456789ABCDEF" for ch in value):
        raise ValueError("invalid recovery code")
    return value


def hash_recovery_code(code: str) -> str:
    """Return the SHA-256 digest of a normalized 144-bit recovery code."""
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii")).hexdigest()
