"""WebAuthn verification adapters backed by the maintained py_webauthn library."""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class WebAuthnVerificationError(ValueError):
    """A browser credential response failed WebAuthn verification."""


@dataclass(frozen=True, slots=True)
class VerifiedRegistration:
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int
    device_type: str
    backed_up: bool


@dataclass(frozen=True, slots=True)
class VerifiedAuthentication:
    new_sign_count: int
    device_type: str
    backed_up: bool
    user_verified: bool


def generate_webauthn_challenge() -> bytes:
    """Return a high-entropy, one-time challenge for a persisted ceremony."""
    return secrets.token_bytes(32)


def hash_webauthn_challenge(challenge: bytes) -> str:
    """Return the lowercase SHA-256 digest stored by the challenge repository."""
    if len(challenge) < 16:
        raise ValueError("WebAuthn challenge must contain at least 128 bits")
    return hashlib.sha256(challenge).hexdigest()


def _validate_relying_party(*, expected_origin: str, rp_id: str) -> None:
    if not expected_origin or len(expected_origin) > 512:
        raise ValueError("A configured WebAuthn origin is required")
    if not rp_id or len(rp_id) > 253 or any(ch.isspace() for ch in rp_id):
        raise ValueError("A valid WebAuthn RP ID is required")
    parsed = urlsplit(expected_origin)
    if (
        parsed.username or parsed.password or parsed.path not in ("", "/")
        or parsed.query or parsed.fragment
    ):
        raise ValueError("WebAuthn origin must be an exact origin without path or credentials")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
    ):
        raise ValueError("WebAuthn origins must use HTTPS outside local development")
    if not parsed.netloc:
        raise ValueError("WebAuthn origin must include a host")


def verify_webauthn_registration(
    *,
    credential: dict[str, Any] | str,
    expected_challenge: bytes,
    expected_origin: str,
    rp_id: str,
    require_user_verification: bool = True,
) -> VerifiedRegistration:
    """Verify attestation and return only public credential material."""
    _validate_relying_party(expected_origin=expected_origin, rp_id=rp_id)
    if len(expected_challenge) < 16:
        raise ValueError("WebAuthn challenge must contain at least 128 bits")
    try:
        from webauthn import verify_registration_response

        result = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            require_user_verification=require_user_verification,
        )
        return VerifiedRegistration(
            credential_id=result.credential_id,
            credential_public_key=result.credential_public_key,
            sign_count=result.sign_count,
            device_type=str(getattr(result.credential_device_type, "value", result.credential_device_type)),
            backed_up=bool(result.credential_backed_up),
        )
    except Exception as exc:
        raise WebAuthnVerificationError("WebAuthn registration verification failed") from exc


def verify_webauthn_authentication(
    *,
    credential: dict[str, Any] | str,
    expected_challenge: bytes,
    expected_origin: str,
    rp_id: str,
    credential_public_key: bytes,
    credential_current_sign_count: int,
    require_user_verification: bool = True,
) -> VerifiedAuthentication:
    """Verify an assertion signature, RP/origin binding and authenticator flags."""
    _validate_relying_party(expected_origin=expected_origin, rp_id=rp_id)
    if len(expected_challenge) < 16:
        raise ValueError("WebAuthn challenge must contain at least 128 bits")
    if not credential_public_key:
        raise ValueError("Stored WebAuthn public key is required")
    if credential_current_sign_count < 0:
        raise ValueError("WebAuthn signature counter must be non-negative")
    try:
        from webauthn import verify_authentication_response

        result = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            credential_public_key=credential_public_key,
            credential_current_sign_count=credential_current_sign_count,
            require_user_verification=require_user_verification,
        )
        if require_user_verification and not result.user_verified:
            raise WebAuthnVerificationError("WebAuthn user verification is required")
        return VerifiedAuthentication(
            new_sign_count=result.new_sign_count,
            device_type=str(getattr(result.credential_device_type, "value", result.credential_device_type)),
            backed_up=bool(result.credential_backed_up),
            user_verified=bool(result.user_verified),
        )
    except WebAuthnVerificationError:
        raise
    except Exception as exc:
        raise WebAuthnVerificationError("WebAuthn authentication verification failed") from exc


def generate_registration_options_json(
    *,
    rp_id: str,
    rp_name: str,
    user_id: bytes,
    user_name: str,
    user_display_name: str,
    challenge: bytes,
    exclude_credential_ids: tuple[bytes, ...] = (),
) -> str:
    """Create browser-ready passkey enrollment options with required user verification."""
    _validate_relying_party(expected_origin=f"https://{rp_id}", rp_id=rp_id)
    if len(challenge) < 16 or not user_id or len(user_id) > 64:
        raise ValueError("WebAuthn challenge and user handle must be valid")
    if not rp_name or len(rp_name) > 128 or not user_name or len(user_name) > 256:
        raise ValueError("WebAuthn relying-party and user names are required")
    if not user_display_name or len(user_display_name) > 256:
        raise ValueError("WebAuthn display name is required")
    if any(not item or len(item) > 1024 for item in exclude_credential_ids):
        raise ValueError("Invalid excluded WebAuthn credential ID")
    try:
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name,
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in exclude_credential_ids
            ],
            timeout=60_000,
        )
        return options_to_json(options)
    except Exception as exc:
        raise WebAuthnVerificationError("Unable to generate WebAuthn registration options") from exc


def generate_authentication_options_json(
    *,
    rp_id: str,
    challenge: bytes,
    allowed_credential_ids: tuple[bytes, ...],
) -> str:
    """Create browser-ready assertion options restricted to this user's credentials."""
    _validate_relying_party(expected_origin=f"https://{rp_id}", rp_id=rp_id)
    if len(challenge) < 16:
        raise ValueError("WebAuthn challenge must contain at least 128 bits")
    if not allowed_credential_ids or any(
        not item or len(item) > 1024 for item in allowed_credential_ids
    ):
        raise ValueError("At least one valid active WebAuthn credential is required")
    try:
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=credential_id)
                for credential_id in allowed_credential_ids
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60_000,
        )
        return options_to_json(options)
    except Exception as exc:
        raise WebAuthnVerificationError("Unable to generate WebAuthn authentication options") from exc
