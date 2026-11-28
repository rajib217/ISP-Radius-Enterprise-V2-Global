from types import SimpleNamespace
import sys

import pytest

from isp_radius.security.webauthn import (
    WebAuthnVerificationError,
    generate_webauthn_challenge,
    hash_webauthn_challenge,
    verify_webauthn_authentication,
    verify_webauthn_registration,
)


def test_challenge_is_random_and_digest_is_hex():
    first = generate_webauthn_challenge()
    second = generate_webauthn_challenge()
    assert len(first) == 32
    assert first != second
    assert len(hash_webauthn_challenge(first)) == 64


def test_short_challenge_is_rejected():
    with pytest.raises(ValueError, match="128 bits"):
        hash_webauthn_challenge(b"short")


@pytest.mark.parametrize("origin", [
    "http://console.example.com",
    "https://console.example.com/admin",
    "https://user:pass@example.com",
    "https://console.example.com?next=/",
])
def test_untrusted_origin_shapes_are_rejected(origin):
    with pytest.raises(ValueError):
        verify_webauthn_registration(
            credential={}, expected_challenge=b"x" * 32,
            expected_origin=origin, rp_id="example.com",
        )


def test_registration_delegates_trust_checks_to_library(monkeypatch):
    calls = {}
    def verify(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(
            credential_id=b"credential", credential_public_key=b"public-key",
            sign_count=0, credential_device_type="multi_device",
            credential_backed_up=True,
        )
    monkeypatch.setitem(sys.modules, "webauthn", SimpleNamespace(
        verify_registration_response=verify
    ))
    result = verify_webauthn_registration(
        credential={"id": "abc"}, expected_challenge=b"c" * 32,
        expected_origin="https://console.example.com", rp_id="example.com",
    )
    assert result.credential_id == b"credential"
    assert result.credential_public_key == b"public-key"
    assert calls["expected_origin"] == "https://console.example.com"
    assert calls["expected_rp_id"] == "example.com"
    assert calls["require_user_verification"] is True


def test_authentication_requires_user_verification(monkeypatch):
    def verify(**kwargs):
        return SimpleNamespace(
            new_sign_count=2, credential_device_type="single_device",
            credential_backed_up=False, user_verified=False,
        )
    monkeypatch.setitem(sys.modules, "webauthn", SimpleNamespace(
        verify_authentication_response=verify
    ))
    with pytest.raises(WebAuthnVerificationError, match="user verification"):
        verify_webauthn_authentication(
            credential={}, expected_challenge=b"c" * 32,
            expected_origin="https://console.example.com", rp_id="example.com",
            credential_public_key=b"public-key", credential_current_sign_count=1,
        )


def test_authentication_returns_verified_counter_and_backup_state(monkeypatch):
    def verify(**kwargs):
        return SimpleNamespace(
            new_sign_count=3, credential_device_type="multi_device",
            credential_backed_up=True, user_verified=True,
        )
    monkeypatch.setitem(sys.modules, "webauthn", SimpleNamespace(
        verify_authentication_response=verify
    ))
    result = verify_webauthn_authentication(
        credential={}, expected_challenge=b"c" * 32,
        expected_origin="https://console.example.com", rp_id="example.com",
        credential_public_key=b"public-key", credential_current_sign_count=2,
    )
    assert result.new_sign_count == 3
    assert result.backed_up is True
    assert result.user_verified is True
