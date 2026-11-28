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


def _install_fake_webauthn_modules(monkeypatch, *, root, structs):
    import types

    package = types.ModuleType("webauthn")
    package.__path__ = []
    for name, value in root.items():
        setattr(package, name, value)
    helpers = types.ModuleType("webauthn.helpers")
    helpers.__path__ = []
    structs_module = types.ModuleType("webauthn.helpers.structs")
    for name, value in vars(structs).items():
        if not name.startswith("_"):
            setattr(structs_module, name, value)
    monkeypatch.setitem(sys.modules, "webauthn", package)
    monkeypatch.setitem(sys.modules, "webauthn.helpers", helpers)
    monkeypatch.setitem(sys.modules, "webauthn.helpers.structs", structs_module)


def test_registration_options_require_discoverable_uv_passkey(monkeypatch):
    calls = {}
    class Selection:
        def __init__(self, **kwargs):
            calls["selection"] = kwargs
    class Descriptor:
        def __init__(self, **kwargs):
            calls.setdefault("excluded", []).append(kwargs)
    class Resident:
        REQUIRED = "required"
    class UV:
        REQUIRED = "required"
    def generate(**kwargs):
        calls.update(kwargs)
        return {"challenge": "generated"}
    structs = SimpleNamespace(
        AuthenticatorSelectionCriteria=Selection,
        ResidentKeyRequirement=Resident,
        UserVerificationRequirement=UV,
        PublicKeyCredentialDescriptor=Descriptor,
    )
    _install_fake_webauthn_modules(monkeypatch, root={
        "generate_registration_options": generate,
        "options_to_json": lambda value: '{"publicKey":true}',
    }, structs=structs)
    from isp_radius.security.webauthn import generate_registration_options_json
    result = generate_registration_options_json(
        rp_id="example.com", rp_name="ISP Console", user_id=b"user-id",
        user_name="operator@example.com", user_display_name="Operator",
        challenge=b"c" * 32, exclude_credential_ids=(b"existing",),
    )
    assert result == '{"publicKey":true}'
    assert calls["selection"] == {
        "resident_key": "required", "user_verification": "required"
    }
    assert calls["excluded"] == [{"id": b"existing"}]


def test_authentication_options_are_uv_required_and_user_scoped(monkeypatch):
    calls = {}
    class Descriptor:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
    class UV:
        REQUIRED = "required"
    def generate(**kwargs):
        calls.update(kwargs)
        return {"challenge": "generated"}
    structs = SimpleNamespace(
        PublicKeyCredentialDescriptor=Descriptor,
        UserVerificationRequirement=UV,
    )
    _install_fake_webauthn_modules(monkeypatch, root={
        "generate_authentication_options": generate,
        "options_to_json": lambda value: '{"allowCredentials":[]}',
    }, structs=structs)
    from isp_radius.security.webauthn import generate_authentication_options_json
    result = generate_authentication_options_json(
        rp_id="example.com", challenge=b"c" * 32,
        allowed_credential_ids=(b"credential-1", b"credential-2"),
    )
    assert result == '{"allowCredentials":[]}'
    assert calls["user_verification"] == "required"
    assert [item.kwargs["id"] for item in calls["allow_credentials"]] == [
        b"credential-1", b"credential-2"
    ]


def test_authentication_options_reject_empty_credential_list():
    from isp_radius.security.webauthn import generate_authentication_options_json
    with pytest.raises(ValueError, match="At least one"):
        generate_authentication_options_json(
            rp_id="example.com", challenge=b"c" * 32, allowed_credential_ids=(),
        )
