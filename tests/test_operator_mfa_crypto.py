from datetime import UTC, datetime

import pytest

from isp_radius.security.operator_mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    totp_provisioning_uri,
    verify_totp,
)


class FakeKMS:
    def __init__(self):
        self.key = b"k" * 32
        self.wrapped = b"wrapped-key"
        self.version = "kms-key-version-7"

    def generate_data_key(self):
        return self.key, self.wrapped, self.version

    def decrypt_data_key(self, *, wrapped_key, key_version):
        assert wrapped_key == self.wrapped
        assert key_version == self.version
        return self.key


def test_totp_matches_rfc_6238_sha1_test_vector():
    # RFC 6238 SHA-1 test secret and timestamp 59 seconds (step 1).
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert verify_totp(secret, "287082", now=datetime.fromtimestamp(59, UTC)) == 1


def test_totp_verification_accepts_one_step_skew_only_when_configured():
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    now = datetime.fromtimestamp(60, UTC)
    assert verify_totp(secret, "287082", now=now) == 1
    assert verify_totp(secret, "287082", now=now, allowed_skew_steps=0) is None


def test_totp_rejects_malformed_codes_and_unsafe_skew():
    secret = generate_totp_secret()
    now = datetime.fromtimestamp(90, UTC)
    assert verify_totp(secret, "１２３４５６", now=now) is None
    assert verify_totp(secret, "12345", now=now) is None
    with pytest.raises(ValueError, match="clock skew"):
        verify_totp(secret, "123456", now=now, allowed_skew_steps=2)
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_totp(secret, "123456", now=datetime(2026, 1, 1))


def test_totp_secret_round_trips_through_kms_envelope_encryption():
    kms = FakeKMS()
    secret = generate_totp_secret()
    encrypted = encrypt_totp_secret(
        secret, user_id="user-1", factor_id="factor-1", key_provider=kms
    )
    assert encrypted.ciphertext != secret.encode()
    assert encrypted.nonce and len(encrypted.nonce) == 12
    assert encrypted.wrapped_data_key == kms.wrapped
    assert decrypt_totp_secret(
        encrypted, user_id="user-1", factor_id="factor-1", key_provider=kms
    ) == secret


def test_totp_ciphertext_cannot_be_moved_to_another_factor():
    kms = FakeKMS()
    encrypted = encrypt_totp_secret(
        generate_totp_secret(), user_id="user-1", factor_id="factor-1", key_provider=kms
    )
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_totp_secret(
            encrypted, user_id="user-1", factor_id="factor-2", key_provider=kms
        )


def test_totp_secret_generation_and_uri_are_authenticator_compatible():
    secret = generate_totp_secret()
    uri = totp_provisioning_uri(
        secret, account_name="operator@example.com", issuer="ISP Console"
    )
    assert uri.startswith("otpauth://totp/")
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri



def test_aws_kms_provider_uses_scoped_encryption_context():
    from isp_radius.security.aws_kms import AwsKmsDataKeyProvider

    class FakeKms:
        def generate_data_key(self, **kwargs):
            assert kwargs["KeyId"] == "alias/operator-totp"
            assert kwargs["KeySpec"] == "AES_256"
            assert kwargs["EncryptionContext"]["purpose"] == "operator-totp"
            return {"Plaintext": b"k" * 32, "CiphertextBlob": b"wrapped", "KeyId": "arn:aws:kms:region:acct:key/id"}

        def decrypt(self, **kwargs):
            assert kwargs["KeyId"].endswith("key/id")
            assert kwargs["EncryptionContext"]["application"] == "isp-radius-enterprise"
            return {"Plaintext": b"k" * 32}

    provider = AwsKmsDataKeyProvider(FakeKms(), key_id="alias/operator-totp")
    plaintext, wrapped, version = provider.generate_data_key()
    assert plaintext == b"k" * 32 and wrapped == b"wrapped"
    assert provider.decrypt_data_key(wrapped_key=wrapped, key_version=version) == plaintext
