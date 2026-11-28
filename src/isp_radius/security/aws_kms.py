"""AWS KMS envelope-encryption adapter for operator TOTP secrets."""
from __future__ import annotations

import os
from typing import Any, ClassVar


class AwsKmsDataKeyProvider:
    """Generate and unwrap AES-256 data keys using an AWS KMS customer key."""

    _ENCRYPTION_CONTEXT: ClassVar[dict[str, str]] = {
        "application": "isp-radius-enterprise",
        "purpose": "operator-totp",
        "schema": "v1",
    }

    def __init__(self, client: Any, *, key_id: str) -> None:
        if not key_id or len(key_id) > 2048:
            raise ValueError("A valid AWS KMS key ID or ARN is required")
        self._client = client
        self._key_id = key_id

    @classmethod
    def from_environment(cls) -> AwsKmsDataKeyProvider:
        key_id = os.environ.get("OPERATOR_TOTP_KMS_KEY_ID", "").strip()
        if not key_id:
            raise RuntimeError("OPERATOR_TOTP_KMS_KEY_ID is not configured")
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("Install the aws-kms optional dependency to enable TOTP") from exc
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        client = boto3.client("kms", region_name=region)
        return cls(client, key_id=key_id)

    def generate_data_key(self) -> tuple[bytes, bytes, str]:
        try:
            response = self._client.generate_data_key(
                KeyId=self._key_id,
                KeySpec="AES_256",
                EncryptionContext=self._ENCRYPTION_CONTEXT,
            )
        except Exception as exc:
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(exc, (BotoCoreError, ClientError)):
                raise RuntimeError("AWS KMS data-key generation failed") from exc
            raise
        plaintext = bytes(response["Plaintext"])
        wrapped = bytes(response["CiphertextBlob"])
        key_version = str(response["KeyId"])
        if len(plaintext) != 32 or not wrapped or not key_version:
            raise RuntimeError("AWS KMS returned invalid data-key material")
        return plaintext, wrapped, key_version

    def decrypt_data_key(self, *, wrapped_key: bytes, key_version: str) -> bytes:
        try:
            response = self._client.decrypt(
                KeyId=key_version,
                CiphertextBlob=wrapped_key,
                EncryptionContext=self._ENCRYPTION_CONTEXT,
            )
        except Exception as exc:
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(exc, (BotoCoreError, ClientError)):
                raise RuntimeError("AWS KMS data-key decryption failed") from exc
            raise
        plaintext = bytes(response["Plaintext"])
        if len(plaintext) != 32:
            raise RuntimeError("AWS KMS returned an invalid AES-256 data key")
        return plaintext
