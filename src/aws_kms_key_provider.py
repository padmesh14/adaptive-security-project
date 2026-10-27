"""Optional AWS KMS envelope wrapper for 256-bit data-encryption keys.

This adapter wraps the existing tier-generated AES keys with AWS KMS Encrypt.
The AWS SDK default credential chain is used; credentials are never accepted as
constructor arguments or persisted in manifests. No cloud resource is created.
"""

from __future__ import annotations

import base64
import hashlib
import re

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from src.key_management import KeyManagementError, KeyProvider


AWS_KMS_PROVIDER_ID = "aws-kms"
AWS_KMS_WRAPPING_ALGORITHM = "AWS-KMS-Encrypt-SYMMETRIC-DEFAULT"
_MAX_CIPHERTEXT_BYTES = 8192
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$")


def _context_for_kms(context: bytes) -> dict[str, str]:
    if not isinstance(context, bytes) or not context or len(context) > 16_384:
        raise KeyManagementError("AWS KMS encryption context is invalid")
    return {
        "purpose": "adaptive-security-data-key-wrap-v1",
        "context-sha256": hashlib.sha256(context).hexdigest(),
    }


class AWSKMSKeyProvider(KeyProvider):
    """KeyProvider backed by an explicitly configured symmetric AWS KMS key.

    The KMS ciphertext blob is stored as base64 in key metadata. Decryption
    omits KeyId because KMS ciphertext identifies its source key; KMS still
    enforces the same encryption context. This allows KMS-managed key rotation
    while the historical key remains enabled and authorized.
    """

    provider_id = AWS_KMS_PROVIDER_ID
    wrapping_algorithm = AWS_KMS_WRAPPING_ALGORITHM

    def __init__(self, key_id: str, region: str, *, client=None):
        if not isinstance(key_id, str) or not key_id.strip() or any(ch.isspace() for ch in key_id):
            raise KeyManagementError("AWS KMS key ID or ARN must be explicitly configured")
        if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
            raise KeyManagementError("AWS KMS region must be explicitly configured")
        self.key_id = key_id.strip()
        self.region = region
        if client is None:
            try:
                # Use the AWS credential provider chain (environment, profile,
                # web identity, instance/task role, etc.). No static secrets.
                client = boto3.client(
                    "kms",
                    region_name=region,
                    config=Config(
                        connect_timeout=3,
                        read_timeout=10,
                        retries={"mode": "standard", "max_attempts": 3},
                    ),
                )
            except (BotoCoreError, ValueError) as exc:
                raise KeyManagementError("AWS KMS client configuration failed") from None
        self._client = client

    @staticmethod
    def _service_failure(exc: ClientError) -> KeyManagementError:
        code = (exc.response.get("Error") or {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "NotAuthorizedException"}:
            message = "AWS KMS access was denied"
        elif code in {"Throttling", "ThrottlingException", "TooManyRequestsException"}:
            message = "AWS KMS request was throttled"
        elif code == "InvalidCiphertextException":
            message = "AWS KMS rejected the wrapped key or encryption context"
        elif code in {"NotFoundException", "ResourceNotFoundException", "IncorrectKeyException"}:
            message = "AWS KMS key or wrapped key was not found"
        elif code == "ValidationException":
            message = "AWS KMS rejected the request configuration"
        else:
            message = "AWS KMS request failed"
        return KeyManagementError(message)

    def wrap_key(self, data_key: bytes, *, context: bytes) -> str:
        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise KeyManagementError("only 32-byte AES data keys can be wrapped")
        kms_context = _context_for_kms(context)
        try:
            response = self._client.encrypt(
                KeyId=self.key_id,
                Plaintext=data_key,
                EncryptionContext=kms_context,
            )
        except ClientError as exc:
            raise self._service_failure(exc) from None
        except BotoCoreError:
            raise KeyManagementError("AWS KMS service is unavailable") from None
        ciphertext = response.get("CiphertextBlob") if isinstance(response, dict) else None
        if not isinstance(ciphertext, bytes) or not ciphertext or len(ciphertext) > _MAX_CIPHERTEXT_BYTES:
            raise KeyManagementError("AWS KMS returned an invalid wrapped key")
        return base64.b64encode(ciphertext).decode("ascii")

    def unwrap_key(self, wrapped_key: str, *, context: bytes) -> bytes:
        if not isinstance(wrapped_key, str):
            raise KeyManagementError("AWS KMS wrapped-key encoding is invalid")
        try:
            ciphertext = base64.b64decode(wrapped_key, validate=True)
        except (ValueError, TypeError):
            raise KeyManagementError("AWS KMS wrapped-key encoding is invalid") from None
        if not ciphertext or len(ciphertext) > _MAX_CIPHERTEXT_BYTES:
            raise KeyManagementError("AWS KMS wrapped-key size is invalid")
        kms_context = _context_for_kms(context)
        try:
            # CiphertextBlob contains its originating KMS key identifier.
            response = self._client.decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext=kms_context,
            )
        except ClientError as exc:
            raise self._service_failure(exc) from None
        except BotoCoreError:
            raise KeyManagementError("AWS KMS service is unavailable") from None
        plaintext = response.get("Plaintext") if isinstance(response, dict) else None
        if not isinstance(plaintext, bytes) or len(plaintext) != 32:
            raise KeyManagementError("AWS KMS returned invalid data-key material")
        return plaintext
