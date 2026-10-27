import base64
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from botocore.exceptions import ClientError, ReadTimeoutError

from src.aws_kms_key_provider import AWSKMSKeyProvider
from src.key_management import KeyManagementError


def client_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": "do not expose provider message"}}, operation)


class AWSKMSProviderTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.encrypt.return_value = {"CiphertextBlob": b"opaque-kms-ciphertext"}
        self.client.decrypt.return_value = {"Plaintext": b"d" * 32}
        self.provider = AWSKMSKeyProvider(
            "arn:aws:kms:us-east-1:111122223333:key/test-key",
            "us-east-1",
            client=self.client,
        )

    def test_wrap_unwrap_uses_kms_context_and_never_serializes_plaintext_key(self):
        context = b"synthetic-record-context"
        wrapped = self.provider.wrap_key(b"d" * 32, context=context)
        self.assertEqual(base64.b64decode(wrapped), b"opaque-kms-ciphertext")
        self.assertNotIn(base64.b64encode(b"d" * 32).decode(), wrapped)
        self.assertEqual(self.client.encrypt.call_args.kwargs["KeyId"], self.provider.key_id)
        self.assertEqual(self.client.encrypt.call_args.kwargs["Plaintext"], b"d" * 32)
        kms_context = self.client.encrypt.call_args.kwargs["EncryptionContext"]
        self.assertEqual(kms_context["purpose"], "adaptive-security-data-key-wrap-v1")
        self.assertEqual(len(kms_context["context-sha256"]), 64)

        restored = self.provider.unwrap_key(wrapped, context=context)
        self.assertEqual(restored, b"d" * 32)
        self.client.decrypt.assert_called_once_with(
            CiphertextBlob=b"opaque-kms-ciphertext",
            EncryptionContext=kms_context,
        )

    def test_record_or_tier_context_changes_the_kms_encryption_context(self):
        self.provider.wrap_key(b"d" * 32, context=b"record-a:High")
        first = self.client.encrypt.call_args.kwargs["EncryptionContext"]
        self.provider.wrap_key(b"d" * 32, context=b"record-b:High")
        second = self.client.encrypt.call_args.kwargs["EncryptionContext"]
        self.assertNotEqual(first, second)

    def test_rejects_invalid_configuration_and_key_material(self):
        with self.assertRaises(KeyManagementError):
            AWSKMSKeyProvider("", "us-east-1", client=self.client)
        with self.assertRaises(KeyManagementError):
            AWSKMSKeyProvider("alias/test", "auto", client=self.client)
        with self.assertRaises(KeyManagementError):
            self.provider.wrap_key(b"too-short", context=b"ctx")
        with self.assertRaises(KeyManagementError):
            self.provider.unwrap_key("not-base64!", context=b"ctx")

    def test_client_uses_explicit_region_and_sdk_credential_chain_without_static_secrets(self):
        with patch("src.aws_kms_key_provider.boto3.client", return_value=self.client) as factory:
            AWSKMSKeyProvider("alias/synthetic", "us-west-2")
        kwargs = factory.call_args.kwargs
        self.assertEqual(factory.call_args.args, ("kms",))
        self.assertEqual(kwargs["region_name"], "us-west-2")
        self.assertNotIn("aws_access_key_id", kwargs)
        self.assertNotIn("aws_secret_access_key", kwargs)
        self.assertEqual(kwargs["config"].connect_timeout, 3)
        self.assertEqual(kwargs["config"].read_timeout, 10)

    def test_maps_permission_throttle_invalid_ciphertext_and_missing_key_errors(self):
        cases = [
            ("AccessDeniedException", "AWS KMS access was denied", "encrypt"),
            ("ThrottlingException", "AWS KMS request was throttled", "encrypt"),
            ("InvalidCiphertextException", "AWS KMS rejected the wrapped key or encryption context", "decrypt"),
            ("NotFoundException", "AWS KMS key or wrapped key was not found", "encrypt"),
        ]
        for code, expected_message, method in cases:
            with self.subTest(code=code):
                getattr(self.client, method).side_effect = client_error(code, method)
                with self.assertRaisesRegex(KeyManagementError, expected_message) as raised:
                    if method == "encrypt":
                        self.provider.wrap_key(b"d" * 32, context=b"ctx")
                    else:
                        self.provider.unwrap_key(base64.b64encode(b"wrapped").decode(), context=b"ctx")
                self.assertNotIn("do not expose", str(raised.exception))
                getattr(self.client, method).side_effect = None

    def test_maps_network_timeouts_without_exposing_exception_details(self):
        self.client.encrypt.side_effect = ReadTimeoutError(endpoint_url="https://redacted.invalid")
        with self.assertRaisesRegex(KeyManagementError, "AWS KMS service is unavailable"):
            self.provider.wrap_key(b"d" * 32, context=b"ctx")

    def test_rejects_invalid_kms_response(self):
        self.client.encrypt.return_value = {"CiphertextBlob": "not-bytes"}
        with self.assertRaisesRegex(KeyManagementError, "invalid wrapped key"):
            self.provider.wrap_key(b"d" * 32, context=b"ctx")
        self.client.decrypt.return_value = {"Plaintext": b"short"}
        with self.assertRaisesRegex(KeyManagementError, "invalid data-key material"):
            self.provider.unwrap_key(base64.b64encode(b"wrapped").decode(), context=b"ctx")


if __name__ == "__main__":
    unittest.main()
