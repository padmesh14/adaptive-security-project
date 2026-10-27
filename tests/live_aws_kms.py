"""Explicit opt-in live AWS KMS check; not collected in the default pytest run.

Run only after reviewing current KMS request charges and obtaining explicit
authorization to use the configured AWS account/key.
"""

import os

import pytest

from src.aws_kms_key_provider import AWSKMSKeyProvider


def test_live_kms_synthetic_wrap_unwrap():
    if os.environ.get("RUN_LIVE_AWS_KMS_TESTS") != "1":
        pytest.skip("set RUN_LIVE_AWS_KMS_TESTS=1 after authorizing a live KMS request")
    key_id = os.environ.get("AWS_KMS_KEY_ID", "")
    region = os.environ.get("AWS_REGION", "")
    if not key_id or not region:
        pytest.skip("AWS_KMS_KEY_ID and AWS_REGION are required for the opted-in live test")
    provider = AWSKMSKeyProvider(key_id, region)
    key = os.urandom(32)
    context = b"adaptive-security-live-test:synthetic-only:v1"
    wrapped = provider.wrap_key(key, context=context)
    assert provider.unwrap_key(wrapped, context=context) == key
