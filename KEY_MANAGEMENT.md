# Managed encryption keys for future records

## Scope and legacy data

This is an opt-in envelope-key workflow for **new** records. It calls the
existing Low, Medium, and High encryptors unchanged, then wraps the generated
AES data keys. Low and Medium each retain one wrapped key; High retains two
independently wrapped keys for its two AES-GCM layers. The ciphertext format
and `encryption` object remain the same.

The existing 27-entry manifests and ciphertexts are not migrated or changed.
Their original keys were not found, so this workflow does not make those
entries decryptable.

## Development provider and security limits

No KMS was configured in this project. `LocalDevelopmentKeyProvider` is a
replaceable provider implementing the `KeyProvider` interface. It wraps each
32-byte data key with AES-256-GCM under a random local key-encryption key
(KEK). Wrapping uses a fresh nonce and authenticated context binding the
opaque record reference, tier, key slot, provider ID, wrapping algorithm,
format version, and key ID. The manifest stores the wrapped key bytes in
Base64 plus that minimum metadata; it does not store plaintext data keys.

By default the KEK is created at
`~/.adaptive-security/dev-kek-v1.key`, with owner-only file permissions
(`0600`) and an owner-only parent directory (`0700`). Initialization refuses to overwrite
an existing key. `.key` files are excluded by the root `.gitignore`.

This provider is **development-only**, not production-grade key management.
The KEK is a plaintext file on the local host; file permissions do not protect
it from host compromise, malicious administrators, insecure backups, or loss
of the machine. There is no central authorization, HSM protection, audit
service, or automatic recovery. Use encrypted disks and carefully controlled
access even for local development. Never log or print the KEK or unwrapped
data keys.

## Initialize once

From the repository root, using the project virtual environment:

```sh
.venv/bin/python -m src.key_management init
```

To select a different location, use `--key-file /secure/local/path/dev-kek-v1.key`.
Keep the same key file for every future decryption of entries wrapped by it.
Do not initialize a replacement at the same path as a way to recover data;
the new key cannot unwrap existing wrapped keys.

## Encrypt new records with managed keys

The existing `encrypt_dataset_by_column(df)` behavior is unchanged. Supply a
provider explicitly to opt in for a new dataset run:

```python
import json
from pathlib import Path

from src.encryption_pipeline import encrypt_dataset_by_column
from src.key_management import LocalDevelopmentKeyProvider

provider = LocalDevelopmentKeyProvider()
result = encrypt_dataset_by_column(df, key_provider=provider)
new_manifest = Path("output/new_managed_manifest.json")
new_manifest.write_text(json.dumps(result["manifest"], indent=2) + "\n")
```

Choose a new output path. This call does not write to or overwrite either
existing manifest. Each managed entry has the usual `encryption` data plus a
random opaque `record_ref` and `key_management` object. Do not substitute a
personal identifier or raw column label for `record_ref`.

To pin a newly created manifest through the existing storage implementation,
use separate input and output paths:

```python
from src.decentralized_storage import pin_manifest

pin_manifest(
    "output/new_managed_manifest.json",
    "output/new_managed_manifest_with_cids.json",
)
```

The storage provider continues to upload only the `encryption` object. The
wrapped keys remain in the manifest and are not included in the payload or
sent to the CIDRegistry. The existing local blockchain registration command,
when used for a new manifest, registers only CIDs and the existing record-ID
digest metadata.

## Retrieve and decrypt

Load the same development KEK and call the managed retrieval API. The API
retrieves bytes using the entry's existing CID, compares fetched ciphertext
and metadata with the manifest, verifies the BLAKE2 digest, authenticates and
unwraps the data keys, then performs the existing AES-GCM decryption. High
entries must successfully authenticate both layers.

```python
from src.key_management import (
    LocalDevelopmentKeyProvider,
    retrieve_and_decrypt_managed,
)

provider = LocalDevelopmentKeyProvider()
plaintext_bytes = retrieve_and_decrypt_managed(entry, provider, "auto")
# Handle plaintext only in the authorized caller; do not print or log it.
```

`auto` prefers local IPFS and falls back to Filebase where configured. Use
`"ipfs"` or `"filebase"` to choose a provider explicitly. Integrity hashes
detect mismatches but do not establish authenticity by themselves; AES-GCM
authentication remains mandatory. Missing/wrong key IDs, missing wrapped
slots, invalid metadata, corrupted wrapped keys, and GCM tag failures stop
decryption.

## Backup and recovery

1. Treat the local KEK as the recovery root for every entry that references
   its `key_id`. Make backups only in an approved encrypted backup system or
   encrypted removable storage protected by a separate recovery credential.
   Never make an unencrypted copy or put a backup under the project tree.
2. Restrict access to both the live key and backup. Record the non-secret key
   ID and owner/custodian in the operational inventory; do not record key
   bytes.
3. Periodically perform a restore drill into a protected location, set its
   permissions to `0600`, load it with `LocalDevelopmentKeyProvider`, and
   decrypt a synthetic test record. Do not use a real data record for routine
   drills.
4. If the KEK is lost and no valid backup exists, wrapped keys under that KEK
   cannot be recovered. Do not regenerate the key and claim recovery.

## Rotation

Newly initialized KEKs have different key IDs and can protect new records.
Existing records remain associated with their original key IDs. Keep each
old KEK available under the backup and access policy until every referenced
wrapped key has either been securely rewrapped and verified under a new KEK
or its data has been retired. Rewrapping should unwrap each data key with the
old provider and wrap it with the new provider, preserving the data
ciphertext; it should be a separately reviewed, backed-up, auditable
operation. This project does not yet implement bulk key rotation.

## Replacing the development provider with an authorized KMS

Implement a `KeyProvider` subclass with stable `provider_id`, `key_id`, and
`wrapping_algorithm` metadata. Implement `wrap_key(data_key, context)` using
the KMS encrypt/wrap API and `unwrap_key(wrapped_key, context)` using its
decrypt/unwrap API. Bind the supplied context to the KMS encryption context
or equivalent authenticated metadata. Use workload identity and least
privilege policies; do not embed cloud credentials or private keys in this
repository. Ensure the KMS key is backed up according to the provider's
recovery guarantees, then test decrypting entries across a fresh process
before switching production writes. Keep provider and algorithm versions
backward-compatible for old manifest entries.

The project now includes `AWSKMSKeyProvider` in `src/aws_kms_key_provider.py`.
It implements the same interface with AWS KMS `Encrypt`/`Decrypt` calls for
the existing 32-byte data keys. KMS encryption context contains a purpose
label and a SHA-256 digest of the complete record/tier/key-slot context; raw
record references and tiers are not sent as context fields. The returned KMS
ciphertext blob is stored Base64-encoded in the manifest. Decryption relies
on the key identifier embedded in that blob and must present the same
encryption context.

The adapter requires an explicit symmetric KMS key identifier and AWS region.
It uses `boto3`'s default credential provider chain and does not accept or
persist static cloud credentials. SDK connection/read timeouts and standard
retries are configured. Permission, throttle, invalid-ciphertext, missing-key,
network, and malformed-response failures are converted to safe errors. AWS
selection fails closed; it never falls back to the local provider.

### Optional AWS KMS setup

Create or select a symmetric encryption KMS key in your AWS account using your
normal approved AWS process. This application does not create or modify cloud
resources. Grant the calling IAM identity only the required `kms:Encrypt` and
`kms:Decrypt` permissions on the selected key. Use an IAM role, web identity,
or another AWS credential-chain mechanism; do not put access keys in source,
manifests, or command history. Review AWS KMS request pricing and your account
policy before the first API operation; every record and every High-tier layer
uses KMS wrapping calls.

Set the non-secret key reference and region in the shell, then explicitly
select managed AWS KMS mode for a new, unique manifest:

```sh
export AWS_KMS_KEY_ID='arn:aws:kms:REGION:ACCOUNT:key/KEY-ID'
export AWS_REGION='us-east-1'
.venv/bin/python main.py --new-run --managed-key-provider aws-kms
```

Replace the example ARN and region with your authorized key's values. The
adapter does not print these settings. `--new-run` is required for managed
mode so the default legacy manifest is not overwritten. Existing legacy
ciphertexts and manifests are not migrated.

The live check below calls KMS Encrypt and Decrypt on a synthetic 32-byte key
and may incur charges. It is not run by the default test suite; run it only
after explicit account authorization and pricing review:

```sh
RUN_LIVE_AWS_KMS_TESTS=1 \
AWS_KMS_KEY_ID='arn:aws:kms:REGION:ACCOUNT:key/KEY-ID' \
AWS_REGION='us-east-1' \
.venv/bin/python -m pytest -q tests/live_aws_kms.py
```

Mocked adapter tests run offline. No live AWS KMS operation has been performed
as part of this implementation. The adapter's code path and mocked behavior
do not constitute a live integration validation or production readiness
assessment. AWS key policy, IAM role assignment, regional availability,
rotation, account recovery, and audit operations remain the operator's
responsibility.

## Reproduction and tests

Initialize the local provider (only once per key path), then run the
synthetic separate-process and negative tests:

```sh
.venv/bin/python -m src.key_management init
.venv/bin/python -m unittest tests.test_key_management tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
.venv/bin/python -m pytest -q tests/test_aws_kms_key_provider.py tests/test_main_managed.py
(cd blockchain && npx hardhat test)
```

The first command refuses to overwrite an existing key. The tests create
temporary synthetic keys and payloads and do not access, modify, or attempt to
decrypt the existing 27 entries.
