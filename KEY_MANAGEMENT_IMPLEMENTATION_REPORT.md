# Key Management Implementation Report

## Changes made

- Added `src/key_management.py` with a `KeyProvider` abstraction and an opt-in `LocalDevelopmentKeyProvider`.
- The local provider wraps the existing tier encryptors' AES data keys with AES-256-GCM. Each wrapped key is bound to an opaque record reference, sensitivity tier, key slot, provider, algorithm, format version, and key ID.
- Added managed encryption and retrieval/decryption functions. Low and Medium records retain one wrapped AES key; High records retain separately wrapped keys for both AES-GCM layers.
- Added an optional `key_provider` parameter to `encrypt_dataset_by_column`. Existing calls without a provider retain the existing behavior and output format. Managed calls add wrapped-key metadata to newly created manifest entries.
- Added synthetic tests, including encryption and subsequent retrieval/decryption in a separate Python process.
- Added `KEY_MANAGEMENT.md` with setup, usage, backup and recovery, rotation, and KMS replacement guidance. Linked it from the project `README.md`.

## Tests

Python command:

```sh
.venv/bin/python -m unittest tests.test_key_management tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
```

Result: **21 tests passed**: 8 managed-key tests, 8 secure-retrieval tests, and 5 existing blockchain integration tests.

Hardhat command, run from `blockchain/`:

```sh
npx hardhat test
```

Result: **4 tests passed**.

The managed-key tests use temporary keys and synthetic payloads. The cross-process test encrypts and writes test records in one process, then loads, verifies, unwraps, and decrypts them in another.

## Existing data and limitations

- The existing 27-entry manifests still have no managed key metadata. No existing payload or manifest was migrated, overwritten, or decrypted.
- No production KMS adapter is included. The local provider stores its KEK in a local owner-only file and does not provide hardware protection, central authorization, managed backups, or production recovery guarantees.
- Bulk rewrapping/rotation is documented but not implemented. Retain each old provider key until every record that references it has been rewrapped and verified or retired.
- No key was initialized in the user's home directory during implementation. No real payload was uploaded, and no blockchain transaction was made.

## Reproduction

Initialize the local development key once, if it does not already exist. Initialization refuses to overwrite an existing key:

```sh
.venv/bin/python -m src.key_management init
```

Run the Python and Hardhat test suites:

```sh
.venv/bin/python -m unittest tests.test_key_management tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
(cd blockchain && npx hardhat test)
```

For managed encryption, load `LocalDevelopmentKeyProvider` and pass it explicitly as `key_provider` to `encrypt_dataset_by_column(df)`. Write the result to a new manifest path; details and a retrieval example are in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).
