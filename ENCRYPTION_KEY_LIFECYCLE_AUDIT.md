# Encryption Key Lifecycle Audit

## Scope and outcome

The audit inspected the encryption implementation, column pipeline, retrieval/decryption code, manifests, project configuration, and available project files for key-manager or backup evidence. No encryption code or manifest was changed, and no secret values were printed.

**Finding:** No legitimate recovery mechanism for the existing encryption keys was found in the inspected project. None of the 27 existing entries is currently validated as recoverable.

## Key lifecycle findings

- **Low:** `encrypt_low()` generates a random AES-256 key and uses it for AES-GCM. The key is returned in the in-memory `EncryptionResult._debug_keys` field.
- **Medium:** `encrypt_medium()` creates sender and recipient P-256 key pairs, derives an AES key through ECDH and HKDF-SHA256, then encrypts with AES-GCM. The runtime debug field holds the derived key, recipient private key, and sender public key. The manifest omits these values.
- **High:** `encrypt_high()` derives two independent ECDH/HKDF AES keys and applies two AES-GCM layers. The runtime debug field holds the two derived AES keys; the manifest omits them and the ECDH key material.
- `EncryptionResult.to_public_dict()` deliberately excludes `_debug_keys`. The pipeline writes only this public dictionary into each manifest entry, then discards its reference to the result as it continues processing.
- The project manifests contain 27 entries (12 Low, 6 Medium, 9 High) with ciphertext and integrity metadata, but no key fields. No project key-manager configuration, key backup, or candidate key/backup files were found. No key-related environment variable names were configured in the inspected process environment.

Python does not explicitly zeroize key material when object references are released. No active project encryption run or configured key manager was evidenced during this audit. A past process's memory cannot be checked retrospectively. The workspace has no `.git` metadata, so Git history and tracked-file status could not be audited.

## Existing data recoverability

No original decryption keys were located or validated. The current project artifacts alone therefore do not establish that any existing entry is recoverable:

| Tier | Required original material | Audit status |
|---|---|---|
| Low | Random AES-256 key | Not found |
| Medium | ECDH-derived AES key, or matching recipient private key and sender public key | Not found |
| High | Both independent AES layer keys | Not found |

The BLAKE2 digest and blockchain CID metadata do not recover encryption keys. No decryption attempt was made against real entries. Treat the existing data as unrecoverable unless an authorized key custodian locates the original material and validates it against ciphertext.

## Synthetic test reproducibility

Ran:

```sh
.venv/bin/python -m unittest tests.test_secure_retrieval -v
```

Result: **8 tests passed.** Successful round trips create fresh encryption keys and synthetic plaintext in memory. They do not use the existing dataset, existing manifests, or the original encryption keys.

## Recommended design for future runs

Adopt managed envelope encryption. Generate data-encryption keys, wrap them with an authorized KMS or recipient key, and retain an opaque key reference and algorithm metadata with each record. Keep the wrapped key material in an approved key store, with access controls, backups, recovery procedures, and rotation. For High tier, preserve separately recoverable references for both layer keys. Test decryption after the encryption process has exited.

Do not rely on the current in-memory `_debug_keys` field or the retrieval module's plaintext key-bundle format as production key management. Do not put plaintext secrets in manifests, source control, or logs.

## Next steps for existing entries

Ask the authorized operator to check the configured KMS, secure backups, or original runtime key exports. If original keys are found, validate them with authenticated decryption before declaring any entry recoverable. If they cannot be located, preserve the ciphertext and report its recovery status honestly; do not regenerate keys and associate them with old ciphertext.
