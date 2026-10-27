# Secure encrypted data retrieval and decryption

## What changed

`src/secure_retrieval.py` retrieves an existing payload by its recorded CID (local IPFS first, with Filebase fallback in `auto` mode), validates its tier/scheme/ciphertext metadata against the manifest, checks the existing BLAKE2b-256 ciphertext digest, and only then performs tier-specific AES-256-GCM decryption. AES-GCM tag failure is an error; plaintext is returned only after all checks pass. The digest is used for integrity comparison, not as proof of authenticity. GCM authentication supplies the ciphertext authenticity check.

The module supports:

- **Low:** one AES-256-GCM key (`aes_key_b64`).
- **Medium:** one AES-256-GCM key previously derived through ECDH, or the original recipient private key and sender public point to reproduce the existing HKDF-SHA256 derivation.
- **High:** the existing outer AES-GCM layer (`layer2_key_b64`) followed by its inner layer (`layer1_key_b64`). Both keys are the independent ECDH-derived AES keys used by the existing encryptor.

It does not change the encryption format, pipeline, stored payloads, manifest, blockchain contract, or blockchain registration.

## Existing key-management limitation

The checked-in encryption manifests contain the ciphertext, tier, scheme, layers, and BLAKE2 digest, but no decryption keys. `encrypt_for_tier` keeps key material only in an in-memory `_debug_keys` field and `to_public_dict()` deliberately excludes it. In addition, the Medium manifest does not retain the public point required to rederive its ECDH key; High does not retain either ECDH exchange's private/public key material. Therefore the existing stored entries cannot be decrypted from the current manifest and repository alone. This implementation does not guess keys or add keys to manifests. To decrypt an existing entry, supply the original keys through an approved external key-management process. If those keys were not retained elsewhere, those ciphertexts are not recoverable by this project.

The key bundle is a user-managed JSON file outside source control. It contains keys encoded with Base64 and selected by zero-based manifest index:

```json
{
  "entries": {
    "0": {"aes_key_b64": "<base64 32-byte Low key>"},
    "1": {
      "recipient_private_key_pem": "<PEM private key>",
      "sender_public_key_hex": "<uncompressed P-256 public point hex>"
    },
    "2": {
      "layer1_key_b64": "<base64 32-byte High inner key>",
      "layer2_key_b64": "<base64 32-byte High outer key>"
    }
  }
}
```

Use restrictive filesystem permissions and an approved secrets/key manager for this file. Do not put real values in the example, manifest, logs, or Git. The root `.gitignore` excludes environment files, virtual environments, Python caches, common private-key formats, and credential files while allowing `.env.example`.

## Demonstration

With the project dependencies installed, the local IPFS daemon running (or Filebase credentials available to the process), the existing CID manifest present, and a valid external key bundle containing the retained key for the selected entry:

```sh
.venv/bin/python -m src.secure_retrieval --manifest output/encryption_manifest_with_cids.json --index 0 --keys-file /secure/path/retrieval-keys.json --provider auto
```

Use `--provider ipfs` or `--provider filebase` to select one provider explicitly. The command reports only the entry index, sensitivity tier, and success/failure; it never prints the decrypted content, column label, CID, or keys. A command against the current repository's manifest will fail closed if no external key is supplied. **A successful retrieval/decryption demonstration against one of the existing real entries cannot be claimed until its original key material is available.** The automated tests use only synthetic plaintext and temporary in-memory test keys.

## Tests

```sh
.venv/bin/python -m unittest tests.test_secure_retrieval -v
.venv/bin/python -m unittest tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
(cd blockchain && npx hardhat test)
```

The test suite covers synthetic successful round trips for all three tiers, ECDH key re-derivation for Medium, local-IPFS retrieval by the existing CID, missing payload, corrupted payload, wrong key/authentication-tag failure, missing key, and manifest digest mismatch.

## Validation performed for this change

- `.venv/bin/python -m unittest tests.test_secure_retrieval blockchain.integration.test_register_manifest -v`: **13 tests passed** (8 retrieval/decryption tests and 5 existing local blockchain integration tests).
- From `blockchain/`, `npx hardhat test`: **4 Solidity tests passed**.
- Retrieval tests used synthetic ciphertext and temporary in-memory keys. No payload was uploaded and the existing 27-entry manifest was not changed.
- The retrieval command was not run against real stored content because the repository does not retain the corresponding keys, and no external key bundle was provided. End-to-end decryption of an existing CID remains unverified until original keys are retrieved from the project's key custodian/KMS.
