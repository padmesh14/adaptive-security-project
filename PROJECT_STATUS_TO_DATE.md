# Adaptive Multi-Layer Security — Project Status to Date

Updated: 2026-10-23

## Overview

The project now has a working column-wise Python encryption and storage pipeline, a local-only CIDRegistry integration, managed key wrapping for new records, and a synthetic end-to-end workflow. The latest managed synthetic run was retrieved and decrypted from both local IPFS and Filebase, and its CIDs were registered and verified on a local Hardhat chain.

No secret values, credentials, private keys, plaintext records, or encryption keys are included in this report.

## Existing dataset pipeline

- `main.py --new-run` created a unique encryption manifest for the 1,200-row dataset. The run processed 27 columns: 12 Low, 6 Medium, and 9 High. The manifest was `output/encryption_manifest_run_20261023T084254Z_83aff03c.json`.
- The tier-aware storage command stored the 12 Low-tier encrypted payloads in local SQLite and attempted to dual-pin the 15 Medium/High payloads to local IPFS and Filebase.
- Filebase initially returned `AccessDenied`. A separate tiny synthetic object later passed upload, read-back, and cleanup. No existing dataset payload was used for that credential check.
- A Filebase-only retry command was added to `src/decentralized_storage.py`. It retrieves each existing Medium/High payload by its local IPFS CID, verifies it against the manifest, uploads the same bytes using a unique Filebase object key, and writes to a new manifest. It does not rerun encryption or replace the source manifest.
- The retry completed with **15 uploaded, 12 skipped, and 0 failed**. A later read-only Filebase retrieval and integrity check passed for all 15 entries.
- Low-tier records remain local SQLite records and have no public CID; the blockchain registration flow skips them.

Manifests from this workflow:

- `output/encryption_manifest_tiered_20261023T084401Z_bdfcf592.json` — original tier-aware storage result.
- `output/encryption_manifest_filebase_retry_20261023T094317Z_d54c3ea6.json` — Filebase retry result.
- `output/encryption_manifest_filebase_retry_20261023T094317Z_d54c3ea6_blockchain.json` — separate copy containing local blockchain registration metadata.

## CIDRegistry and local blockchain

- Solidity contract: `blockchain/contracts/CIDRegistry.sol`; the contract source was not changed during the latest integration work.
- The Python integration in `blockchain/integration/` uses a stable HMAC-derived `bytes32` record ID. Raw column labels and dataset values are not sent to the contract.
- All submissions were restricted to the loopback Hardhat node and chain ID `31337`; no public chain or real funds were used.
- The 15 CID-backed entries were registered. A repeat registration reported **15 already registered** and **12 skipped**, with no duplicate transactions.
- Read-only checks confirmed **15/15** successful transaction receipts, matching contract addresses and chain IDs, on-chain CID read-backs, and nonzero timestamps.
- A simulated conflicting CID was rejected before transaction submission. The original on-chain CID and timestamp remained unchanged; the check submitted **0 transactions**.
- The verifier now reports entries with no stored CID as skipped. The existing 15 eligible records verified successfully and the 12 local-only records were skipped.
- Hardhat node state is local and ephemeral. Restarting the node resets its chain state; redeploy and re-register when starting a fresh node.

## Managed key workflow

- `src/key_management.py` defines a replaceable `KeyProvider` interface and a `LocalDevelopmentKeyProvider` for new records.
- Managed encryption wraps the tier encryptors' generated data keys and records wrapped-key metadata. It preserves the existing AES-256-GCM and ECDH/HKDF encryption formats; High-tier records retain both required wrapped keys.
- The local development wrapping key is stored outside the repository with owner-only file permissions. The record-ID HMAC secret was stored by the user in macOS Keychain. Neither secret value was printed or written to a manifest.
- Synthetic tests confirm separate-process recovery for all tiers and fail-closed handling of missing or corrupted wrapped keys, invalid metadata, incorrect keys, and authenticated decryption failures.
- The local file-backed provider is for development. **No production KMS is configured.** The project already has the adapter boundary; choosing and configuring AWS KMS, Google Cloud KMS, or Azure Key Vault remains pending.

## Managed synthetic end-to-end runs

The opt-in workflow in `src/managed_demo.py` creates a new, uniquely named output directory and uses synthetic values only. It reuses the project's classifier, encryptors, storage helpers, managed key provider, retrieval and integrity checks, and local blockchain integration. It does not read or overwrite the existing 27-entry manifests.

Two successful runs were completed:

1. `output/managed_synthetic_demo/192d4153cdd249fdba259336377671e1` — 3 records, one per tier; local IPFS and local chain passed. Filebase credentials were unavailable to that execution session, so Filebase was not exercised in this run.
2. `output/managed_synthetic_demo/90c1fe60484c4c2c8d6904185488c139` — 3 records, one per tier; 3 local CIDs and 3 Filebase CIDs matched. All 3 local-chain receipts, contract addresses, and CID read-backs passed. A separate read-only command retrieved each payload from Filebase, checked integrity, decrypted it with the managed provider, and compared the recovered synthetic bytes to the original. Result: **3/3 passed**.

## Browser application

The repository also contains a separate browser-encrypted web demonstration and API. It has its own recovery-code and file format. It is separate from the Python column pipeline and was not part of the successful managed synthetic run documented above.

## Test and verification results

Relevant Python tests passed:

```sh
.venv/bin/python -m unittest \
  blockchain.integration.test_verify_manifest \
  tests.test_managed_demo \
  tests.test_key_management \
  tests.test_secure_retrieval \
  blockchain.integration.test_register_manifest -v
```

Result: **28 tests passed**.

Hardhat tests passed:

```sh
cd blockchain
npx hardhat test
```

Result: **6 tests passed**. The tests cover deployment, CID storage and retrieval, timestamps and submitters, empty-CID rejection, owner-only writes, overwrite prevention, and separate record IDs.

These are the relevant Python and Hardhat suites; the entire repository test suite was not run as part of the latest validation.

## Existing-data recovery limitation

The existing 27-entry manifests were created by the legacy pipeline and do not contain managed wrapped-key metadata. The original encryption keys for those entries have not been located and validated. Their recoverability is therefore **not established**; this work did not attempt to decrypt or modify them. Managed key recovery has been demonstrated only for new synthetic records.

## Current next milestone

Select and configure an authorized production KMS, then implement and test a provider adapter behind `KeyProvider`. No KMS vendor, key identifier, cloud role, or production authorization is configured yet. Keep the local provider for development demonstrations only.
