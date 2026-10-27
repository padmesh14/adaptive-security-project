# Local Blockchain Integration Validation

## Validation results

The manifest registration command and verifier used the same deterministic ID derivation: HMAC-SHA256 over the project namespace and manifest column label, keyed by `CID_REGISTRY_RECORD_ID_SECRET`. A single secret was generated in memory and reused throughout the run; it was not printed or saved.

All 27 manifest entries had eligible stored CIDs.

| Check | Result |
|---|---:|
| First registration pass | 27 registered, 0 skipped, 0 failures |
| First verification | 27 verified |
| Repeat registration | 0 new registrations, 27 matching records skipped, 0 failures |
| Live conflict probe | 1 conflicting record rejected |
| Final verification | 27 verified |
| Existing storage fields preserved | Yes |

The conflict probe did not modify the registered record. Registration metadata was added for all 27 entries in `output/encryption_manifest_with_cids.json`; the existing storage fields were compared before and after and remained unchanged. The local Hardhat node used chain ID `31337` and has since been stopped.

The existing Hardhat suite passed **4 tests**, and the offline Python registration suite passed **5 tests**. No encryption, classification, storage, or Solidity code was changed for this review.

## Secret and Git audit

The source and configuration scan found no literal credential or private-key values and no secret files. Manifest 64-hex values are integrity hashes, record ID digests, and transaction hashes; no secret fields were added. Hardhat account and private-key startup lines were suppressed.

The workspace has no Git metadata, so commit status could not be checked. There is no project-root `.gitignore`; `blockchain/.gitignore` excludes environment files within `blockchain/` only. The recommended minimal fix is a root `.gitignore` covering `.env` files, virtual environments, and private-key/credential files, while allowing `.env.example`.

## Reproduce from a clean local session

Use the existing manifest and stored CIDs. Do not rerun encryption or storage for this demonstration.

Install the integration dependency if needed:

```sh
python3 -m pip install -r blockchain/integration/requirements.txt
```

In one terminal, start the local Hardhat node:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

In another terminal at the repository root, deploy locally, set one HMAC secret for the session, and run registration, verification, and the repeat pass:

```sh
python3 -m blockchain.integration.deploy_local
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m blockchain.integration.register_manifest
python3 -m blockchain.integration.verify_manifest
python3 -m blockchain.integration.register_manifest
python3 -m blockchain.integration.verify_manifest
```

Use the same secret and namespace for registration and verification. The command above creates a fresh secret for a new session; securely retain and re-enter it if the same record IDs are needed across sessions. The secret is not written to the manifest.

Run the tests with:

```sh
python3 -m unittest blockchain.integration.test_register_manifest -v
cd blockchain
npx hardhat test
```

All blockchain calls are restricted to loopback RPC and chain ID `31337`; no public blockchain is used.
