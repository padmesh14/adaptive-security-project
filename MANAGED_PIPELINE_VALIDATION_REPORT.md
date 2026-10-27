# Managed Pipeline Validation Report

## Implemented workflow

Added `src/managed_demo.py`, an explicit synthetic-only orchestration command.
It creates an isolated UUID directory under
`output/managed_synthetic_demo/`, obtains or safely initializes the local
development key provider, classifies synthetic columns, encrypts through the
existing managed column pipeline, stores the existing encryption object via
`dual_pin`, records available CIDs, retrieves through the existing managed
retrieval API, verifies integrity/authentication, and compares recovered bytes
with the synthetic source. Blockchain registration is optional. When enabled,
the workflow uses the existing local connector/deployment/registration code
and keeps deployment metadata inside the run directory.

README commands and limitations are documented in [MANAGED_SYNTHETIC_DEMO.md](MANAGED_SYNTHETIC_DEMO.md).

## Safety and architectural findings

- The workflow creates new per-run output paths and never opens either legacy
  manifest or the dataset.
- Storage keys use random run-specific synthetic column names to avoid
  replacing existing Filebase object keys. Existing `dual_pin` is reused; it
  attempts both configured providers, but unit tests mock this boundary.
- The blockchain branch requires the existing connector's loopback HTTP
  endpoint and chain ID `31337`; CID registration sends no key material.
- `main.py` remains in its current default unmanaged mode. The managed demo is
  a separate opt-in path.
- The local development KEK is a plaintext file outside the repository with
  owner-only permissions. It is not a production KMS and must be backed up
  securely before relying on stored records.
- The legacy 27-entry manifests remain unchanged and have no managed-key
  metadata. They were not decrypted or migrated.

## Test results

Python command:

```sh
.venv/bin/python -m unittest tests.test_managed_demo tests.test_key_management tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
```

Result: **27 tests passed**: 6 orchestration tests, 8 managed-key tests, 8
secure-retrieval tests, and 5 existing blockchain integration tests. These
tests use synthetic values and temporary keys; storage and chain boundaries
are mocked, so they require neither Filebase credentials nor a live Hardhat
node.

Hardhat command, run from `blockchain/`:

```sh
npx hardhat test
```

Result: **4 tests passed**.

The existing artifact check found 27 entries in each legacy manifest and zero
`key_management` fields in either. The new demo output directory was not
created by the tests.

## Live end-to-end status

**A live end-to-end demonstration was not run.** Local IPFS was listening, but
no local development KEK existed and no Hardhat node was listening. Running
the demo would initialize a persistent KEK and pin new synthetic content;
those side effects were not performed during this validation. Filebase
credentials were not configured. Therefore storage retrieval and actual chain
registration have not been demonstrated together by this run.

## Reproduction commands

Install dependencies, start IPFS in another terminal, and run without the
optional chain stage:

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -r blockchain/integration/requirements.txt
ipfs daemon
.venv/bin/python -m src.managed_demo
```

The first demo run initializes the local key file if needed. Back it up using
an approved encrypted backup method before relying on demo output for future
decryption.

For local chain registration, start a Hardhat node in another terminal:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

Then, from the repository root, set/retain the local record-ID secret and run:

```sh
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/python -m src.managed_demo --with-blockchain
```

The demo deploys CIDRegistry only to the local node and records its deployment
inside that run's new output directory. It does not overwrite the normal
blockchain deployment file.
