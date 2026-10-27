# Managed synthetic pipeline demonstration

## Workflow

`src.managed_demo` is a separate, explicit synthetic-data workflow. It creates
three synthetic columns chosen to exercise Low, Medium, and High sensitivity,
then uses the existing `classify_columns` path through
`encrypt_dataset_by_column(..., key_provider=...)`. Existing tier encryptors
are unchanged. Managed key wrapping is performed by
`LocalDevelopmentKeyProvider`; decryption uses
`retrieve_and_decrypt_managed` and the existing integrity and AES-GCM checks.

Each run gets a new UUID directory under
`output/managed_synthetic_demo/`. It writes only a new `manifest.json`, an
optional local deployment file, and a stage `result.json`. The column names
include the random run ID, which also makes Filebase object keys unique. The
workflow does not load the original dataset or open either existing manifest.

Storage calls the existing `dual_pin` helper with the encryption object only.
That helper attempts local IPFS and Filebase; it catches provider errors. The
demo records only object key, CIDs, and the matching flag, and requires at
least one CID. If both CIDs exist but differ, it stops. If Filebase credentials
are configured, the synthetic ciphertext can be uploaded to Filebase as well
as local IPFS. No Filebase credentials are required by unit tests.

The optional blockchain stage uses the existing local JSON-RPC, deployment,
registry, and manifest registration helpers. It writes the contract deployment
metadata inside the new run directory, so it does not overwrite the normal
`localhost.json` deployment. The connector requires HTTP on loopback and chain
ID `31337`. Contract registration receives only the CID and HMAC-derived
record digest; key metadata and plaintext are not transaction inputs.

## Limitations

- The regular `main.py` pipeline remains unchanged and continues to use its
  legacy unmanaged mode by default. The demo is opt-in and passes the local
  provider explicitly.
- The current `dual_pin` helper always tries both configured providers rather
  than offering a local-only option. The demo reuses that behavior rather
  than duplicating the upload logic.
- The local provider is development-only. Its KEK is a plaintext local file
  protected by owner-only permissions. It is not backed by an HSM, KMS policy,
  central audit, or automatic recovery. Preserve and back up the key before
  relying on output manifests for future decryption.
- The automated orchestration tests mock storage and blockchain boundaries.
  They validate workflow, serialization, registration routing, integrity,
  decryption, and failure behavior without credentials or live services.
- A full live demonstration was not run during this validation. Local IPFS
  was listening, but no development KEK existed and no Hardhat node was
  listening. Running the command would create a persistent KEK and pin new
  synthetic content. No such key was initialized and no storage upload or
  blockchain transaction was made.

## Run commands

Install Python dependencies and start the local IPFS daemon in a separate
terminal (or configure Filebase as the existing storage module requires):

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -r blockchain/integration/requirements.txt
ipfs daemon
```

Run without blockchain registration:

```sh
.venv/bin/python -m src.managed_demo
```

On its first run, the command safely creates the development KEK at
`~/.adaptive-security/dev-kek-v1.key`; later runs reuse it. The provider refuses
to overwrite an existing key and rejects key paths inside the project. Keep a
secure backup of this key. Use `--key-file /secure/outside-project/path.key`
to select another protected path.

For a local blockchain run, start Hardhat in another terminal:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

In a separate repository-root terminal, set the local record-ID secret and
run the opt-in blockchain workflow:

```sh
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/python -m src.managed_demo --with-blockchain
```

Keep the same HMAC secret if verifying or repeating transactions on the same
Hardhat node. The demo deploys CIDRegistry to chain `31337` in its unique run
directory. It does not use the public network or the existing deployment
file.

## Tests

Run the offline Python suites and existing Hardhat suite:

```sh
.venv/bin/python -m unittest tests.test_managed_demo tests.test_key_management tests.test_secure_retrieval blockchain.integration.test_register_manifest -v
(cd blockchain && npx hardhat test)
```

The orchestration tests use synthetic values and temporary keys. They cover
success without blockchain, optional local-chain routing, missing chain
secret, unavailable blockchain, storage failure, and integrity failure. They
do not call IPFS, Filebase, or a live Hardhat node.
