# Python Pipeline to Local CIDRegistry Integration

## What is integrated

After encryption and IPFS/Filebase storage, an explicit Python command can register the CIDs already written to `output/encryption_manifest_with_cids.json` in the local Hardhat `CIDRegistry` contract. Registration does not rerun encryption or upload content. The normal pipeline remains usable without a running blockchain.

The integration:

- Uses only loopback JSON-RPC endpoints and requires Hardhat chain ID `31337`.
- Derives `bytes32` record IDs with HMAC-SHA256 from a namespace and logical column label. The raw label and HMAC secret are not sent to the contract or written to the manifest.
- Stores only the CID and the contract's existing record metadata on-chain. Dataset values and encrypted payloads stay off-chain.
- Records the record ID digest, submitted CID, transaction hash, chain ID, contract address, timestamp, and status in the manifest after a confirmed transaction and matching read-back.
- Skips repeat submissions for a matching on-chain CID. It refuses to overwrite a record ID associated with a different CID.
- Reports failures without changing the entry's existing storage results or marking a failed submission as registered.

## Run the local flow

Install the Python dependencies from the repository root:

```sh
python3 -m pip install -r requirements.txt
python3 -m pip install -r blockchain/integration/requirements.txt
```

Start local IPFS if it is not already running:

```sh
ipfs daemon
```

Configure the existing Filebase environment variables, then run encryption and storage from the repository root:

```sh
python3 main.py
python3 -m src.decentralized_storage
```

Start Hardhat in its own terminal. Output is suppressed because Hardhat prints local development account details at startup:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

From another terminal at the repository root, deploy the contract locally, set a stable local HMAC secret, and register the CIDs already in the output manifest:

```sh
python3 -m blockchain.integration.deploy_local
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m blockchain.integration.register_manifest
```

Keep the generated secret in your local environment for repeat registration and verification. Never commit it. Use the same namespace (default `adaptive-security-project`) and secret when verifying:

```sh
python3 -m blockchain.integration.verify_manifest
```

Run the Solidity contract tests from `blockchain/`:

```sh
npx hardhat test
```

## Test and demonstration results

- Hardhat: **4 passing** tests covering deployment, CID/timestamp/submitter retrieval, empty-CID rejection, and separate record IDs.
- Python unit tests: **5 passing** tests covering new registration, idempotent repeats, submission failure preservation, conflicting CIDs, and missing CIDs. They do not require a live blockchain.
- Local end-to-end demonstration: all 27 eligible CIDs from the existing output manifest were registered on chain `31337` and read back with matching values. A second registration pass skipped all 27; a live conflicting-record probe was rejected. Final verification passed for all 27.

The HMAC secret was generated once in memory and reused for the full run; it was not printed or saved. The original storage fields were compared before and after and remained unchanged. The manifest now contains registration metadata for all 27 entries. The local Hardhat node was stopped after verification, so its in-memory state will need to be redeployed in a later session.

## Scope

The encryption, classification, IPFS/Filebase storage logic, and Solidity contract are unchanged. Registration remains an opt-in command after storage; it is not automatically invoked by `main.py`. No public blockchain was used.
