# Local Python to CIDRegistry integration

This integration is for development against a local Hardhat node only. It sends the CID, a deterministic HMAC-derived `bytes32` record ID, and normal transaction metadata. Dataset values, encrypted payloads, and raw record labels are not written to the contract.

## Setup

From the repository root, install the isolated Python dependency:

```sh
python3 -m pip install -r blockchain/integration/requirements.txt
```

Start a local Hardhat JSON-RPC node. Its startup output includes development account details, so keep it out of shared logs and terminals:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

In another terminal, from the repository root:

```sh
python3 -m blockchain.integration.deploy_local
```

This deploys using the node's first unlocked development account and writes only the contract address and chain ID to `blockchain/integration/deployments/localhost.json`.

## Register the pipeline's stored CIDs

Set a local mapping secret without committing it. Generate a fresh value for local development and retain the same value for repeatable record IDs:

```sh
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

From the repository root, after `python3 -m src.decentralized_storage` has
written `output/encryption_manifest_with_cids.json`, register the existing
storage results:

```sh
python3 -m blockchain.integration.register_manifest
```

This command reads `storage.local_cid` (or `storage.filebase_cid` when the
local CID is unavailable), submits it without uploading again, and records
registration metadata after successful transaction confirmation and
read-back. It skips a matching CID already registered for the same digest,
and refuses to overwrite a digest that points to another CID. It exits
nonzero and reports failed entries without changing their storage results.

Verify manifest entries against the connected local contract:

```sh
python3 -m blockchain.integration.verify_manifest
```

The integration rejects non-loopback RPC URLs and requires chain ID `31337`. The secret is used only to compute `HMAC-SHA256("adaptive-multi-layer-security:{namespace}:{logical_identifier}")`; its value and the raw label are not sent to RPC. Changing the secret changes all derived record IDs. Do not reuse a local demo secret for production.

The integration remains an explicit opt-in step after the pipeline's storage
command; normal encryption and storage runs do not require a blockchain node.
For a one-off manual CID demo, `python3 -m blockchain.integration.demo --namespace adaptive-security-project --record-label column:timestamp --cid <CID>` uses the same local contract helpers.
