# CIDRegistry Implementation Status

## Completed

- Resolved the Hardhat compiler-list lock timeout by adding the matching `solc` 0.8.34 package and configuring Hardhat to use its project-local `soljson.js`. This avoids writing to the user-level compiler cache during compilation.
- Added the Hardhat 3 Node test runner and Viem plugins. The normal `npx hardhat test` command now compiles and passes all four CIDRegistry tests.
- Added a Python Web3 module scoped to `blockchain/integration/` for deployment, CID submission, and read-back on a local Hardhat JSON-RPC node.
- Restricted the Python integration to loopback HTTP and Hardhat chain ID 31337. It uses the local node's unlocked development account through JSON-RPC; no private key is configured in Python.
- Added deterministic `bytes32` record ID derivation using HMAC-SHA256 over a project namespace and logical record label. Only the digest is included in the transaction; the raw label and dataset values remain off-chain.
- Completed a full local end-to-end run over all 27 eligible entries in `output/encryption_manifest_with_cids.json` on chain ID 31337. All 27 registered and verified against the stored CIDs.
- Added an opt-in `register_manifest` command that consumes existing storage CIDs, skips repeat registrations, writes registration metadata to the manifest only after successful read-back, and preserves storage data on failure.
- Added a read-only `verify_manifest` command and five offline Python tests for registration behavior.

## Verification

```sh
cd blockchain
npx hardhat test
```

Result: **4 passing** (deployment; CID/timestamp/submitter retrieval; empty-CID rejection; separate record IDs).

The repeat run skipped all 27 matching records and created no new registrations. A live conflict probe against an existing record was rejected without changing that record. Final verification again passed for all 27 entries. Manifest storage fields were compared before and after and remained unchanged. The HMAC secret was generated once in memory and reused for registration, verification, repeat registration, and the conflict probe; it was not printed or saved.

## Scope and limitations

The encryption and IPFS/Filebase storage code remains unchanged. Blockchain registration is an explicit command after the storage step; the normal pipeline does not require a running node. Registration for the current manifest is supported, while automatic invocation from `main.py` is intentionally not enabled. No public blockchain is involved. The local Hardhat node used for this verification has been stopped; its state was in-memory and will need redeployment after restart.

See [integration/README.md](integration/README.md) for setup and repeatable local commands.
