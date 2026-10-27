"""Read registered CIDs from the local contract and compare them to the manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from web3 import Web3

from .cid_registry import LOCAL_CHAIN_ID, connect_local, derive_record_id, load_registry
from .register_manifest import DEFAULT_MANIFEST_PATH


def verify_manifest_entries(entries: list[dict], registry, web3, *, namespace: str, secret: str) -> list[dict]:
    if web3.eth.chain_id != LOCAL_CHAIN_ID:
        raise RuntimeError(f"Expected local Hardhat chain ID {LOCAL_CHAIN_ID}")
    results = []
    for index, entry in enumerate(entries):
        storage = entry.get("storage") or {}
        local_cid = storage.get("local_cid")
        filebase_cid = storage.get("filebase_cid")
        if not local_cid and not filebase_cid:
            results.append({"index": index, "status": "skipped", "reason": "no stored CID"})
            continue
        registration = entry.get("blockchain_registration") or {}
        if registration.get("status") not in {"registered", "already_registered"}:
            results.append({"index": index, "status": "missing_registration"})
            continue
        try:
            record_id = derive_record_id(namespace, str(entry["column"]), secret)
            if Web3.to_hex(record_id) != registration.get("record_id"):
                raise ValueError("record ID digest does not match current namespace and secret")
            if registration.get("chain_id") != LOCAL_CHAIN_ID:
                raise ValueError("manifest registration is not for local chain 31337")
            if registration.get("contract_address", "").lower() != registry.address.lower():
                raise ValueError("manifest registration contract address does not match the connected registry")
            actual_cid, timestamp, _submitter = registry.functions.getCID(record_id).call()
            expected_cid = registration.get("cid")
            if local_cid and filebase_cid and local_cid != filebase_cid:
                raise ValueError("local IPFS and Filebase CIDs differ")
            manifest_cid = local_cid or filebase_cid
            if actual_cid != expected_cid or expected_cid != manifest_cid:
                raise ValueError("on-chain CID does not match the stored manifest CID")
            if timestamp <= 0:
                raise ValueError("on-chain timestamp is zero")
            results.append({"index": index, "status": "verified", "cid": actual_cid})
        except Exception as exc:
            results.append({"index": index, "status": "failed", "reason": f"{type(exc).__name__}: {exc}"})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--namespace", default="adaptive-security-project")
    parser.add_argument("--secret-env", default="CID_REGISTRY_RECORD_ID_SECRET")
    args = parser.parse_args()
    secret = os.getenv(args.secret_env)
    if not secret:
        parser.error(f"Set {args.secret_env} in the environment; its value is never written to the manifest")
    try:
        entries = json.loads(args.manifest.read_text(encoding="utf-8"))
        web3 = connect_local()
        registry = load_registry(web3)
        results = verify_manifest_entries(entries, registry, web3, namespace=args.namespace, secret=secret)
    except Exception as exc:
        print(f"Verification could not start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    for result in results:
        prefix = f"Manifest entry {result['index'] + 1}"
        if result["status"] == "verified":
            print(f"{prefix}: verified CID {result['cid']}")
        elif result["status"] == "skipped":
            print(f"{prefix}: skipped ({result.get('reason', 'not eligible')})")
        else:
            print(f"{prefix}: {result['status']} {result.get('reason', '')}", file=sys.stderr)
    return int(any(result["status"] not in {"verified", "skipped"} for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
