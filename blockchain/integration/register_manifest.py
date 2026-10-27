"""Register CIDs already present in the pipeline's storage manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from web3 import Web3

from .cid_registry import (
    DEPLOYMENT_PATH,
    LOCAL_CHAIN_ID,
    connect_local,
    derive_record_id,
    load_registry,
    store_and_read_cid,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = PROJECT_ROOT / "output/encryption_manifest_with_cids.json"


def _stored_cid(entry: dict) -> str | None:
    storage = entry.get("storage") or {}
    local_cid = storage.get("local_cid")
    filebase_cid = storage.get("filebase_cid")
    if local_cid and filebase_cid and local_cid != filebase_cid:
        raise ValueError("local IPFS and Filebase CIDs differ; refusing to choose one")
    return local_cid or filebase_cid


def register_manifest_entries(
    entries: list[dict],
    registry,
    web3,
    *,
    namespace: str,
    secret: str,
    contract_address: str,
) -> list[dict]:
    """Register eligible stored CIDs; mutate only blockchain metadata on success."""
    if web3.eth.chain_id != LOCAL_CHAIN_ID:
        raise RuntimeError(f"Expected local Hardhat chain ID {LOCAL_CHAIN_ID}")
    results = []
    for index, entry in enumerate(entries):
        try:
            cid = _stored_cid(entry)
            if not cid:
                results.append({"index": index, "status": "skipped", "reason": "no stored CID"})
                continue

            # Raw column labels are used locally as HMAC input and never sent to RPC.
            record_id_bytes = derive_record_id(namespace, str(entry["column"]), secret)
            record_id = Web3.to_hex(record_id_bytes)
            existing_cid, timestamp, _submitter = registry.functions.getCID(record_id_bytes).call()

            if existing_cid and existing_cid != cid:
                raise ValueError("record ID is already associated with a different CID")

            deployment = {
                "record_id": record_id,
                "chain_id": LOCAL_CHAIN_ID,
                "contract_address": Web3.to_checksum_address(contract_address),
                "cid": cid,
            }
            if existing_cid == cid:
                previous = entry.get("blockchain_registration") or {}
                if (
                    previous.get("record_id") == record_id
                    and previous.get("cid") == cid
                    and previous.get("chain_id") == LOCAL_CHAIN_ID
                    and previous.get("contract_address", "").lower() == contract_address.lower()
                ):
                    for key in ("transaction_hash", "timestamp"):
                        if key in previous:
                            deployment[key] = previous[key]
                deployment["status"] = "already_registered"
                deployment["timestamp"] = deployment.get("timestamp", int(timestamp))
                entry["blockchain_registration"] = deployment
                results.append({"index": index, "status": "already_registered", "cid": cid})
                continue

            read_cid, stored_timestamp, _submitter, transaction_hash = store_and_read_cid(
                registry, web3, record_id_bytes, cid
            )
            if read_cid != cid:
                raise RuntimeError("contract read-back CID did not match the submitted CID")
            deployment.update(
                {
                    "status": "registered",
                    "transaction_hash": Web3.to_hex(bytes.fromhex(transaction_hash.removeprefix("0x"))),
                    "timestamp": int(stored_timestamp),
                }
            )
            entry["blockchain_registration"] = deployment
            results.append({"index": index, "status": "registered", "cid": cid})
        except Exception as exc:
            results.append(
                {
                    "index": index,
                    "status": "failed",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
    return results


def _write_manifest_atomically(path: Path, entries: list[dict]) -> None:
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as output_file:
            temporary_path = Path(output_file.name)
            json.dump(entries, output_file, indent=2)
            output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def register_manifest_file(
    manifest_path: Path,
    *,
    namespace: str,
    secret: str,
    web3=None,
    registry=None,
    contract_address: str | None = None,
) -> list[dict]:
    """Register CIDs from a manifest without invoking the storage pipeline."""
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("Expected the encryption manifest to contain a list of entries")
    web3 = web3 or connect_local()
    if web3.eth.chain_id != LOCAL_CHAIN_ID:
        raise RuntimeError(f"Expected local Hardhat chain ID {LOCAL_CHAIN_ID}")
    registry = registry or load_registry(web3)
    if contract_address is None:
        deployment = json.loads(DEPLOYMENT_PATH.read_text(encoding="utf-8"))
        contract_address = deployment["address"]
    if not Web3.is_address(contract_address):
        raise ValueError("Invalid CIDRegistry deployment address")

    results = register_manifest_entries(
        entries,
        registry,
        web3,
        namespace=namespace,
        secret=secret,
        contract_address=contract_address,
    )
    if any(result["status"] in {"registered", "already_registered"} for result in results):
        _write_manifest_atomically(manifest_path, entries)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--namespace", default="adaptive-security-project")
    parser.add_argument(
        "--secret-env", default="CID_REGISTRY_RECORD_ID_SECRET",
        help="environment variable containing the stable local HMAC secret",
    )
    args = parser.parse_args()
    secret = os.getenv(args.secret_env)
    if not secret:
        parser.error(f"Set {args.secret_env} in the environment; its value is never written to the manifest")

    try:
        outcomes = register_manifest_file(
            args.manifest, namespace=args.namespace, secret=secret
        )
    except Exception as exc:
        print(f"Blockchain registration or manifest update failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    for outcome in outcomes:
        prefix = f"Manifest entry {outcome['index'] + 1}"
        if outcome["status"] in {"registered", "already_registered"}:
            print(f"{prefix}: {outcome['status']} CID {outcome['cid']}")
        elif outcome["status"] == "skipped":
            print(f"{prefix}: skipped ({outcome['reason']})")
        else:
            print(f"{prefix}: FAILED ({outcome['reason']})", file=sys.stderr)
    failed = any(outcome["status"] == "failed" for outcome in outcomes)
    if failed:
        print("Failed submissions were not marked as registered; existing storage entries were preserved.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
