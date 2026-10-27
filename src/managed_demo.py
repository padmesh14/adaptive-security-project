"""Isolated synthetic-data demonstration of the managed-key pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import pandas as pd

from blockchain.integration.cid_registry import (
    LOCAL_CHAIN_ID,
    connect_local,
    deploy_local_registry,
    load_registry,
)
from blockchain.integration.register_manifest import register_manifest_entries
from src.decentralized_storage import dual_pin
from src.encryption_pipeline import encrypt_dataset_by_column
from src.key_management import (
    DEFAULT_MASTER_KEY_PATH,
    KeyManagementError,
    LocalDevelopmentKeyProvider,
    retrieve_and_decrypt_managed,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEMO_ROOT = PROJECT_ROOT / "output" / "managed_synthetic_demo"
DEMO_NAMESPACE = "adaptive-managed-synthetic-demo"


def load_or_create_provider(key_file: str | Path = DEFAULT_MASTER_KEY_PATH) -> LocalDevelopmentKeyProvider:
    """Reuse a valid local key, or initialize a missing one without overwrite."""
    path = Path(key_file).expanduser()
    try:
        return LocalDevelopmentKeyProvider(path)
    except KeyManagementError:
        if path.exists():
            # Existing but invalid/insecure files must not be silently replaced.
            raise
    try:
        return LocalDevelopmentKeyProvider.initialize(path)
    except KeyManagementError:
        # A concurrent demo may have won the exclusive-create race. Load it
        # only if it now validates under all provider permission checks.
        return LocalDevelopmentKeyProvider(path)


def _synthetic_frame(run_id: str) -> pd.DataFrame:
    """Synthetic-only columns intentionally exercise the three classifier tiers."""
    return pd.DataFrame({
        f"demo_{run_id}_temperature": ["20", "21", "20", "22", "21"],
        f"demo_{run_id}_diagnosis": [
            "synthetic-condition-a", "synthetic-condition-b", "synthetic-condition-c",
            "synthetic-condition-d", "synthetic-condition-e",
        ],
        f"demo_{run_id}_email": [
            f"synthetic-{index}@example.invalid" for index in range(1, 6)
        ],
    })


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run_managed_demo(
    *,
    with_blockchain: bool = False,
    key_file: str | Path = DEFAULT_MASTER_KEY_PATH,
    demo_root: str | Path = DEFAULT_DEMO_ROOT,
) -> dict:
    """Run the synthetic workflow in a new isolated output directory.

    Failures are summarized by stage and exception type only, preventing
    provider errors, secrets, plaintext, and CIDs from reaching console output.
    """
    run_id = uuid.uuid4().hex
    root = Path(demo_root)
    run_dir = root / run_id
    stage = "preflight"
    try:
        if with_blockchain and not os.getenv("CID_REGISTRY_RECORD_ID_SECRET"):
            raise RuntimeError("blockchain record-ID secret is not configured")
        root.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir(mode=0o700, exist_ok=False)

        stage = "key_provider"
        key_provider = load_or_create_provider(key_file)

        stage = "classification_and_encryption"
        frame = _synthetic_frame(run_id)
        plaintext_by_column = {
            column: json.dumps(frame[column].tolist()).encode("utf-8")
            for column in frame.columns
        }
        result = encrypt_dataset_by_column(frame, key_provider=key_provider)
        entries = result["manifest"]
        manifest_path = run_dir / "manifest.json"
        _write_json(manifest_path, entries)

        stage = "storage"
        for entry in entries:
            # The UUID in the synthetic column name makes provider object keys
            # unique across runs and avoids replacing existing Filebase objects.
            object_key = f"{entry['column']}.json"
            stored = dual_pin(object_key, entry["encryption"])
            local_cid = stored.get("local_cid")
            filebase_cid = stored.get("filebase_cid")
            entry["storage"] = {
                "key": object_key,
                "local_cid": local_cid,
                "filebase_cid": filebase_cid,
                "cids_match": bool(local_cid and filebase_cid and local_cid == filebase_cid),
            }
            _write_json(manifest_path, entries)
            if local_cid and filebase_cid and local_cid != filebase_cid:
                raise RuntimeError("storage providers returned different payload CIDs")
            cid = local_cid or filebase_cid
            if not cid:
                raise RuntimeError("no storage provider returned a CID")

        blockchain_enabled = bool(with_blockchain)
        if with_blockchain:
            stage = "local_blockchain_registration"
            # connect_local enforces loopback HTTP and chain ID 31337. The
            # demo deployment is written only inside this unique run directory.
            web3 = connect_local()
            if web3.eth.chain_id != LOCAL_CHAIN_ID:
                raise RuntimeError("local chain ID check failed")
            deployment_path = run_dir / "localhost_deployment.json"
            address = deploy_local_registry(web3, deployment_path)
            registry = load_registry(web3, deployment_path)
            outcomes = register_manifest_entries(
                entries,
                registry,
                web3,
                namespace=DEMO_NAMESPACE,
                secret=os.environ["CID_REGISTRY_RECORD_ID_SECRET"],
                contract_address=address,
            )
            if any(outcome["status"] not in {"registered", "already_registered"} for outcome in outcomes):
                _write_json(manifest_path, entries)
                raise RuntimeError("one or more local CID registrations failed")
            _write_json(manifest_path, entries)

        stage = "retrieval_and_decryption"
        for entry in entries:
            recovered = retrieve_and_decrypt_managed(entry, key_provider, "auto")
            expected = plaintext_by_column[entry["column"]]
            if recovered != expected:
                raise RuntimeError("recovered synthetic record did not match its source")

        summary = {
            "status": "success",
            "run_id": run_id,
            "records_verified": len(entries),
            "blockchain_enabled": blockchain_enabled,
            "chain_id": LOCAL_CHAIN_ID if blockchain_enabled else None,
        }
        _write_json(run_dir / "result.json", summary)
        return {**summary, "output_dir": str(run_dir)}
    except Exception as exc:
        summary = {
            "status": "failed",
            "run_id": run_id,
            "stage": stage,
            "error_type": type(exc).__name__,
            "blockchain_enabled": bool(with_blockchain),
        }
        if run_dir.exists():
            try:
                _write_json(run_dir / "result.json", summary)
            except OSError:
                pass
        return {**summary, "output_dir": str(run_dir) if run_dir.exists() else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-blockchain", action="store_true",
                        help="deploy/register on a running local Hardhat chain 31337")
    parser.add_argument("--key-file", type=Path, default=DEFAULT_MASTER_KEY_PATH,
                        help="local development KEK path outside the project")
    args = parser.parse_args()
    result = run_managed_demo(with_blockchain=args.with_blockchain, key_file=args.key_file)
    if result["status"] == "success":
        print(f"Synthetic managed-key demo passed for {result['records_verified']} records.")
        print(f"Blockchain step: {'enabled on local chain 31337' if result['blockchain_enabled'] else 'disabled'}.")
        print(f"Demo artifacts: {result['output_dir']}")
        return 0
    print(f"Synthetic managed-key demo failed during {result['stage']} ({result['error_type']}).", file=sys.stderr)
    if result.get("output_dir"):
        print(f"Isolated demo artifacts: {result['output_dir']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
