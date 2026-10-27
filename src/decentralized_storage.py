"""
decentralized_storage.py

Uploads encrypted column blocks to TWO independent storage providers:
  1. Your own local IPFS node (free, run via `ipfs daemon`)
  2. Filebase (free tier, 5GB, S3-compatible API, auto-pins to IPFS with
     3x geo-distributed replication on their end)

Pinning to both means no single provider's outage takes your data down --
this is what makes the "decentralized, no single point of failure" claim
actually true, rather than just running one node and hoping it stays on.

SETUP REQUIRED BEFORE RUNNING:
  1. Install & start a local IPFS node:
       ipfs init
       ipfs daemon          <- leave running in its own terminal
  2. Create a free Filebase account (filebase.com), create a bucket with
     network type "IPFS", and generate an Access Key + Secret Key.
  3. Fill in FILEBASE_ACCESS_KEY, FILEBASE_SECRET_KEY, FILEBASE_BUCKET
     below (or set them as environment variables -- recommended, so keys
     aren't committed to source control).
  4. pip install requests boto3
"""

import os
import io
import json
import time
import uuid

import requests
import boto3
from botocore.exceptions import ClientError
from src.local_low_tier_storage import store_low_tier_payload

# --- Configuration -----------------------------------------------------
FILEBASE_ACCESS_KEY = os.environ.get("FILEBASE_ACCESS_KEY", "")
FILEBASE_SECRET_KEY = os.environ.get("FILEBASE_SECRET_KEY", "")
FILEBASE_BUCKET = os.environ.get("FILEBASE_BUCKET", "")
FILEBASE_ENDPOINT = "https://s3.filebase.io"

IPFS_API_BASE = "http://127.0.0.1:5001/api/v0"


def upload_to_local_ipfs(data: dict) -> str:
    payload = json.dumps(data).encode("utf-8")
    files = {"file": ("data.json", payload, "application/json")}
    try:
        resp = requests.post(f"{IPFS_API_BASE}/add", params={"pin": "true"}, files=files, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            "Could not connect to local IPFS node. Is the daemon running? "
            "Start it with: ipfs daemon"
        ) from e
    return resp.json()["Hash"]


def _get_filebase_client():
    if not (FILEBASE_ACCESS_KEY and FILEBASE_SECRET_KEY and FILEBASE_BUCKET):
        raise RuntimeError(
            "Filebase credentials not set. Set FILEBASE_ACCESS_KEY, "
            "FILEBASE_SECRET_KEY, and FILEBASE_BUCKET as environment "
            "variables, or edit them at the top of decentralized_storage.py."
        )
    return boto3.client(
        "s3",
        endpoint_url=FILEBASE_ENDPOINT,
        aws_access_key_id=FILEBASE_ACCESS_KEY,
        aws_secret_access_key=FILEBASE_SECRET_KEY,
        region_name="auto",
    )


def _extract_cid(response: dict) -> str:
    """Reads the CID straight from the raw HTTP response header
    x-amz-meta-cid, which Filebase reliably includes (lowercase) --
    confirmed directly against a real response. This is more reliable
    than the parsed Metadata dict, whose key casing ("Cid" vs "cid")
    isn't consistent."""
    headers = response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    if "x-amz-meta-cid" in headers:
        return headers["x-amz-meta-cid"]
    # Fallback: check Metadata dict with both possible casings
    metadata = response.get("Metadata", {})
    return metadata.get("cid") or metadata.get("Cid") or ""


def upload_to_filebase(key_name: str, data: dict, max_retries: int = 15, retry_delay: float = 3.0) -> str:
    """Uploads a JSON-serializable dict to Filebase. Returns the CID.
    Filebase pins asynchronously, so we poll HEAD with retries until the
    CID metadata appears."""
    client = _get_filebase_client()
    payload = json.dumps(data).encode("utf-8")

    put_response = client.put_object(
        Bucket=FILEBASE_BUCKET,
        Key=key_name,
        Body=io.BytesIO(payload),
        ContentType="application/json",
    )

    cid = _extract_cid(put_response)
    if cid:
        return cid

    for attempt in range(max_retries):
        head = client.head_object(Bucket=FILEBASE_BUCKET, Key=key_name)
        cid = _extract_cid(head)
        if cid:
            return cid
        time.sleep(retry_delay)

    return ""


def upload_existing_payload_to_filebase(key_name: str, payload: bytes,
                                        max_retries: int = 15,
                                        retry_delay: float = 3.0) -> str:
    """Upload already-stored ciphertext bytes without reserializing them."""
    client = _get_filebase_client()
    response = client.put_object(
        Bucket=FILEBASE_BUCKET,
        Key=key_name,
        Body=io.BytesIO(payload),
        ContentType="application/json",
    )
    cid = _extract_cid(response)
    if cid:
        return cid
    for _ in range(max_retries):
        head = client.head_object(Bucket=FILEBASE_BUCKET, Key=key_name)
        cid = _extract_cid(head)
        if cid:
            return cid
        time.sleep(retry_delay)
    return ""


def retry_filebase_manifest(manifest_path: str, output_path: str) -> dict:
    """Copy existing Medium/High IPFS payloads to new Filebase object keys.

    Each payload is fetched by its existing local CID and verified against the
    source manifest before upload. The source manifest is never modified.
    """
    from src.secure_retrieval import retrieve_payload, verify_payload

    with open(manifest_path, "r", encoding="utf-8") as source:
        manifest = json.load(source)
    stats = {"uploaded": 0, "skipped": 0, "failed": 0}

    for entry in manifest:
        storage = entry.get("storage") or {}
        if entry.get("sensitivity_tier") not in {"Medium", "High"}:
            stats["skipped"] += 1
            continue
        if storage.get("filebase_cid"):
            stats["skipped"] += 1
            continue
        if not storage.get("local_cid"):
            storage["filebase_error"] = "No existing local IPFS CID; not uploaded"
            entry["storage"] = storage
            stats["failed"] += 1
            continue

        try:
            payload = retrieve_payload(entry, provider="ipfs")
            verify_payload(entry, payload)
            # A fresh opaque key avoids overwriting any existing bucket object.
            key_name = f"retry/{uuid.uuid4().hex}.json"
            cid = upload_existing_payload_to_filebase(key_name, payload)
            if not cid:
                raise RuntimeError("Filebase did not return CID metadata")
            storage["key"] = key_name
            storage["filebase_cid"] = cid
            storage["cids_match"] = cid == storage["local_cid"]
            storage.pop("filebase_error", None)
            if cid != storage["local_cid"]:
                storage["filebase_error"] = "Uploaded CID differs from the existing local IPFS CID"
                stats["failed"] += 1
            else:
                stats["uploaded"] += 1
        except Exception as exc:
            # Keep failure details non-sensitive and avoid printing payload data.
            storage["filebase_error"] = f"Retry failed ({type(exc).__name__})"
            stats["failed"] += 1
        entry["storage"] = storage

    with open(output_path, "x", encoding="utf-8") as target:
        json.dump(manifest, target, indent=2)
    return stats


def dual_pin(key_name: str, data: dict) -> dict:
    result = {"key": key_name}

    try:
        result["local_cid"] = upload_to_local_ipfs(data)
    except Exception as e:
        result["local_cid"] = None
        result["local_error"] = str(e)

    try:
        cid = upload_to_filebase(key_name, data)
        result["filebase_cid"] = cid if cid else None
        if not cid:
            result["filebase_error"] = "Upload succeeded but CID not found after retries -- pinning may still be in progress; check the Filebase dashboard."
    except Exception as e:
        result["filebase_cid"] = None
        result["filebase_error"] = str(e)

    result["cids_match"] = (
        result.get("local_cid") is not None
        and result.get("local_cid") == result.get("filebase_cid")
    )
    return result


def pin_manifest(manifest_path: str, output_path: str, route_low_to_sqlite: bool = False) -> list:
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    for entry in manifest:
        key_name = f"{entry['column']}.json"
        if route_low_to_sqlite and entry.get("sensitivity_tier") == "Low":
            storage_result = store_low_tier_payload(entry["encryption"])
        else:
            storage_result = dual_pin(key_name, entry["encryption"])
        entry["storage"] = storage_result
        if storage_result.get("provider") == "sqlite":
            print(f"{entry['column']:20s} tier=Low    provider=local SQLite")
        else:
            print(f"{entry['column']:20s} tier={entry['sensitivity_tier']:6s} "
                  f"local_cid={storage_result.get('local_cid')}  "
                  f"filebase_cid={storage_result.get('filebase_cid')}  "
                  f"match={storage_result.get('cids_match')}")
        if storage_result.get("filebase_error"):
            print(f"   -> filebase_error: {storage_result['filebase_error']}")

    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest


if __name__ == "__main__":
    import sys
    import argparse
    from datetime import datetime, timezone
    import uuid

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description="Store encrypted column payloads")
    parser.add_argument("--route-low-to-sqlite", action="store_true",
                        help="store Low-tier encrypted payloads locally; dual-pin Medium/High")
    parser.add_argument("--manifest", type=str,
                        help="input encryption manifest (defaults to output/encryption_manifest.json)")
    parser.add_argument("--retry-filebase-only", action="store_true",
                        help="copy existing verified Medium/High IPFS payloads to Filebase only")
    args = parser.parse_args()
    manifest_path = args.manifest or os.path.join(base_dir, "output", "encryption_manifest.json")
    if args.retry_filebase_only:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        output_path = os.path.join(base_dir, "output", f"encryption_manifest_filebase_retry_{stamp}_{suffix}.json")
    elif args.route_low_to_sqlite:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        output_path = os.path.join(base_dir, "output", f"encryption_manifest_tiered_{stamp}_{suffix}.json")
    else:
        output_path = os.path.join(base_dir, "output", "encryption_manifest_with_cids.json")

    if not os.path.exists(manifest_path):
        print(f"No manifest found at {manifest_path}. Run main.py first.")
        sys.exit(1)
    if (args.route_low_to_sqlite or args.retry_filebase_only) and os.path.exists(output_path):
        print(f"Refusing to overwrite existing tier-aware manifest: {output_path}", file=sys.stderr)
        sys.exit(1)

    if args.retry_filebase_only:
        print("Retrying Filebase for existing Medium/High IPFS payloads; source manifest is unchanged...\n")
        try:
            stats = retry_filebase_manifest(manifest_path, output_path)
        except FileExistsError:
            print(f"Refusing to overwrite existing output: {output_path}", file=sys.stderr)
            sys.exit(1)
        print(f"\nRetry summary: uploaded={stats['uploaded']} skipped={stats['skipped']} failed={stats['failed']}")
        print(f"New manifest written to {output_path}")
        sys.exit(0 if stats["failed"] == 0 else 2)
    elif args.route_low_to_sqlite:
        print("Routing Low-tier encrypted columns to local SQLite; dual-pinning Medium/High...\n")
    else:
        print("Dual-pinning encrypted columns to local IPFS node + Filebase...\n")
    pin_manifest(manifest_path, output_path, route_low_to_sqlite=args.route_low_to_sqlite)
    print(f"\nDone. Updated manifest written to {output_path}")
