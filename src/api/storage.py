"""Store opaque encrypted bytes without JSON encoding or encryption changes."""
from __future__ import annotations

import io
import time
import requests
from src.decentralized_storage import (
    FILEBASE_ACCESS_KEY, FILEBASE_BUCKET, FILEBASE_ENDPOINT, FILEBASE_SECRET_KEY,
    _extract_cid, _get_filebase_client, IPFS_API_BASE,
)


class StorageUnavailable(RuntimeError):
    pass


def selected_provider(requested: str = "auto") -> str:
    if requested not in {"auto", "ipfs", "filebase"}:
        raise ValueError("Unsupported storage provider")
    filebase_ready = bool(FILEBASE_ACCESS_KEY and FILEBASE_SECRET_KEY and FILEBASE_BUCKET)
    if requested == "auto":
        return "filebase" if filebase_ready else "ipfs"
    if requested == "filebase" and not filebase_ready:
        raise StorageUnavailable("Filebase is not configured")
    return requested


def upload_encrypted_bytes(payload: bytes, object_key: str, provider: str = "auto") -> tuple[str, str]:
    """Accept already encrypted bytes; never invokes the legacy JSON uploader."""
    selected = selected_provider(provider)
    if not payload:
        raise ValueError("Encrypted payload cannot be empty")
    if selected == "ipfs":
        try:
            response = requests.post(
                f"{IPFS_API_BASE}/add", params={"pin": "true"},
                files={"file": ("encrypted.amls", io.BytesIO(payload), "application/octet-stream")}, timeout=60,
            )
            response.raise_for_status()
            cid = response.json()["Hash"]
        except Exception as exc:
            raise StorageUnavailable("Local IPFS upload failed") from exc
        return selected, cid
    try:
        client = _get_filebase_client()
        result = client.put_object(Bucket=FILEBASE_BUCKET, Key=object_key, Body=io.BytesIO(payload), ContentType="application/octet-stream")
        cid = _extract_cid(result)
        if not cid:
            for _ in range(15):
                head = client.head_object(Bucket=FILEBASE_BUCKET, Key=object_key)
                cid = _extract_cid(head)
                if cid:
                    break
                time.sleep(3)
        if not cid:
            raise StorageUnavailable("Filebase did not return a content identifier")
        return selected, cid
    except StorageUnavailable:
        raise
    except Exception as exc:
        raise StorageUnavailable("Filebase upload failed") from exc


def retrieve_encrypted_bytes(cid: str, provider: str, object_key: str | None = None) -> bytes:
    if provider == "ipfs":
        try:
            response = requests.post(f"{IPFS_API_BASE}/cat", params={"arg": cid}, timeout=60)
            response.raise_for_status()
            return response.content
        except Exception as exc:
            raise StorageUnavailable("Local IPFS retrieval failed") from exc
    if provider == "filebase":
        try:
            if not object_key:
                raise StorageUnavailable("Filebase object key is unavailable")
            result = _get_filebase_client().get_object(Bucket=FILEBASE_BUCKET, Key=object_key)
            return result["Body"].read()
        except Exception as exc:
            raise StorageUnavailable("Filebase retrieval requires the saved object key") from exc
    raise ValueError("Unsupported storage provider")
