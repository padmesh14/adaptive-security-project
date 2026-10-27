"""Local SQLite storage for already-encrypted Low-tier column payloads."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOW_TIER_DB = PROJECT_ROOT / "output" / "low_tier_store" / "low_tier_store.sqlite3"
DATABASE_REFERENCE = "low_tier_store/low_tier_store.sqlite3"


def _ensure_database(path: Path = DEFAULT_LOW_TIER_DB) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.is_symlink():
        raise RuntimeError("Low-tier SQLite path must not be a symlink")
    if not path.exists():
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    path.chmod(0o600)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS encrypted_objects ("
            "record_id TEXT PRIMARY KEY, payload BLOB NOT NULL, "
            "payload_sha256 TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )


def store_low_tier_payload(data: dict) -> dict:
    """Store serialized encrypted metadata/payload without plaintext values."""
    if not isinstance(data, dict) or data.get("tier") != "Low":
        raise ValueError("local SQLite storage accepts Low-tier encrypted payloads only")
    payload = json.dumps(data).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    record_id = uuid.uuid4().hex
    _ensure_database()
    with sqlite3.connect(DEFAULT_LOW_TIER_DB) as connection:
        connection.execute(
            "INSERT INTO encrypted_objects (record_id, payload, payload_sha256) VALUES (?, ?, ?)",
            (record_id, payload, digest),
        )
    return {
        "provider": "sqlite",
        "database": DATABASE_REFERENCE,
        "record_id": record_id,
        "payload_sha256": digest,
        "local_cid": None,
        "filebase_cid": None,
        "cids_match": None,
    }


def retrieve_low_tier_payload(storage: dict) -> bytes:
    """Read a local encrypted record and verify its stored-byte digest."""
    if storage.get("database") != DATABASE_REFERENCE:
        raise ValueError("manifest references an unsupported Low-tier database")
    record_id = storage.get("record_id")
    try:
        if not isinstance(record_id, str) or uuid.UUID(hex=record_id).hex != record_id:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise ValueError("manifest has an invalid Low-tier record reference") from exc

    path = DEFAULT_LOW_TIER_DB
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("Low-tier SQLite storage is unavailable")
    uri = f"file:{path.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        row = connection.execute(
            "SELECT payload, payload_sha256 FROM encrypted_objects WHERE record_id = ?",
            (record_id,),
        ).fetchone()
    if row is None:
        raise FileNotFoundError("Low-tier encrypted record is missing from SQLite")
    payload, stored_digest = bytes(row[0]), row[1]
    expected_digest = storage.get("payload_sha256")
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != stored_digest or actual_digest != expected_digest:
        raise ValueError("Low-tier SQLite payload integrity check failed")
    return payload
