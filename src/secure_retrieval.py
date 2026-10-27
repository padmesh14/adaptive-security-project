"""Retrieve, verify, and decrypt an encrypted manifest entry.

The manifest and storage providers contain ciphertext only. Decryption keys
must come from a separate, trusted key-management process and are never
written back to the manifest or printed by this module.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


IPFS_API_BASE = "http://127.0.0.1:5001/api/v0"
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "output/encryption_manifest_with_cids.json"


class RetrievalError(Exception):
    """Base class for safe retrieval/decryption failures."""


class IntegrityError(RetrievalError):
    """Retrieved payload does not match the manifest integrity metadata."""


class DecryptionError(RetrievalError):
    """Authentication failed or decryption metadata/keys were invalid."""


def _expected_cid(entry: dict) -> str:
    storage = entry.get("storage") or {}
    local_cid, filebase_cid = storage.get("local_cid"), storage.get("filebase_cid")
    if local_cid and filebase_cid and local_cid != filebase_cid:
        raise RetrievalError("manifest storage providers have conflicting CIDs")
    cid = local_cid or filebase_cid
    if not isinstance(cid, str) or not cid:
        raise RetrievalError("manifest entry has no stored CID")
    return cid


def retrieve_payload(entry: dict, provider: str = "auto") -> bytes:
    """Fetch encrypted bytes from local SQLite, IPFS, or Filebase."""
    if provider not in {"auto", "sqlite", "ipfs", "filebase"}:
        raise ValueError("provider must be auto, sqlite, ipfs, or filebase")
    storage = entry.get("storage") or {}
    if storage.get("provider") == "sqlite":
        if provider not in {"auto", "sqlite"}:
            raise RetrievalError("entry is stored in SQLite, not the requested provider")
        try:
            from src.local_low_tier_storage import retrieve_low_tier_payload
            return retrieve_low_tier_payload(storage)
        except Exception as exc:
            raise RetrievalError(f"local SQLite retrieval failed ({type(exc).__name__})") from exc
    if provider == "sqlite":
        raise RetrievalError("manifest entry does not reference local SQLite storage")
    cid = _expected_cid(entry)
    errors = []
    if provider in {"auto", "ipfs"} and storage.get("local_cid"):
        try:
            response = requests.post(
                f"{IPFS_API_BASE}/cat", params={"arg": cid}, timeout=30
            )
            response.raise_for_status()
            return response.content
        except requests.RequestException as exc:
            errors.append(f"local IPFS retrieval failed ({type(exc).__name__})")
            if provider == "ipfs":
                raise RetrievalError(errors[-1]) from exc
    if provider in {"auto", "filebase"} and storage.get("filebase_cid"):
        key = storage.get("key")
        if not key:
            errors.append("Filebase object key is missing from storage metadata")
        else:
            try:
                # Import lazily so synthetic/unit use does not need cloud credentials.
                from src.decentralized_storage import FILEBASE_BUCKET, _get_filebase_client

                response = _get_filebase_client().get_object(Bucket=FILEBASE_BUCKET, Key=key)
                return response["Body"].read()
            except Exception as exc:
                errors.append(f"Filebase retrieval failed ({type(exc).__name__})")
    raise RetrievalError("; ".join(errors) if errors else "no configured provider can retrieve this CID")


def verify_payload(entry: dict, payload: bytes) -> bytes:
    """Validate fetched envelope, ciphertext equality, and BLAKE2b-256 digest.

    The hash detects accidental/corrupt data and binds bytes to the manifest;
    it is not treated as an authenticity mechanism. AES-GCM authentication is
    required before plaintext is returned.
    """
    if not isinstance(payload, bytes) or not payload:
        raise IntegrityError("retrieved payload is empty or not bytes")
    try:
        fetched = json.loads(payload)
        expected = entry["encryption"]
        fetched_tier = fetched["tier"]
        fetched_ciphertext = fetched["final_ciphertext_b64"]
        fetched_digest = fetched["integrity_hash_blake2"]
        expected_ciphertext = expected["final_ciphertext_b64"]
        expected_digest = expected["integrity_hash_blake2"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IntegrityError("retrieved payload or manifest encryption metadata is invalid") from exc

    if fetched_tier != entry.get("sensitivity_tier") or fetched_tier != expected.get("tier"):
        raise IntegrityError("retrieved payload sensitivity tier does not match the manifest")
    if fetched.get("scheme") != expected.get("scheme") or fetched.get("layers") != expected.get("layers"):
        raise IntegrityError("retrieved encryption scheme metadata does not match the manifest")
    if fetched_ciphertext != expected_ciphertext:
        raise IntegrityError("retrieved ciphertext does not match the manifest")
    if fetched_digest != expected_digest:
        raise IntegrityError("retrieved integrity metadata does not match the manifest")
    try:
        blob = base64.b64decode(fetched_ciphertext, validate=True)
    except (ValueError, TypeError) as exc:
        raise IntegrityError("ciphertext encoding is invalid") from exc
    actual_digest = hashlib.blake2b(blob, digest_size=32).hexdigest()
    if not actual_digest or actual_digest != expected_digest:
        raise IntegrityError("ciphertext integrity digest mismatch")
    return blob


def _key_from_bundle(bundle: dict, name: str) -> bytes:
    value = bundle.get(name)
    if not isinstance(value, str):
        raise DecryptionError(f"required key field {name} is missing")
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise DecryptionError(f"key field {name} is not valid base64") from exc
    if len(key) != 32:
        raise DecryptionError(f"key field {name} must decode to 32 bytes")
    return key


def _decrypt_aes_gcm(key: bytes, blob: bytes, layer: str) -> bytes:
    if len(blob) < 12 + 16:
        raise DecryptionError(f"{layer} ciphertext is too short")
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)
    except InvalidTag as exc:
        raise DecryptionError(f"{layer} AES-GCM authentication failed") from exc
    except (ValueError, TypeError) as exc:
        raise DecryptionError(f"{layer} key or ciphertext is invalid") from exc


def _medium_key(bundle: dict) -> bytes:
    # An exported ECDH-derived AES key is accepted directly. Alternatively,
    # derive the same key from the original recipient private key and sender
    # public point (the existing encryption scheme uses info=b"tier-medium").
    if "aes_key_b64" in bundle:
        return _key_from_bundle(bundle, "aes_key_b64")
    private_pem, public_hex = bundle.get("recipient_private_key_pem"), bundle.get("sender_public_key_hex")
    if not private_pem or not public_hex:
        raise DecryptionError("Medium tier requires its ECDH-derived key or recipient/sender key pair")
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(public_hex))
        shared = private_key.exchange(ec.ECDH(), public_key)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tier-medium").derive(shared)
    except (ValueError, TypeError) as exc:
        raise DecryptionError("Medium tier ECDH key material is invalid") from exc


def decrypt_verified_entry(entry: dict, payload: bytes, key_bundle: dict) -> bytes:
    """Verify stored bytes then decrypt according to the manifest tier."""
    blob = verify_payload(entry, payload)
    tier = entry.get("sensitivity_tier")
    if not isinstance(key_bundle, dict):
        raise DecryptionError("key bundle entry must be an object")
    if tier == "Low":
        return _decrypt_aes_gcm(_key_from_bundle(key_bundle, "aes_key_b64"), blob, "Low tier")
    if tier == "Medium":
        return _decrypt_aes_gcm(_medium_key(key_bundle), blob, "Medium tier")
    if tier == "High":
        # High tier encrypts the plaintext with key1, then wraps that blob with key2.
        intermediate = _decrypt_aes_gcm(_key_from_bundle(key_bundle, "layer2_key_b64"), blob, "High outer layer")
        return _decrypt_aes_gcm(_key_from_bundle(key_bundle, "layer1_key_b64"), intermediate, "High inner layer")
    raise DecryptionError("manifest has an unsupported sensitivity tier")


def retrieve_and_decrypt(entry: dict, key_bundle: dict, provider: str = "auto") -> bytes:
    """Retrieve by the stored CID and return plaintext only after all checks."""
    return decrypt_verified_entry(entry, retrieve_payload(entry, provider), key_bundle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrieve, verify, and decrypt one stored manifest entry")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--index", type=int, required=True, help="zero-based manifest entry index")
    parser.add_argument("--keys-file", type=Path, required=True, help="user-managed JSON key bundle; never commit it")
    parser.add_argument("--provider", choices=("auto", "sqlite", "ipfs", "filebase"), default="auto")
    args = parser.parse_args()
    try:
        entries = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or args.index < 0 or args.index >= len(entries):
            raise RetrievalError("manifest entry index is invalid")
        key_data = json.loads(args.keys_file.read_text(encoding="utf-8"))
        key_bundle = key_data.get("entries", {}).get(str(args.index))
        if key_bundle is None:
            raise DecryptionError("key bundle has no key for the selected entry")
        entry = entries[args.index]
        retrieve_and_decrypt(entry, key_bundle, args.provider)
        # Deliberately avoid printing the label, CID, or plaintext.
        print(f"Entry {args.index}: {entry.get('sensitivity_tier')} retrieval, integrity, and authenticated decryption succeeded.")
        return 0
    except Exception as exc:
        print(f"Entry retrieval/decryption failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
