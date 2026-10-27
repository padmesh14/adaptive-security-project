"""Opt-in envelope-key management for newly encrypted records.

The encryption bytes are produced by the existing tier encryptors. This module
wraps only their generated AES keys; it does not change any ciphertext format.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption import encrypt_for_tier


FORMAT_VERSION = 1
WRAPPING_ALGORITHM = "AES-256-GCM"
LOCAL_PROVIDER_ID = "local-development"
DEFAULT_MASTER_KEY_PATH = Path.home() / ".adaptive-security" / "dev-kek-v1.key"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
TIER_KEY_SLOTS = {
    "Low": ("aes_key",),
    "Medium": ("aes_key",),
    "High": ("layer1_key", "layer2_key"),
}
TIER_DEBUG_KEY_NAMES = {
    "Low": {"aes_key": "aes_key"},
    "Medium": {"aes_key": "aes_key"},
    "High": {"layer1_key": "key1", "layer2_key": "key2"},
}


class KeyManagementError(Exception):
    """Key provider or wrapped-key metadata failure."""


class KeyProvider(ABC):
    """Adapter boundary for a local provider or an authorized cloud KMS."""

    provider_id: str
    key_id: str
    wrapping_algorithm: str

    @abstractmethod
    def wrap_key(self, data_key: bytes, *, context: bytes) -> str:
        """Return an encoded wrapped key; never return plaintext key metadata."""

    @abstractmethod
    def unwrap_key(self, wrapped_key: str, *, context: bytes) -> bytes:
        """Return the data key only to the authorized caller's process memory."""


class LocalDevelopmentKeyProvider(KeyProvider):
    """Development-only AES-GCM wrapper backed by a mode-0600 local KEK file.

    This file-backed key-encryption key is not a production KMS: it is not
    hardware protected, centrally authorized, or automatically backed up.
    """

    provider_id = LOCAL_PROVIDER_ID
    wrapping_algorithm = WRAPPING_ALGORITHM

    @staticmethod
    def _validate_key_path(path: Path) -> None:
        resolved = path.resolve()
        if resolved == PROJECT_ROOT or PROJECT_ROOT in resolved.parents:
            raise KeyManagementError("development key must be stored outside the project directory")

    def __init__(self, master_key_path: str | Path = DEFAULT_MASTER_KEY_PATH):
        self.master_key_path = Path(master_key_path).expanduser()
        self._validate_key_path(self.master_key_path)
        try:
            metadata = self.master_key_path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise KeyManagementError("development key file must be a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise KeyManagementError("development key file permissions must be owner-only (0600)")
            if metadata.st_nlink != 1:
                raise KeyManagementError("development key file must not have additional hard links")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise KeyManagementError("development key file must be owned by the current user")
            parent_metadata = self.master_key_path.parent.stat()
            parent_mode = stat.S_IMODE(parent_metadata.st_mode)
            if not stat.S_ISDIR(parent_metadata.st_mode) or parent_mode & 0o077:
                raise KeyManagementError("development key directory permissions must be owner-only (0700)")
            if hasattr(os, "geteuid") and parent_metadata.st_uid != os.geteuid():
                raise KeyManagementError("development key directory must be owned by the current user")
            master_key = self.master_key_path.read_bytes()
        except FileNotFoundError as exc:
            raise KeyManagementError("development key is missing; initialize it before use") from exc
        except OSError as exc:
            raise KeyManagementError("development key file could not be read") from exc
        if len(master_key) != 32:
            raise KeyManagementError("development key file has invalid length")
        self._master_key = master_key
        # A stable, non-secret key identifier lets manifests reject the wrong KEK.
        self.key_id = "dev-kek-" + hashlib.sha256(master_key).hexdigest()[:16]

    @classmethod
    def initialize(cls, master_key_path: str | Path = DEFAULT_MASTER_KEY_PATH) -> "LocalDevelopmentKeyProvider":
        path = Path(master_key_path).expanduser()
        cls._validate_key_path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_metadata = path.parent.stat()
        if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_IMODE(parent_metadata.st_mode) & 0o077:
            raise KeyManagementError("development key directory permissions must be owner-only (0700)")
        if hasattr(os, "geteuid") and parent_metadata.st_uid != os.geteuid():
            raise KeyManagementError("development key directory must be owned by the current user")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise KeyManagementError("refusing to overwrite an existing development key") from exc
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as key_file:
                key_file.write(secrets.token_bytes(32))
                key_file.flush()
                os.fsync(key_file.fileno())
        except Exception:
            try:
                path.unlink(missing_ok=True)
            finally:
                raise
        return cls(path)

    def wrap_key(self, data_key: bytes, *, context: bytes) -> str:
        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise KeyManagementError("only 32-byte AES data keys can be wrapped")
        nonce = secrets.token_bytes(12)
        try:
            wrapped = AESGCM(self._master_key).encrypt(nonce, data_key, context)
        except Exception as exc:
            raise KeyManagementError("data key wrapping failed") from exc
        return base64.b64encode(nonce + wrapped).decode("ascii")

    def unwrap_key(self, wrapped_key: str, *, context: bytes) -> bytes:
        try:
            raw = base64.b64decode(wrapped_key, validate=True)
            if len(raw) != 12 + 32 + 16:
                raise ValueError("invalid wrapped key size")
            data_key = AESGCM(self._master_key).decrypt(raw[:12], raw[12:], context)
        except (ValueError, TypeError, InvalidTag) as exc:
            raise KeyManagementError("wrapped key authentication failed") from exc
        if len(data_key) != 32:
            raise KeyManagementError("unwrapped key has invalid length")
        return data_key


def _aad(*, record_ref: str, tier: str, slot: str, provider_id: str, key_id: str,
         wrapping_algorithm: str) -> bytes:
    value = {
        "format_version": FORMAT_VERSION,
        "record_ref": record_ref,
        "tier": tier,
        "slot": slot,
        "provider": provider_id,
        "key_id": key_id,
        "wrapping_algorithm": wrapping_algorithm,
    }
    return ("adaptive-security-wrapped-key:" + json.dumps(value, sort_keys=True, separators=(",", ":"))).encode()


def encrypt_managed_record(
    tier: str,
    plaintext: bytes,
    key_provider: KeyProvider,
    *,
    record_ref: str | None = None,
) -> dict:
    """Encrypt with the existing tier format and return durable wrapped-key metadata.

    `record_ref` should be an opaque UUID, never a personal identifier or raw
    column label. It is generated when omitted and authenticated as AES-GCM AAD.
    """
    if not isinstance(key_provider, KeyProvider):
        raise KeyManagementError("a configured KeyProvider instance is required")
    record_ref = record_ref or str(uuid.uuid4())
    if not isinstance(record_ref, str) or not record_ref or len(record_ref) > 128:
        raise KeyManagementError("record_ref must be a non-empty opaque identifier")
    try:
        encrypted = encrypt_for_tier(tier, plaintext)
        slots = TIER_KEY_SLOTS[tier]
    except (KeyError, ValueError) as exc:
        raise KeyManagementError("unsupported sensitivity tier") from exc

    wrapped_keys = {}
    for slot in slots:
        raw_key = encrypted._debug_keys.get(TIER_DEBUG_KEY_NAMES[tier][slot])
        if not isinstance(raw_key, bytes) or len(raw_key) != 32:
            raise KeyManagementError("existing encryptor did not provide the expected data key")
        wrapped_keys[slot] = key_provider.wrap_key(
            raw_key,
            context=_aad(
                record_ref=record_ref,
                tier=tier,
                slot=slot,
                provider_id=key_provider.provider_id,
                key_id=key_provider.key_id,
                wrapping_algorithm=key_provider.wrapping_algorithm,
            ),
        )

    return {
        "record_ref": record_ref,
        "sensitivity_tier": tier,
        "encryption": encrypted.to_public_dict(),
        "key_management": {
            "format_version": FORMAT_VERSION,
            "provider": key_provider.provider_id,
            "wrapping_algorithm": key_provider.wrapping_algorithm,
            "key_id": key_provider.key_id,
            "wrapped_keys": wrapped_keys,
        },
    }


def decrypt_managed_entry(entry: dict, payload: bytes, key_provider: KeyProvider) -> bytes:
    """Verify ciphertext and unwrap/decrypt only with matching key metadata."""
    if not isinstance(key_provider, KeyProvider):
        raise KeyManagementError("a configured KeyProvider instance is required")
    try:
        record_ref = entry["record_ref"]
        tier = entry["sensitivity_tier"]
        metadata = entry["key_management"]
        version = metadata["format_version"]
        provider_id = metadata["provider"]
        algorithm = metadata["wrapping_algorithm"]
        key_id = metadata["key_id"]
        wrapped_keys = metadata["wrapped_keys"]
        slots = TIER_KEY_SLOTS[tier]
    except (KeyError, TypeError) as exc:
        raise KeyManagementError("managed key metadata is incomplete or invalid") from exc
    if version != FORMAT_VERSION or algorithm != key_provider.wrapping_algorithm:
        raise KeyManagementError("unsupported key metadata version or wrapping algorithm")
    if provider_id != key_provider.provider_id or key_id != key_provider.key_id:
        raise KeyManagementError("configured key provider does not match the manifest reference")
    if not isinstance(record_ref, str) or not isinstance(wrapped_keys, dict):
        raise KeyManagementError("managed key metadata is invalid")
    if set(wrapped_keys) != set(slots):
        raise KeyManagementError("managed key slots do not match the sensitivity tier")

    key_bundle = {}
    bundle_names = {"Low": {"aes_key": "aes_key_b64"},
                    "Medium": {"aes_key": "aes_key_b64"},
                    "High": {"layer1_key": "layer1_key_b64", "layer2_key": "layer2_key_b64"}}[tier]
    for slot in slots:
        raw_key = key_provider.unwrap_key(
            wrapped_keys[slot],
            context=_aad(record_ref=record_ref, tier=tier, slot=slot,
                         provider_id=provider_id, key_id=key_id,
                         wrapping_algorithm=algorithm),
        )
        key_bundle[bundle_names[slot]] = base64.b64encode(raw_key).decode("ascii")

    # This call verifies the retrieved envelope, manifest binding, digest and
    # every AES-GCM data layer before returning plaintext.
    from src.secure_retrieval import decrypt_verified_entry
    return decrypt_verified_entry(entry, payload, key_bundle)


def retrieve_and_decrypt_managed(entry: dict, key_provider: KeyProvider, storage_provider: str = "auto") -> bytes:
    """Fetch existing bytes using the stored CID, then verify and decrypt."""
    from src.secure_retrieval import retrieve_payload
    payload = retrieve_payload(entry, storage_provider)
    return decrypt_managed_entry(entry, payload, key_provider)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the local development wrapping key")
    parser.add_argument("command", choices=("init",))
    parser.add_argument("--key-file", type=Path, default=DEFAULT_MASTER_KEY_PATH)
    args = parser.parse_args()
    try:
        LocalDevelopmentKeyProvider.initialize(args.key_file)
        print("Initialized owner-only local development key file. Keep a separately encrypted backup.")
        return 0
    except Exception as exc:
        print(f"Key-provider initialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
