"""
encryption.py

Adaptive multi-layer encryption module.

This is the concrete version of the proposal's "Basic / Strong / Multi-layer
encryption" tiers -- previously named but not mapped to specific algorithms.
Mapping used here:

  Low    -> "Basic encryption":      AES-256-GCM, single layer.
  Medium -> "Strong encryption":     AES-256-GCM, with the AES key itself
                                      protected via ECC (ECDH key agreement +
                                      HKDF), simulating a secure key-exchange
                                      step before storage/transmission.
  High   -> "Multi-layer encryption": data is AES-256-GCM encrypted TWICE
                                      with independently ECC-derived keys
                                      (defense in depth), then a BLAKE2b
                                      hash of the final ciphertext is
                                      computed -- this hash is exactly what
                                      would later become the IPFS CID input
                                      once the storage layer is added.

All three tiers use the `cryptography` library:
  - AES-256-GCM  : cryptography.hazmat.primitives.ciphers.aead.AESGCM
  - ECC (ECDH)   : cryptography.hazmat.primitives.asymmetric.ec (SECP256R1)
  - Key derivation: HKDF-SHA256 over the ECDH shared secret
  - Hashing      : hashlib.blake2b (BLAKE2)

Nothing here touches storage (IPFS/Filecoin) or the blockchain layer --
per your request this module stops at "encrypted, ready to be stored".
"""

import os
import hashlib
import base64
import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# ECC helpers (secure key exchange -> derives an AES key from a shared secret)
# ---------------------------------------------------------------------------

def generate_ecc_keypair():
    """Generate an ECC (SECP256R1) private/public keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def derive_aes_key_via_ecc(local_private_key, peer_public_key, info: bytes = b"adaptive-security-tier") -> bytes:
    """
    Perform an ECDH key exchange between local_private_key and peer_public_key,
    then run the shared secret through HKDF-SHA256 to derive a 32-byte AES-256 key.
    """
    shared_secret = local_private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived_key


# ---------------------------------------------------------------------------
# AES-256-GCM primitive
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": nonce, "ciphertext": ciphertext}


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# BLAKE2 hashing (integrity fingerprint -- future CID input)
# ---------------------------------------------------------------------------

def blake2_hash(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class EncryptionResult:
    tier: str
    scheme: str
    layers: list = field(default_factory=list)   # list of per-layer metadata dicts
    final_ciphertext_b64: str = ""
    integrity_hash_blake2: str = ""
    # Keys returned ONLY so this demo can round-trip/decrypt for verification.
    # In a real deployment these would be handled by a key-management service,
    # never stored alongside the ciphertext.
    _debug_keys: dict = field(default_factory=dict, repr=False)

    def to_public_dict(self) -> dict:
        """Metadata safe to log/print -- excludes raw key material."""
        return {
            "tier": self.tier,
            "scheme": self.scheme,
            "layers": self.layers,
            "final_ciphertext_b64": self.final_ciphertext_b64,
            "integrity_hash_blake2": self.integrity_hash_blake2,
        }


# ---------------------------------------------------------------------------
# Tier-specific encryption
# ---------------------------------------------------------------------------

def encrypt_low(plaintext: bytes) -> EncryptionResult:
    """Low sensitivity -> Basic encryption: single-layer AES-256-GCM."""
    key = AESGCM.generate_key(bit_length=256)
    enc = aes_encrypt(key, plaintext)
    blob = enc["nonce"] + enc["ciphertext"]
    return EncryptionResult(
        tier="Low",
        scheme="AES-256-GCM (single layer)",
        layers=[{"layer": 1, "algorithm": "AES-256-GCM"}],
        final_ciphertext_b64=base64.b64encode(blob).decode(),
        integrity_hash_blake2=blake2_hash(blob),
        _debug_keys={"aes_key": key},
    )


def encrypt_medium(plaintext: bytes) -> EncryptionResult:
    """Medium sensitivity -> Strong encryption: AES-256-GCM with ECC-derived key (ECDH)."""
    # Simulate sender/recipient ECC keypairs for a secure key exchange.
    sender_priv, sender_pub = generate_ecc_keypair()
    recipient_priv, recipient_pub = generate_ecc_keypair()

    aes_key = derive_aes_key_via_ecc(sender_priv, recipient_pub, info=b"tier-medium")
    enc = aes_encrypt(aes_key, plaintext)
    blob = enc["nonce"] + enc["ciphertext"]

    sender_pub_bytes = sender_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return EncryptionResult(
        tier="Medium",
        scheme="AES-256-GCM + ECC (ECDH) key exchange",
        layers=[
            {"layer": 1, "algorithm": "ECC SECP256R1 ECDH", "role": "key agreement"},
            {"layer": 2, "algorithm": "AES-256-GCM", "role": "data encryption"},
        ],
        final_ciphertext_b64=base64.b64encode(blob).decode(),
        integrity_hash_blake2=blake2_hash(blob),
        _debug_keys={
            "aes_key": aes_key,
            "sender_public_key_hex": sender_pub_bytes.hex(),
            "recipient_private_key": recipient_priv,
        },
    )


def encrypt_high(plaintext: bytes) -> EncryptionResult:
    """
    High sensitivity -> Multi-layer encryption:
      Layer 1: AES-256-GCM with ECC-derived key #1
      Layer 2: AES-256-GCM (again) with an independently ECC-derived key #2
      Then: BLAKE2 hash of the final ciphertext (future CID input).
    """
    # Layer 1 key exchange
    priv1, pub1 = generate_ecc_keypair()
    peer_priv1, peer_pub1 = generate_ecc_keypair()
    key1 = derive_aes_key_via_ecc(priv1, peer_pub1, info=b"tier-high-layer1")
    enc1 = aes_encrypt(key1, plaintext)
    layer1_blob = enc1["nonce"] + enc1["ciphertext"]

    # Layer 2 key exchange (independent keypairs -> independent key)
    priv2, pub2 = generate_ecc_keypair()
    peer_priv2, peer_pub2 = generate_ecc_keypair()
    key2 = derive_aes_key_via_ecc(priv2, peer_pub2, info=b"tier-high-layer2")
    enc2 = aes_encrypt(key2, layer1_blob)
    layer2_blob = enc2["nonce"] + enc2["ciphertext"]

    final_hash = blake2_hash(layer2_blob)

    return EncryptionResult(
        tier="High",
        scheme="AES-256-GCM x2 (independent ECC-derived keys) + BLAKE2 integrity hash",
        layers=[
            {"layer": 1, "algorithm": "ECC SECP256R1 ECDH -> AES-256-GCM", "role": "inner encryption"},
            {"layer": 2, "algorithm": "ECC SECP256R1 ECDH -> AES-256-GCM", "role": "outer encryption"},
            {"layer": 3, "algorithm": "BLAKE2b-256", "role": "integrity fingerprint (future CID input)"},
        ],
        final_ciphertext_b64=base64.b64encode(layer2_blob).decode(),
        integrity_hash_blake2=final_hash,
        _debug_keys={"key1": key1, "key2": key2},
    )


TIER_ENCRYPTORS = {
    "Low": encrypt_low,
    "Medium": encrypt_medium,
    "High": encrypt_high,
}


def encrypt_for_tier(tier: str, plaintext: bytes) -> EncryptionResult:
    if tier not in TIER_ENCRYPTORS:
        raise ValueError(f"Unknown sensitivity tier: {tier}")
    return TIER_ENCRYPTORS[tier](plaintext)


if __name__ == "__main__":
    sample = json.dumps({"patient_name": "Jane Doe", "diagnosis": "asthma"}).encode()
    for tier in ["Low", "Medium", "High"]:
        result = encrypt_for_tier(tier, sample)
        print(f"--- {tier} ---")
        print(json.dumps(result.to_public_dict(), indent=2))
