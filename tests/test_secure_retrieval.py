import base64
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from src.encryption import aes_encrypt, derive_aes_key_via_ecc, encrypt_for_tier, generate_ecc_keypair
from src.secure_retrieval import (
    DecryptionError, IntegrityError, RetrievalError, decrypt_verified_entry,
    retrieve_payload, verify_payload,
)


def b64(data):
    return base64.b64encode(data).decode("ascii")


class SecureRetrievalTests(unittest.TestCase):
    def test_aes_gcm_requests_a_fresh_96_bit_nonce_per_invocation(self):
        from unittest.mock import patch

        key = b"k" * 32
        nonce1, nonce2 = b"\x01" * 12, b"\x02" * 12
        with patch("src.encryption.os.urandom", side_effect=(nonce1, nonce2)) as random_bytes:
            first = aes_encrypt(key, b"synthetic")
            second = aes_encrypt(key, b"synthetic")
        self.assertEqual(first["nonce"], nonce1)
        self.assertEqual(second["nonce"], nonce2)
        self.assertEqual(len(first["nonce"]), 12)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertEqual(random_bytes.call_args_list[0].args, (12,))
        self.assertEqual(random_bytes.call_args_list[1].args, (12,))

    def test_hkdf_info_separates_high_layer_keys(self):
        private, _ = generate_ecc_keypair()
        _, peer_public = generate_ecc_keypair()
        layer1 = derive_aes_key_via_ecc(private, peer_public, info=b"tier-high-layer1")
        layer2 = derive_aes_key_via_ecc(private, peer_public, info=b"tier-high-layer2")
        self.assertEqual(len(layer1), 32)
        self.assertNotEqual(layer1, layer2)

    def make_case(self, tier):
        plaintext = b'["synthetic-value", "not-real-data"]'
        result = encrypt_for_tier(tier, plaintext)
        entry = {
            "sensitivity_tier": tier,
            "encryption": result.to_public_dict(),
            "storage": {"local_cid": "bafytest", "filebase_cid": "bafytest"},
        }
        payload = json.dumps(result.to_public_dict()).encode()
        if tier == "Low":
            keys = {"aes_key_b64": b64(result._debug_keys["aes_key"])}
        elif tier == "Medium":
            keys = {"aes_key_b64": b64(result._debug_keys["aes_key"])}
        else:
            keys = {
                "layer1_key_b64": b64(result._debug_keys["key1"]),
                "layer2_key_b64": b64(result._debug_keys["key2"]),
            }
        return entry, payload, keys, plaintext

    def test_successful_round_trip_for_each_tier(self):
        for tier in ("Low", "Medium", "High"):
            with self.subTest(tier=tier):
                entry, payload, keys, plaintext = self.make_case(tier)
                self.assertEqual(decrypt_verified_entry(entry, payload, keys), plaintext)

    def test_corrupted_payload_fails_integrity(self):
        entry, payload, keys, _ = self.make_case("Low")
        corrupted = payload[:-2] + b"xx"
        with self.assertRaises(IntegrityError):
            decrypt_verified_entry(entry, corrupted, keys)

    def test_wrong_key_fails_gcm_authentication(self):
        entry, payload, keys, _ = self.make_case("Low")
        keys["aes_key_b64"] = b64(b"\x00" * 32)
        with self.assertRaisesRegex(DecryptionError, "authentication failed"):
            decrypt_verified_entry(entry, payload, keys)

    def test_manifest_integrity_mismatch_fails_before_decryption(self):
        entry, payload, _, _ = self.make_case("High")
        entry["encryption"]["integrity_hash_blake2"] = "0" * 64
        with self.assertRaises(IntegrityError):
            verify_payload(entry, payload)

    def test_medium_tier_can_rederive_key_from_ecdh_key_material(self):
        entry, payload, _, plaintext = self.make_case("Medium")
        # The encryptor's test-only key material demonstrates the existing
        # ECDH relationship; production keys must be supplied externally.
        result = encrypt_for_tier("Medium", plaintext)
        entry = {"sensitivity_tier": "Medium", "encryption": result.to_public_dict()}
        payload = json.dumps(result.to_public_dict()).encode()
        recipient_pem = result._debug_keys["recipient_private_key"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        keys = {
            "recipient_private_key_pem": recipient_pem,
            "sender_public_key_hex": result._debug_keys["sender_public_key_hex"],
        }
        self.assertEqual(decrypt_verified_entry(entry, payload, keys), plaintext)

    def test_medium_tier_rejects_invalid_ecdh_peer_point(self):
        entry, payload, _, _ = self.make_case("Medium")
        result = encrypt_for_tier("Medium", b"synthetic")
        entry = {"sensitivity_tier": "Medium", "encryption": result.to_public_dict()}
        payload = json.dumps(result.to_public_dict()).encode()
        private_pem = result._debug_keys["recipient_private_key"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        keys = {
            "recipient_private_key_pem": private_pem,
            "sender_public_key_hex": "00",
        }
        with self.assertRaisesRegex(DecryptionError, "ECDH key material is invalid"):
            decrypt_verified_entry(entry, payload, keys)

    def test_high_tier_layer_order_is_authenticated(self):
        entry, payload, keys, _ = self.make_case("High")
        keys["layer1_key_b64"], keys["layer2_key_b64"] = (
            keys["layer2_key_b64"], keys["layer1_key_b64"]
        )
        with self.assertRaisesRegex(DecryptionError, "authentication failed"):
            decrypt_verified_entry(entry, payload, keys)

    @patch("src.secure_retrieval.requests.post")
    def test_retrieves_existing_cid_from_local_ipfs(self, post):
        entry, payload, _, _ = self.make_case("Low")
        post.return_value.content = payload
        post.return_value.raise_for_status.return_value = None
        self.assertEqual(retrieve_payload(entry, "ipfs"), payload)
        self.assertEqual(post.call_args.kwargs["params"], {"arg": "bafytest"})

    @patch("src.secure_retrieval.requests.post")
    def test_missing_payload_is_reported(self, post):
        import requests
        post.side_effect = requests.ConnectionError("offline")
        entry, _, _, _ = self.make_case("Low")
        with self.assertRaises(RetrievalError):
            retrieve_payload(entry, "ipfs")

    def test_missing_key_fails_closed(self):
        entry, payload, _, _ = self.make_case("Medium")
        with self.assertRaises(DecryptionError):
            decrypt_verified_entry(entry, payload, {})


if __name__ == "__main__":
    unittest.main()
