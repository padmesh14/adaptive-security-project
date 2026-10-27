import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.encryption_pipeline import encrypt_dataset_by_column
from src.key_management import (
    KeyManagementError,
    LocalDevelopmentKeyProvider,
    decrypt_managed_entry,
    encrypt_managed_record,
)


SYNTHETIC_PLAINTEXT = b'["synthetic-key-lifecycle-test"]'
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ManagedKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.provider = LocalDevelopmentKeyProvider.initialize(self.root / "dev-kek.key")

    def tearDown(self):
        self.temp.cleanup()

    def encrypted(self, tier="Low"):
        entry = encrypt_managed_record(tier, SYNTHETIC_PLAINTEXT, self.provider)
        payload = json.dumps(entry["encryption"]).encode("utf-8")
        return entry, payload

    def test_encrypt_in_one_process_decrypt_in_another_for_all_tiers(self):
        bundle_path = self.root / "synthetic_records.json"
        key_path = self.root / "dev-kek.key"
        writer = r'''
import base64, json, sys
from pathlib import Path
from src.key_management import LocalDevelopmentKeyProvider, encrypt_managed_record
root, key_path = Path(sys.argv[1]), Path(sys.argv[2])
provider = LocalDevelopmentKeyProvider(key_path)
records = []
for tier in ("Low", "Medium", "High"):
    entry = encrypt_managed_record(tier, b'["synthetic-key-lifecycle-test"]', provider)
    payload = json.dumps(entry["encryption"]).encode()
    payload_name = f"payload-{tier.lower()}.json"
    (root / payload_name).write_bytes(payload)
    records.append({"entry": entry, "payload_name": payload_name})
(root / "records.json").write_text(json.dumps(records))
'''
        reader = r'''
import json, sys
from pathlib import Path
from src.key_management import LocalDevelopmentKeyProvider, decrypt_managed_entry
root, key_path = Path(sys.argv[1]), Path(sys.argv[2])
provider = LocalDevelopmentKeyProvider(key_path)
records = json.loads((root / "records.json").read_text())
expected = b'["synthetic-key-lifecycle-test"]'
for record in records:
    payload = (root / record["payload_name"]).read_bytes()
    assert decrypt_managed_entry(record["entry"], payload, provider) == expected
print("verified 3 synthetic records")
'''
        writer_result = subprocess.run(
            [sys.executable, "-c", writer, str(self.root), str(key_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(writer_result.returncode, 0, writer_result.stderr)
        reader_result = subprocess.run(
            [sys.executable, "-c", reader, str(self.root), str(key_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(reader_result.returncode, 0, reader_result.stderr)
        self.assertEqual(reader_result.stdout.strip(), "verified 3 synthetic records")
        self.assertNotIn("synthetic-key-lifecycle-test", reader_result.stdout)

    def test_missing_wrapped_key_fails_closed(self):
        entry, payload = self.encrypted("High")
        del entry["key_management"]["wrapped_keys"]["layer2_key"]
        with self.assertRaises(KeyManagementError):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_wrong_wrapping_key_is_rejected(self):
        entry, payload = self.encrypted("Medium")
        wrong_provider = LocalDevelopmentKeyProvider.initialize(self.root / "wrong-kek.key")
        with self.assertRaisesRegex(KeyManagementError, "does not match"):
            decrypt_managed_entry(entry, payload, wrong_provider)

    def test_corrupted_wrapped_key_fails_authentication(self):
        entry, payload = self.encrypted("Low")
        wrapped = bytearray(base64.b64decode(entry["key_management"]["wrapped_keys"]["aes_key"]))
        wrapped[-1] ^= 1
        entry["key_management"]["wrapped_keys"]["aes_key"] = base64.b64encode(wrapped).decode()
        with self.assertRaisesRegex(KeyManagementError, "wrapped key authentication failed"):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_invalid_version_metadata_fails_closed(self):
        entry, payload = self.encrypted("Low")
        entry["key_management"]["format_version"] = 999
        with self.assertRaisesRegex(KeyManagementError, "unsupported key metadata"):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_record_reference_substitution_fails_wrapped_key_authentication(self):
        entry, payload = self.encrypted("Medium")
        entry["record_ref"] = "different-opaque-record-reference"
        with self.assertRaisesRegex(KeyManagementError, "wrapped key authentication failed"):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_tier_substitution_fails_wrapped_key_authentication(self):
        entry, payload = self.encrypted("Low")
        entry["sensitivity_tier"] = "Medium"
        with self.assertRaisesRegex(KeyManagementError, "wrapped key authentication failed"):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_data_ciphertext_authentication_failure_is_not_bypassed_by_updated_hash(self):
        entry, _ = self.encrypted("Low")
        entry = copy.deepcopy(entry)
        blob = bytearray(base64.b64decode(entry["encryption"]["final_ciphertext_b64"]))
        blob[-1] ^= 1
        entry["encryption"]["final_ciphertext_b64"] = base64.b64encode(blob).decode()
        entry["encryption"]["integrity_hash_blake2"] = hashlib.blake2b(blob, digest_size=32).hexdigest()
        payload = json.dumps(entry["encryption"]).encode()
        # The hash and manifest now agree with the altered bytes. GCM must
        # still reject the ciphertext before any plaintext is returned.
        from src.secure_retrieval import DecryptionError
        with self.assertRaisesRegex(DecryptionError, "authentication failed"):
            decrypt_managed_entry(entry, payload, self.provider)

    def test_manifest_contains_only_wrapped_key_material(self):
        entry, _ = self.encrypted("High")
        json_text = json.dumps(entry)
        self.assertNotIn("key1", json_text)
        self.assertNotIn("key2", json_text)
        self.assertEqual(set(entry["key_management"]["wrapped_keys"]), {"layer1_key", "layer2_key"})

    def test_pipeline_opt_in_emits_managed_metadata(self):
        result = encrypt_dataset_by_column(
            pd.DataFrame({"synthetic_metric": ["17", "19"]}),
            key_provider=self.provider,
        )
        entry = result["manifest"][0]
        self.assertIn("record_ref", entry)
        self.assertEqual(entry["key_management"]["provider"], "local-development")
        self.assertIn("wrapped_keys", entry["key_management"])
        self.assertNotIn("_debug_keys", json.dumps(entry))


if __name__ == "__main__":
    unittest.main()
