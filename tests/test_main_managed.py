import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import main
from src.key_management import LocalDevelopmentKeyProvider


class ManagedPipelineSelectionTests(unittest.TestCase):
    def test_aws_selection_requires_explicit_nonsecret_key_id_and_region(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "AWS_KMS_KEY_ID and AWS_REGION"):
                main.build_managed_key_provider("aws-kms")

    def test_aws_selection_uses_only_explicitly_configured_kms_adapter(self):
        with patch.dict(os.environ, {"AWS_KMS_KEY_ID": "alias/synthetic", "AWS_REGION": "us-east-1"}, clear=True), \
             patch("boto3.client") as boto_client:
            boto_client.return_value = object()
            provider = main.build_managed_key_provider("aws-kms")
        self.assertEqual(provider.provider_id, "aws-kms")
        boto_client.assert_called_once()

    def test_managed_pipeline_writes_new_unique_manifest_with_wrapped_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            provider = LocalDevelopmentKeyProvider.initialize(root / "kek.key")
            manifest = root / "new-managed-run.json"
            with patch.object(main, "OUTPUT_DIR", str(root)), \
                 patch.object(main.pd, "read_csv", return_value=pd.DataFrame({"temperature_c": ["21", "22"]})):
                main.run_pipeline(str(manifest), refuse_overwrite=True, key_provider=provider)
            entries = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["key_management"]["provider"], "local-development")
            self.assertIn("wrapped_keys", entries[0]["key_management"])
            self.assertNotIn("_debug_keys", manifest.read_text(encoding="utf-8"))

            reader = r'''
import json, sys
from pathlib import Path
from src.key_management import LocalDevelopmentKeyProvider, decrypt_managed_entry
manifest_path, key_path = map(Path, sys.argv[1:])
entry = json.loads(manifest_path.read_text())[0]
payload = json.dumps(entry["encryption"]).encode()
restored = decrypt_managed_entry(entry, payload, LocalDevelopmentKeyProvider(key_path))
assert restored == b'["21", "22"]'
print("fresh-process synthetic recovery passed")
'''
            recovered = subprocess.run(
                [sys.executable, "-c", reader, str(manifest), str(root / "kek.key")],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertEqual(recovered.stdout.strip(), "fresh-process synthetic recovery passed")

    def test_legacy_pipeline_still_passes_no_managed_provider_by_default(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "legacy.json"
            with patch.object(main, "OUTPUT_DIR", str(root)), \
                 patch.object(main.pd, "read_csv", return_value=pd.DataFrame({"temperature_c": ["21", "22"]})):
                main.run_pipeline(str(manifest), refuse_overwrite=True)
            entry = json.loads(manifest.read_text(encoding="utf-8"))[0]
            self.assertNotIn("key_management", entry)


if __name__ == "__main__":
    unittest.main()
