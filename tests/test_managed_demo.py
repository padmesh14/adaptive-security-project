import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import managed_demo


class ManagedDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key_file = self.root / "private" / "demo-kek.key"
        self.demo_root = self.root / "demo-output"
        self.payloads = {}
        self.cid_counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def fake_dual_pin(self, key_name, encryption):
        cid = f"bafy-synthetic-{self.cid_counter}"
        self.cid_counter += 1
        self.payloads[cid] = json.dumps(encryption).encode()
        return {
            "key": key_name,
            "local_cid": cid,
            "filebase_cid": None,
            "cids_match": False,
        }

    def fake_retrieve(self, entry, provider):
        cid = entry["storage"]["local_cid"]
        return self.payloads[cid]

    @patch("src.managed_demo.connect_local")
    @patch("src.secure_retrieval.retrieve_payload")
    @patch("src.managed_demo.dual_pin")
    def test_synthetic_workflow_completes_without_blockchain(self, dual_pin, retrieve, connect):
        dual_pin.side_effect = self.fake_dual_pin
        retrieve.side_effect = self.fake_retrieve
        result = managed_demo.run_managed_demo(key_file=self.key_file, demo_root=self.demo_root)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["records_verified"], 3)
        self.assertFalse(result["blockchain_enabled"])
        connect.assert_not_called()
        manifest = json.loads((Path(result["output_dir"]) / "manifest.json").read_text())
        self.assertEqual(len(manifest), 3)
        self.assertEqual({entry["sensitivity_tier"] for entry in manifest}, {"Low", "Medium", "High"})
        self.assertTrue(all(entry.get("key_management", {}).get("wrapped_keys") for entry in manifest))
        self.assertTrue(all(entry.get("storage", {}).get("local_cid") for entry in manifest))
        self.assertTrue(all("blockchain_registration" not in entry for entry in manifest))

    @patch("src.managed_demo.dual_pin")
    def test_storage_failure_is_not_reported_as_success(self, dual_pin):
        dual_pin.return_value = {"local_cid": None, "filebase_cid": None}
        result = managed_demo.run_managed_demo(key_file=self.key_file, demo_root=self.demo_root)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "storage")
        self.assertEqual(result["error_type"], "RuntimeError")
        stored = json.loads((Path(result["output_dir"]) / "manifest.json").read_text())
        self.assertTrue(all("blockchain_registration" not in entry for entry in stored))

    @patch("src.secure_retrieval.retrieve_payload", return_value=b"corrupted synthetic payload")
    @patch("src.managed_demo.dual_pin")
    def test_integrity_failure_does_not_report_decryption_success(self, dual_pin, retrieve):
        dual_pin.side_effect = self.fake_dual_pin
        result = managed_demo.run_managed_demo(key_file=self.key_file, demo_root=self.demo_root)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "retrieval_and_decryption")
        self.assertEqual(result["error_type"], "IntegrityError")

    @patch.dict("os.environ", {"CID_REGISTRY_RECORD_ID_SECRET": "synthetic-test-only-secret"})
    @patch("src.managed_demo.connect_local", side_effect=ConnectionError("offline"))
    @patch("src.managed_demo.dual_pin")
    def test_blockchain_connection_failure_is_reported_and_local_only(self, dual_pin, connect):
        dual_pin.side_effect = self.fake_dual_pin
        result = managed_demo.run_managed_demo(
            with_blockchain=True,
            key_file=self.key_file,
            demo_root=self.demo_root,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "local_blockchain_registration")
        self.assertEqual(result["error_type"], "ConnectionError")
        connect.assert_called_once_with()
        manifest = json.loads((Path(result["output_dir"]) / "manifest.json").read_text())
        self.assertTrue(all(entry["storage"]["local_cid"] for entry in manifest))
        self.assertTrue(all("blockchain_registration" not in entry for entry in manifest))

    def test_blockchain_requires_local_secret_before_creating_output(self):
        with patch.dict("os.environ", {}, clear=True):
            result = managed_demo.run_managed_demo(
                with_blockchain=True,
                key_file=self.key_file,
                demo_root=self.demo_root,
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "preflight")
        self.assertFalse(self.demo_root.exists())

    @patch.dict("os.environ", {"CID_REGISTRY_RECORD_ID_SECRET": "synthetic-test-only-secret"})
    @patch("src.managed_demo.register_manifest_entries")
    @patch("src.managed_demo.load_registry")
    @patch("src.managed_demo.deploy_local_registry", return_value="0x" + "12" * 20)
    @patch("src.managed_demo.connect_local")
    @patch("src.secure_retrieval.retrieve_payload")
    @patch("src.managed_demo.dual_pin")
    def test_optional_blockchain_stage_registers_using_local_chain_adapter(
        self, dual_pin, retrieve, connect, deploy, load_registry, register
    ):
        dual_pin.side_effect = self.fake_dual_pin
        retrieve.side_effect = self.fake_retrieve
        web3 = SimpleNamespace(eth=SimpleNamespace(chain_id=31337))
        connect.return_value = web3
        register.side_effect = lambda entries, *_args, **_kwargs: [
            {"index": index, "status": "registered"} for index, _entry in enumerate(entries)
        ]

        result = managed_demo.run_managed_demo(
            with_blockchain=True,
            key_file=self.key_file,
            demo_root=self.demo_root,
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["chain_id"], 31337)
        connect.assert_called_once_with()
        deploy.assert_called_once()
        self.assertTrue(str(deploy.call_args.args[1]).startswith(result["output_dir"]))
        self.assertEqual(register.call_args.kwargs["secret"], "synthetic-test-only-secret")
        manifest = json.loads((Path(result["output_dir"]) / "manifest.json").read_text())
        self.assertEqual(len(manifest), 3)


if __name__ == "__main__":
    unittest.main()
