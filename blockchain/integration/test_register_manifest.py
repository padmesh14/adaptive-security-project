"""Offline unit tests for manifest-to-CIDRegistry registration behavior."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from web3 import Web3

from .cid_registry import LOCAL_CHAIN_ID, derive_record_id
from . import register_manifest as register_manifest_module
from .register_manifest import register_manifest_entries


CID = "QmdpcvPPPSo69QEtJn4eKc6L3H3rVWKWdywUSKABE3SN9y"
CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
SUBMITTER = "0x0000000000000000000000000000000000000001"


def make_entry() -> dict:
    return {
        "column": "timestamp",
        "sensitivity_tier": "Low",
        "encryption": {"final_ciphertext_b64": "kept-off-chain"},
        "storage": {"local_cid": CID, "filebase_cid": CID, "cids_match": True},
    }


class RegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = Mock()
        self.web3 = SimpleNamespace(eth=SimpleNamespace(chain_id=LOCAL_CHAIN_ID))
        self.registry.functions.getCID.return_value.call.return_value = ("", 0, "0x0000000000000000000000000000000000000000")

    @patch.object(register_manifest_module, "store_and_read_cid")
    def test_successful_registration_records_only_registration_metadata(self, store: Mock) -> None:
        store.return_value = (CID, 1234, SUBMITTER, "0x" + "ab" * 32)
        entry = make_entry()

        results = register_manifest_entries(
            [entry], self.registry, self.web3, namespace="test-project",
            secret="unit-test-secret", contract_address=CONTRACT,
        )

        self.assertEqual(results[0]["status"], "registered")
        registration = entry["blockchain_registration"]
        self.assertEqual(registration["status"], "registered")
        self.assertEqual(registration["cid"], CID)
        self.assertEqual(registration["chain_id"], LOCAL_CHAIN_ID)
        self.assertEqual(registration["contract_address"], Web3.to_checksum_address(CONTRACT))
        self.assertEqual(registration["transaction_hash"], "0x" + "ab" * 32)
        self.assertEqual(registration["timestamp"], 1234)
        self.assertNotIn("column", registration)
        self.assertEqual(entry["storage"]["local_cid"], CID)
        self.assertIn("encryption", entry)
        self.assertEqual(store.call_args.args[2], bytes.fromhex(registration["record_id"][2:]))
        self.assertEqual(store.call_args.args[3], CID)

    @patch.object(register_manifest_module, "store_and_read_cid")
    def test_repeat_registration_skips_transaction_and_keeps_original_hash(self, store: Mock) -> None:
        record_id = Web3.to_hex(derive_record_id("test-project", "timestamp", "unit-test-secret"))
        previous = {
            "status": "registered", "record_id": record_id, "chain_id": LOCAL_CHAIN_ID,
            "contract_address": Web3.to_checksum_address(CONTRACT), "cid": CID,
            "transaction_hash": "0x" + "34" * 32, "timestamp": 123,
        }
        entry = make_entry()
        entry["blockchain_registration"] = previous.copy()
        self.registry.functions.getCID.return_value.call.return_value = (CID, 123, SUBMITTER)

        results = register_manifest_entries(
            [entry], self.registry, self.web3, namespace="test-project",
            secret="unit-test-secret", contract_address=CONTRACT,
        )

        self.assertEqual(results[0]["status"], "already_registered")
        store.assert_not_called()
        self.assertEqual(entry["blockchain_registration"]["transaction_hash"], previous["transaction_hash"])
        self.assertEqual(entry["blockchain_registration"]["status"], "already_registered")

    @patch.object(register_manifest_module, "store_and_read_cid")
    def test_failed_submission_does_not_claim_registration_or_change_storage(self, store: Mock) -> None:
        store.side_effect = RuntimeError("simulated RPC failure")
        entry = make_entry()
        original_storage = entry["storage"].copy()

        results = register_manifest_entries(
            [entry], self.registry, self.web3, namespace="test-project",
            secret="unit-test-secret", contract_address=CONTRACT,
        )

        self.assertEqual(results[0]["status"], "failed")
        self.assertIn("simulated RPC failure", results[0]["reason"])
        self.assertNotIn("blockchain_registration", entry)
        self.assertEqual(entry["storage"], original_storage)
        self.assertIn("encryption", entry)

    @patch.object(register_manifest_module, "store_and_read_cid")
    def test_conflicting_on_chain_cid_is_not_overwritten(self, store: Mock) -> None:
        self.registry.functions.getCID.return_value.call.return_value = ("QmDifferentCID", 123, SUBMITTER)
        entry = make_entry()

        results = register_manifest_entries(
            [entry], self.registry, self.web3, namespace="test-project",
            secret="unit-test-secret", contract_address=CONTRACT,
        )

        self.assertEqual(results[0]["status"], "failed")
        self.assertIn("different CID", results[0]["reason"])
        store.assert_not_called()
        self.assertNotIn("blockchain_registration", entry)

    def test_no_cid_skips_without_a_transaction(self) -> None:
        entry = make_entry()
        entry["storage"] = {"local_cid": None, "filebase_cid": None}

        results = register_manifest_entries(
            [entry], self.registry, self.web3, namespace="test-project",
            secret="unit-test-secret", contract_address=CONTRACT,
        )

        self.assertEqual(results[0]["status"], "skipped")
        self.assertNotIn("blockchain_registration", entry)


if __name__ == "__main__":
    unittest.main()
