"""Tests for local CID manifest verification eligibility."""

from types import SimpleNamespace
import unittest

from .verify_manifest import verify_manifest_entries


class ManifestVerificationTests(unittest.TestCase):
    def test_entry_without_stored_cid_is_skipped_without_contract_access(self):
        entry = {
            "column": "synthetic_local_only",
            "sensitivity_tier": "Low",
            "storage": {"provider": "sqlite"},
        }
        web3 = SimpleNamespace(eth=SimpleNamespace(chain_id=31337))

        results = verify_manifest_entries(
            [entry], None, web3,
            namespace="test-namespace",
            secret="test-secret",
        )

        self.assertEqual(
            results,
            [{"index": 0, "status": "skipped", "reason": "no stored CID"}],
        )


if __name__ == "__main__":
    unittest.main()
