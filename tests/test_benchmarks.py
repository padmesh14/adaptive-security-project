import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks import tier_benchmark


class TierBenchmarkTests(unittest.TestCase):
    def test_exports_raw_trials_summary_and_failed_trials(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            original = tier_benchmark._timed_trial

            def fail_high(mode, payload):
                if mode == "High":
                    raise ValueError("synthetic injected failure")
                return original(mode, payload)

            with patch.object(tier_benchmark, "_timed_trial", side_effect=fail_high):
                csv_path, json_path = tier_benchmark.run_benchmark(
                    sizes=[128], modes=["Low", "High", "SingleAESBaseline"],
                    repetitions=2, warmups=1, seed=17, output_dir=output,
                    distribution={"Low": 1, "High": 1},
                )

            rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 12)
            failed = [row for row in rows if row["mode"] == "High"]
            self.assertEqual(len(failed), 4)
            self.assertTrue(all(row["status"] == "failed" for row in failed))
            self.assertTrue(all(row["error_type"] == "ValueError" for row in failed))
            self.assertEqual(report["failed_measured_trials"], 4)
            self.assertEqual(report["configuration"]["warmup_failures_by_mode"]["High"], 1)
            low = next(row for row in report["summary"]
                       if row["scenario"] == "isolated" and row["mode"] == "Low")
            self.assertEqual(low["successful_trials"], 2)
            self.assertIsNone(low["encrypt_seconds_p95"])
            self.assertEqual(report["measurement_method"]["memory"].split(";")[0],
                             "peak tracemalloc allocation from separate encryption and decryption probes")


if __name__ == "__main__":
    unittest.main()
