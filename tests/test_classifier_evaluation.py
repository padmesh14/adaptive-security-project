import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.classifier_evaluation import _load_benchmark, evaluate
from benchmarks.synthetic_classification_dataset import build_dataset


class ClassifierEvaluationTests(unittest.TestCase):
    def test_dataset_is_seeded_and_split_cases_are_disjoint(self):
        first, metadata = build_dataset(seed=55, rows=32)
        second, _ = build_dataset(seed=55, rows=32)
        self.assertEqual(first["test"].to_dict(), second["test"].to_dict())
        names = [set(frame.columns) for frame in first.values()]
        self.assertFalse(names[0] & names[1] or names[0] & names[2] or names[1] & names[2])
        self.assertEqual(len(metadata), 54)
        self.assertTrue(any(item["kind"] == "all_missing" for item in metadata))
        self.assertTrue(any(item["kind"] == "missing_malformed_email" for item in metadata))

    def test_benchmark_cost_lookup_is_scoped_to_payload_size(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bench.json"
            path.write_text(json.dumps({"summary": [
                {"scenario": "isolated", "payload_bytes": 1024, "mode": "Low", "encrypt_seconds_median": 1.0},
                {"scenario": "isolated", "payload_bytes": 1024, "mode": "Medium", "encrypt_seconds_median": 2.0},
                {"scenario": "isolated", "payload_bytes": 16384, "mode": "Low", "encrypt_seconds_median": 10.0},
                {"scenario": "isolated", "payload_bytes": 16384, "mode": "Medium", "encrypt_seconds_median": 20.0},
            ]}))
            self.assertEqual(_load_benchmark(path), {
                1024: {"Low": 1.0, "Medium": 2.0},
                16384: {"Low": 10.0, "Medium": 20.0},
            })

    def test_evaluation_uses_heldout_labels_and_reports_all_comparators(self):
        with tempfile.TemporaryDirectory() as temp:
            csv_path, json_path, config_path, plot_path = evaluate(
                benchmark_json=None, output_dir=Path(temp), rows=32, seed=100
            )
            report = json.loads(json_path.read_text())
            config = json.loads(config_path.read_text())
            self.assertEqual(report["split_counts"], {"development": 18, "validation": 12, "test": 24})
            self.assertEqual(set(report["metrics"]), {
                "adaptive", "fixed_thresholds", "rule_baseline", "validation_tuned_thresholds"
            })
            self.assertTrue(report["threshold_selection"]["validation_only"])
            self.assertTrue(all(item["split"] for item in config["cases"]))
            self.assertEqual(len(csv_path.read_text().splitlines()), 1 + 24 * 4)
            self.assertIn("<svg", plot_path.read_text())
            self.assertTrue(all(metric["sample_size"] == 24 for metric in report["metrics"].values()))


if __name__ == "__main__":
    unittest.main()
