"""Held-out synthetic evaluation of adaptive and baseline tier classifiers."""

from __future__ import annotations

import argparse
import csv
import html
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from benchmarks.synthetic_classification_dataset import build_dataset, generator_config
from src.sensitivity_classifier import classify_columns


TIERS = ("Low", "Medium", "High")
ORDER = {tier: index for index, tier in enumerate(TIERS)}
METHODS = ("adaptive", "fixed_thresholds", "rule_baseline", "validation_tuned_thresholds")


def _metrics(expected: list[str], predicted: list[str], *, seed: int = 99173, resamples: int = 2000) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(
        expected, predicted, labels=TIERS, zero_division=0
    )
    matrix = confusion_matrix(expected, predicted, labels=TIERS)
    per_tier = {}
    for index, tier in enumerate(TIERS):
        tp = int(matrix[index, index])
        fn = int(matrix[index, :].sum() - tp)
        fp = int(matrix[:, index].sum() - tp)
        tn = int(matrix.sum() - tp - fn - fp)
        per_tier[tier] = {
            "precision": float(precision[index]), "recall": float(recall[index]),
            "f1": float(f1[index]), "support": int(support[index]),
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        }
    rng = np.random.default_rng(seed)
    samples = []
    indexes = np.arange(len(expected))
    exp = np.asarray(expected)
    pred = np.asarray(predicted)
    for _ in range(resamples):
        selected = rng.choice(indexes, size=len(indexes), replace=True)
        p, r, f, _ = precision_recall_fscore_support(
            exp[selected], pred[selected], labels=TIERS, zero_division=0
        )
        samples.append((float(np.mean(exp[selected] == pred[selected])), float(np.mean(f))))
    return {
        "sample_size": len(expected), "labels_order": list(TIERS),
        "confusion_matrix_rows_expected_columns_predicted": matrix.tolist(),
        "accuracy": float(np.mean(np.asarray(expected) == np.asarray(predicted))),
        "accuracy_bootstrap_95pct_ci": np.quantile([item[0] for item in samples], [0.025, 0.975]).tolist(),
        "macro_precision": float(precision.mean()), "macro_recall": float(recall.mean()),
        "macro_f1": float(f1.mean()),
        "macro_f1_bootstrap_95pct_ci": np.quantile([item[1] for item in samples], [0.025, 0.975]).tolist(),
        "per_tier": per_tier,
    }


def _rule_baseline(frame) -> dict[str, str]:
    """Transparent conservative baseline, independent of the scored classifier."""
    import re

    direct_patterns = [
        re.compile(pattern, re.I) for pattern in (
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$", r"^\d{3}-\d{2}-\d{4}$",
            r"^\+?\d[\d\-]{7,}$", r"^[A-Z]\d{7,8}$",
            r"^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$",
        )
    ]
    high_name = re.compile(r"(person|recipient|taxpayer|mailbox|account|contact|passport|birth|position|origin|token|signature|clinical)", re.I)
    medium_name = re.compile(r"(care|health|therapy|coverage|visit|dose|district|shift|session|profile|billing|allergy|risk|service|treatment|asset|zone|purchase|wellness)", re.I)
    output = {}
    for name in frame.columns:
        values = [str(value).strip() for value in frame[name].dropna() if str(value).strip()]
        pattern_sensitive = any(pattern.fullmatch(value) for value in values for pattern in direct_patterns)
        if high_name.search(name) or pattern_sensitive:
            tier = "High"
        elif medium_name.search(name) or (values and len(set(values)) / len(values) > 0.65):
            tier = "Medium"
        else:
            tier = "Low"
        output[name] = tier
    return output


def _score_frame(frame) -> dict[str, dict]:
    result = classify_columns(frame, use_adaptive_thresholds=False)
    return {row["column"]: row.to_dict() for _, row in result.iterrows()}


def _tier_from_score(score: float, low_max: float, medium_max: float) -> str:
    if score <= low_max:
        return "Low"
    if score <= medium_max:
        return "Medium"
    return "High"


def _tune_thresholds(validation_cases: list[dict], scores: dict[str, dict]) -> tuple[float, float]:
    """Select cutoffs on validation only; maximize macro-F1, then minimize under-tiering."""
    expected = [case["tier"] for case in validation_cases]
    best_key = None
    best_thresholds = (25, 55)
    for low_max in range(0, 100, 5):
        for medium_max in range(low_max + 5, 101, 5):
            predicted = []
            for case in validation_cases:
                row = scores[case["name"]]
                tier = _tier_from_score(float(row["risk_score"]), low_max, medium_max)
                if row.get("name_keyword_group") in ("identifier", "biometric") and row["fill_ratio"] > 0.05:
                    tier = "High"
                predicted.append(tier)
            p, r, f, _ = precision_recall_fscore_support(expected, predicted, labels=TIERS, zero_division=0)
            under = sum(ORDER[predicted[i]] < ORDER[expected[i]] for i in range(len(expected)))
            over = sum(ORDER[predicted[i]] > ORDER[expected[i]] for i in range(len(expected)))
            key = (float(np.mean(f)), -under, -over)
            if best_key is None or key > best_key:
                best_key, best_thresholds = key, (low_max, medium_max)
    return best_thresholds


def _predict_methods(frame, thresholds: tuple[float, float]) -> tuple[dict[str, dict[str, str]], dict[str, dict]]:
    scores = _score_frame(frame)
    adaptive_result = classify_columns(frame, use_adaptive_thresholds=True)
    adaptive = dict(zip(adaptive_result["column"], adaptive_result["sensitivity_tier"]))
    fixed_result = classify_columns(frame, use_adaptive_thresholds=False)
    fixed = dict(zip(fixed_result["column"], fixed_result["sensitivity_tier"]))
    tuned = {}
    for name, row in scores.items():
        tier = _tier_from_score(float(row["risk_score"]), *thresholds)
        if row.get("name_keyword_group") in ("identifier", "biometric") and row["fill_ratio"] > 0.05:
            tier = "High"
        tuned[name] = tier
    return {"adaptive": adaptive, "fixed_thresholds": fixed,
            "rule_baseline": _rule_baseline(frame), "validation_tuned_thresholds": tuned}, scores


def _load_benchmark(path: Path | None) -> dict[int, dict[str, float]]:
    if path is None:
        return {}
    report = json.loads(path.read_text(encoding="utf-8"))
    by_size = {}
    for row in report["summary"]:
        if row["scenario"] == "isolated" and row["encrypt_seconds_median"] is not None:
            by_size.setdefault(int(row["payload_bytes"]), {})[row["mode"]] = row["encrypt_seconds_median"]
    return by_size


def _plot(metrics: dict, under: dict, destination: Path) -> None:
    width, height = 980, 480
    names = list(metrics)
    colors = ("#4e79a7", "#59a14f", "#f28e2b", "#e15759")
    left, base, scale = 150, 390, 310
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
           '<rect width="100%" height="100%" fill="white"/>',
           '<text x="30" y="35" font-family="sans-serif" font-size="22" font-weight="bold">Held-out classifier results</text>',
           '<text x="30" y="75" font-family="sans-serif" font-size="14">Accuracy bars; labels show under-tier / over-tier counts</text>']
    for idx, method in enumerate(names):
        y = 125 + idx * 78
        accuracy = metrics[method]["accuracy"]
        svg.append(f'<text x="{left-10}" y="{y+22}" text-anchor="end" font-family="sans-serif" font-size="14">{html.escape(method)}</text>')
        svg.append(f'<rect x="{left}" y="{y}" width="{accuracy*scale:.1f}" height="32" fill="{colors[idx]}"/>')
        svg.append(f'<text x="{left+accuracy*scale+9:.1f}" y="{y+21}" font-family="sans-serif" font-size="13">{accuracy:.3f}  |  {under[method]["under"]} / {under[method]["over"]}</text>')
    svg.append('<text x="150" y="440" font-family="sans-serif" font-size="12">0.0</text><text x="448" y="440" font-family="sans-serif" font-size="12">1.0 accuracy</text>')
    svg.append('</svg>')
    destination.write_text("\n".join(svg), encoding="utf-8")


def evaluate(*, benchmark_json: Path | None, output_dir: Path, seed: int = 20261023, rows: int = 128) -> tuple[Path, Path, Path, Path]:
    frames, label_metadata = build_dataset(seed=seed, rows=rows)
    case_by_name = {item["name"]: item for item in label_metadata}
    benchmark = _load_benchmark(benchmark_json)
    validation_names = [name for name in frames["validation"].columns]
    test_names = [name for name in frames["test"].columns]
    val_scores = _score_frame(frames["validation"])
    thresholds = _tune_thresholds([case_by_name[name] for name in validation_names], val_scores)

    predictions, test_scores = _predict_methods(frames["test"], thresholds)
    split_reports = {}
    for split_name, frame in frames.items():
        split_predictions, _ = _predict_methods(frame, thresholds)
        split_expected = [case_by_name[name]["tier"] for name in frame.columns]
        split_reports[split_name] = {}
        for method in METHODS:
            split_predicted = [split_predictions[method][name] for name in frame.columns]
            split_reports[split_name][method] = _metrics(
                split_expected, split_predicted, seed=seed + len(split_name) + METHODS.index(method)
            )
            split_reports[split_name][method]["under_classified_fields"] = sum(
                ORDER[split_predictions[method][name]] < ORDER[case_by_name[name]["tier"]]
                for name in frame.columns
            )
            split_reports[split_name][method]["over_classified_fields"] = sum(
                ORDER[split_predictions[method][name]] > ORDER[case_by_name[name]["tier"]]
                for name in frame.columns
            )
    expected = [case_by_name[name]["tier"] for name in test_names]
    report_metrics = {}
    under_over = {}
    csv_rows = []
    for method_index, method in enumerate(METHODS):
        predicted = [predictions[method][name] for name in test_names]
        report_metrics[method] = _metrics(expected, predicted, seed=seed + method_index)
        under = sum(ORDER[predictions[method][name]] < ORDER[case_by_name[name]["tier"]] for name in test_names)
        over = sum(ORDER[predictions[method][name]] > ORDER[case_by_name[name]["tier"]] for name in test_names)
        under_over[method] = {"under": under, "over": over}
        cost_total = 0.0
        cost_low = 0.0
        assigned_counts = {tier: 0 for tier in TIERS}
        for name in test_names:
            case = case_by_name[name]
            predicted_tier = predictions[method][name]
            assigned_counts[predicted_tier] += 1
            payload_bytes = len(json.dumps(frames["test"][name].tolist(), separators=(",", ":")).encode())
            nearest = min(benchmark, key=lambda size: abs(size - payload_bytes)) if benchmark else None
            size_costs = benchmark.get(nearest, {}) if nearest is not None else {}
            assigned_cost, low_cost = size_costs.get(predicted_tier), size_costs.get("Low")
            if assigned_cost is not None:
                cost_total += assigned_cost
            if low_cost is not None:
                cost_low += low_cost
            csv_rows.append({
                "method": method, "split": "test", "synthetic_field": name,
                "expected_tier": case["tier"], "predicted_tier": predicted_tier,
                "risk_score": test_scores[name]["risk_score"],
                "name_keyword_group": test_scores[name]["name_keyword_group"],
                "under_tiered": ORDER[predicted_tier] < ORDER[case["tier"]],
                "over_tiered": ORDER[predicted_tier] > ORDER[case["tier"]],
                "synthetic_payload_bytes": payload_bytes, "nearest_benchmark_bytes": nearest,
                "assigned_encrypt_seconds_median": assigned_cost,
                "low_tier_encrypt_seconds_median": low_cost,
            })
        report_metrics[method]["assigned_tier_counts"] = assigned_counts
        report_metrics[method]["under_classified_fields"] = under
        report_metrics[method]["over_classified_fields"] = over
        report_metrics[method]["estimated_total_encrypt_seconds"] = cost_total if benchmark else None
        report_metrics[method]["estimated_all_low_encrypt_seconds"] = cost_low if benchmark else None
        report_metrics[method]["estimated_extra_seconds_vs_all_low"] = cost_total - cost_low if benchmark else None

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"classifier-evaluation-v2-{stamp}"
    csv_path, json_path = output_dir / f"{stem}.csv", output_dir / f"{stem}.json"
    config_path, plot_path = output_dir / f"{stem}-config.json", output_dir / f"{stem}-heldout.svg"
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(csv_rows[0]))
        writer.writeheader(); writer.writerows(csv_rows)
    config = generator_config(seed=seed, rows=rows)
    config["cases"] = label_metadata
    config["split_policy"] = (
        "Field names and individual generated examples are disjoint across splits; six development, four validation, "
        "and eight test cases per tier. Some broad value generators are reused to cover common data families, "
        "while test fields include held-out names and value patterns. Test set was not used for threshold selection."
    )
    with config_path.open("x", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2); handle.write("\n")
    report = {
        "evaluation": "synthetic-heldout-classifier-v2", "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed, "rows_per_field": rows, "split_counts": config["split_counts"],
        "label_caveat": config["caveat"], "label_rubric": config["rubric"],
        "threshold_selection": {"validation_only": True, "objective": "maximize macro-F1; ties prefer fewer under-tiered, then fewer over-tiered fields", "selected_low_max": thresholds[0], "selected_medium_max": thresholds[1]},
        "methods": {
            "adaptive": "Existing score model and data-set percentiles (40th/75th), computed only within held-out columns.",
            "fixed_thresholds": "Existing score model with LOW_MAX=25 and MEDIUM_MAX=55.",
            "rule_baseline": "Separate transparent policy: direct synthetic patterns or broad name tokens -> High; sensitive-domain tokens or high uniqueness -> Medium; otherwise Low.",
            "validation_tuned_thresholds": "Existing score model and identifier override; cutoffs selected on validation split only.",
        },
        "metrics": report_metrics, "split_diagnostics": split_reports,
        "under_over_by_method": under_over,
        "cost_model": "Sum nearest-size isolated encryption median from the supplied local benchmark; separate from confidentiality-risk interpretation. No benchmark means cost fields are null.",
        "limitations": ["Author-labeled synthetic data do not establish real-world classifier accuracy.", "Held-out sample is modest and labels are rubric judgments.", "Bootstrap intervals resample fields and do not account for new-domain distribution shift."],
        "raw_csv": csv_path.name, "dataset_config": config_path.name,
        "benchmark_json": str(benchmark_json) if benchmark_json else None,
    }
    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2); handle.write("\n")
    _plot(report_metrics, under_over, plot_path)
    return csv_path, json_path, config_path, plot_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-json", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--rows", type=int, default=128)
    parser.add_argument("--seed", type=int, default=20261023)
    args = parser.parse_args()
    try:
        paths = evaluate(benchmark_json=args.benchmark_json, output_dir=args.output_dir, rows=args.rows, seed=args.seed)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print("Classifier evaluation saved:", "; ".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
