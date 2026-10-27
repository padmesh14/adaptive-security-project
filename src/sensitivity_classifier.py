"""
sensitivity_classifier.py

Column-level (field-level) sensitivity classification -- generalized to
work on ANY tabular dataset, not just the IoT + healthcare sample used
during development.

Two things make this dataset-agnostic:

1. All keyword groups and content-pattern regexes live in an external
   file, sensitivity_rules.json, instead of being hardcoded in Python.
   Supporting a new domain (e.g. e-commerce, banking, government records)
   means editing that JSON file -- no code changes required.

2. Thresholds are ADAPTIVE by default: instead of fixed cutoffs tuned to
   one dataset's score distribution, Low/Medium/High boundaries are
   computed from the percentile distribution of THIS dataset's own scores
   each time it runs. A dataset with a different overall risk profile
   self-calibrates instead of silently bunching everything into one tier.
   (Fixed thresholds are still available via use_adaptive_thresholds=False
   for reproducibility/comparison.)

Signals used per column (unchanged from the original design):
  - name_keyword_score   : does the column name itself suggest PII/health/
                            financial/location/biometric/demographic data?
  - pattern_match_ratio   : fraction of non-empty values matching a known
                            sensitive content pattern (email, SSN, GPS, IP,
                            phone, credit card, IBAN, DOB, passport, zip)
  - uniqueness_ratio      : identifier-like columns have near-1.0 unique
                            values; ambient/categorical columns repeat
  - numeric_bounded       : purely numeric columns with a small, physically
                            bounded range skew toward Low
"""

import os
import re
import json
import pandas as pd
import numpy as np

_RULES_PATH = os.path.join(os.path.dirname(__file__), "sensitivity_rules.json")

# Fixed-threshold fallback (used only if use_adaptive_thresholds=False)
LOW_MAX = 25
MEDIUM_MAX = 55


def _load_rules(rules_path: str = _RULES_PATH) -> dict:
    with open(rules_path, "r") as f:
        rules = json.load(f)
    # Pre-compile regex patterns once
    rules["_compiled_patterns"] = [re.compile(p) for p in rules["patterns"].values()]
    return rules


def _non_empty_values(series: pd.Series):
    return series.dropna().astype(str).map(str.strip)


def _name_keyword_match(col_name: str, rules: dict) -> tuple:
    """Returns (best_score, matched_group) for a column name, using the
    externally-configured keyword groups."""
    col_lower = col_name.lower()
    best_score, best_group = 0, None
    for group, spec in rules["name_keywords"].items():
        if any(kw in col_lower for kw in spec["keywords"]):
            if spec["score"] > best_score:
                best_score, best_group = spec["score"], group
    return best_score, best_group


def _pattern_match_ratio(values: pd.Series, rules: dict) -> float:
    non_empty = values[values != ""]
    if len(non_empty) == 0:
        return 0.0
    patterns = rules["_compiled_patterns"]
    hits = non_empty.apply(lambda v: any(p.match(v) for p in patterns))
    return hits.mean()


def _uniqueness_ratio(values: pd.Series) -> float:
    non_empty = values[values != ""]
    if len(non_empty) == 0:
        return 0.0
    return non_empty.nunique() / len(non_empty)


def _is_bounded_numeric(values: pd.Series, rules: dict) -> bool:
    non_empty = values[values != ""]
    if len(non_empty) == 0:
        return False
    try:
        nums = non_empty.astype(float)
    except ValueError:
        return False
    return (nums.max() - nums.min()) < rules["bounded_numeric_range"]


def compute_column_features(df: pd.DataFrame, col: str, rules: dict) -> dict:
    values = _non_empty_values(df[col])
    fill_ratio = len(values) / max(len(df), 1)
    kw_score, kw_group = _name_keyword_match(col, rules)

    return {
        "column": col,
        "name_keyword_score": kw_score,
        "name_keyword_group": kw_group,
        "pattern_match_ratio": round(_pattern_match_ratio(values, rules), 3),
        "uniqueness_ratio": round(_uniqueness_ratio(values), 3),
        "is_bounded_numeric": _is_bounded_numeric(values, rules),
        "fill_ratio": round(fill_ratio, 3),
    }


def compute_column_risk_score(features: dict, rules: dict) -> int:
    score = 0
    score += features["name_keyword_score"]
    score += features["pattern_match_ratio"] * 40
    score += min(features["uniqueness_ratio"] * 25, 25)
    if features["is_bounded_numeric"]:
        score += rules["bounded_numeric_penalty"]
    score *= features["fill_ratio"]
    return int(max(0, min(round(score), 100)))


def _adaptive_cutoffs(scores: list) -> tuple:
    """Computes Low/Medium boundary cutoffs from THIS dataset's own score
    distribution (40th and 75th percentile), instead of fixed values tuned
    to one specific dataset. Falls back to the fixed cutoffs if the
    dataset is too small or has no spread (e.g. a single-column dataset)."""
    if len(scores) < 5 or np.std(scores) < 1e-6:
        return LOW_MAX, MEDIUM_MAX
    low_cut = float(np.percentile(scores, 40))
    med_cut = float(np.percentile(scores, 75))
    if med_cut <= low_cut:
        med_cut = low_cut + 1
    return round(low_cut, 1), round(med_cut, 1)


def classify_columns(
    df: pd.DataFrame,
    exclude=("row_id", "record_id", "source_dataset", "id"),
    rules_path: str = _RULES_PATH,
    use_adaptive_thresholds: bool = True,
) -> pd.DataFrame:
    """Returns one row per column: column, features..., risk_score, sensitivity_tier.

    Works on any tabular dataset -- keyword/pattern rules are loaded from
    sensitivity_rules.json, and thresholds adapt to this dataset's own
    score distribution by default.
    """
    rules = _load_rules(rules_path)

    raw_results = []
    for col in df.columns:
        if col.lower() in [e.lower() for e in exclude]:
            continue
        feats = compute_column_features(df, col, rules)
        score = compute_column_risk_score(feats, rules)
        feats["risk_score"] = score
        raw_results.append(feats)

    scores = [r["risk_score"] for r in raw_results]
    if use_adaptive_thresholds:
        low_max, medium_max = _adaptive_cutoffs(scores)
    else:
        low_max, medium_max = LOW_MAX, MEDIUM_MAX

    for feats in raw_results:
        score = feats["risk_score"]
        if score <= low_max:
            tier = "Low"
        elif score <= medium_max:
            tier = "Medium"
        else:
            tier = "High"

        # Direct-identifier override: a column whose NAME clearly denotes a
        # direct identifier (name/email/ssn/phone/passport/etc.) is High
        # regardless of incidental uniqueness stats in this particular
        # sample. Applies to "identifier" and "biometric" groups -- the
        # two categories where under-protection is least acceptable.
        if feats["name_keyword_group"] in ("identifier", "biometric") and feats["fill_ratio"] > 0.05:
            tier = "High"
            score = max(score, medium_max + 1)

        feats["risk_score"] = score
        feats["sensitivity_tier"] = tier

    return pd.DataFrame(raw_results)


if __name__ == "__main__":
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "combined_dataset.csv")
    df = pd.read_csv(data_path, dtype=str, keep_default_na=False)
    result = classify_columns(df)
    pd.set_option("display.width", 140)
    pd.set_option("display.max_columns", None)
    print(result[["column", "name_keyword_score", "pattern_match_ratio",
                   "uniqueness_ratio", "is_bounded_numeric", "fill_ratio",
                   "risk_score", "sensitivity_tier"]].to_string(index=False))
