"""
main.py

Adaptive Multi-Layer Security -- Base Pipeline (column-wise)

Steps:
  1. Load the combined dataset (IoT smart-home + synthetic healthcare records).
  2. Classify each COLUMN's sensitivity (Low/Medium/High) based on that
     column's content across all rows (name-keyword signals, regex
     pattern matches, uniqueness, numeric-range).
  3. Encrypt each column's full set of values as one block, using the
     tier-appropriate scheme (AES-256-GCM / +ECC / double-layer +ECC).
  4. Write output/encryption_manifest.json with, per column:
     tier, risk score, encryption scheme, integrity hash.

Run:
    python main.py
"""

import os
import json
import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

from src.encryption_pipeline import encrypt_dataset_by_column

BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "data", "combined_dataset.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
MANIFEST_PATH = os.path.join(OUTPUT_DIR, "encryption_manifest.json")


def run_pipeline(manifest_path: str = MANIFEST_PATH, *, refuse_overwrite: bool = False, key_provider=None):
    df = pd.read_csv(DATA_PATH, dtype=str, keep_default_na=False)

    print(f"Loaded {len(df)} rows, {len(df.columns)} columns.")
    print("Classifying + encrypting column by column...\n")

    result = encrypt_dataset_by_column(df, key_provider=key_provider)
    manifest = result["manifest"]

    tier_counts = {"Low": 0, "Medium": 0, "High": 0}
    for entry in manifest:
        tier_counts[entry["sensitivity_tier"]] += 1
        print(f"  {entry['column']:20s} -> {entry['sensitivity_tier']:6s} "
              f"(risk_score={entry['risk_score']:3d}, n_values={entry['n_values']})")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if refuse_overwrite and os.path.exists(manifest_path):
        raise FileExistsError(f"Refusing to overwrite existing manifest: {manifest_path}")
    with open(manifest_path, "x" if refuse_overwrite else "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nColumns processed: {len(manifest)}")
    print(f"Column sensitivity distribution: {tier_counts}")
    print(f"Manifest written to {manifest_path}")


def build_managed_key_provider(provider_name: str, *, key_file: str | None = None):
    """Build only the explicitly selected provider; never fall back silently."""
    if provider_name == "local":
        from src.key_management import LocalDevelopmentKeyProvider
        return LocalDevelopmentKeyProvider(key_file) if key_file else LocalDevelopmentKeyProvider()
    if provider_name == "aws-kms":
        from src.aws_kms_key_provider import AWSKMSKeyProvider
        key_id = os.environ.get("AWS_KMS_KEY_ID", "").strip()
        region = os.environ.get("AWS_REGION", "").strip()
        if not key_id or not region:
            raise ValueError("AWS KMS mode requires AWS_KMS_KEY_ID and AWS_REGION")
        return AWSKMSKeyProvider(key_id=key_id, region=region)
    raise ValueError("managed key provider must be local or aws-kms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classify and encrypt the configured dataset")
    parser.add_argument("--new-run", action="store_true",
                        help="write a unique manifest without overwriting existing output")
    parser.add_argument("--managed-key-provider", choices=("local", "aws-kms"),
                        help="opt in to managed keys for a new run; legacy encryption is the default")
    parser.add_argument("--key-file", type=Path,
                        help="existing local development KEK file (local provider only)")
    args = parser.parse_args()
    if args.managed_key_provider and not args.new_run:
        parser.error("managed-key mode requires --new-run to avoid overwriting an existing manifest")
    if args.key_file and args.managed_key_provider != "local":
        parser.error("--key-file can only be used with --managed-key-provider local")
    if args.new_run:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_path = os.path.join(OUTPUT_DIR, f"encryption_manifest_run_{stamp}_{uuid.uuid4().hex[:8]}.json")
        provider = None
        if args.managed_key_provider:
            try:
                provider = build_managed_key_provider(args.managed_key_provider,
                                                      key_file=str(args.key_file) if args.key_file else None)
            except Exception as exc:
                parser.error(f"managed key provider configuration failed ({type(exc).__name__})")
        run_pipeline(run_path, refuse_overwrite=True, key_provider=provider)
    else:
        run_pipeline()
