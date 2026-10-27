"""
encryption_pipeline.py

Applies the SAME tiered encryption schemes as encryption.py (Low ->
single-layer AES-256-GCM, Medium -> AES-256-GCM + ECC key exchange,
High -> double AES-256-GCM with independent ECC-derived keys), keyed
by COLUMN -- this is the project's actual, single classification +
encryption granularity.

For each column, every value in that column is serialized together and
encrypted as one block, using the tier assigned to that column by
sensitivity_classifier.py. This means, e.g., the entire `patient_name`
column is protected at the High tier, while the entire `temperature_c`
column only needs the Low tier -- instead of every field in a row being
dragged up to one uniform tier regardless of that field's own content.
"""

import os
import json
import pandas as pd

from src.encryption import encrypt_for_tier, EncryptionResult
from src.sensitivity_classifier import classify_columns


def encrypt_dataset_by_column(df: pd.DataFrame, key_provider=None) -> dict:
    """
    Returns:
      {
        "column_tiers": DataFrame of per-column classification (for inspection),
        "manifest": [ { column, sensitivity_tier, risk_score, encryption }, ... ]
      }
    """
    col_class_df = classify_columns(df)

    manifest = []
    for _, row in col_class_df.iterrows():
        col = row["column"]
        tier = row["sensitivity_tier"]

        # Serialize the entire column's values as the plaintext payload.
        values = df[col].tolist()
        plaintext = json.dumps(values).encode()

        if key_provider is None:
            enc_result: EncryptionResult = encrypt_for_tier(tier, plaintext)
            encryption_metadata = enc_result.to_public_dict()
            managed_metadata = {}
        else:
            # Opt-in future-run path. This wraps the existing encryptor keys;
            # the default pipeline behavior and ciphertext format are unchanged.
            from src.key_management import encrypt_managed_record
            managed = encrypt_managed_record(tier, plaintext, key_provider)
            encryption_metadata = managed["encryption"]
            managed_metadata = {
                "record_ref": managed["record_ref"],
                "key_management": managed["key_management"],
            }

        manifest.append({
            "column": col,
            "sensitivity_tier": tier,
            "risk_score": int(row["risk_score"]),
            "n_values": len(values),
            "encryption": encryption_metadata,
            **managed_metadata,
        })

    return {"column_tiers": col_class_df, "manifest": manifest}


if __name__ == "__main__":
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "combined_dataset.csv")
    df = pd.read_csv(data_path, dtype=str, keep_default_na=False)
    result = encrypt_dataset_by_column(df)
    for entry in result["manifest"]:
        print(f"{entry['column']:20s} tier={entry['sensitivity_tier']:6s} "
              f"score={entry['risk_score']:3d}  scheme={entry['encryption']['scheme']}")
