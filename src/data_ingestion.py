"""
data_ingestion.py

Converts any supported input format into a single CSV file -- the format
the rest of the pipeline (sensitivity_classifier.py, encryption_pipeline.py)
is built around. This is the "any format -> one format" step: whatever
a user uploads, it becomes a CSV before classification/encryption ever
sees it.

Supported inputs:
  .csv, .tsv          -> read directly
  .xlsx, .xls         -> Excel, first sheet by default
  .json                -> a JSON array of objects, or a single nested
                           object -- automatically flattened
                           (e.g. "patient.contact.email" becomes a column)
  .jsonl, .ndjson      -> newline-delimited JSON (one record per line)
  .xml                 -> XML with repeated record elements
  .parquet             -> columnar format, read directly

Why CSV as the target format, not something else: it's the simplest
universal tabular representation, every downstream library already reads
it natively (pandas, csv module), and it's human-inspectable for
debugging/demos -- unlike Parquet or a database dump.
"""

import os
import json
import pandas as pd


SUPPORTED_EXTENSIONS = [".csv", ".tsv", ".xlsx", ".xls", ".json", ".jsonl", ".ndjson", ".xml", ".parquet"]


def _load_json_to_df(path: str) -> pd.DataFrame:
    with open(path, "r") as f:
        data = json.load(f)

    # A single nested object (e.g. one record) -> wrap in a list
    if isinstance(data, dict):
        # Common pattern: {"records": [...]} or {"data": [...]}
        for key in ("records", "data", "items", "results"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]

    # json_normalize flattens nested objects: patient.contact.email
    return pd.json_normalize(data, sep=".")


def _load_jsonl_to_df(path: str) -> pd.DataFrame:
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return pd.json_normalize(records, sep=".")


def _load_xml_to_df(path: str) -> pd.DataFrame:
    # pandas.read_xml handles the common "repeated record element" XML shape
    return pd.read_xml(path)


def load_any_to_dataframe(input_path: str) -> pd.DataFrame:
    """Detects the input file's format and returns a flat pandas DataFrame,
    regardless of whether the source was structured (CSV/Excel) or
    semi-structured (JSON/JSONL/XML)."""
    ext = os.path.splitext(input_path)[1].lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported format '{ext}'. Supported: {', '.join(SUPPORTED_EXTENSIONS)}. "
            f"Fully unstructured formats (PDF, images, raw text) are out of scope -- "
            f"see README for details."
        )

    if ext == ".csv":
        df = pd.read_csv(input_path, dtype=str, keep_default_na=False)
    elif ext == ".tsv":
        df = pd.read_csv(input_path, sep="\t", dtype=str, keep_default_na=False)
    elif ext in (".xlsx", ".xls"):
        df = pd.read_excel(input_path, dtype=str)
    elif ext == ".json":
        df = _load_json_to_df(input_path)
    elif ext in (".jsonl", ".ndjson"):
        df = _load_jsonl_to_df(input_path)
    elif ext == ".xml":
        df = _load_xml_to_df(input_path)
    elif ext == ".parquet":
        df = pd.read_parquet(input_path)
    else:
        raise ValueError(f"No loader implemented for '{ext}'")

    # Normalize everything to string so downstream feature extraction
    # (regex matching, keyword matching) behaves consistently regardless
    # of the source format's original types.
    df = df.astype(str).replace("nan", "")
    return df


def convert_to_csv(input_path: str, output_csv_path: str) -> pd.DataFrame:
    """Loads any supported format and writes it out as a single CSV file.
    Returns the resulting DataFrame as well, for immediate use in the
    classification/encryption pipeline without a re-read from disk."""
    df = load_any_to_dataframe(input_path)
    os.makedirs(os.path.dirname(output_csv_path) or ".", exist_ok=True)
    df.to_csv(output_csv_path, index=False)
    return df


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python data_ingestion.py <input_file> <output_csv>")
        sys.exit(1)
    df = convert_to_csv(sys.argv[1], sys.argv[2])
    print(f"Converted {sys.argv[1]} -> {sys.argv[2]}  ({len(df)} rows, {len(df.columns)} columns)")
    print(f"Columns: {list(df.columns)}")
