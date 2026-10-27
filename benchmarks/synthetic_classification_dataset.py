"""Deterministic, synthetic-only column cases for classifier evaluation.

Each case is independently labeled from a documented data-governance rubric,
not from the classifier output. Names and value families are disjoint across
development, validation, and held-out test sets.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass

import pandas as pd


@dataclass(frozen=True)
class Case:
    name: str
    tier: str
    kind: str
    rationale: str
    split: str


# Rubric: High means direct identity/contact/account/precise-location or
# sensitive health/financial detail that can identify or directly affect a
# person. Medium means person-linked or sensitive domain detail without a
# direct identifier. Low means public, coarse, or non-linkable operational
# data. This is a synthetic governance rubric, not a legal standard.
_CATALOG = {
    "High": [
        ("mailbox_handle", "email", "direct contact address"),
        ("taxpayer_ref", "ssn", "government-style unique identifier"),
        ("subscriber_line", "phone", "direct contact number"),
        ("ledger_account", "account", "financial account identifier"),
        ("precise_fix", "gps", "precise location trace"),
        ("network_origin", "ip", "potentially identifying network address"),
        ("care_recipient", "person_name", "direct personal name"),
        ("payment_token", "card", "payment credential-shaped synthetic value"),
        ("travel_document", "passport", "government travel identifier"),
        ("birth_marker", "dob", "directly identifying date of birth"),
        ("clinical_narrative", "sensitive_text", "individual-level health detail"),
        ("face_template", "unique_bio", "biometric-like unique vector"),
        ("bank_routing_ref", "account", "financial routing/account reference"),
        ("contact_channel", "missing_malformed_email", "contact field with malformed and valid values"),
        ("home_position", "gps", "precise coordinates mixed with blanks"),
        ("member_secret_ref", "opaque_unique", "unique person-linked reference"),
        ("medical_claim_amount", "money", "person-linked financial claim amount"),
        ("voice_signature", "unique_bio", "biometric-like feature values"),
    ],
    "Medium": [
        ("care_category", "health_category", "health category without direct identity"),
        ("therapy_class", "health_category", "treatment class without a person identifier"),
        ("coverage_family", "finance_category", "insurance product category"),
        ("visit_band", "health_category", "coarse health-service utilization"),
        ("dose_range", "health_category", "treatment intensity without identity"),
        ("district_code", "coarse_location", "coarse location that may support linkage"),
        ("shift_pattern", "schedule", "person-linked schedule pattern"),
        ("device_session", "opaque_unique", "unique operational session reference"),
        ("energy_profile", "numeric_wide", "fine-grained behavioral telemetry"),
        ("billing_band", "money", "financial amount band without account identifier"),
        ("allergy_group", "health_category", "sensitive health category"),
        ("risk_segment", "finance_category", "financial risk segment"),
        ("service_duration", "numeric_wide", "potentially linkable service behavior"),
        ("treatment_phase", "health_category", "health status over time"),
        ("asset_serial", "opaque_unique", "unique device reference that can link activity"),
        ("work_zone", "coarse_location", "workplace zone with contextual sensitivity"),
        ("purchase_bracket", "finance_category", "coarse personal spending category"),
        ("wellness_index", "numeric_wide", "individual-level wellness measurement"),
    ],
    "Low": [
        ("ambient_degrees", "ambient_numeric", "coarse ambient measurement"),
        ("sky_state", "public_category", "public weather category"),
        ("relay_online", "binary", "non-identifying device availability flag"),
        ("protocol_revision", "public_category", "public software metadata"),
        ("sample_bucket", "coarse_numeric", "coarse non-personal bucket"),
        ("room_noise_band", "coarse_numeric", "coarse environmental measurement"),
        ("public_station", "public_category", "public infrastructure label"),
        ("wind_class", "public_category", "coarse weather category"),
        ("fan_state", "binary", "non-identifying equipment state"),
        ("region_summary", "public_category", "public non-personal region label"),
        ("firmware_track", "public_category", "public release channel"),
        ("light_band", "coarse_numeric", "coarse ambient light measurement"),
        ("event_counter", "coarse_numeric", "aggregate event count"),
        ("calendar_quarter", "public_category", "coarse public time metadata"),
        ("sensor_family", "all_missing", "synthetic field with all values missing; conservative fallback case"),
        ("air_quality_band", "coarse_numeric", "coarse environmental measurement"),
        ("maintenance_state", "public_category", "generic equipment state"),
        ("rack_temperature", "ambient_numeric", "bounded non-personal telemetry"),
    ],
}

_SPLIT_BY_INDEX = ("development", "development", "development", "development", "development", "development",
                   "validation", "validation", "validation", "validation",
                   "test", "test", "test", "test", "test", "test", "test", "test")


def cases() -> list[Case]:
    result = []
    for tier, items in _CATALOG.items():
        for index, (name, kind, rationale) in enumerate(items):
            result.append(Case(name, tier, kind, rationale, _SPLIT_BY_INDEX[index]))
    return result


def _values(kind: str, rows: int, rng: random.Random) -> list[object]:
    if kind == "all_missing":
        return [None] * rows
    cycle = {
        "email": lambda i: f"synthetic{i:04d}@example.invalid",
        "ssn": lambda i: f"999-88-{i:04d}",
        "phone": lambda i: f"+1555000{i:04d}",
        "account": lambda i: f"ACCT-SYN-{i:06d}",
        "gps": lambda i: f"{37 + i % 10}.{i:04d}, -122.{i % 10000:04d}",
        "ip": lambda i: f"192.0.2.{1 + i % 253}",
        "person_name": lambda i: f"Synthetic Person {i:04d}",
        "card": lambda i: f"9999 0000 0000 {i % 10000:04d}",
        "passport": lambda i: f"Z{i:07d}",
        "dob": lambda i: f"1980-{1 + i % 12:02d}-{1 + i % 27:02d}",
        "sensitive_text": lambda i: f"synthetic care note category {i % 7}",
        "unique_bio": lambda i: f"bio-vector-synthetic-{i:06d}",
        "health_category": lambda i: f"synthetic-health-{i % 5}",
        "finance_category": lambda i: f"synthetic-finance-{i % 6}",
        "coarse_location": lambda i: f"district-{i % 8}",
        "schedule": lambda i: f"shift-{i % 4}-week-{i % 13}",
        "opaque_unique": lambda i: f"ref-{rng.getrandbits(48):012x}",
        "numeric_wide": lambda i: str((i * 7919) % 100000),
        "money": lambda i: str((i % 20) * 25),
        "ambient_numeric": lambda i: str(18 + i % 7),
        "public_category": lambda i: f"category-{i % 4}",
        "binary": lambda i: "on" if i % 2 else "off",
        "coarse_numeric": lambda i: str((i // 10) * 5),
    }
    if kind == "missing_malformed_email":
        generator = lambda i: f"invalid-{i}" if i % 4 == 0 else f"synthetic{i:04d}@example.invalid"
    else:
        generator = cycle[kind]
    result: list[object] = [generator(i) for i in range(rows)]
    # Explicit supported edge cases: sparse values and empty/malformed cells.
    if kind in {"missing_malformed_email", "gps"}:
        result[::11] = [None] * len(result[::11])
    if kind == "email":
        for i in range(5, rows, 17):
            result[i] = "malformed-synthetic-address"
    return result


def build_dataset(*, rows: int = 128, seed: int = 20261023) -> tuple[dict[str, pd.DataFrame], list[dict]]:
    """Return one-column-per-case dataframes by split and their label metadata."""
    if rows < 20:
        raise ValueError("rows must be at least 20 to exercise sparse and repeated values")
    rng = random.Random(seed)
    splits = {name: {} for name in ("development", "validation", "test")}
    metadata = []
    for case in cases():
        splits[case.split][case.name] = _values(case.kind, rows, rng)
        metadata.append(asdict(case) | {"rows": rows, "seed": seed})
    return {name: pd.DataFrame(columns) for name, columns in splits.items()}, metadata


def generator_config(seed: int = 20261023, rows: int = 128) -> dict:
    return {
        "generator": "synthetic-column-catalog-v1",
        "seed": seed,
        "rows_per_column": rows,
        "split_counts": {split: sum(case.split == split for case in cases()) for split in ("development", "validation", "test")},
        "rubric": {
            "High": "direct identity/contact/account/precise location or sensitive individual-level health/financial data",
            "Medium": "person-linked or sensitive-domain detail without direct identity",
            "Low": "public, coarse, aggregate, or non-linkable operational data",
        },
        "caveat": "Author-defined synthetic labels; not a legal standard or evidence of real-world accuracy.",
    }
