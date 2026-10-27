"""Microbenchmark constituent crypto operations and complete tier encryptors.

Layer-only cases are experimental instrumentation that mirrors the production
High tier using the same helpers. They are not alternate production APIs.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import cryptography
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.encryption import (
    aes_encrypt,
    derive_aes_key_via_ecc,
    encrypt_for_tier,
    generate_ecc_keypair,
)


def _high_layer(plaintext: bytes, info: bytes) -> bytes:
    local_private, _ = generate_ecc_keypair()
    _, peer_public = generate_ecc_keypair()
    key = derive_aes_key_via_ecc(local_private, peer_public, info=info)
    result = aes_encrypt(key, plaintext)
    return result["nonce"] + result["ciphertext"]


def _operations(size: int, seed: int):
    payload = random.Random(seed).randbytes(size)
    shared = bytes((index * 17 + 11) % 256 for index in range(32))
    local_private, _ = generate_ecc_keypair()
    _, peer_public = generate_ecc_keypair()

    return {
        "AES-GCM encryption": lambda: aes_encrypt(bytes(32), payload),
        "ECDH key-pair generation": lambda: generate_ecc_keypair(),
        "ECDH agreement": lambda: local_private.exchange(ec.ECDH(), peer_public),
        "HKDF-SHA256 derivation": lambda: HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"microbenchmark"
        ).derive(shared),
        "ECDH plus HKDF": lambda: derive_aes_key_via_ecc(local_private, peer_public, info=b"microbenchmark"),
        "Medium complete encryption": lambda: encrypt_for_tier("Medium", payload),
        "High layer 1 experimental": lambda: _high_layer(payload, b"tier-high-layer1"),
        "High layer 2 experimental": lambda: _high_layer(payload + bytes(28), b"tier-high-layer2"),
        "High complete encryption": lambda: encrypt_for_tier("High", payload),
    }


def run(*, sizes: list[int], repetitions: int, warmups: int, seed: int, output_dir: Path):
    if repetitions < 2 or warmups < 0 or not sizes or any(size < 0 for size in sizes):
        raise ValueError("provide non-negative sizes, at least two repetitions, and non-negative warmups")
    rows = []
    schedule_rng = random.Random(seed ^ 0x31AC)
    warmup_failures = {}
    for size_index, size in enumerate(sizes):
        operations = _operations(size, seed + size_index)
        warmup_schedule = list(operations) * warmups
        schedule_rng.shuffle(warmup_schedule)
        for name in warmup_schedule:
            try:
                operations[name]()
            except Exception:
                warmup_failures[name] = warmup_failures.get(name, 0) + 1
        tasks = [(name, trial) for name in operations for trial in range(1, repetitions + 1)]
        schedule_rng.shuffle(tasks)
        for position, (name, trial) in enumerate(tasks, start=1):
            row = {
                "payload_bytes": size,
                "operation": name,
                "trial": trial,
                "schedule_position": position,
                "status": "failed",
                "error_type": "",
                "wall_seconds": None,
                "cpu_seconds": None,
            }
            try:
                cpu_start = time.process_time()
                wall_start = time.perf_counter()
                operations[name]()
                row["wall_seconds"] = time.perf_counter() - wall_start
                row["cpu_seconds"] = time.process_time() - cpu_start
                row["status"] = "ok"
            except Exception as exc:
                row["error_type"] = type(exc).__name__
            rows.append(row)

    names = list(dict.fromkeys(row["operation"] for row in rows))
    summary = []
    for size in sizes:
        for name in names:
            group = [r for r in rows if r["payload_bytes"] == size and r["operation"] == name]
            values = [r["wall_seconds"] for r in group if r["status"] == "ok"]
            summary.append({
                "payload_bytes": size,
                "operation": name,
                "trials": len(group),
                "successful_trials": len(values),
                "failed_trials": len(group) - len(values),
                "wall_mean_seconds": statistics.mean(values) if values else None,
                "wall_median_seconds": statistics.median(values) if values else None,
                "wall_stdev_seconds": statistics.stdev(values) if len(values) > 1 else (0.0 if values else None),
                "wall_p95_seconds": float(np.percentile(values, 95)) if len(values) >= 30 else None,
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"crypto-microbenchmark-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}"
    csv_path, json_path = output_dir / f"{stem}.csv", output_dir / f"{stem}.json"
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "benchmark": "crypto-components-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": {"sizes_bytes": sizes, "repetitions": repetitions, "warmups": warmups, "seed": seed,
                          "warmup_failures_by_operation": warmup_failures},
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "cryptography": cryptography.__version__,
            "numpy": np.__version__,
        },
        "notes": {
            "microbenchmarks": "ECDH keygen, agreement, HKDF, and AES-GCM isolate one operation; key pairs/shared inputs are pre-generated where the operation under test is agreement or derivation.",
            "layer_experiments": "High layer-only cases use the existing ECDH/HKDF/AES helpers with the corresponding layer info labels; these are benchmark-only compositions, not production functions.",
            "complete_operations": "Medium and High use the existing encrypt_for_tier entry points, including key setup and serialized result generation.",
        },
        "raw_csv": csv_path.name,
        "failed_measured_trials": sum(row["status"] != "ok" for row in rows),
        "summary": summary,
    }
    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return csv_path, json_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1024,16384,262144,1048576")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261023)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/results"))
    args = parser.parse_args()
    try:
        csv_path, json_path = run(
            sizes=[int(value) for value in args.sizes.split(",")],
            repetitions=args.repetitions, warmups=args.warmups,
            seed=args.seed, output_dir=args.output_dir,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Crypto microbenchmark completed; CSV: {csv_path}; JSON: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
