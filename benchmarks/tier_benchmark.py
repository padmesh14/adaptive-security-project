"""Repeatable tier benchmark using seeded synthetic in-memory payloads.

The timer covers encryption including key setup and serialized ciphertext/hash
creation, then decryption including serialization decode, digest verification,
and AEAD verification. Memory probes run separately from latency trials.
No dataset, storage provider, KMS, or blockchain is accessed.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

import cryptography
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption import EncryptionResult, aes_decrypt, aes_encrypt, encrypt_for_tier


MODES = ("SingleAESBaseline", "Low", "Medium", "High")
RAW_FIELDS = (
    "scenario", "distribution", "payload_bytes", "payload_sha256", "mode",
    "trial", "schedule_position", "status", "error_type", "encrypt_seconds",
    "decrypt_seconds", "encrypt_cpu_seconds", "decrypt_cpu_seconds",
    "encrypt_mib_per_second", "decrypt_mib_per_second", "ciphertext_bytes",
    "ciphertext_overhead_bytes", "peak_traced_bytes", "memory_error_type",
)


def _encrypt(mode: str, payload: bytes) -> dict:
    if mode == "SingleAESBaseline":
        key = AESGCM.generate_key(bit_length=256)
        encrypted = aes_encrypt(key, payload)
        blob = encrypted["nonce"] + encrypted["ciphertext"]
        result = EncryptionResult(
            tier="Low",
            scheme="AES-256-GCM (single layer)",
            layers=[{"layer": 1, "algorithm": "AES-256-GCM"}],
            final_ciphertext_b64=base64.b64encode(blob).decode("ascii"),
            integrity_hash_blake2=hashlib.blake2b(blob, digest_size=32).hexdigest(),
            _debug_keys={"aes_key": key},
        )
        return {
            "encoded": result.final_ciphertext_b64.encode("ascii"),
            "digest": result.integrity_hash_blake2,
            "keys": {"aes_key": key},
            "ciphertext_bytes": len(blob),
        }

    result = encrypt_for_tier(mode, payload)
    blob = base64.b64decode(result.final_ciphertext_b64, validate=True)
    return {
        "encoded": result.final_ciphertext_b64.encode("ascii"),
        "digest": result.integrity_hash_blake2,
        "keys": result._debug_keys,
        "ciphertext_bytes": len(blob),
    }


def _decrypt(mode: str, encrypted: dict) -> bytes:
    blob = base64.b64decode(encrypted["encoded"], validate=True)
    digest = hashlib.blake2b(blob, digest_size=32).hexdigest()
    if not hmac.compare_digest(digest, encrypted["digest"]):
        raise ValueError("synthetic ciphertext digest mismatch")
    keys = encrypted["keys"]
    if mode in ("SingleAESBaseline", "Low"):
        key = keys["aes_key"] if mode == "SingleAESBaseline" else keys["aes_key"]
        return aes_decrypt(key, blob[:12], blob[12:])
    if mode == "Medium":
        return aes_decrypt(keys["aes_key"], blob[:12], blob[12:])
    if mode == "High":
        inner = aes_decrypt(keys["key2"], blob[:12], blob[12:])
        return aes_decrypt(keys["key1"], inner[:12], inner[12:])
    raise ValueError(f"unknown benchmark mode: {mode}")


def _timed_trial(mode: str, payload: bytes) -> dict:
    encrypt_cpu_start = time.process_time()
    encrypt_wall_start = time.perf_counter()
    encrypted = _encrypt(mode, payload)
    encrypt_seconds = time.perf_counter() - encrypt_wall_start
    encrypt_cpu_seconds = time.process_time() - encrypt_cpu_start

    decrypt_cpu_start = time.process_time()
    decrypt_wall_start = time.perf_counter()
    recovered = _decrypt(mode, encrypted)
    decrypt_seconds = time.perf_counter() - decrypt_wall_start
    decrypt_cpu_seconds = time.process_time() - decrypt_cpu_start
    if recovered != payload:
        raise RuntimeError("synthetic benchmark round-trip mismatch")
    return {
        "encrypted": encrypted,
        "encrypt_seconds": encrypt_seconds,
        "decrypt_seconds": decrypt_seconds,
        "encrypt_cpu_seconds": encrypt_cpu_seconds,
        "decrypt_cpu_seconds": decrypt_cpu_seconds,
    }


def _peak_memory(mode: str, payload: bytes) -> int:
    """Measure peak traced allocations separately from latency measurements."""
    peaks = []
    encrypted = None
    tracemalloc.start()
    try:
        encrypted = _encrypt(mode, payload)
        _, peak = tracemalloc.get_traced_memory()
        peaks.append(peak)
    finally:
        tracemalloc.stop()
    tracemalloc.start()
    try:
        recovered = _decrypt(mode, encrypted)
        if recovered != payload:
            raise RuntimeError("synthetic memory-probe round-trip mismatch")
        _, peak = tracemalloc.get_traced_memory()
        peaks.append(peak)
    finally:
        tracemalloc.stop()
    return max(peaks)


def _bootstrap_median_ci(values: list[float], seed: int, samples: int = 2000) -> list[float] | None:
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    n = len(values)
    medians = [statistics.median(rng.choices(values, k=n)) for _ in range(samples)]
    return [float(np.percentile(medians, 2.5)), float(np.percentile(medians, 97.5))]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _summary(rows: list[dict], seed: int) -> list[dict]:
    output = []
    for scenario in ("isolated", "mixed"):
        for mode in MODES:
            for size in sorted({row["payload_bytes"] for row in rows}):
                group = [r for r in rows if r["scenario"] == scenario and r["mode"] == mode and r["payload_bytes"] == size]
                if not group:
                    continue
                successful = [r for r in group if r["status"] == "ok"]
                item = {
                    "scenario": scenario,
                    "mode": mode,
                    "payload_bytes": size,
                    "trials": len(group),
                    "successful_trials": len(successful),
                    "failed_trials": len(group) - len(successful),
                    "memory_probe_failures": sum(bool(row["memory_error_type"]) for row in successful),
                }
                for field in (
                    "encrypt_seconds", "decrypt_seconds", "encrypt_cpu_seconds",
                    "decrypt_cpu_seconds", "encrypt_mib_per_second",
                    "decrypt_mib_per_second", "ciphertext_bytes",
                    "ciphertext_overhead_bytes", "peak_traced_bytes",
                ):
                    values = [float(row[field]) for row in successful if row[field] not in (None, "")]
                    if not values:
                        item[field + "_mean"] = None
                        item[field + "_median"] = None
                        item[field + "_stdev"] = None
                        item[field + "_p95"] = None
                        continue
                    item[field + "_mean"] = statistics.mean(values)
                    item[field + "_median"] = statistics.median(values)
                    item[field + "_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
                    # Report the empirical p95 only at n>=30; at n=30 it is
                    # still an exploratory tail estimate with high uncertainty.
                    item[field + "_p95"] = float(np.percentile(values, 95)) if len(values) >= 30 else None
                latency_values = [float(r["encrypt_seconds"]) for r in successful]
                item["encrypt_median_95pct_bootstrap_ci"] = _bootstrap_median_ci(
                    latency_values, seed + size + len(output)
                )
                item["decrypt_median_95pct_bootstrap_ci"] = _bootstrap_median_ci(
                    [float(r["decrypt_seconds"]) for r in successful], seed + size + len(output) + 1
                )
                output.append(item)
    return output


def run_benchmark(
    *, sizes: list[int], modes: list[str], repetitions: int, warmups: int,
    seed: int, output_dir: Path, distribution: dict[str, int],
) -> tuple[Path, Path]:
    if repetitions < 1 or warmups < 0 or not sizes or any(size < 0 for size in sizes):
        raise ValueError("sizes must be non-negative and non-empty; repetitions positive; warmups non-negative")
    if not modes or any(mode not in MODES for mode in modes):
        raise ValueError("modes must be selected from: " + ", ".join(MODES))
    if not distribution or any(mode not in ("Low", "Medium", "High") or weight < 1 for mode, weight in distribution.items()):
        raise ValueError("distribution must assign positive integer weights to Low, Medium, and/or High")
    if any(mode not in modes for mode in distribution):
        raise ValueError("every distribution tier must also be selected in --modes")

    payload_rng = random.Random(seed)
    schedule_rng = random.Random(seed ^ 0x5A17)
    rows: list[dict] = []
    warmup_failures: dict[str, int] = {mode: 0 for mode in modes}
    distribution_label = ",".join(f"{mode}:{weight}" for mode, weight in distribution.items())
    payloads = [(size, payload_rng.randbytes(size)) for size in sizes]

    def warmup(mode: str, payload: bytes) -> None:
        try:
            _timed_trial(mode, payload)
        except Exception:
            warmup_failures[mode] += 1

    def add_trial(mode: str, payload: bytes, size: int, digest: str, scenario: str,
                  trial: int, position: int, label: str) -> None:
        row = {
            "scenario": scenario,
            "distribution": label,
            "payload_bytes": size,
            "payload_sha256": digest,
            "mode": mode,
            "trial": trial,
            "schedule_position": position,
            "status": "failed",
            "error_type": "",
            "encrypt_seconds": None,
            "decrypt_seconds": None,
            "encrypt_cpu_seconds": None,
            "decrypt_cpu_seconds": None,
            "encrypt_mib_per_second": None,
            "decrypt_mib_per_second": None,
            "ciphertext_bytes": None,
            "ciphertext_overhead_bytes": None,
            "peak_traced_bytes": None,
            "memory_error_type": "",
        }
        try:
            measurement = _timed_trial(mode, payload)
            encrypted = measurement["encrypted"]
            es = measurement["encrypt_seconds"]
            ds = measurement["decrypt_seconds"]
            row.update({
                "status": "ok",
                "encrypt_seconds": es,
                "decrypt_seconds": ds,
                "encrypt_cpu_seconds": measurement["encrypt_cpu_seconds"],
                "decrypt_cpu_seconds": measurement["decrypt_cpu_seconds"],
                "encrypt_mib_per_second": (size / (1024 * 1024)) / es if es else None,
                "decrypt_mib_per_second": (size / (1024 * 1024)) / ds if ds else None,
                "ciphertext_bytes": encrypted["ciphertext_bytes"],
                "ciphertext_overhead_bytes": encrypted["ciphertext_bytes"] - size,
            })
            try:
                row["peak_traced_bytes"] = _peak_memory(mode, payload)
            except Exception as exc:
                row["memory_error_type"] = type(exc).__name__
        except Exception as exc:
            # Preserve failed operation rows without exception text, which may
            # contain environment-specific or sensitive provider information.
            row["error_type"] = type(exc).__name__
        rows.append(row)

    for size, payload in payloads:
        warmup_tasks = [(mode, payload) for mode in modes for _ in range(warmups)]
        schedule_rng.shuffle(warmup_tasks)
        for mode, test_payload in warmup_tasks:
            warmup(mode, test_payload)

        tasks = [("isolated", mode, trial, "equal-per-mode")
                 for mode in modes for trial in range(1, repetitions + 1)]
        for trial in range(1, repetitions + 1):
            for mode, weight in distribution.items():
                tasks.extend(("mixed", mode, trial, distribution_label) for _ in range(weight))
            if "SingleAESBaseline" in modes:
                tasks.append(("mixed", "SingleAESBaseline", trial, distribution_label))
        schedule_rng.shuffle(tasks)
        counters: dict[tuple[str, str], int] = {}
        payload_digest = hashlib.sha256(payload).hexdigest()
        for position, (scenario, mode, batch, label) in enumerate(tasks, start=1):
            counter_key = (scenario, mode)
            counters[counter_key] = counters.get(counter_key, 0) + 1
            trial_number = counters[counter_key] if scenario == "isolated" else batch
            add_trial(mode, payload, size, payload_digest, scenario, trial_number, position, label)

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"tier-benchmark-{stamp}-{os.getpid()}"
    csv_path = output_dir / f"{stem}.csv"
    json_path = output_dir / f"{stem}.json"
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    report = {
        "benchmark": "synthetic-tier-encryption-v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "payload_sizes_bytes": sizes,
            "modes": modes,
            "repetitions_per_isolated_mode": repetitions,
            "warmups_per_mode_and_size": warmups,
            "synthetic_payload_seed": seed,
            "trial_schedule_seed": seed ^ 0x5A17,
            "mixed_tier_distribution_weights": distribution,
            "warmup_failures_by_mode": warmup_failures,
        },
        "environment": {
            "python": sys.version,
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "cryptography": cryptography.__version__,
            "numpy": np.__version__,
            "implementation": "existing project encryptors; local in-memory; no external services",
        },
        "source_sha256": {
            "benchmark_harness": _sha256_file(Path(__file__).resolve()),
            "encryption_implementation": _sha256_file(Path(__file__).resolve().parents[1] / "src" / "encryption.py"),
        },
        "measurement_method": {
            "encryption_wall_and_cpu": "encrypt API return, including key setup, nonce generation, serialization and BLAKE2b digest creation",
            "decryption_wall_and_cpu": "base64 decoding, BLAKE2b verification and authenticated decryption of all layers",
            "throughput": "input plaintext MiB divided by corresponding measured wall time",
            "ciphertext_expansion": "raw nonce plus ciphertext and GCM tag bytes, minus plaintext bytes; excludes base64, JSON metadata, digest, and provider metadata",
            "memory": "peak tracemalloc allocation from separate encryption and decryption probes; excluded from timed values; not RSS",
            "p95": "empirical nearest percentile reported only for groups with at least 30 successful samples; small-sample p95 is suppressed",
            "confidence_interval": "95% percentile bootstrap intervals for encryption and decryption medians; deterministic seed, 2000 resamples",
            "failures": "each measured operation is retained with status and exception class; no exception messages or secrets are recorded",
        },
        "raw_csv": csv_path.name,
        "failed_measured_trials": sum(row["status"] != "ok" for row in rows),
        "summary": _summary(rows, seed),
        "interpretation": {
            "high_vs_single_aes": (
                "High uses two independent ECDH/HKDF-derived AES-GCM layers; the baseline uses one random AES-256-GCM key. "
                "Both share the same process and application trust boundary. The benchmark measures overhead, not security advantage."
            ),
            "memory": "Python traced allocations only, not total process RSS",
        },
    }
    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return csv_path, json_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1024,16384,262144,1048576",
                        help="comma-separated synthetic payload sizes in bytes")
    parser.add_argument("--modes", default=",".join(MODES),
                        help="comma-separated modes: " + ", ".join(MODES))
    parser.add_argument("--distribution", default="Low:6,Medium:3,High:1",
                        help="mixed workload integer weights, e.g. Low:6,Medium:3,High:1")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261023)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/results"))
    args = parser.parse_args()
    try:
        sizes = [int(value) for value in args.sizes.split(",")]
        modes = [value.strip() for value in args.modes.split(",")]
        distribution = {}
        for item in args.distribution.split(","):
            mode, weight = item.split(":", 1)
            mode = mode.strip()
            if mode in distribution:
                raise ValueError("distribution modes must not be repeated")
            distribution[mode] = int(weight)
        csv_path, json_path = run_benchmark(
            sizes=sizes, modes=modes, repetitions=args.repetitions,
            warmups=args.warmups, seed=args.seed, output_dir=args.output_dir,
            distribution=distribution,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Synthetic benchmark completed: {len(sizes)} payload sizes, {len(modes)} modes, {args.repetitions} isolated trials per mode.")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
