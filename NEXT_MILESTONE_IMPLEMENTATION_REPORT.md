# Research Evaluation and AWS KMS Milestone

**Date:** 2026-10-23

## Completed

- Validated and corrected the benchmark harness: randomized trial ordering, per-mode warmups, comparable timing boundaries, separate memory probes, failure rows, CPU timings, throughput, ciphertext expansion, p95, and bootstrap confidence intervals.
- Added a separate crypto component microbenchmark for AES-GCM, ECDH, HKDF, Medium, and High-layer operations.
- Added a synthetic classifier evaluation with per-tier precision, recall, F1, false-positive/negative rates, confusion matrix, and estimated encryption-time effects of tier mistakes.
- Added an optional AWS KMS `KeyProvider` adapter with explicit key ID and region, AWS SDK credential-chain support, context binding, sanitized errors, retries/timeouts, and no local fallback.
- Added explicit managed-key selection for new `main.py` runs. Managed mode requires `--new-run`; legacy behavior remains the default.
- Updated key-management, README, and research evaluation documentation.

## Actual evaluation

The local tier benchmark used synthetic payloads of 1 KiB, 16 KiB, 256 KiB, and 1 MiB; 30 measured trials per mode after 3 warmups; and a Low:6, Medium:3, High:1 mixed workload. It recorded **zero failed measured trials**.

At 1 MiB, observed median encryption times were:

| Mode | Median encryption | Ciphertext expansion |
|---|---:|---:|
| Single AES-GCM | 2,079.271 µs | 28 bytes |
| Low | 4,229.271 µs | 28 bytes |
| Medium | 4,303.916 µs | 28 bytes |
| High | 4,567.813 µs | 56 bytes |

These are measurements from one Mac environment, not production performance guarantees or evidence that High-tier double encryption is more secure.

On a hand-labeled synthetic set of nine columns, adaptive classification scored 7/9 and assigned two expected Medium fields to Low. Fixed thresholds scored 9/9 on that constructed set; this does not establish general classifier accuracy.

## Test results

- `.venv/bin/python -m pytest -q` — **59 passed**, 2 warnings, 7 subtests passed.
- `(cd blockchain && npx hardhat test)` — **6 passing**.
- `(cd frontend && npm test -- --run)` — **3 test files passed; 8 tests passed**.

## Files

- `src/aws_kms_key_provider.py`
- `main.py`
- `benchmarks/tier_benchmark.py`
- `benchmarks/crypto_microbenchmark.py`
- `benchmarks/classifier_evaluation.py`
- `benchmarks/analyze_tier_results.py`
- `tests/test_aws_kms_key_provider.py`
- `tests/test_main_managed.py`
- `tests/test_benchmarks.py`
- `tests/test_classifier_evaluation.py`
- `tests/live_aws_kms.py` — opt-in; excluded from the default suite
- `KEY_MANAGEMENT.md`, `README.md`, `CRYPTO_REVIEW_AND_BENCHMARK_REPORT.md`, `RESEARCH_EVALUATION.md`
- New timestamped artifacts under `benchmarks/results/`; prior smoke artifacts remain intact.

## Limitations

- AWS adapter behavior was tested with mocks only. No live AWS request was made; live KMS calls may incur charges and require explicit authorization.
- The AWS adapter does not create KMS resources and is not by itself a complete production key-management deployment.
- Existing legacy ciphertexts were not modified or decrypted.
- The checkout has no discoverable `.git` metadata, so tracked-file state and history remain unaudited.
- No public blockchain transactions or external storage operations were performed for this milestone.

## Reproduce

```sh
.venv/bin/python -m pytest -q
(cd blockchain && npx hardhat test)
(cd frontend && npm test -- --run)

.venv/bin/python -m benchmarks.tier_benchmark \
  --sizes 1024,16384,262144,1048576 \
  --distribution Low:6,Medium:3,High:1 \
  --repetitions 30 --warmups 3 --output-dir benchmarks/results
```

See `RESEARCH_EVALUATION.md` for the complete statistical tables, raw-data paths, threat model, classifier details, AWS setup, and optional live-test instructions.
