# Cryptographic Review and Benchmark Report

**Project:** Adaptive Multi-Layer Security for Decentralized Systems  
**Date:** 2026-10-23

> **Status note:** This report records the earlier cryptographic review and smoke benchmark. The subsequent milestone added the AWS KMS adapter, expanded the benchmark suite, and ran a 30-repetition evaluation. See [RESEARCH_EVALUATION.md](RESEARCH_EVALUATION.md) for current results and KMS limitations.

## Scope

This milestone reviewed the existing encryption and key-management code, added focused synthetic tests where coverage was missing, and created a local benchmark harness. No encryption algorithms, key formats, existing manifests, ciphertexts, cloud resources, or blockchain contracts were changed.

## Cryptographic review findings

- AES-GCM encryption requests a fresh 12-byte nonce from `os.urandom` for each invocation. As with any random 96-bit nonce scheme, uniqueness is probabilistic; current tier encryptors also generate fresh data keys or ECDH material per record/layer.
- Medium uses P-256 ECDH and HKDF-SHA256. High uses separate ECDH key pairs and distinct HKDF context labels for its two encryption layers.
- High-tier decryption checks the outer GCM layer before the inner layer. Each layer's authentication tag must validate before plaintext is returned.
- Managed key wrapping binds authenticated context to the format version, opaque record reference, sensitivity tier, key slot, provider, key ID, and wrapping algorithm. Changing the record reference or tier causes wrapped-key authentication to fail.
- Retrieval compares stored encryption metadata and recalculates the BLAKE2b digest before decryption. The digest detects byte mismatches; it does not authenticate the manifest or prove who produced the content. Legacy AES-GCM calls use no associated data, so metadata is not directly authenticated by the GCM operation.
- No concrete issue requiring an encryption algorithm or format change was established in this review. Legacy ciphertext whose original keys have not been found remains unrecoverable unless those original keys are located and validated.

## Tests added

Synthetic tests now cover:

- AES-GCM requesting a fresh 12-byte nonce on each call.
- HKDF context separation between High-tier layer labels.
- Rejection of managed-key record-reference and tier substitution.
- Rejection of malformed ECDH peer points.
- Rejection of swapped High-tier decryption keys/layer order.

Existing tests also cover successful tier round trips, tampered payloads and digests, wrong keys, missing keys, corrupted wrapped keys, and authenticated-decryption failures.

## Benchmark harness

`benchmarks/tier_benchmark.py` runs on seeded synthetic bytes and does not access dataset files or external services. It compares Low, Medium, High, and a single AES-256-GCM baseline. Payload sizes, trial count, warmups, selected tiers, and mixed tier weights are configurable.

The harness records raw per-trial data in CSV and a JSON summary with environment metadata. Measurements include encryption/decryption time and throughput, ciphertext expansion, CPU time, and peak Python allocations reported by `tracemalloc`. The memory figure is not total process RSS.

### Smoke run performed

Command:

```sh
.venv/bin/python -m benchmarks.tier_benchmark \
  --sizes 1024,16384 \
  --distribution Low:2,Medium:1,High:1 \
  --repetitions 5 \
  --warmups 1 \
  --output-dir benchmarks/results
```

The run completed with 1 KiB and 16 KiB payloads, five isolated trials per mode and payload size, and mixed observations of 10 Low, 5 Medium, and 5 High operations per payload size, plus five single-AES controls.

Artifacts:

- `benchmarks/results/tier-benchmark-20261023T104819Z-52158.csv`
- `benchmarks/results/tier-benchmark-20261023T104819Z-52158.json`

Observed median timings from this smoke run:

| Payload | Mode | Encryption (µs) | Decryption (µs) | Ciphertext expansion |
|---:|---|---:|---:|---:|
| 1 KiB | Low | 11.333 | 7.292 | 28 bytes |
| 1 KiB | Medium | 91.000 | 7.583 | 28 bytes |
| 1 KiB | High | 155.000 | 10.959 | 56 bytes |
| 1 KiB | Single AES-GCM | 5.667 | 6.500 | 28 bytes |
| 16 KiB | Low | 36.708 | 38.625 | 28 bytes |
| 16 KiB | Medium | 109.125 | 38.875 | 28 bytes |
| 16 KiB | High | 182.833 | 45.542 | 56 bytes |
| 16 KiB | Single AES-GCM | 20.791 | 37.708 | 28 bytes |

These timings document an actual local smoke run, not a statistically stable performance conclusion. High-tier double encryption adds a second independently derived key and AEAD layer, but both layers currently share one process and key-provider trust boundary. The measurements quantify implementation overhead; they do not establish a security advantage.

## Verification results

Commands and outcomes:

```sh
.venv/bin/python -m pytest -q
# 45 passed, 2 warnings, 3 subtests passed

cd blockchain && npx hardhat test
# 6 passing

cd frontend && npm test -- --run
# 3 test files passed; 8 tests passed
```

The two Python warnings concern deprecated `websockets.legacy` and the Starlette/httpx test-client integration.

## Remaining limitations

- The benchmark smoke sample is too small to support production or general performance claims. Larger repeated runs on documented hardware are needed.
- No AWS KMS provider or live KMS test was performed.
- No IPFS, Filebase, or public-chain operation was part of this milestone.
- No formal cryptographic proof, regulatory-compliance assessment, production-readiness review, or large-scale scalability test was performed.
- The project checkout has no discoverable `.git` metadata, so Git tracking/history could not be audited in this work.

## Reproduction

Run the local test suites:

```sh
.venv/bin/python -m pytest -q
(cd blockchain && npx hardhat test)
(cd frontend && npm test -- --run)
```

Run a synthetic benchmark:

```sh
.venv/bin/python -m benchmarks.tier_benchmark \
  --sizes 1024,16384,262144 \
  --distribution Low:6,Medium:3,High:1 \
  --repetitions 30 \
  --warmups 3 \
  --output-dir benchmarks/results
```
