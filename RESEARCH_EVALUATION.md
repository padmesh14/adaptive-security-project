# Research Evaluation and Optional AWS KMS

**Evaluation date:** 2026-10-23  
**Status:** Local synthetic evaluation completed; AWS KMS adapter implemented and mock-tested; no live AWS requests made.

## Research questions and hypotheses

1. **RQ1 — Classification:** Does adaptive sensitivity classification improve on fixed thresholds on independently labeled, varied synthetic fields? **H1:** adaptive classification will improve held-out macro-F1 without increasing sensitive under-classification.
2. **RQ2 — Error consequences:** How often does each classifier assign a lower tier than the rubric expects, and what is the measured encryption-time difference? No numerical compromise probability or financial loss is inferred.
3. **RQ3 — Tier performance:** What latency, throughput, CPU, memory-probe, and ciphertext-expansion overhead do Low, Medium, and High add over one AES-256-GCM operation?
4. **RQ4 — High-tier security:** Does the second AEAD layer address an additional threat under an explicit trust-boundary model strongly enough to justify its measured overhead? The current evidence does not establish such a benefit.
5. **Key-management context:** Can the provider interface support optional AWS KMS wrapping without changing legacy ciphertext formats? Mocked tests establish adapter behavior only; live AWS operation is unverified.

## Experimental method

### Tier benchmark

The harness `benchmarks/tier_benchmark.py` uses deterministic synthetic byte strings at 1 KiB, 16 KiB, 256 KiB, and 1 MiB. It measures four isolated modes: single AES-256-GCM baseline, existing Low, Medium, and High. Each configuration has 30 measured trials after three warmups. A seeded randomized schedule interleaves modes; each mode uses the same payload bytes for a given size. A separate weighted mixed workload uses Low:6, Medium:3, High:1, with an AES-GCM control in each batch.

Encryption timing includes key setup, nonce generation, the existing tier encryption call, serialization of ciphertext to Base64, and BLAKE2b digest creation. Baseline follows the same single-layer output construction. Decryption timing includes Base64 decoding, BLAKE2b verification, and authenticated decryption of all required layers. Throughput is plaintext MiB divided by the respective measured stage's wall time. Ciphertext expansion is raw nonce plus ciphertext/tag bytes minus plaintext; it excludes Base64, manifest metadata, digests, and provider metadata.

Wall and process CPU timings are recorded separately for encryption and decryption. `tracemalloc` peak allocations are measured in separate probes and do not run during timed trials; they are Python allocations, not process RSS. Measured failures remain in the raw CSV with an error class and no exception text. The JSON records configuration, random seeds, software/hardware metadata, source hashes, timing definitions, failure counts, mean, median, standard deviation, p95 for groups with at least 30 successful trials, and deterministic 2,000-resample percentile bootstrap intervals for medians.

### Environment and outputs

- Python 3.12.10, CPython
- macOS 15.8.1, arm64, 8 logical CPUs
- `cryptography` 50.0.2; NumPy 2.5.4
- No storage, KMS, or blockchain services were contacted

Current 30-trial run and derived artifacts:

- [Raw CSV](benchmarks/results/tier-benchmark-20261023T111343Z-54179.csv)
- [Raw JSON and environment metadata](benchmarks/results/tier-benchmark-20261023T111343Z-54179.json)
- [Summary table](benchmarks/results/tier-benchmark-20261023T111343Z-54179-summary.md)
- [Summary CSV](benchmarks/results/tier-benchmark-20261023T111343Z-54179-summary.csv)
- [Latency plot (SVG)](benchmarks/results/tier-benchmark-20261023T111343Z-54179-latency.svg)

The run recorded **zero failed measured trials**. The following medians are selected from the actual isolated-mode summary; the linked summary includes means, standard deviations, p95, throughput, and confidence intervals for every size.

| Payload | Single AES-GCM encrypt / decrypt (µs) | Low (µs) | Medium (µs) | High (µs) | Expansion: single/Low/Medium/High |
|---:|---:|---:|---:|---:|---:|
| 1 KiB | 5.854 / 5.042 | 8.166 / 4.979 | 74.146 / 5.125 | 136.355 / 6.645 | 28 / 28 / 28 / 56 bytes |
| 16 KiB | 34.480 / 49.208 | 64.729 / 46.812 | 131.104 / 47.063 | 198.562 / 50.750 | 28 / 28 / 28 / 56 bytes |
| 256 KiB | 480.167 / 753.250 | 1,022.104 / 760.750 | 1,092.708 / 760.417 | 1,194.604 / 785.083 | 28 / 28 / 28 / 56 bytes |
| 1 MiB | 2,061.166 / 3,139.438 | 4,324.834 / 3,196.437 | 4,442.208 / 3,226.417 | 4,710.417 / 3,315.417 | 28 / 28 / 28 / 56 bytes |

These are local measurements on one machine with 30 observations per isolated mode/size. At 1 MiB, High encryption's median was about 2.28x the single AES-GCM median and about 8.9% above Low; it added 28 bytes relative to one AEAD envelope. The 30-sample p95 is only a rough tail estimate, and this is not a cross-machine or production-capacity claim. The run recorded zero failed measured trials. CPU timing, throughput, standard deviation, confidence intervals, and separate `tracemalloc` probes are in the linked summary. Traced Python allocations are not total process memory.

At 1 MiB, encryption mean / standard deviation / p95 in microseconds were: single AES 2,668 / 2,171 / 6,223; Low 4,418 / 296 / 5,013; Medium 5,056 / 1,585 / 7,981; High 5,201 / 1,361 / 7,497. The single-AES sample had a large outlier, so its mean and p95 are substantially above its median.

### Component microbenchmarks

`benchmarks/crypto_microbenchmark.py` separates AES-GCM, ECDH pair generation, ECDH agreement, HKDF, ECDH+HKDF, complete Medium and High encryptors, and experimental per-layer High compositions. The layer-only cases compose the existing helper functions and are explicitly benchmark-only; they do not modify the production encryptors. Thirty trials and three warmups were run per operation and payload size, with no measured failures.

At 1 KiB, current measured medians included: AES-GCM encryption 3.146 µs; ECDH pair generation 13.813 µs; ECDH agreement 32.083 µs; HKDF 3.271 µs; ECDH plus HKDF 35.000 µs; complete Medium encryption 83.896 µs; experimental High layer 1 79.833 µs; experimental High layer 2 74.126 µs; and complete High encryption 157.167 µs. There were zero measured failures. Full results are in:

- [Microbenchmark CSV](benchmarks/results/crypto-microbenchmark-20261023T111445Z-54270.csv)
- [Microbenchmark JSON](benchmarks/results/crypto-microbenchmark-20261023T111445Z-54270.json)

Component timings isolate operations, while complete tier timings include key setup and result construction. The two figures answer different questions and should not be added together as though they were a controlled security comparison.

## Synthetic classifier evaluation

The previous nine-column evaluation is retained as an initial diagnostic only: it scored adaptive 7/9 and fixed 9/9, and its two adaptive mistakes were `diagnosis` and `medication`. Each had name score 30, uniqueness contribution 1, and total risk score 31; the adaptive Low cutoff was 31, so the `score <= low_cut` branch assigned Low. The fixed Low cutoff was 25, so each scored Medium. Neither field hit the direct-identifier override. This small constructed example motivated the evaluation below; it does not establish which threshold method generalizes.

The new `benchmarks/synthetic_classification_dataset.py` generates 54 synthetic fields with 128 values each from a fixed seed: 18 development fields (six/tier), 12 validation fields (four/tier), and 24 held-out test fields (eight/tier). The label rubric is documented in the generator and output config: direct identifiers, contact/account data, precise location, and sensitive individual-level health/financial details are High; person-linked or sensitive-domain details without direct identity are Medium; coarse, public, aggregate, or non-linkable operational values are Low. Names are disjoint across splits, and the test includes held-out field names and patterns. The same broad synthetic value families are deliberately reused where appropriate to exercise known classes; this is not a claim of full distributional independence. Values are synthetic only, including reserved `.invalid` emails, and include malformed, sparse, all-missing, repeated, bounded, and high-uniqueness cases. Labels were assigned from the rubric before classifier results, not from classifier scores. This remains author-labeled test data, not a regulatory standard or real-world ground truth.

Thresholds were not selected using the held-out test set. A fixed-threshold candidate pair was selected on validation by maximizing macro-F1, breaking ties by fewer under-tiered and then fewer over-tiered fields. The held-out comparison includes the existing adaptive classifier, existing 25/55 fixed thresholds, a separately implemented transparent rule baseline, and those validation-tuned cutoffs. Development and validation metrics are saved as diagnostics; only held-out metrics are used for the comparative conclusion.

| Method | Accuracy (95% bootstrap CI) | Macro-F1 (95% bootstrap CI) | Confusion matrix: expected rows, predicted Low/Medium/High | Under / over |
|---|---:|---:|---|---:|
| Adaptive | 0.500 [0.292, 0.708] | 0.465 [0.297, 0.629] | `[[8,0,0],[2,2,4],[1,5,2]]` | 8 / 4 |
| Fixed 25/55 | 0.458 [0.250, 0.667] | 0.385 [0.199, 0.576] | `[[8,0,0],[4,2,2],[5,2,1]]` | 11 / 2 |
| Rule baseline | 0.833 [0.667, 0.958] | 0.817 [0.633, 0.955] | `[[8,0,0],[0,8,0],[1,3,4]]` | 4 / 0 |
| Validation-tuned cutoffs (5/30) | 0.458 [0.250, 0.667] | 0.410 [0.254, 0.563] | `[[8,0,0],[3,1,4],[1,5,2]]` | 9 / 4 |

On this 24-field held-out set, the rule baseline scored higher than adaptive and both fixed-threshold methods. It assigned four expected-High fields below High (one to Low, three to Medium), so it still misses sensitive examples. Per-tier precision/recall/F1 and false-positive/negative rates are in JSON. Bootstrap intervals resample fields and do not capture new-domain shift; they are wide with only eight examples per tier. The rule baseline and synthetic catalog were authored in the same project milestone, so the baseline may align unusually well with the rubric and field naming choices. Treat its result as exploratory, not as evidence that rule-based classification is generally superior. An external labeler and a preregistered baseline would improve independence.

Classification-error costs are reported separately from confidentiality-risk interpretation. Using the nearest payload-size median in the current local tier benchmark, estimated total encryption times for the 24 test fields were 1.427 ms adaptive, 0.844 ms fixed 25/55, 1.435 ms rule baseline, and 1.361 ms validation-tuned; the corresponding all-Low estimate was 0.196 ms. These are synthetic workload estimates, not risk scores or production estimates. The qualitative threat-model implication is that each under-tiered field receives fewer configured encryption layers than the rubric calls for; no probability of compromise or harm is inferred.

Artifacts:

- [Held-out classifier CSV](benchmarks/results/classifier-evaluation-v2-20261023T111736Z.csv)
- [Metrics and split diagnostics JSON](benchmarks/results/classifier-evaluation-v2-20261023T111736Z.json)
- [Generation configuration and label rationales](benchmarks/results/classifier-evaluation-v2-20261023T111736Z-config.json)
- [Held-out comparison plot (SVG)](benchmarks/results/classifier-evaluation-v2-20261023T111736Z-heldout.svg)

## Threat model and security interpretation

### Assumptions and adversaries

- Storage providers may withhold, corrupt, or substitute encrypted bytes.
- A party who can read a public CID or chain entry can retrieve ciphertext and observe public metadata; encryption is relied on for confidentiality.
- An attacker may alter an untrusted manifest. The application process, authorized decryption key provider, and AWS IAM/KMS policy are trusted for the relevant workflow.
- A compromised host or authorized process can expose plaintext and unwrapped keys in memory. Local file permissions and KMS do not protect against a fully compromised caller.
- Classification is a heuristic and can assign a lower tier than an authorized reviewer expects. The held-out synthetic evaluation has 24 fields and author labels; its best observed method is not a validated real-world model.

### What the controls establish

- **AES-GCM:** authenticates ciphertext and any supplied associated data under the key. The legacy Python tier format supplies `None` as AAD, so its GCM operation does not authenticate the tier label, record reference, or manifest fields. Managed-key wrapping separately binds record reference, tier, slot, provider, key ID, format version, and wrapping algorithm through AEAD AAD.
- **BLAKE2b digest:** detects ciphertext mismatch relative to a trusted expected digest. It is unkeyed; an attacker able to replace both data and expected digest can recompute it. It does not identify the creator or provide authorization.
- **CID/IPFS:** a CID addresses particular content bytes and makes altered bytes produce a different identifier. Availability is not guaranteed.
- **Blockchain anchoring:** an immutable registry can preserve the CID-to-opaque-record-digest association, provided verifiers compare against a trusted chain, chain ID, and contract. It exposes transaction metadata and does not encrypt content, grant access control, or authenticate manifest fields that were not anchored.
- **High double encryption:** a second independently derived AEAD layer could help if the threat specifically compromises one layer's key while an independently protected second key remains secret. Here both layers are created and used by the same application process, share its permissions and host, and are handled under the same configured key-provider trust boundary. High's 1 MiB median encrypt time was 4.710 ms versus 2.061 ms for single AES-GCM, with 28 additional ciphertext bytes. The measurements establish overhead only; they do not establish improved security. Without a separate administrative/compromise domain for the layers, the defensible claim is defense-in-depth under an unproven independence assumption, not a demonstrated security benefit. Research should compare a genuinely separated key boundary or narrow the claim to layered construction and measured cost.

## Optional AWS KMS adapter

`src/aws_kms_key_provider.py` implements the existing `KeyProvider` interface using AWS KMS `Encrypt` and `Decrypt` for the existing 32-byte tier data keys. It requires `AWS_KMS_KEY_ID` and `AWS_REGION`, uses `boto3`'s default credential chain, and sends only a purpose string plus a SHA-256 digest of the record/tier/key-slot context as KMS encryption context. It stores a Base64 KMS ciphertext blob and non-secret provider/key metadata. The adapter has explicit network timeouts and standard retries; permission denial, throttling, invalid ciphertext/context, missing keys, timeout/network failure, and malformed responses fail closed. It does not create KMS keys and has no local-key fallback.

The default tests mock the KMS boundary. `tests/live_aws_kms.py` is excluded from normal test discovery and is opt-in. **No live AWS API call was run**, because KMS operations may incur account charges and require explicit authorization. An AWS key policy, IAM role, key recovery/rotation plan, and review of current regional pricing remain deployment responsibilities. This adapter and its mocked tests are not a production-readiness certification.

For a new run only, legacy `main.py` behavior remains the default. Managed selection requires `--new-run` and produces a unique manifest:

```sh
# Local provider (initialize once; never overwrite an existing KEK)
.venv/bin/python -m src.key_management init
.venv/bin/python main.py --new-run --managed-key-provider local

# AWS KMS (use an authorized symmetric KMS key and AWS credential chain)
export AWS_KMS_KEY_ID='arn:aws:kms:REGION:ACCOUNT:key/KEY-ID'
export AWS_REGION='us-east-1'
.venv/bin/python main.py --new-run --managed-key-provider aws-kms
```

Mocked tests and local fresh-process recovery for the local provider do not establish live AWS recoverability. Do not use the AWS live test until explicitly approved and authorized.

## Reproduction commands

```sh
# Test suites
.venv/bin/python -m pytest -q
(cd blockchain && npx hardhat test)
(cd frontend && npm test -- --run)

# Full local tier evaluation
.venv/bin/python -m benchmarks.tier_benchmark \
  --sizes 1024,16384,262144,1048576 \
  --distribution Low:6,Medium:3,High:1 \
  --repetitions 30 --warmups 3 --output-dir benchmarks/results

# Derive Markdown/CSV summary and SVG plot from the generated JSON
.venv/bin/python -m benchmarks.analyze_tier_results benchmarks/results/NEW-RUN.json

# Component microbenchmark and classifier evaluation
.venv/bin/python -m benchmarks.crypto_microbenchmark \
  --sizes 1024,16384,262144,1048576 --repetitions 30 --warmups 3
.venv/bin/python -m benchmarks.classifier_evaluation \
  --benchmark-json benchmarks/results/NEW-RUN.json \
  --seed 20261023 --rows 128
```

The exact run files named above preserve the actual measurements used in this report. New commands create new timestamped files and do not overwrite the earlier smoke-run artifacts.

## Test results and limitations

Verified commands and actual results:

```sh
.venv/bin/python -m pytest -q
# 60 passed, 2 warnings, 7 subtests passed in 17.99s
(cd blockchain && npx hardhat test)
# 6 passing
(cd frontend && npm test -- --run)
# 3 test files passed; 8 tests passed
```

The Python warnings are the existing `websockets.legacy` deprecation and the Starlette/httpx test-client deprecation notice. The focused classifier evaluation tests also passed: `3 passed`. Existing legacy ciphertexts were not modified or decrypted. No AWS resources were created, no KMS calls were made, and no public blockchain transaction was sent. The repository checkout has no discoverable `.git` metadata, so tracked-file state and Git history could not be verified.
