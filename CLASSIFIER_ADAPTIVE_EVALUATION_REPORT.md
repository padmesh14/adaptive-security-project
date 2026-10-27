# Adaptive Classification and Security–Performance Evaluation

**Project:** Adaptive Multi-Layer Security for Decentralized Systems  
**Evaluation date:** 2026-10-23

## Scope and changes

This milestone audited the existing sensitivity classifier, evaluated it on reproducible synthetic fields, compared it with threshold and rule-based baselines, reran the encryption performance benchmarks, and documented the High-tier threat-model limitations.

The production classifier, encryption algorithms, manifests, ciphertexts, and prior benchmark outputs were left unchanged. All evaluation values are synthetic. No AWS KMS calls, public blockchain transactions, or external storage operations were performed.

Files changed or added:

- `benchmarks/synthetic_classification_dataset.py` — deterministic synthetic catalog, label rubric, split metadata, and edge cases.
- `benchmarks/classifier_evaluation.py` — comparisons, metrics, confidence intervals, tier-cost estimates, and SVG visualization.
- `tests/test_classifier_evaluation.py` — deterministic split and evaluation tests.
- `RESEARCH_EVALUATION.md` — full research methods, findings, limitations, and reproduction instructions.
- `benchmarks/results/` — new uniquely named CSV, JSON, summary, and SVG artifacts. Earlier artifacts remain intact.

## Audit of the prior classifier errors

The previous nine-column evaluation classified `diagnosis` and `medication` as Low, despite their author-assigned Medium labels. Each column had 100 synthetic values cycling through four categories, a medical-name score of 30, a uniqueness ratio of 0.04 contributing 1 point, no pattern matches, and a total risk score of 31. The dataset-specific adaptive Low cutoff was 31, so the `score <= low_cut` branch assigned Low. The fixed Low cutoff was 25, so the fixed-threshold method assigned Medium. Neither field triggered the direct-identifier override. No production classification rule was changed.

## Synthetic evaluation design

The deterministic generator creates 54 synthetic fields with 128 values per field:

- Development: 18 fields, six per tier.
- Validation: 12 fields, four per tier.
- Held-out test: 24 fields, eight per tier.

Labels are assigned from a documented rubric independently of classifier output. High covers direct identifiers, contact or account data, precise location, and sensitive individual-level health or financial detail. Medium covers person-linked or sensitive-domain details without direct identity. Low covers public, coarse, aggregate, or non-linkable operational values.

Field names and generated examples are split across sets. Some broad synthetic value families are reused to exercise common classes; held-out cases include new names and value patterns. Data include reserved `.invalid` emails, malformed and sparse values, all-missing values, repeated categories, bounded numeric values, and high-uniqueness synthetic references. These author-labeled cases do not establish real-world accuracy or represent a regulatory standard.

Thresholds for the validation-tuned method were chosen on validation only, maximizing macro-F1 and breaking ties by fewer under-tiered then fewer over-tiered fields. The selected cutoffs were 5 and 30. The test split was not used to select thresholds.

## Held-out classifier results

Confusion matrices below use expected tiers as rows and predicted Low, Medium, High as columns.

| Method | Accuracy (95% bootstrap CI) | Macro-F1 (95% bootstrap CI) | Confusion matrix | Under-tiered | Over-tiered |
|---|---:|---:|---|---:|---:|
| Adaptive thresholds | 0.500 (0.292–0.708) | 0.465 (0.297–0.629) | `[[8,0,0],[2,2,4],[1,5,2]]` | 8 | 4 |
| Existing fixed thresholds (25/55) | 0.458 (0.250–0.667) | 0.385 (0.199–0.576) | `[[8,0,0],[4,2,2],[5,2,1]]` | 11 | 2 |
| Rule baseline | 0.833 (0.667–0.958) | 0.817 (0.633–0.955) | `[[8,0,0],[0,8,0],[1,3,4]]` | 4 | 0 |
| Validation-tuned thresholds (5/30) | 0.458 (0.250–0.667) | 0.410 (0.254–0.563) | `[[8,0,0],[3,1,4],[1,5,2]]` | 9 | 4 |

The adaptive method modestly exceeded the existing fixed thresholds on this test set, while the rule baseline scored higher. The rule baseline under-tiered four expected-High fields, so it did not eliminate false negatives. Its rules and the synthetic catalog were authored within the same milestone and may align unusually well; treat its score as exploratory. Bootstrap intervals resample only 24 fields, are wide, and do not measure generalization to new domains. Per-tier precision, recall, F1, false-positive/negative rates, and development/validation diagnostics are in the JSON output.

### Estimated computational cost of assignments

For each held-out field, the cost analysis uses the measured median for the nearest payload size in the local tier benchmark. It sums encryption-time estimates by predicted tier and compares them with assigning every field Low. It is a computation-only model; no numerical compromise probability, financial loss, or security score is inferred.

| Method | Estimated total encryption time | All-Low estimate | Extra vs all Low |
|---|---:|---:|---:|
| Adaptive | 1.427 ms | 0.196 ms | 1.231 ms |
| Existing fixed thresholds | 0.844 ms | 0.196 ms | 0.648 ms |
| Rule baseline | 1.435 ms | 0.196 ms | 1.239 ms |
| Validation-tuned thresholds | 1.361 ms | 0.196 ms | 1.165 ms |

Under-tiering means the field receives fewer configured encryption layers than the author-defined rubric calls for. The evaluation does not quantify the probability or impact of compromise.

## Security–performance measurements

The existing benchmark harness ran four payload sizes, 30 measured trials per mode and size, and three warmups. The modes were single AES-256-GCM, Low, Medium, and High. It recorded zero failed measured trials. The table shows encryption/decryption medians in microseconds and ciphertext expansion:

| Payload | Single AES-GCM | Low | Medium | High | Expansion: single / Low / Medium / High |
|---:|---:|---:|---:|---:|---:|
| 1 KiB | 5.854 / 5.042 | 8.166 / 4.979 | 74.146 / 5.125 | 136.355 / 6.645 | 28 / 28 / 28 / 56 bytes |
| 16 KiB | 34.480 / 49.208 | 64.729 / 46.812 | 131.104 / 47.063 | 198.562 / 50.750 | 28 / 28 / 28 / 56 bytes |
| 256 KiB | 480.167 / 753.250 | 1,022.104 / 760.750 | 1,092.708 / 760.417 | 1,194.604 / 785.083 | 28 / 28 / 28 / 56 bytes |
| 1 MiB | 2,061.166 / 3,139.438 | 4,324.834 / 3,196.437 | 4,442.208 / 3,226.417 | 4,710.417 / 3,315.417 | 28 / 28 / 28 / 56 bytes |

At 1 MiB, encryption mean / standard deviation / p95 were 2,668 / 2,171 / 6,223 µs for single AES-GCM, 4,418 / 296 / 5,013 µs for Low, 5,056 / 1,585 / 7,981 µs for Medium, and 5,201 / 1,361 / 7,497 µs for High. A large single-AES outlier raised its mean and p95 above its median. Full CPU, throughput, variability, confidence intervals, and memory-probe data are in the benchmark summary. Memory measurements use `tracemalloc`; they are not total process RSS.

The crypto microbenchmark at 1 KiB measured median AES-GCM encryption at 3.146 µs, ECDH key-pair generation at 13.813 µs, ECDH agreement at 32.083 µs, HKDF at 3.271 µs, ECDH plus HKDF at 35.000 µs, complete Medium encryption at 83.896 µs, and complete High encryption at 157.167 µs. It recorded zero failures.

## High-tier threat-model conclusion

High encrypts with two independently generated ECDH/HKDF-derived AES-GCM keys. However, both layers run in the same application process on the same host and share the configured key-provider trust boundary. The current system does not demonstrate separate administrative controls or an independent compromise domain for each layer. At 1 MiB, High measured 4.710 ms median encryption versus 2.061 ms for one AES-GCM layer and added 28 ciphertext bytes compared with one AEAD envelope.

These measurements demonstrate overhead, not additional security. A defensible benefit would require a threat model in which one layer's key or trust boundary can fail while the other remains independently protected. That separation is not established here; avoid claiming that two layers provide twice the security.

## Reproduction commands

```sh
# Reproduce the tier benchmark and derive its summary and plot
.venv/bin/python -m benchmarks.tier_benchmark \
  --sizes 1024,16384,262144,1048576 \
  --distribution Low:6,Medium:3,High:1 \
  --repetitions 30 --warmups 3 --output-dir benchmarks/results
.venv/bin/python -m benchmarks.analyze_tier_results benchmarks/results/NEW-RUN.json

# Run the crypto component microbenchmark
.venv/bin/python -m benchmarks.crypto_microbenchmark \
  --sizes 1024,16384,262144,1048576 \
  --repetitions 30 --warmups 3 --output-dir benchmarks/results

# Run synthetic classifier comparison using the chosen benchmark JSON
.venv/bin/python -m benchmarks.classifier_evaluation \
  --benchmark-json benchmarks/results/NEW-RUN.json \
  --seed 20261023 --rows 128 --output-dir benchmarks/results

# Test suites
.venv/bin/python -m pytest -q
(cd blockchain && npx hardhat test)
(cd frontend && npm test -- --run)
```

## Actual verification results

- `.venv/bin/python -m pytest -q` — **60 passed**, 2 deprecation warnings, 7 subtests passed.
- `.venv/bin/python -m pytest -q tests/test_classifier_evaluation.py` — **3 passed**.
- `(cd blockchain && npx hardhat test)` — **6 passing**.
- `(cd frontend && npm test -- --run)` — **8 tests passed**.
- Full tier benchmark and crypto microbenchmark — **zero measured failures** each.

The two Python warnings concern `websockets.legacy` and the Starlette/httpx test-client integration. No live AWS or external storage calls were made. The checkout has no discoverable `.git` metadata, so Git tracking and history were not audited.

## Research limitations and next work

- Synthetic labels and a 24-field held-out sample do not establish accuracy on real datasets.
- The rule baseline and catalog share an authoring process; an external labeler and preregistered baseline would improve independence.
- Repeat with a larger held-out set and independently labeled schemas before changing production classification rules.
- Test across additional hardware and workloads before making performance generalizations.
- Establish an independent High-tier key or administrative boundary before claiming a security advantage for double encryption.
- AWS KMS remains mock-tested only; a live KMS run was outside this milestone.
