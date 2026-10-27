# Research-Grade Upgrade: Phase 1 Audit

**Audit date:** 2026-10-23  
**Scope:** Repository inspection, current-state verification, and baseline tests only. No application code, encryption artifacts, manifests, or stored payloads were changed for this audit.

## Executive summary

The repository contains a working Python column-encryption pipeline, local/IPFS and Filebase storage paths, local Hardhat CID registration, a development-only managed-key path for new records, and a separate browser file-vault application. The browser vault and Python column pipeline use different formats and key workflows; they should be evaluated and described separately.

Baseline tests passed in the current environment:

- Python: **39 passed**, with **2 warnings** and **3 subtests passed**.
- Hardhat: **6 passing**; contracts were already compiled.
- Frontend: **3 test files and 8 tests passed**.

There is no discoverable `.git` directory in or above the project checkout. Therefore Git status, tracked-file membership, and whether any local file is committed cannot be verified. A root `.env` exists with restrictive mode `0600`; its values were not displayed. The `.gitignore` covers environment files and common secret/key patterns, but does not generally exclude generated `output/` manifests.

## Verified architecture and capabilities

### Python pipeline

- `main.py`, `src/sensitivity_classifier.py`, `src/sensitivity_rules.json`, and `src/encryption_pipeline.py` implement column-level classification and encryption. The most recent dataset manifest inspected represents **27 processed columns**: 12 Low, 6 Medium, and 9 High.
- `src/encryption.py` uses AES-256-GCM for Low; Medium uses P-256 ECDH and HKDF-SHA256 to derive an AES-GCM key; High applies two ECDH/HKDF-derived AES-GCM layers and records a BLAKE2b-256 digest.
- The legacy encryption pipeline remains the default path in `main.py`. It calls the column encryption function without a managed key provider. Existing legacy manifests inspected do not contain managed wrapped-key metadata. The original keys for those legacy ciphertexts were not located or validated in this audit; their recoverability is **not established**.
- `src/key_management.py` defines a `KeyProvider` abstraction and `LocalDevelopmentKeyProvider`. The local provider wraps data keys with a local KEK, authenticates wrapping context, and stores the KEK outside the repository with restrictive permissions. It is a development provider, not a production KMS: no cloud KMS, HSM, centralized access policy, or production recovery guarantee is configured.
- `src/managed_demo.py` provides a separate synthetic workflow for new data. The workflow can classify, encrypt with managed metadata, store, retrieve, verify, and decrypt synthetic records. Optional blockchain operation is constrained to the local loopback Hardhat node and chain ID 31337.

### Storage

- `src/decentralized_storage.py` provides the local/IPFS, Filebase S3-compatible, and Low-tier local SQLite paths. `src/secure_retrieval.py` retrieves and verifies stored payloads before decryption.
- The inspected retry manifest contains Filebase CIDs for the 15 Medium/High entries; the 12 Low-tier entries are local-only. The repository status report records a successful read-back/integrity check for those 15 Filebase objects. This audit did not repeat external storage operations.
- `src/debug_filebase.py` is an ad-hoc utility that reads the Filebase environment configuration, performs `head_object` for a fixed key (`timestamp.json`), and prints the response. It was not run during this audit. It should be reviewed for removal or safer parameterization before routine use; it is not part of the normal storage pipeline.

### Blockchain

- `blockchain/contracts/CIDRegistry.sol` and `blockchain/integration/` provide CID registration and verification. The local integration derives opaque `bytes32` record identifiers using an HMAC secret and enforces loopback RPC plus chain ID 31337.
- Hardhat is configured as an ESM Hardhat 3 project and tests use the installed Viem-compatible setup.
- Prior project records document local registration and read-back for the CID-backed entries, idempotent repeat registration, and rejection of conflicting CID associations. The local Hardhat chain is ephemeral; this audit did not redeploy or submit transactions.
- A separate optional Sepolia integration exists. Its presence is not evidence that a public deployment has been performed. The browser API's optional chain registration path calls that separate adapter; keep its configuration and security boundary distinct from the Python local-only integration.

### Browser vault and API

- `frontend/src/crypto/` implements a separate binary file envelope using AES-256-GCM. The browser creates a random per-file data key and wraps it using a user-held recovery code. The browser authenticates and decrypts locally after downloading ciphertext.
- `src/api/auth.py` stores Argon2 password hashes and session-token hashes. `src/api/files.py` checks ownership, validates upload intent and file envelope metadata, verifies a ciphertext SHA-256 digest, stores ciphertext, and returns ciphertext for browser-side decryption. The digest is an integrity check for accidental or external changes, not an authenticity mechanism; authenticated decryption is still required.
- `PUBLIC_DEMO_SECURITY.md` correctly describes the browser recovery code as user-held and unrecoverable through password reset. It also states that the browser format and legacy Python tier formats are separate.
- The browser notice identifies the deployment as a synthetic-data demonstration and warns that CIDs are public. Do not characterize the browser service or the entire project as production-ready based on passing tests.

## Configuration and repository hygiene

- `.env` exists and has file mode `0600`. Only configured variable names were inspected; secret values were not printed or copied into this report.
- `.gitignore` covers `.env`, `.env.*` while allowing `.env.example`, virtual environments, Python caches, private-key extensions, and common credential directories.
- General output manifests are not ignored as a class. If Git metadata is added later, review generated manifests and demo metadata before staging; manifests may contain CIDs, record labels, and wrapped-key/provider metadata. Wrapped keys are not plaintext keys, but still warrant appropriate handling.
- Because no `.git` metadata was found, this audit cannot establish whether `.env`, manifests, keys, or other files are tracked or committed. No claim that secrets are absent from Git history is made.
- The project has `boto3` available, but no AWS KMS provider, configured AWS key identifier/region, or live cloud KMS test setup was identified. The SDK dependency alone does not establish KMS integration.

## Existing baseline tests

Commands were run from the project root unless noted:

| Suite | Command | Actual result |
|---|---|---|
| Python | `.venv/bin/python -m pytest -q` | **39 passed**, 2 warnings, 3 subtests passed in 2.09 seconds. Warnings concern deprecated `websockets.legacy` and Starlette's test-client/httpx compatibility notice. |
| Solidity / Hardhat | `(cd blockchain && npx hardhat test)` | **6 passing**; Hardhat reported “No contracts to compile.” |
| Browser | `(cd frontend && npm test -- --run)` | **3 test files passed; 8 tests passed.** |

No benchmark suite was found outside dependency files. No live AWS KMS test was run. This audit did not repeat Filebase, IPFS, blockchain registration, or public-network operations.

## Risks and gaps to resolve before research claims

1. **Repository provenance is unknown.** Without `.git`, there is no auditable status or history. Establish a repository baseline before making or claiming tracked-file security findings.
2. **Output artifact hygiene needs an explicit policy.** Generated manifests and demo outputs exist, while general `output/` files are not ignored. Decide which artifacts should be versioned and which must remain local.
3. **No production key manager is configured.** The local provider's file-based KEK is suitable for development demonstrations only. AWS KMS work must fail closed and must not fall back silently to local keys.
4. **Legacy key recovery is unproven.** The original keys for the existing legacy ciphertexts have not been located and validated. Do not attempt decryption with newly generated keys or claim those records are recoverable.
5. **Research evaluation is absent.** No benchmark package or reproducible performance measurements were found. Therefore no latency, scalability, cost, or comparative-security claims are supported yet.
6. **Security properties must be stated precisely.** GCM provides authenticated encryption when keys/nonces and verification are used correctly. A digest detects mismatches but does not identify who created content. A CID or blockchain entry provides a reference/anchor, not confidentiality or access control.
7. **The benefit of High-tier double encryption is unmeasured.** It may add cost without a demonstrated security advantage over a correctly implemented single AEAD layer. Treat this as a research question, not an established benefit.
8. **Classification is heuristic.** Tier selection does not establish privacy, compliance, or resistance to inference. False-positive/false-negative rates need a defined dataset and evaluation method.
9. **Browser and Python formats are separate.** Their shared concepts do not constitute an integrated cross-format key lifecycle. Document and test them as distinct clients unless an explicit interoperability design is implemented.
10. **Filebase debug utility is unsafe for routine diagnostics.** It targets a fixed object and prints a full service response. It is not known to print credentials, but diagnostics should return only sanitized status fields and should use an explicit synthetic test object if write access must be tested.

## Unverified claims and exclusions

- No secret-value scan can prove absence of secrets in Git history because repository history is unavailable. Secret values were not displayed during this audit.
- The existence of historical success reports does not mean external services are currently configured or reachable. No live provider check was run.
- No public-chain deployment, AWS KMS call, formal cryptographic proof, or production-scale load test was performed.
- This audit did not alter or validate decryptability of any existing dataset ciphertext.

## Prioritized implementation plan

This is a proposed sequence, not work already performed.

### Priority 1 — Establish a reviewable repository baseline

**Files/areas:** repository root, `.gitignore`, generated `output/` policy, CI configuration (if introduced).

- Restore or initialize Git history through the project owner; inspect status and history before edits.
- Set a deliberate policy for manifests, local databases, demo output, and benchmark results. Ignore private runtime artifacts while allowing explicitly selected sanitized research outputs.
- Run a secret scanner against tracked files/history once Git metadata is available. Do not print matched secret contents.
- Remove or harden `src/debug_filebase.py`; make diagnostics explicit, non-destructive, and redacted.

### Priority 2 — Complete cryptographic and key-lifecycle review

**Files/areas:** `src/encryption.py`, `src/encryption_pipeline.py`, `src/key_management.py`, `src/secure_retrieval.py`, `tests/`.

- Build a format-level checklist for nonce uniqueness, ECDH peer-key validation, HKDF context separation, layer ordering, metadata binding, and fail-closed decryption.
- Add targeted synthetic negative tests for substitution and altered metadata only where coverage is currently missing.
- Keep legacy formats readable; version any future format change. Do not change algorithms until a concrete issue and migration path are demonstrated.
- Evaluate the High-tier two-layer design against single AEAD as a hypothesis.

### Priority 3 — Add optional AWS KMS provider

**Proposed file:** `src/aws_kms_key_provider.py`; related tests and configuration docs.

- Extend the existing `KeyProvider` abstraction only as needed. Use envelope encryption, explicit KMS key ID and region, and encryption context bound to opaque record/tier metadata.
- Use the AWS credential provider chain or workload identity. Do not store cloud credentials in files or manifests.
- Require explicit provider selection. If AWS KMS is selected and unavailable, fail closed; never fall back to the local provider.
- Unit-test the adapter with mocks. Keep live AWS tests separately opt-in and report them only when actually run.

### Priority 4 — Make managed keys an opt-in path for future Python pipeline runs

**Files/areas:** `main.py`, `src/encryption_pipeline.py`, manifest schema, docs, tests.

- Provide an explicit provider/config flag for new records while preserving current legacy behavior unless the user chooses managed mode.
- Persist only wrapped key material or secure key references plus version/provider/algorithm metadata. Keep the existing 27-entry manifest and ciphertexts untouched.
- Test process restart recovery before documenting new managed output as recoverable.

### Priority 5 — Add reproducible benchmarks

**Proposed package:** `benchmarks/`.

- Use synthetic inputs, configurable payload sizes and tier mixes, warm-up, repetitions, stable environment metadata, and raw CSV/JSON output.
- Separate local/mocked measurements from real Filebase, IPFS, Hardhat, and AWS measurements. Do not create plots or numerical claims until actual runs produce data.
- Measure encryption/decryption overhead, payload expansion, provider latency, verification and registration, concurrency, and failure rates.

### Priority 6 — Reliability and security integration coverage

**Files/areas:** `src/decentralized_storage.py`, `src/secure_retrieval.py`, `blockchain/integration/`, API tests, Hardhat tests.

- Add deterministic tests for missing objects, provider outages/timeouts, CID mismatch, malformed metadata, failed transactions, wrong chain ID, and contract-address mismatch.
- Keep ordinary tests offline. Gate external integration tests behind explicit environment/config checks and label infrastructure used.
- Preserve local-only blockchain checks and keep any public testnet adapter separate.

### Priority 7 — Research framing and publication evidence

**Files/areas:** architecture/threat-model documentation, experiment protocol, results template, related-work review.

- Define the threat model, research question, hypotheses, baselines, metrics, and limits before claiming novelty.
- Compare classification outcomes and tier costs; quantify overhead and evaluate whether added encryption layers provide measurable value.
- Separate design properties, test evidence, measured performance, assumptions, and future work. Add citations only after a real literature review.

## Phase 1 conclusion

The current local test baseline is healthy across Python, Hardhat, and the browser suite. The strongest immediate blockers to research-grade claims are the missing Git audit trail, absence of production KMS integration, lack of benchmarks, and unmeasured security/performance value of the tier design. This report completes Phase 1 only; no Phase 2–9 implementation was started.
