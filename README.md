# Adaptive Multi-Layer Security for Decentralized Systems
### Column-wise classification, adaptive encryption, dual storage, and opt-in local CID anchoring

The Python workflow classifies and encrypts columns, then can pin encrypted
payloads to local IPFS and Filebase. An optional follow-up command anchors
the resulting CIDs to the local Hardhat `CIDRegistry` contract. Blockchain
registration is separate from the normal pipeline and never uploads data.

---

## What this does

1. **Loads any supported input format** (`src/data_ingestion.py`) — CSV,
   TSV, Excel, JSON, JSONL/NDJSON, XML, Parquet — and normalizes it into
   a single flat table, flattening nested JSON automatically.
2. **Classifies each COLUMN's sensitivity** (`src/sensitivity_classifier.py`,
   rules in `src/sensitivity_rules.json`) as Low / Medium / High, using:
   - column-name keyword matching (identifier / medical / financial /
     location / biometric / demographic / behavioral / ambient)
   - content pattern matching (email, SSN, GPS, IP, phone, credit card,
     IBAN, date of birth, passport, zip code)
   - uniqueness ratio (identifier-like columns are near-unique)
   - bounded-numeric check (small-range numeric columns skew Low)
   - adaptive thresholds (Low/Medium/High cutoffs are computed from each
     dataset's own score distribution, not fixed to one dataset)
   - a safety override: any column named like a direct identifier or
     biometric field is always High, regardless of computed score
3. **Encrypts each column** (`src/encryption.py`, `src/encryption_pipeline.py`)
   as one block, using the tier-appropriate scheme:

   | Tier   | Scheme                                                    |
   |--------|------------------------------------------------------------|
   | Low    | AES-256-GCM (single layer)                                 |
   | Medium | AES-256-GCM, key derived via ECC (ECDH) exchange           |
   | High   | AES-256-GCM applied twice, independently ECC-derived keys, + BLAKE2b integrity hash |

4. **Writes an encryption manifest** (`output/encryption_manifest.json`) recording,
   per column: sensitivity tier, risk score, encryption scheme, and the
   BLAKE2 integrity hash — this hash is exactly what gets used as the
   CID input in the next stage (see below).

---

## Project structure

```
adaptive_security_project/
├── main.py                        # entry point - run this
├── requirements.txt
├── data/
│   ├── combined_dataset.csv       # IoT + healthcare sample (1200 rows)
│   ├── ecommerce_dataset.csv      # second domain, proves generalization
│   └── generate_dataset.py
├── src/
│   ├── data_ingestion.py          # any format -> unified DataFrame/CSV
│   ├── sensitivity_rules.json     # keyword groups + regex patterns (edit this for new domains)
│   ├── sensitivity_classifier.py  # column-level risk score + classification
│   ├── encryption.py              # AES-256-GCM / ECC tiered encryption primitives
│   └── encryption_pipeline.py     # orchestrates: classify columns -> encrypt each column
└── output/
    └── encryption_manifest.json   # generated after running main.py
```

---

## Setup & run

```bash
pip install -r requirements.txt
python main.py
```

To classify/encrypt a different file (any supported format):
```python
from src.data_ingestion import load_any_to_dataframe
from src.encryption_pipeline import encrypt_dataset_by_column

df = load_any_to_dataframe("path/to/your_data.json")   # or .csv, .xlsx, .xml, .jsonl...
result = encrypt_dataset_by_column(df)
```

---

## Legacy Python limitations

- The legacy un-managed Python pipeline retains its original key lifecycle;
  the browser file format below is separate and does not retrofit or recover
  the existing dataset ciphertexts.
- Keyword/pattern coverage is broad but not exhaustive — new domains may
  need additions to `sensitivity_rules.json`.
- Existing Python manifest registration stays local-only. The web API has a
  separate, explicit local/Sepolia registration path.

## Local IPFS/Filebase storage and blockchain registration

The storage stage writes `output/encryption_manifest_with_cids.json` with
`storage.local_cid` and `storage.filebase_cid` for each successfully stored
encrypted column. The blockchain command reads those existing CIDs; it does
not repeat uploads or modify encryption.

Install the Python dependencies:

```sh
python3 -m pip install -r requirements.txt
python3 -m pip install -r blockchain/integration/requirements.txt
```

Start IPFS in its own terminal if it is not already running:

```sh
ipfs daemon
```

Configure the existing Filebase environment variables as described in
`src/decentralized_storage.py`, then run the normal encryption and storage
steps from the repository root:

```sh
python3 main.py
python3 -m src.decentralized_storage
```

The storage command writes `output/encryption_manifest_with_cids.json`.
Run the blockchain step only when you want to register those stored CIDs.

To opt in to tier-aware storage, route newly stored Low-tier encrypted
column payloads to a private local SQLite file while Medium and High entries
continue to dual-pin to local IPFS and Filebase:

```sh
python3 main.py --new-run
# Copy the unique manifest path printed by the command into RUN_MANIFEST.
RUN_MANIFEST='output/encryption_manifest_run_PASTE_ID.json'
python3 -m src.decentralized_storage --route-low-to-sqlite --manifest "$RUN_MANIFEST"
```

`--new-run` writes a unique encryption manifest and refuses to overwrite an
existing run. The storage command writes another timestamped
`output/encryption_manifest_tiered_*.json`; both the existing encryption
manifest and regular CID manifest remain untouched. SQLite contains
serialized encrypted payloads only; its directory is created with
owner-only permissions and ignored by Git. Low-tier SQLite records have no
public CID, so the blockchain registration command skips them. Medium/High
entries still need the normal IPFS/Filebase setup. Set `TIERED_MANIFEST` to
the output path printed by the storage command, then retrieve a SQLite entry:

```sh
TIERED_MANIFEST='output/encryption_manifest_tiered_PASTE_ID.json'
KEY_BUNDLE=/secure/location/legacy-key-bundle.json
python3 -m src.secure_retrieval --manifest "$TIERED_MANIFEST" --index 0 \
  --keys-file "$KEY_BUNDLE" --provider auto
```

This changes storage placement only. It does not compress data, deduplicate
values, change encryption, or recover encryption keys. Decryption still
requires separately retained valid key material.

In a separate terminal, start the local Hardhat node. Its default startup
includes development account details, so the command below suppresses them:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

In another terminal at the repository root, deploy locally and provide a
stable local HMAC secret. Keep the generated value in your local environment;
it is needed to derive the same record IDs for future submissions and checks.

```sh
python3 -m blockchain.integration.deploy_local
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m blockchain.integration.register_manifest
```

The registration command uses the local IPFS CID when present (otherwise
Filebase CID), and refuses entries whose two provider CIDs disagree. It
stores only the CID and an HMAC-SHA256 `bytes32` digest derived from the
project namespace and logical column label. Dataset values, encrypted
payloads, raw labels, encryption keys, and the HMAC secret are not sent to
the contract or written to the manifest. The manifest is updated with
registration status, record ID digest, CID, transaction hash, chain ID,
contract address, and timestamp only after a successful transaction and
matching read-back. Failed entries retain their existing storage results
and are not marked registered. Matching repeat submissions are skipped.

Verify every manifest registration against the local contract:

```sh
python3 -m blockchain.integration.verify_manifest
```

The record ID mapping depends on `CID_REGISTRY_RECORD_ID_SECRET`; use the
same secret and namespace (default `adaptive-security-project`) for
registration and verification. Changing the secret creates different record
IDs. The integration rejects non-loopback RPC endpoints and any chain ID
other than `31337`.

For the four Solidity tests, run:

```sh
cd blockchain
npx hardhat test
```

## Managed keys for future records

New records can opt into a local development envelope-key provider without
changing the existing AES/ECDH ciphertext formats. The provider stores its
wrapping key outside the project with owner-only permissions and adds only
authenticated wrapped data keys and non-secret provider metadata to new
manifest entries. Existing `main.py` behavior remains legacy/unmanaged unless
you explicitly select a managed provider and `--new-run`.

```sh
.venv/bin/python -m src.key_management init
.venv/bin/python main.py --new-run --managed-key-provider local
```

An optional AWS KMS adapter is available through the same provider interface.
Configure the key ID and region and rely on the AWS credential provider chain;
no cloud resources are created automatically. KMS Encrypt/Decrypt calls may
incur charges, so review account authorization and current pricing before
running in AWS:

```sh
export AWS_KMS_KEY_ID='arn:aws:kms:REGION:ACCOUNT:key/KEY-ID'
export AWS_REGION='us-east-1'
.venv/bin/python main.py --new-run --managed-key-provider aws-kms
```

AWS mode fails closed and never falls back to the local key provider. Mocked
tests are offline; live AWS KMS testing is separately opt-in and has not been
run. The local provider is development-only and the AWS adapter is not, by
itself, a complete production key-management deployment. See
[`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) for initialization, encryption,
retrieval, backup, recovery, rotation, IAM policy guidance, and live-test
instructions.

## Research evaluation

`benchmarks/tier_benchmark.py` runs local synthetic measurements for the
existing tiers and a single AES-GCM baseline. `benchmarks/analyze_tier_results.py`
creates a CSV/Markdown summary and SVG plot from a real JSON run. The latest
30-repetition evaluation and classifier results are described in
[`RESEARCH_EVALUATION.md`](RESEARCH_EVALUATION.md); these results are
machine-specific research measurements, not production performance claims.

## Synthetic managed-pipeline demonstration

This separate demo creates only synthetic data and writes each run to a new
`output/managed_synthetic_demo/<run-id>/` directory. It reuses the classifier,
encryption, storage, managed retrieval, and local blockchain integration
modules. It never reads or writes the existing 27-entry manifests. The first
run safely initializes the local development KEK if it is missing; retain and
back it up according to `KEY_MANAGEMENT.md`.

Install dependencies and start local IPFS (or configure Filebase as described
above):

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -r blockchain/integration/requirements.txt
ipfs daemon
```

Run the full synthetic data, storage, retrieval, integrity, and decryption
workflow without blockchain registration:

```sh
.venv/bin/python -m src.managed_demo
```

To include a local chain registration, start Hardhat in another terminal and
set the stable local record-ID mapping secret in the demo shell:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

```sh
export CID_REGISTRY_RECORD_ID_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/python -m src.managed_demo --with-blockchain
```

The demo verifies a loopback JSON-RPC endpoint on chain ID `31337` and deploys
CIDRegistry into that unique demo directory. No KMS key, wrapped key, or
plaintext data is sent to the chain. The local file-backed provider is for
development only. The AWS KMS adapter requires an authorized AWS setup and
does not by itself constitute a complete production key-management
deployment. See
[`MANAGED_SYNTHETIC_DEMO.md`](MANAGED_SYNTHETIC_DEMO.md) for workflow details,
failure behavior, and test commands.

## Browser-encrypted web demonstration

The separate `frontend/` and `src/api/` application supports user accounts
and owner-only file metadata. It does not replace or change the legacy Python
encryption format. Browser format v1 is binary: `AMLS` magic (4 bytes), a
4-byte big-endian header length, a bounded JSON envelope, then AES-256-GCM
ciphertext and tag. Each file gets an independent random 256-bit key and a
fresh 96-bit nonce. A user-exported random recovery code derives a wrapping
key with HKDF-SHA256; that key wraps the file key with AES-256-GCM. Format,
algorithm, random file ID, tier, plaintext size, and purpose are authenticated
as AAD. The backend receives only encrypted bytes and non-secret metadata.

The browser classifier imports the existing `src/sensitivity_rules.json`.
CSV classification runs locally; the maximum column tier is suggested, and
the user may keep it or select a higher tier. Unsupported file types default
to High. All browser tiers use the same AES-GCM format in this initial
version; the tier is authenticated metadata and does not add custom or
repeated encryption layers. Classification remains a heuristic and needs
review. See [`PUBLIC_DEMO_SECURITY.md`](PUBLIC_DEMO_SECURITY.md).

### Local development

```sh
.venv/bin/python -m pip install -r requirements.txt
npm --prefix frontend ci
```

For local development with SQLite and IPFS, run `ipfs daemon` separately,
then migrate the development database:

```sh
ADAPTIVE_DATABASE_URL=sqlite:///./adaptive_api_dev.db \
ADAPTIVE_FRONTEND_ORIGIN=http://127.0.0.1:5173 \
.venv/bin/alembic upgrade head
```

Start the API in one terminal:

```sh
ADAPTIVE_DATABASE_URL=sqlite:///./adaptive_api_dev.db \
ADAPTIVE_FRONTEND_ORIGIN=http://127.0.0.1:5173 \
ADAPTIVE_STORAGE_PROVIDER=ipfs \
.venv/bin/uvicorn src.api.main:app --host 127.0.0.1 --port 8001
```

Then start the frontend in another terminal:

```sh
npm --prefix frontend run dev
```

Vite proxies `/api` and `/health` to `http://127.0.0.1:8001` by default.
If the API uses another local port, set `VITE_API_PROXY_TARGET` before
starting Vite (for example, `VITE_API_PROXY_TARGET=http://127.0.0.1:8010
npm --prefix frontend run dev`).

Open `http://127.0.0.1:5173` and use synthetic files only. For retrieval
while the Mac is offline, configure Filebase credentials only in the backend
environment and set `ADAPTIVE_STORAGE_PROVIDER=filebase`; local IPFS alone
is not remotely durable.

For optional local CID registration, run a Hardhat node in another terminal
with its development-account output suppressed, compile, and deploy the
registry to the local node:

```sh
cd blockchain
npx hardhat node > /dev/null 2>&1
```

```sh
cd blockchain
npx hardhat compile
cd ..
.venv/bin/python -m blockchain.integration.deploy_local
```

Set `ETHEREUM_NETWORK=local`, `ETHEREUM_CHAIN_ID=31337`, and
`CID_REGISTRY_RPC_URL=http://127.0.0.1:8545` in the API process environment.
Run local-chain mode with the API on the host; the Docker Compose API
container cannot use the host's loopback node by default.

Routes include `POST /api/auth/register`, `/api/auth/login`,
`/api/auth/logout`, `GET /api/auth/me`, plus owner-scoped file initiate,
complete, list, detail, ciphertext, verify, delete, and optional blockchain
register/verify operations under `/api/files`.

### Container and public hosting

Copy `.env.example` to `.env`, set a long random alphanumeric PostgreSQL
password, configure the matching database URL, and configure Filebase in the
private environment file. Start the local container stack with:

```sh
cp .env.example .env
docker compose up --build
```

This provides PostgreSQL, migrations, the API, and frontend, bound to
`127.0.0.1:8080`. It is not publicly exposed. Public hosting requires TLS
termination, persistent PostgreSQL, Filebase or another durable remote object
store, backups, monitoring, and a managed secrets facility. Set
`ADAPTIVE_COOKIE_SECURE=true` and the exact HTTPS frontend origin. Keep the
API private behind the frontend reverse proxy. Free-tier services may sleep,
impose quotas, or use ephemeral storage.

### Optional Sepolia CID anchoring

The existing registry is now deployer-only and append-only. A random UUID
digest and CID are public on-chain; CIDs are not authorization. Registration
is opt-in per file, and the operator's Sepolia wallet pays gas. The backend
checks the network, chain ID, contract bytecode and owner, transaction receipt,
and read-back. Matching repeats are idempotent; conflicting writes fail.
The demo defaults to at most 10 successful registrations globally and 2 per
user per day; configure `ADAPTIVE_BLOCKCHAIN_DAILY_LIMIT` and
`ADAPTIVE_BLOCKCHAIN_PER_USER_DAILY_LIMIT` carefully. These are demonstration
limits, not a public-service spending policy.
Local Hardhat registration remains available on chain 31337. Deployment is
manual and was not performed here.

For a Sepolia deployment, obtain an HTTPS Sepolia RPC endpoint and test ETH
for a dedicated deployer from a Sepolia faucet. Set `SEPOLIA_RPC_URL` and
`SEPOLIA_DEPLOYER_PRIVATE_KEY` in an ignored `.env` file. Never use a Hardhat
development key. Then run:

```sh
cd blockchain
set -a
source ../.env
set +a
npx hardhat test
npm run deploy:sepolia
```

The script refuses non-Sepolia chain IDs, non-public/non-HTTPS endpoints, and
standard Hardhat development accounts. Verify the saved address and owner in
a block explorer, then set `CID_REGISTRY_ADDRESS`,
`ETHEREUM_NETWORK=sepolia`, and `ETHEREUM_CHAIN_ID=11155111` in the API
environment. Keep the funded deployer key server-side. No mainnet deployment
or transaction is supported by these commands.

## Web application limitations

This is a synthetic-data demo, not a production-ready public service. It has
no KMS, email verification, password reset, sharing, malware scanning,
distributed rate limiting, account recovery, or independent security audit.
The current API rate limiter is process-local; use a shared gateway limiter
before multi-worker hosting. Browser v1 files are separate from the existing
Python manifests and are not compatible with legacy ciphertexts.
