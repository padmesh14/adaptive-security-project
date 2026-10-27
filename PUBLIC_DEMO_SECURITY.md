# Browser encrypted public demonstration: security notes

## Data flow

1. Registration/login sends an account password over the API connection; the
   backend hashes it with Argon2id and does not log request bodies.
2. CSV values and column names are classified in the browser using the
   canonical `src/sensitivity_rules.json`. Unsupported formats receive a
   conservative High suggestion. The user can keep the suggestion or choose
   a higher tier.
3. The browser creates an independent random 256-bit data key per file and
   encrypts with AES-256-GCM and a fresh 96-bit nonce. A separate random
   recovery code is used as HKDF-SHA256 input to derive a wrapping key; the
   data key is AES-GCM wrapped. Both GCM invocations authenticate the format,
   algorithm, random file ID, tier, plaintext size, and purpose as AAD.
4. Binary format v1 is `AMLS` magic (4 bytes), header length (uint32
   big-endian), JSON envelope (maximum 16 KiB), then ciphertext and the
   16-byte GCM tag. It accepts up to 50 MiB plaintext. The header contains the
   version, algorithm, tier, random file ID, base64url nonces/salt, wrapped
   key, and size. The original filename is not sent to the backend.
5. The API stores opaque encrypted bytes and minimal metadata in IPFS or
   Filebase. PostgreSQL stores owner, CID, SHA-256 digest, tier, size, storage
   reference, and optional chain registration metadata. The digest detects
   accidental changes; it is not treated as authentication. AES-GCM
   authentication is required for decryption.
6. Retrieval is owner-checked. The API returns ciphertext only. The browser
   verifies the digest, unwraps the key locally, authenticates and decrypts
   locally, then starts a browser download.

## Recovery

Create the recovery code in the browser, save it using a private password
manager or offline secure backup, and confirm it was saved before uploading.
To recover on another browser/device, sign in, enter the saved code, and
decrypt a test file. The code is never saved in localStorage or sent to the
server. It is displayed in browser memory only. Losing it makes the wrapped
file keys and data unrecoverable. Password reset cannot restore encryption
access; there is no escrow or server recovery mechanism.

The current format uses one recovery secret to unwrap independent per-file
keys. Future rotation should rewrap file keys under a new recovery key only
after the user has imported and verified the old key; ciphertext need not be
re-encrypted. Rotation is not automated in this demonstration.

## Classification and tier mapping

Python and TypeScript load the same JSON rules and have a parity test for
supported synthetic tables. The browser currently parses CSV up to 5 MiB. It
chooses the maximum column tier for the file and disallows lowering below
that suggestion. Unsupported formats are assigned High and require manual
review. The classifier is a heuristic, not a guarantee of privacy or
regulatory compliance.

Browser format v1 uses the tier as authenticated metadata; all tiers use one
AES-256-GCM layer. The old Python Low/Medium/High schemes remain unchanged for
legacy records. This separation avoids implying that repeated encryption
alone improves security or silently reinterpreting old ciphertext.

## API and storage controls

- Owner identity comes only from the server-side session, never a request
  `user_id`. File lookup scopes by file ID and owner and returns the same 404
  for missing and other-user files.
- Passwords are Argon2id-hashed. Random session tokens are stored as SHA-256
  hashes in PostgreSQL and carried in HttpOnly, SameSite=Strict cookies.
  Mutations require a separate CSRF cookie/header pair. Enable Secure cookies
  behind HTTPS.
- CORS is restricted to one configured frontend origin. Upload size and the
  envelope shape are bounded. Object keys are random and contain no filenames
  or account identifiers. Public CIDs are not access controls.
- Removing a file deletes its metadata only. Public IPFS/Filebase content may
  remain pinned and retrievable; the UI warns before removal.
- API errors do not include passwords, request bodies, ciphertext, or secret
  environment values. The demonstration rate limiter is per-process and
  in-memory; replace it with a shared gateway/limiter before multi-worker use.

## Blockchain

`CIDRegistry` is owner-write-only and append-only. Tests cover both controls.
Record IDs are SHA-256 digests of a random UUID and domain separator; no
filename, email, account ID, plaintext, key, or recovery code is used. CIDs
and record digests are public metadata. The API checks the selected network
and chain ID, loopback-only local RPC or HTTPS Sepolia RPC, contract bytecode,
owner, receipt, and read-back. Matching retries are idempotent; conflicts
fail. Sepolia writes require an operator-owned environment key and funded
testnet ETH. Browser keys are never transaction keys. Deployment is manual
and was not executed here.

The registry has no ownership-transfer operation. If its deployer account is
lost, new registrations stop; already written immutable records remain
readable. Protect the dedicated operator wallet with an appropriate backup
and access-control policy.

## Limitations

- This is not production-ready: no KMS, server recovery, sharing, email
  verification, password reset, malware scanning, abuse review, or independent
  security audit is included.
- No live Filebase request, production database, Sepolia RPC, browser hosting,
  or public URL was configured or tested here.
- Docker Compose is a local deployment scaffold. Public hosting needs TLS,
  persistent PostgreSQL, durable object storage, backups, monitoring, abuse
  controls, managed secrets, and provider quota review.
- Existing Python manifests and ciphertexts use different formats and are
  not migrated. Existing unrecoverable entries are untouched.
