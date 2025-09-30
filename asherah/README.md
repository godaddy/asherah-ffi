Asherah AppEncryption (Rust)
===========================

Drop‑in compatible Rust port of Go Asherah’s AppEncryption SDK.

Highlights
- Go‑compatible JSON shapes for EnvelopeKeyRecord/DataRowRecord
- API parity: SessionFactory, Session, encrypt/decrypt and store/load (+ ctx variants)
- Crypto: AES‑256‑GCM with nonce appended to ciphertext (mirrors Go)
- KMS: StaticKMS (dev), AWS KMS (real), MultiKms with preferred region + fallbacks
- Metastores: In‑memory (dev), SQLite, MySQL, Postgres, DynamoDB
- Caching: SK/IK caches + optional shared IK cache; optional session cache
- Region suffix precedence: metastore decorator overrides config suffix
- Metrics hooks (simple timers) and examples

Crate features
- `sqlite` — enable SQLite metastore (`rusqlite` bundled)
- `mysql` — enable MySQL metastore (`mysql`)
- `postgres` — enable Postgres metastore (`postgres`)
- `dynamodb` — enable DynamoDB metastore (`aws-sdk-dynamodb`)

Quick start
1) In‑memory metastore + StaticKMS
- `cargo run --example simple`

2) SQLite
- `cargo run --features sqlite --example sqlite`

3) MySQL
- `export MYSQL_URL=mysql://user:pass@host/db`
- `cargo run --features mysql --example mysql`

4) Postgres
- `export POSTGRES_URL=postgres://user:pass@host/db`
- `cargo run --features postgres --example postgres`

5) AWS KMS (real)
- `export KMS_KEY_ID=arn:aws:kms:...`
- `export AWS_REGION=us-west-2` (optional; otherwise SDK default chain)
- `cargo run --example aws_kms`

Design notes
- All async AWS SDK calls run on an internal `tokio::runtime::Runtime` to keep a synchronous API surface consistent with Go.
- Secret bytes are held in `memguard-rs` LockedBuffer backed by `memcall-rs` memory protections.
- JSON shapes exactly match the Go SDK’s struct tags to preserve cross‑language compatibility.

Tests
- `cargo test` runs core tests: JSON shapes, session roundtrip, region suffix precedence, MultiKms behavior.
- Metastore contract tests are available for all backends; they require env vars for networked backends and are skipped otherwise:
  - `MYSQL_URL`, `POSTGRES_URL`, `DDB_TABLE` and AWS credentials.

Cross-language Cucumber tests (mandatory)
- Cucumber BDD tests verify compatibility with Node’s Asherah SDK.
- Setup (required):
  - `cd asherah/cucumber/js && npm install`
  - Ensure `node` is on PATH
- With Dockerized backends:
  - Follow cucumber/README.md to start Postgres/MySQL and LocalStack KMS
  - `cd asherah && cargo test --test cucumber --features postgres`
- Notes:
  - Tests will fail fast if Node/asherah is not installed.
  - Uses a shared RDBMS metastore (Postgres/MySQL) and LocalStack KMS so Node and Rust can interoperate.

SQL schemas
- MySQL
  - Table created automatically on connect:
    - `envelope_keys(id VARCHAR(255), created BIGINT, record JSON, PRIMARY KEY(id, created))`
- Postgres
  - Table created automatically on connect:
    - `envelope_keys(id TEXT, created BIGINT, record JSONB, PRIMARY KEY(id, created))`
- SQLite
  - Table created automatically on open:
    - `envelope_keys(id TEXT, created INTEGER, record TEXT, PRIMARY KEY(id, created))` (record contains JSON string)
