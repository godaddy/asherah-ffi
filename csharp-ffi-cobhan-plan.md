# Plan: Preserve C# AppEncryption API while moving core to asherah-ffi or asherah-cobhan

This plan is based on the bespoke C# implementation in `csharp/AppEncryption`, `csharp/Crypto`, and `csharp/SecureMemory`
from the upstream GoDaddy Asherah repo. It does not refer to the simplistic C# wrapper in this repo.

## Value and ergonomics to preserve
- Public API surface and ABI: namespaces, class names, method signatures, generic types, async Task variants, and
  disposal semantics (`SessionFactory`, `Session<TP, TD>`, `SessionBytesImpl`, `SessionJsonImpl`, `CryptoPolicy`,
  `IMetastore<T>`, `IKeyManagementService`, `Persistence<T>`, `Json` helpers, `SecureMemory` classes).
- Builder ergonomics: fluent `SessionFactory.NewBuilder` steps, `CryptoPolicy` builders, `DynamoDbMetastoreImpl`,
  `AdoMetastoreImpl`, `StaticKeyManagementServiceImpl`, `AwsKeyManagementServiceImpl`.
- Behavior: per-partition sessions, session caching with usage tracking, async wrappers, `Load/Store` helpers,
  `JObject` support, JSON DataRowRecord shape compatibility, and backward-compatible constructors without logging.
- Operational hooks: logging via `Microsoft.Extensions.Logging`, metrics via `App.Metrics`, and deterministic error
  types (`AppEncryptionException`, `KmsException`, `MetadataMissingException`).
- Security posture: secure memory expectations, key caching and eviction behaviors, and no leakage of plaintext in logs.

## Compatibility constraints and mapping (both options)
- DataRowRecord JSON shape must remain Go-compatible: `Data`, `Key`, `ParentKeyMeta`, `Created`, `KeyId`, base64 for
  bytes. Validate against `asherah/src/types.rs`.
- `SessionBytes` must continue returning JSON-encoded DRR as `byte[]`, `SessionJson` must continue returning `JObject`.
- `SessionFactory` can build multiple instances with different config in the same process (current behavior).
- Configuration mapping from C# builder to native JSON config (asherah-config):

| C# surface | Typical builder/method | Native config field(s) | Translation details / notes |
| --- | --- | --- | --- |
| Product ID | `SessionFactory.NewBuilder(productId, ...)` | `ProductID` | Required. |
| Service name | `SessionFactory.NewBuilder(..., serviceId)` | `ServiceName` | Required. |
| In-memory metastore | `WithInMemoryMetastore` | `Metastore = "memory"` | For tests only. |
| ADO metastore base | `AdoMetastoreImpl.NewBuilder(dbProviderFactory, connectionString)` | `Metastore = "rdbms"`, `ConnectionString` | Pass the same connection string; `asherah-config` detects SQL Server (`MSSQL_URL`) and routes to the Rust adapter. Other SQL servers use the native adapters (Postgres/MySQL/SQLite). |
| DynamoDB metastore base | `DynamoDbMetastoreImpl.NewBuilder(region)` | `Metastore = "dynamodb"`, `DynamoDBRegion` | Preferred region flows into `DynamoDBRegion`. |
| DynamoDB table | `WithTableName(table)` | `DynamoDBTableName` | Default is `EncryptionKey` when omitted. |
| DynamoDB endpoint | `WithEndPointConfiguration(endpoint, signingRegion)` | `DynamoDBEndpoint`, `DynamoDBRegion` | `signingRegion` maps to `DynamoDBRegion`. |
| DynamoDB region override | `WithRegion(region)` | `DynamoDBRegion` | Takes precedence over builder region. |
| DynamoDB key suffix | `WithKeySuffix()` | `EnableRegionSuffix = true` | Must mirror `GetKeySuffix()` behavior (preferred region as suffix). |
| DynamoDB custom client | `WithDynamoDbClient(client)` | No direct mapping | Not supported by native core; throw `NotSupportedException` to avoid silent misconfiguration. |
| DynamoDB credentials | `WithCredentials(credentials)` | AWS env vars | Map to `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`. |
| Static KMS base | `WithStaticKeyManagementService(string)` | `KMS = "static"` | Provide `STATIC_MASTER_KEY_HEX` (64 hex). Convert UTF-8 bytes to hex; enforce 32 bytes (reject otherwise) to match C# AES-256 expectations. |
| AWS KMS base | `AwsKeyManagementServiceImpl.NewBuilder(regionMap, preferredRegion)` | `KMS = "aws"`, `RegionMap`, `PreferredRegion` | `RegionMap` is region->ARN dictionary. |
| AWS KMS credentials | `WithCredentials(credentials)` | AWS env vars | Map to `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`. |
| Crypto policy: key expiration | `BasicExpiringCryptoPolicy.NewBuilder().WithKeyExpirationDays(days)` | `ExpireAfter` | Convert days -> seconds (`days * 86400`). |
| Crypto policy: revoke check | `WithRevokeCheckMinutes(minutes)` | `CheckInterval` | Convert minutes -> seconds (`minutes * 60`). |
| Crypto policy: session cache enable | `WithCanCacheSessions(bool)` | `EnableSessionCaching` | Default false in C# BasicExpiring; default true in config, so set explicitly. |
| Crypto policy: session cache size | `WithSessionCacheMaxSize(size)` | `SessionCacheMaxSize` | Ensure `u32` bounds. |
| Crypto policy: session cache TTL | `WithSessionCacheExpireMillis(ms)` | `SessionCacheDuration` | Convert ms -> seconds (round up to preserve minimum). |
| Crypto policy: rotation strategy | `WithRotationStrategy(...)` | No direct mapping | Preserve API but implement as no-op or extend native config. |
| Crypto policy: cache system/intermediate | `WithCanCacheSystemKeys`, `WithCanCacheIntermediateKeys` | No direct mapping | If required, extend native cache policy or enforce in managed layer. |
| Crypto policy: notify expired reads | `WithNotifyExpiredSystemKeyOnRead`, `WithNotifyExpiredIntermediateKeyOnRead` | No direct mapping | Preserve API; consider logging hooks at managed level. |
| Verbose | No C# builder today | `Verbose` | Optional: add new builder flag if needed to mirror native verbosity. |
| Replica read consistency | Not exposed in C# | `ReplicaReadConsistency` | Only relevant for native DynamoDB; keep unset. |

Conversion rules:
- `ExpireAfter`, `CheckInterval`, and `SessionCacheDuration` are in seconds in native config.
- If C# input does not map to native config (custom KMS/metastore), use a managed fallback or add new FFI hooks.

## Option A: Rebase on asherah-ffi (per-factory handles, JSON DRR)
### Phase 1: Core interop layer
- Add an internal `NativeFfi` layer that P/Invokes the asherah-ffi symbols in `asherah-ffi/src/lib.rs` and exposes:
  `CreateFactoryFromConfig`, `CreateFactoryFromEnv`, `GetSession`, `EncryptToJson`, `DecryptFromJson`, `LastError`.
- Implement a managed `SafeFactoryHandle` and `SafeSessionHandle` mirroring the existing lifetime semantics.
- Convert JSON to and from `byte[]` with UTF-8 without changing the JSON shape; validate with baseline tests.
- Define a structured error code surface in asherah-ffi to support C# exception mapping.

### Phase 2: Preserve public API by bridging to the native core
- Keep public classes and method signatures unchanged; route operations through a new internal engine interface,
  for example `IAppEncryptionCore` with methods `EncryptBytes`, `DecryptBytes`, `EncryptJson`, `DecryptJson`.
- Map `SessionBytesImpl` and `SessionJsonImpl` to `IAppEncryptionCore`, preserving current return types and
  existing async Task wrappers (still Task.Run or Task.FromResult as today).
- Preserve `SessionFactory` builder chain by replacing internal construction logic with config JSON building
  and native factory creation.
- Update builders to emit config for SQL Server metastore and static KMS key policy.

### Phase 3: Feature parity mapping
- CryptoPolicy: map `BasicExpiringCryptoPolicy` and `NeverExpiredCryptoPolicy` into native config fields. Where
  native lacks a concept (key rotation strategy, notification hooks), preserve API but document as no-op or add
  corresponding fields to `asherah-config` and `asherah` if parity is required.
- Session caching: avoid double caching by preferring native session cache; keep C# cache only for usage tracking
  and expiry semantics if required by tests.
- Logging and metrics: add managed-level metrics timers and counters around native calls to preserve existing
  App.Metrics names; log exceptions with the same messages as today.
- Error mapping: extend asherah-ffi to optionally return structured error codes (or error prefixes) so C# can map
  to `KmsException` and `MetadataMissingException` instead of a single generic exception.
- Implement the Rust SQL Server metastore adapter and wire it into `asherah-config`.

### Phase 4: Packaging and runtime loading
- Ship native `asherah_ffi` binaries in the NuGet package with RID-specific assets (`runtimes/*/native/*`).
- Provide a deterministic native library resolver that mirrors current behavior (explicit path env, fallback to
  runtime loader), without changing public APIs.

### Phase 5: Verification and migration safety
- Run existing unit tests and integration tests from the C# repo against the native-backed core.
- Add cross-language tests using the same JSON DRR format to ensure Go/Rust/C# compatibility.
- Keep a temporary feature flag to swap between managed and native cores until parity is validated.
- Add SQL Server integration tests and static/AWS KMS interop tests to validate drop-in behavior.

## Option B: Rebase on asherah-cobhan (global factory, Cobhan buffers)
### Phase 1: Cobhan interop and buffer tooling
- Add a `CobhanInterop` layer for `SetupJson`, `Shutdown`, `SetEnv`, `EstimateBuffer`, `Encrypt`, `Decrypt`,
  `EncryptToJson`, `DecryptFromJson`.
- Implement a managed `CobhanBuffer` helper (8-byte header, capacity tracking) with `Span<byte>` wrappers and
  `ArrayPool<byte>` for output buffers. Retry on `ERR_BUFFER_TOO_SMALL` by re-allocating based on `EstimateBuffer`.
- Define a structured error code mapping from Cobhan errors to C# exceptions.

### Phase 2: Adapt `SessionFactory` to the global factory model
- Introduce a reference-counted singleton wrapper in C# that calls `SetupJson` once and `Shutdown` when the last
  factory is disposed.
- Enforce configuration consistency: either disallow multiple concurrent factories with different config, or
  implement a config hash check and throw a clear exception when mismatch is detected.
- Sessions become lightweight objects that hold the partition id only; encryption calls pass partition ids directly
  to the Cobhan API.
- Update builders to emit config for SQL Server metastore and static KMS key policy.

### Phase 3: Preserve public API behavior
- `SessionBytesImpl` uses `EncryptToJson`/`DecryptFromJson` to match the JSON-based DRR bytes used today.
- `SessionJsonImpl` parses JSON from `EncryptToJson` into `JObject` and serializes `JObject` for decrypt input.
- Preserve async Task wrappers and `Load/Store` helpers unchanged.

### Phase 4: Feature parity mapping and errors
- Use the same config JSON mapping table as Option A; add `SetEnv` support to match C# `SetEnv` usage patterns.
- Map Cobhan error codes to existing exception types (and messages) to preserve caller error handling.
- Preserve logging/metrics by instrumenting managed wrapper calls.
- Implement the Rust SQL Server metastore adapter and wire it into `asherah-config`.

### Phase 5: Packaging and verification
- Ship `asherah_cobhan` binaries in NuGet as runtime assets; use a dedicated resolver name to avoid clashes.
- Re-run the C# test suite and add Cobhan-specific tests for buffer sizing, retry behavior, and concurrency.
- Add SQL Server integration tests and static/AWS KMS interop tests to validate drop-in behavior.

## Key tradeoffs to consider
- Multi-factory support: asherah-ffi aligns with existing `SessionFactory` behavior, while cobhan requires
  a global singleton and may force a new restriction or a managed compatibility layer.
- Error fidelity: asherah-ffi currently has string-only errors, while cobhan has numeric error codes.
  FFI likely needs extensions for parity with C# exception types.
- Performance: cobhan avoids JSON allocations for the non-JSON API path, but current C# sessions are JSON-based
  for bytes, so the gains are mostly in buffer handling and less in JSON parsing.
- Extensibility: custom `IMetastore` and `IKeyManagementService` implementations are out of scope since only the
  built-in C# implementations are in use.

## Drop-in compatibility requirements (actions)
These are the concrete items required to achieve drop-in parity with the bespoke C# implementation:
- **SQL Server metastore parity**: implement the Rust SQL Server adapter with the exact schema/query behavior of
  `AdoMetastoreImpl` (UTC `created`, JSON `key_record`, duplicate insert returns `false`), and accept classic
  ADO-style connection strings by normalizing to the driver format.
- **Static KMS key derivation**: treat the C# string key as UTF-8 bytes and require 32 bytes (AES-256). Convert to
  `STATIC_MASTER_KEY_HEX` deterministically; reject or warn on any other length to avoid silent incompatibility.
- **Session caching semantics**: mirror C# session cache usage tracking and sliding-expiration behavior. If native
  caching is used, keep a managed layer to preserve usage counters and eviction timing.
- **Error mapping**: ensure native errors map to existing `KmsException`, `MetadataMissingException`, and
  `AppEncryptionException` semantics. Extend asherah-ffi or cobhan to surface structured error codes.
- **Custom implementations**: not required; all known usage is covered by built-in C# implementations ported to Rust.
- **Acceptance tests**: add cross-language tests for DRR JSON compatibility, SQL Server metastore integration
  against a live container, and static/AWS KMS interop between C# and Rust.

## Work breakdown (drop-in parity)
| Task | Owner | Dependencies | Applies to |
| --- | --- | --- | --- |
| SQL Server metastore adapter in Rust (schema/query parity, duplicate insert -> false) | Rust | SQL driver choice; test container | FFI + Cobhan |
| SQL Server connection string normalization + `asherah-config` detection (`MSSQL_URL`) | Rust + C# | Driver format decisions | FFI + Cobhan |
| C# static KMS key policy (UTF-8 -> 32 bytes -> hex, explicit errors) | C# | Policy decision | FFI + Cobhan |
| Structured native error codes and C# exception mapping | Rust + C# | Error taxonomy | FFI + Cobhan |
| Session cache parity layer (usage tracking + TTL behavior) | C# | Decide native vs managed caching split | FFI + Cobhan |
| Native packaging + resolver for RIDs | Build + C# | CI pipeline updates | FFI + Cobhan |
| Acceptance tests: DRR JSON, SQL Server, KMS interop | QA + C# + Rust | Test infra; SQL Server container | FFI + Cobhan |

### Detailed implementation checklists
- **SQL Server metastore adapter in Rust**
  - Choose driver (e.g., `sqlx` with `mssql` feature or `tiberius`) and confirm async runtime strategy.
  - Add new module (e.g., `metastore_mssql.rs`) implementing `traits::Metastore`.
  - Implement `load(id, created)` with UTC conversion: `DATEADD(SECOND, created, '1970-01-01')`.
  - Implement `load_latest(id)` with `TOP 1` and `ORDER BY created DESC`.
  - Implement `store(id, created, ekr)` and return `false` on duplicate key:
    - Prefer `MERGE` or `IF NOT EXISTS` guarded insert.
    - If using unique constraint violation, map it to `Ok(false)`.
  - Serialize `EnvelopeKeyRecord` to JSON text matching C# `EnvelopeKeyRecord.ToJson()` semantics.
  - Ensure `created` precision aligns with C# truncation (seconds).
  - Add unit tests for JSON roundtrip and store/duplicate behavior.
  - Add integration tests with SQL Server container (real schema, real queries).
- **SQL Server connection string normalization + config detection**
  - Extend `asherah-config` to detect SQL Server in `ConnectionString`.
  - Support ADO-style strings and normalize to driver format.
  - Set `MSSQL_URL` env (or equivalent) for the new adapter.
  - Add validation errors for missing host/db or unsupported params.
  - Add tests for multiple connection string formats.
- **C# static KMS key policy**
  - Define policy: UTF-8 bytes must be exactly 32 bytes.
  - Convert to hex for `STATIC_MASTER_KEY_HEX` in config JSON.
  - Add explicit error for non-32-byte input (no silent padding or hashing).
  - Add tests for valid/invalid keys and cross-language decrypt compatibility.
- **Structured native error codes + C# exception mapping**
  - Define error taxonomy: KMS failure, metastore failure, config error, invalid input, JSON parse, etc.
  - Extend asherah-ffi and/or cobhan to surface codes (numeric or enum + message).
  - Map codes to C# exceptions (`KmsException`, `MetadataMissingException`, `AppEncryptionException`).
  - Preserve message text patterns used by existing tests/logs.
  - Add tests that assert exception type and message for key failure paths.
- **Session cache parity layer**
  - Decide caching split: native cache vs managed cache with usage tracking.
  - Preserve C# semantics: usage counter, sliding expiration, compaction logic.
  - Ensure `Dispose()` releases sessions in the same order and timing as before.
  - Add concurrency tests (multi-threaded session acquisition and release).
- **Native packaging + resolver**
  - Produce RID-specific binaries for Windows, Linux, macOS.
  - Include them in NuGet `runtimes/*/native`.
  - Keep explicit override env/path support for native library lookup.
  - Add CI validation for packaging layout and runtime load.
- **Acceptance tests**
  - Cross-language DRR JSON tests with known vectors.
  - SQL Server integration tests: Load/LoadLatest/Store/duplicate behavior.
  - Static KMS interop tests between C# and Rust.
  - AWS KMS interop tests (optional, gated by env).
- **Custom metastore/KMS fallback or callback API**
  - Removed: only built-in C# implementations are in use, and these are covered by Rust ports.

## Port C# built-in metastore/KMS to Rust (config-first path)
Goal: eliminate managed runtime dependencies for the built-in C# metastore and KMS implementations by relying on
Rust equivalents configured via JSON, while preserving the public C# API as thin configuration builders.

Mapping and status:
| C# implementation | Rust equivalent | Config path | Status / gaps |
| --- | --- | --- | --- |
| `InMemoryMetastoreImpl` | `metastore` (memory) | `Metastore = "memory"` | Already in Rust. |
| `AdoMetastoreImpl` (SQL Server only) | Rust SQL Server adapter | `Metastore = "rdbms"`, `ConnectionString` | SQL Server metastore implemented in Rust; `asherah-config` detects SQL Server connection strings and sets `MSSQL_URL`. |
| `DynamoDbMetastoreImpl` | `metastore_dynamodb` | `Metastore = "dynamodb"`, `DynamoDBRegion`, `DynamoDBTableName`, `DynamoDBEndpoint`, `EnableRegionSuffix` | Schema aligns (`EncryptionKey`, `Id`, `Created`, `KeyRecord`). Custom AWS client injection is not supported. |
| `StaticKeyManagementServiceImpl` | `kms::StaticKMS` | `KMS = "static"`, `STATIC_MASTER_KEY_HEX` | Requires 32-byte key; add conversion from UTF-8 input to hex in config builder. |
| `AwsKeyManagementServiceImpl` | `kms_aws_envelope::AwsKmsEnvelope` | `KMS = "aws"`, `RegionMap`, `PreferredRegion` (or `KMS_KEY_ID`) | JSON envelope format matches (`encryptedKey`, `kmsKeks`). Credentials via AWS env/SDK chain. |

Porting tasks and verification steps:
- **Schema parity**: confirm SQL table name `encryption_key` and field types match C# (created time stored in UTC,
  unix seconds for DynamoDB). Rust already uses `created` timestamps with unix seconds in DB adapters.
- **DynamoDB map shape**: verify `KeyRecord` map matches C#’s JSON structure, including base64 encoding and optional
  `Revoked`/`ParentKeyMeta`.
- **KMS envelope compatibility**: verify C# and Rust AES-256-GCM parameters (nonce size, tag size) and JSON envelope
  fields match; add cross-language KMS tests for multi-region decryption.
- **Config builders**: update C# builders to produce config JSON rather than construct managed objects; keep the
  existing API surface but make the objects configuration-only.
- **SQL Server adapter**: implement a Rust metastore for SQL Server (table name and schema parity with C#);
  ADO usage is limited to SQL Server per assumption.

SQL Server adapter details (drop-in, no migration):
- **Schema** (must match the existing C# ADO schema; do not alter or migrate):
  - Table name: `encryption_key`
  - Columns:
    - `id` string column (commonly `NVARCHAR`) NOT NULL
    - `created` UTC timestamp (commonly `DATETIME` or `DATETIME2`) NOT NULL
    - `key_record` JSON string (commonly `NVARCHAR(MAX)`) NOT NULL
  - Constraints/indexes: use whatever already exists in production; the adapter must not require schema changes.
- **Reference DDL** (for new deployments only; do not apply to existing databases):
  - `CREATE TABLE encryption_key (id NVARCHAR(512) NOT NULL, created DATETIME2(3) NOT NULL, key_record NVARCHAR(MAX) NOT NULL, PRIMARY KEY (id, created));`
- **Query shapes** (match existing semantics):
  - `Load`: `SELECT key_record FROM encryption_key WHERE id = @id AND created = DATEADD(SECOND, @created, '1970-01-01');`
  - `LoadLatest`: `SELECT TOP 1 key_record FROM encryption_key WHERE id = @id ORDER BY created DESC;`
  - `Store`: `INSERT` if not exists (prefer `MERGE` or `IF NOT EXISTS` to return `false` on duplicate; otherwise
    catch unique constraint violation and return `false`).
- **Connection string expectations** (support existing C# ADO-style strings):
  - Support `sqlserver://user:pass@host:port;database=DbName;encrypt=true` and `mssql://` forms if using `sqlx`.
  - Also accept classic ADO-style strings (`Server=...;Database=...;User ID=...;Password=...;Encrypt=True;`) by
    normalizing to the driver format.
- **Pre-cutover compatibility checklist** (SQL Server):
  - Confirm table exists: `encryption_key`.
  - Confirm column names: `id`, `created`, `key_record` (case-insensitive).
  - Confirm `created` is UTC-compatible (`DATETIME`/`DATETIME2`) and stores the same value C# writes.
  - Confirm `key_record` stores JSON text with UTF-8/Unicode preservation (NVARCHAR recommended).
  - Confirm duplicate insert behavior: existing schema enforces uniqueness on `(id, created)` or the adapter
    will treat unique-constraint violations as `false` returns (no exception).
  - Confirm `LoadLatest` ordering: index or query plan supports `ORDER BY created DESC` for the same results as C#.
  - Optional SQL Server validation script (read-only):

```sql
-- Verify table and columns
SELECT
    t.name AS table_name,
    c.name AS column_name,
    ty.name AS data_type,
    c.max_length,
    c.is_nullable
FROM sys.tables t
JOIN sys.columns c ON c.object_id = t.object_id
JOIN sys.types ty ON ty.user_type_id = c.user_type_id
WHERE t.name = 'encryption_key'
ORDER BY c.column_id;

-- Verify primary key or unique index on (id, created)
SELECT
    i.name AS index_name,
    i.is_unique,
    ic.key_ordinal,
    c.name AS column_name
FROM sys.indexes i
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE i.object_id = OBJECT_ID('encryption_key')
ORDER BY i.is_primary_key DESC, i.is_unique DESC, ic.key_ordinal;

-- Smoke-test LoadLatest behavior for a known key id (replace @id with a real value)
DECLARE @id NVARCHAR(512) = N'your-key-id';
SELECT TOP 1 id, created, key_record
FROM encryption_key
WHERE id = @id
ORDER BY created DESC;

-- Optional JSON validity check (SQL Server 2016+)
SELECT TOP 100 id, created
FROM encryption_key
WHERE ISJSON(key_record) <> 1;
```
  - Update `asherah-config` to detect SQL Server strings and set `MSSQL_URL` (or similar) for the new adapter.

Implications for the C# API:
- Keep the same fluent builder APIs, but treat `AdoMetastoreImpl`, `DynamoDbMetastoreImpl`, `AwsKeyManagementServiceImpl`,
  and `StaticKeyManagementServiceImpl` as configuration wrappers that serialize to config JSON.
- For truly custom implementations, retain the callback/fallback plan in the next section.

## Risk matrix
### Option A: asherah-ffi
| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| FFI error strings lack structured codes | C# exception types become less precise | Medium | Add error codes or prefixed error strings to asherah-ffi and map to existing exceptions. |
| Static KMS key derivation mismatch | Cross-language ciphertext incompatibility | Medium | Enforce 32-byte UTF-8 input and hex-encode to `STATIC_MASTER_KEY_HEX`; document strictness. |
| Session caching semantics drift | Behavioral regression in session reuse and eviction | Medium | Prefer native session caching, keep managed usage tracking, validate with existing tests. |
| Custom metastore/KMS unsupported | Loss of extensibility | High (for users with custom impls) | Keep managed fallback path or design FFI callbacks for metastore/KMS. |
| Native library loading across RIDs | Runtime load failures | Medium | Package RID-native assets and keep deterministic resolver with explicit path overrides. |

### Option B: asherah-cobhan
| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| Global singleton conflicts with multi-factory | Breaks current ability to host multiple configs | High | Add config-hash guard + ref-counted wrapper; document constraints. |
| Cobhan buffer sizing bugs | Data corruption or runtime crashes | Medium | Centralize buffer helpers, use `EstimateBuffer` + retry, add stress tests. |
| Error code mapping gaps | Unclear exceptions to callers | Medium | Map Cobhan error codes to existing exception types with parity test suite. |
| Custom metastore/KMS unsupported | Loss of extensibility | High | Same as Option A: managed fallback or FFI callback API. |
| Performance regressions from JSON roundtrip | Throughput drop in JSON-heavy paths | Low-Medium | Keep DRR JSON path as-is; benchmark and validate. |

## Timeline estimates
### Option A: asherah-ffi
- Week 1: API inventory, config translation rules, static KMS key mapping strategy.
- Weeks 2-3: Native interop layer + core interface; SessionFactory wiring.
- Weeks 4-5: Caching semantics parity, error mapping, metrics/logging instrumentation.
- Week 6: Packaging (RID-native assets) and load resolver integration.
- Weeks 7-8: Full C# unit/integration test pass, cross-language DRR compatibility tests.

### Option B: asherah-cobhan
- Week 1: API inventory, singleton/ref-count design, config translation rules.
- Weeks 2-3: Cobhan interop + buffer helpers + retry logic.
- Weeks 4-5: SessionFactory adaptation, config consistency enforcement, error mapping.
- Week 6: Metrics/logging parity and packaging.
- Weeks 7-10: Full test pass, stress tests for buffers/concurrency, cross-language DRR compatibility tests.

## Custom metastore/KMS compatibility checklist and FFI callback surface
Checklist to preserve current extensibility for users who supply `IMetastore<JObject>` or `IKeyManagementService`
implementations instead of the built-in DynamoDB/ADO/Static/AWS:
- **Inventory current usage**: identify public consumers that pass custom metastore/KMS into `SessionFactory`.
- **Prefer Rust ports for built-ins**: move built-in implementations to Rust so only truly custom implementations
  need callbacks or a managed fallback.
- **Decide fallback policy**: either preserve managed-only code path for custom implementations or require FFI callbacks.
- **Behavioral parity**: ensure custom implementations can still participate in caching, metrics, logging, and
  exception mapping without changing public APIs.
- **Threading and lifetime**: confirm callbacks can be invoked from native threads and that .NET GC handles remain valid.
- **Security**: plaintext key material must not be pinned longer than required; avoid copying where possible.

Proposed FFI callback surface (if native support is required):
- **Metastore callbacks** (sync):
  - `Load(keyId, created) -> (found, json_bytes)`
  - `LoadLatest(keyId) -> (found, json_bytes)`
  - `Store(keyId, created, json_bytes) -> success_bool`
  - `GetKeySuffix() -> string`
- **KMS callbacks** (sync):
  - `EncryptKey(key_bytes, created, revoked) -> encrypted_bytes`
  - `DecryptKey(encrypted_bytes, created, revoked) -> key_bytes`
- **Interop plumbing**:
  - Register a callback table during `SetupJson`/factory creation.
  - Use stable `GCHandle` to keep delegates alive; define clear ownership and disposal.
  - Marshal bytes with length-prefix buffers (similar to `AsherahBuffer` or Cobhan header).
  - Define error codes/messages for callback failures to map to existing C# exceptions.
- **Versioning**:
  - Add a callback API version field and feature flags to allow forward-compatible additions.

## Suggested next steps (applies to both options)
1. Build a public API inventory map (types + signatures) and freeze it as a compatibility checklist.
2. Implement a small proof-of-concept `SessionFactory`/`Session` pair over each native core and run the
   C# unit tests to assess behavioral gaps.
3. Decide whether custom KMS/metastore support must be preserved. If yes, scope an FFI callback design.
