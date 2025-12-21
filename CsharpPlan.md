# ExecPlan: C# Asherah Drop-in Parity via asherah-ffi or asherah-cobhan

This plan is derived from `csharp-ffi-cobhan-plan.md` and focuses on execution steps to preserve the bespoke C#
API/ABI while rebasing the core on native Rust.

## Objectives
- Preserve public C# API/ABI and ergonomics with drop-in compatibility.
- Reuse Rust implementations for built-in metastore and KMS; minimize managed runtime dependencies.
- Maintain cross-language DRR JSON compatibility and key envelope behavior.

## Decision points (early)
1. Choose core: `asherah-ffi` (per-factory) vs `asherah-cobhan` (global singleton).
2. Confirm static KMS key policy: strict 32-byte UTF-8 input with hex conversion.

## Milestones and workstreams

### Milestone 0: Parity inventory (Week 1)
- Freeze public API/ABI checklist from the bespoke C# implementation.
- Confirm drop-in constraints (no SQL Server migration, current exception types/messages).
- Lock test coverage gaps to close during migration.

### Milestone 1: Rust parity for built-ins (Weeks 2-4)
- Implement SQL Server metastore adapter (drop-in schema and query behavior).
- Extend `asherah-config` to detect SQL Server connection strings and set `MSSQL_URL`.
- Validate DynamoDB metastore shape and AWS KMS envelope JSON compatibility.

### Milestone 2: C# config-first builders (Weeks 3-5)
- Update C# builders to emit config JSON and remove managed construction of built-ins.
- Implement static KMS key policy (UTF-8 bytes -> 32 bytes -> hex, explicit errors).
- Preserve logging and metrics hooks around native calls.

### Milestone 3: Native core integration (Weeks 4-7)
- FFI path:
  - Implement native interop layer and structured error codes.
  - Map errors to existing C# exceptions.
- Cobhan path:
  - Implement Cobhan buffers, retries, and error mapping.
  - Enforce global singleton configuration semantics.

### Milestone 4: Session cache parity (Weeks 5-8)
- Implement or retain managed usage tracking with sliding expiration.
- Validate multi-threaded session acquisition/release behavior.

### Milestone 5: Packaging + CI (Weeks 6-9)
- Produce RID-specific native binaries and update NuGet packaging.
- Add runtime native library resolver overrides (explicit path and env).
- CI validation for packaging and runtime load.

### Milestone 6: Acceptance tests (Weeks 7-10)
- Cross-language DRR JSON tests.
- SQL Server integration tests (load/load-latest/store/duplicate).
- Static KMS interop tests; AWS KMS tests gated by env.
- Regression runs for all existing C# unit/integration tests.

## Work breakdown (condensed)
- Rust: SQL Server metastore adapter + config detection.
- C#: config-first builders + static KMS key policy + session cache parity.
- Native: structured error codes and mapping.
- Build/CI: RID packaging and loader validation.
- QA: cross-language and SQL Server integration tests.
- Product/Eng: removed (custom metastore/KMS not required).

## Exit criteria
- All existing C# tests pass without modifications.
- SQL Server integration tests pass against existing schema (no migration).
- Cross-language DRR and KMS interop validated.
- No changes required to public C# API/ABI.

## Risks to monitor
- SQL Server adapter behavior mismatches (timestamp precision or duplicate handling).
- Error mapping differences leading to exception type changes.
- Session cache behavior drift under concurrency.
- (Removed) Custom metastore/KMS usage without callbacks or fallback.

## Execution status
- [x] Public API/ABI inventory completed; see `docs/csharp-api-abi/README.md`.
- [x] SQL Server metastore parity documented; see `docs/sqlserver-parity.md`.
- [x] Static KMS UTF-8 32-byte policy enforced in config builder; tests cover invalid length.
- [x] Session cache disposal semantics fixed; `asherah-dotnet/AsherahDotNet/Asherah.cs`.
- [x] FFI + Cobhan native packaging and resolver updates in place.
- [x] Acceptance test evidence captured; see `docs/csharp-ffi-cobhan-acceptance.md`.
