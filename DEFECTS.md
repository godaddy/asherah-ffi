# Known Defects — Deferred Remediation

Identified 2026-04-12 via full-repository code review. These issues require
design-level changes and should be addressed in separate, focused PRs.

---

## 1. Async Session Lifetime Safety (Findings 9, 10, 11) — RESOLVED

**Severity:** High  
**Scope:** `asherah-ffi/src/lib.rs`, `asherah-java/src/lib.rs`,
`asherah-dotnet/src/GoDaddy.Asherah.AppEncryption/AsherahSession.cs`,
`asherah-ruby/lib/asherah/session.rb`

**Resolution:** Arc-wrapped sessions in C FFI and Java JNI layers prevent
native use-after-free. .NET and Ruby wrappers add pending-ops counters so
Dispose/close waits for in-flight callbacks. See
`docs/design-async-session-lifetime.md` for full design.

### Problem

The async encrypt/decrypt paths across C FFI, Java JNI, .NET, and Ruby all
store a raw native session pointer (cast to `usize`) and reconstruct a borrowed
reference on a tokio worker thread. Nothing prevents the caller from freeing
the session while async work is still in flight. If that happens, the tokio
worker dereferences freed memory.

Each binding has a slightly different manifestation:

- **C FFI** (`asherah-ffi/src/lib.rs`): `AsyncContext` stores `session: usize`,
  reconstructs `&AsherahSession` via `unsafe { &*(addr as *const _) }`. The doc
  comment says the caller must keep the session alive, but the API does not
  enforce it.
- **Java JNI** (`asherah-java/src/lib.rs`): `encryptAsync` / `decryptAsync`
  capture the session address as `usize`, spawn a tokio task, and later cast
  back to `&Session`. `AsherahSession.close()` frees the handle independently.
- **.NET** (`AsherahSession.cs`, `Asherah.cs`): Uses `DangerousGetHandle()` to
  pass raw `IntPtr` into P/Invoke async calls without
  `DangerousAddRef`/`DangerousRelease`. `Dispose()` / `Shutdown()` can free the
  handle while the async callback is pending.
- **Ruby** (`session.rb`): Passes `@pointer` to the C FFI async entry point,
  then `close()` sets `@pointer = NULL` and calls `asherah_session_free` under a
  mutex — but the mutex does not cover in-flight async operations.

### Remediation Plan

#### Phase 1: Ref-counted session handle in the FFI layer

1. Add an `Arc<AsherahSession>` wrapper (e.g., `SharedSession`) that the FFI
   layer owns. Each `asherah_factory_get_session` returns a pointer to a
   `Box<SharedSession>` instead of a raw `AsherahSession`.
2. Change `AsyncContext` to clone the `Arc` and move it into the spawned task.
   The session lives as long as the last `Arc` reference, so freeing the
   caller's handle cannot cause use-after-free while async work is outstanding.
3. `asherah_session_free` drops the caller's `Arc` clone. If async work still
   holds a clone, the underlying session is freed only when the last reference
   drops.

#### Phase 2: Update each binding wrapper

- **Java**: Change `encryptAsync`/`decryptAsync` JNI functions to clone the
  `Arc` before spawning. `closeSession` drops the JNI-side clone. No change to
  the Java API surface.
- **.NET**: Either pass `SafeSessionHandle` directly through marshalling (so the
  CLR prevents premature release), or bracket every native call with
  `DangerousAddRef`/`DangerousRelease`. Add a pending-operation counter so
  `Dispose()` waits for or rejects in-flight work.
- **Ruby**: Add an in-flight operation counter under `@close_mu`. `close()`
  waits until the counter reaches zero before freeing.

#### Phase 3: Tests

- Per-binding stress test that starts async encrypt, immediately closes the
  session from another thread, and asserts deterministic behavior (either
  blocks, returns an error, or completes — no crash/ASAN violation).
- C FFI direct test that races `asherah_session_free` against
  `asherah_encrypt_to_json_async` callback completion.

---

## 2. Config Env Transport Leaks Stale State (Findings 7, 12)

**Severity:** High  
**Scope:** `asherah-config/src/lib.rs`

### Problem

`ConfigOptions::apply_env()` writes config values into process-global
environment variables. The `set_env_opt_*` helpers intentionally preserve
prior values when a field is `None`:

```rust
fn set_env_opt_i64(key: &str, value: Option<i64>) {
    if let Some(v) = value {
        std::env::set_var(key, v.to_string());
    }
    // None → no-op, prior value persists
}
```

This means sequential factory builds in the same process can inherit stale
settings from earlier builds. Affected variables include `EXPIRE_AFTER_SECS`,
`REVOKE_CHECK_INTERVAL_SECS`, `SESSION_CACHE_DURATION_SECS`,
`SESSION_CACHE_MAX_SIZE`, `PREFERRED_REGION`, `KMS_KEY_ID`,
`SECRETS_MANAGER_SECRET_ID`, `VAULT_*`, and `ASHERAH_POOL_*`.

The async variant (`factory_from_config_async`) compounds the problem: it
releases the config lock before the async build completes, so concurrent async
setup calls can read each other's env state.

### Remediation Plan

#### Phase 1: Short-term containment — clear on None (DONE)

All `set_env_opt_*` helpers now remove the variable when `None`.
`test_optional_int_fields_none_clears_env` asserts the new behavior.
`test_sequential_factory_builds_isolated` proves two sequential factory
builds with different configs do not leak state.

#### Phase 2: Structured config plumbing (eliminates env transport)

1. Add a `ResolvedConfig` struct that holds all typed fields needed by
   `factory_from_env()` / `factory_from_env_async()`.
2. Change `factory_from_config()` to build factories directly from
   `ResolvedConfig` without touching environment variables.
3. Keep `factory_from_env()` as a separate entry point that reads env vars
   once and converts to `ResolvedConfig`.
4. Remove `apply_env()` entirely.

This also fixes the async race (Finding 12) because there are no shared
globals to contend over.

#### Phase 3: Binding updates

Each binding that calls `factory_from_config` / `factory_from_config_async`
gets the fix for free. Verify with per-binding tests that call setup twice
with different configs in the same process.

---

## 3. Transitive `rand` Advisory (Finding 13) — RESOLVED

Resolved by upgrading tonic 0.12 → 0.14 (which pulls tower 0.5, dropping
the rand 0.8.5 dependency) and `cargo update` (rand 0.9.2 → 0.9.3,
0.10.0 → 0.10.1). `cargo audit` is now clean.

---

## 4. Java Static Facade Global Lock (Finding 14)

**Severity:** Medium  
**Scope:** `asherah-java/java/src/main/java/com/godaddy/asherah/jni/Asherah.java`

### Problem

The static facade (`Asherah.encrypt`, `Asherah.decrypt`, and the static async
variants) holds a single `synchronized (LOCK)` monitor for the entire
operation — session acquire, encrypt/decrypt, session release. The async
methods just wrap the sync methods in `CompletableFuture.supplyAsync(...)`, so
all work is serialized regardless of partition.

This is correct (no data races) but limits throughput: concurrent callers on
different partitions queue behind the same lock, and async callers burn
`ForkJoinPool.commonPool()` threads waiting for synchronized access.

The lock also serves a safety purpose: it serializes `shutdown()` against
session use, preventing use-after-free. Narrowing the lock without addressing
this creates a lifetime race.

### Remediation Plan

**Prerequisite:** Defect 1 (async session lifetime) is now resolved.
The Arc-wrapped sessions make it safe to narrow the lock scope.

#### Option A: Operation leasing (preferred)

1. Replace the single `LOCK` with two concerns:
   - A `ReadWriteLock` for setup/shutdown state (write-locked during
     `setup()` and `shutdown()`, read-locked during operations).
   - A `ConcurrentHashMap` for the session cache with per-partition
     granularity.
2. `encrypt`/`decrypt` acquire a read lock (non-exclusive), get/create a
   session from the cache, perform the operation, and release.
3. `shutdown()` acquires the write lock (exclusive), waits for in-flight
   read locks to drain, then clears the cache and frees resources.
4. The static async methods delegate to the session-level async API
   (`session.encryptBytesAsync`) instead of wrapping sync methods.

#### Option B: Steer users to session-level API

If the static facade is intended as a convenience for low-concurrency use:

1. Document the serialization behavior in the README and Javadoc.
2. Add a throughput-focused example using the session-level API directly.
3. Keep the static facade conservative and tested as-is.

#### Tests

- Concurrent throughput test: N threads on different partitions, measure
  that operations overlap (not serialized).
- Shutdown-during-operations test: start async work, call `shutdown()`,
  assert defined behavior.
