# Asherah Project Defect Sweep
Date: 2026-03-19

Scope reviewed: `asherah`, `asherah-ffi`, `asherah-cobhan`, `asherah-config`, `asherah-go`, `asherah-node`, `asherah-py`, `asherah-java`, `asherah-server`.

Validation run:
- `pytest -q` in `asherah-py` (pass: 21 passed)

## Design Debt

1. **[DESIGN DEBT] JNI handle model uses raw pointer casts (standard JNI pattern)**
Evidence: `asherah-java/src/lib.rs:25-27`, `asherah-java/src/lib.rs:80-84`, `asherah-java/src/lib.rs:97-99`, `asherah-java/src/lib.rs:161-165`, `asherah-java/src/lib.rs:177-179`.
Impact: Untrusted/stale `jlong` values are cast directly to pointers; this can produce use-after-free, double-free, or invalid-memory dereference.
Note: This is the standard JNI handle pattern used by every JNI library that passes heap pointers through `jlong`. Java code is trusted in-process.
Hardening: Replace raw pointer handles with registry IDs (validated map), and make close/free idempotent through registry state.

2. **[DESIGN DEBT] Unsound lifetime transmute in Node hooks (napi-rs limitation)**
Evidence: `asherah-node/src/lib.rs:519`, `asherah-node/src/lib.rs:544`, `asherah-node/src/lib.rs:609`, `asherah-node/src/lib.rs:630`.
Impact: `std::mem::transmute` to `'static` for N-API function references can violate lifetime guarantees and is a potential UB source.
Note: Mitigated by `FunctionRef` preventing garbage collection. Practical risk is low. Proper fix requires napi-rs upstream API changes.
Hardening: Use safe napi-rs ownership APIs without lifetime transmutes when available.

3. **[POLICY RISK] Default KMS falls back to static test key when `KMS` is unset**
Evidence: `asherah/src/builders.rs:373-375`, `asherah/src/builders.rs:409-417`.
Impact: System defaults to static test key material when `KMS` is unset, which is a confidentiality risk if deployed to production without explicit KMS configuration.
Note: Intentional Go-compatible behavior. Unknown KMS types are now rejected. A `log::warn!` is emitted when static key is used. Production deployments must set `KMS=aws`.
Hardening: Fail closed when KMS mode or key material is missing in non-test operation.

4. **[DESIGN DEBT] Global environment mutation used as config transport**
Evidence: `asherah-config/src/lib.rs:131-205`, `asherah-config/src/lib.rs:287-297`.
Impact: Config application mutates process-global env vars; despite serialization lock, it still creates shared global state and side effects across in-process users.
Hardening: Build factories from explicit typed config objects end-to-end; avoid env as internal transport.

## High

5. **[HIGH] Postgres TLS behavior downgrades `sslmode=prefer/allow/absent` to plaintext**
Evidence: `asherah/src/metastore_postgres.rs:99-100`, `asherah/src/metastore_postgres.rs:126-127`.
Impact: Security posture can be weaker than expected when server supports TLS.
Recommendation: Implement true `prefer/allow` semantics or require explicit secure modes.

6. **[HIGH] Postgres pool hard-fails at max connections instead of waiting/backpressure**
Evidence: `asherah/src/metastore_postgres.rs:181-186`.
Impact: Short bursts can produce avoidable application errors under load.
Recommendation: Add wait/timeout queue semantics for pooled checkout.

7. **[HIGH] Server creates an unbounded spawned task per client stream**
Evidence: `asherah-server/src/service.rs:57-81`.
Impact: Large connection floods can exhaust task/memory resources.
Recommendation: Add connection limits and/or admission control.

## Medium

8. **[MEDIUM] Node metrics/log hooks use unbounded TSFN queues**
Evidence: `asherah-node/src/lib.rs:522`, `asherah-node/src/lib.rs:612`.
Impact: Slow JS consumers can cause unbounded memory growth under high event rates.
Recommendation: Set bounded queue size and drop/backpressure policy.

9. **[MEDIUM] Metrics enablement is process-global, not per-factory**
Evidence: `asherah/src/session.rs:500-503`, `asherah/src/metrics.rs:28`, `asherah/src/metrics.rs:57-59`.
Impact: One factory toggling metrics changes behavior for all factories in-process.
Recommendation: Scope metrics enablement to factory/session instance instead of global static.

10. **[MEDIUM] Session-cache get path clones session wrapper on shared references**
Evidence: `asherah/src/session.rs:569-573`, `asherah/src/session.rs:609-623`.
Impact: Extra cloning/allocation overhead on `get_session` when multiple references exist.
Note: Already optimized with `Arc::try_unwrap` — clone only on shared references.
Recommendation: Return shared handle semantics directly or redesign cache to avoid per-hit cloning.

11. **[MEDIUM] Key cache eviction is full-map scan per eviction**
Evidence: `asherah/src/cache.rs:267-273`, `asherah/src/cache.rs:276-367`.
Impact: Under churn, insertion+eviction cost can degrade toward O(n^2).
Recommendation: Maintain policy-specific priority structures (heaps/lists) for near O(log n)/O(1) eviction.

12. **[MEDIUM] Session cache eviction is full-map scan per eviction**
Evidence: `asherah/src/session_cache.rs:97-103`, `asherah/src/session_cache.rs:106-197`.
Impact: Under churn, insertion+eviction cost can degrade toward O(n^2).
Recommendation: Use dedicated policy structures rather than repeated scans.

13. **[MEDIUM] Unsound signature for C string conversion helper**
Evidence: `asherah-ffi/src/lib.rs:138-142`.
Impact: Function returns `&'str str` with unconstrained lifetime parameter; easy source of accidental unsound use.
Recommendation: Return owned `String` (or tie lifetime explicitly to input wrapper).

14. **[MEDIUM] FFI error reporting is thread-local and can be lost across caller thread hops**
Evidence: `asherah-ffi/src/lib.rs:58-79`.
Impact: Multi-threaded callers may receive empty/incorrect last-error text.
Recommendation: Document strict same-thread semantics or expose explicit error buffer APIs.

15. **[MEDIUM] memguard uses `expect` panics for RNG and slab init failures**
Evidence: `asherah/src/memguard.rs:38`, `asherah/src/memguard.rs:565`.
Impact: Low-level resource failures can hard-crash process instead of propagating recoverable errors.
Note: Intentional — panicking on failed RNG or secure memory is safer than continuing with broken primitives.
Recommendation: Prefer error-returning initialization paths and graceful fallback/fail-fast with context.

## Low

16. **[LOW] Postgres timestamp conversion uses `i64 -> f64`**
Evidence: `asherah/src/metastore_postgres.rs:222`, `asherah/src/metastore_postgres.rs:275`, `asherah/src/metastore_postgres.rs:280-281`.
Impact: Theoretical precision loss for timestamps, but Unix-second timestamps won't lose precision for ~285 million years.
Recommendation: Use integer-safe conversion without float intermediary if refactoring this area.
