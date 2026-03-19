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

## Medium (Additional — from comprehensive sweep)

17. **[MEDIUM] DRK not wiped on early return in encrypt path**
Evidence: `asherah/src/session.rs:771-785`.
Impact: If an error occurs between DRK generation (line 772) and DRK wipe (line 785), the 32-byte data row key remains on the stack until overwritten by subsequent allocations.
Recommendation: Use a `Drop` guard or `scopeguard` to ensure DRK is wiped on all exit paths.

18. **[MEDIUM] Cobhan aborts entire process on canary corruption**
Evidence: `asherah-cobhan/src/lib.rs:95`, `asherah-cobhan/src/lib.rs:112`, `asherah-cobhan/src/lib.rs:120`.
Impact: Buffer overflow detection calls `std::process::abort()` instead of returning an error. In library code, this terminates the host process without cleanup.
Note: This is a deliberate security-vs-availability tradeoff — continuing after detected memory corruption is dangerous. But it removes the host application's ability to handle the failure.
Recommendation: Consider returning an error code and letting the host decide whether to abort.

19. **[MEDIUM] Cobhan RwLock poisoning causes permanent failure cascade**
Evidence: `asherah-cobhan/src/lib.rs:396-398`, `asherah-cobhan/src/lib.rs:520-522`, `asherah-cobhan/src/lib.rs:637-639`.
Impact: If any FFI call panics while holding the FACTORY RwLock, the lock becomes permanently poisoned. All subsequent encrypt/decrypt calls return ERR_PANIC with no recovery mechanism.
Recommendation: Use `PoisonError::into_inner()` to recover the lock, or add a reset/re-setup path.

20. **[MEDIUM] Metastore store error conflated with duplicate key**
Evidence: `asherah/src/session.rs:671-679`.
Impact: `metastore.store()` errors are logged as warnings and treated identically to "duplicate key" (returns false). Callers cannot distinguish persistent storage failure from benign duplicate, leading to repeated retry loops.
Recommendation: Distinguish error types — return the error for non-duplicate failures.

21. **[MEDIUM] Go lastErrorMessage unbounded read**
Evidence: `asherah-go/ffi.go:25-40`.
Impact: The function reads a null-terminated C string byte-by-byte with no maximum length bound. If the Rust side returns a malformed (non-terminated) string, this loops until segfault.
Note: In practice, Rust always returns CString (null-terminated), so risk is theoretical.
Recommendation: Add a max-length bound (e.g., 4096 bytes) to the read loop.

22. **[MEDIUM] Metrics TSFN NonBlocking silently drops events**
Evidence: `asherah-node/src/lib.rs:480-483`.
Impact: Metrics callback uses `NonBlocking` mode and discards the result (`let _ = ...`). Under high event rates, metrics are silently incomplete with no indication of data loss.
Recommendation: Log or count dropped events.

## Low

23. **[LOW] Postgres timestamp conversion uses `i64 -> f64`**
Evidence: `asherah/src/metastore_postgres.rs:222`, `asherah/src/metastore_postgres.rs:275`, `asherah/src/metastore_postgres.rs:280-281`.
Impact: Theoretical precision loss for timestamps, but Unix-second timestamps won't lose precision for ~285 million years.
Recommendation: Use integer-safe conversion without float intermediary if refactoring this area.

24. **[LOW] Partition ID format is ambiguous with underscores**
Evidence: `asherah/src/partition.rs:31-35`.
Impact: If partition ID, service name, or product ID contain underscores, the IK ID format `_IK_{id}_{service}_{product}` becomes ambiguous. Two different partitions could produce the same IK ID prefix.
Note: Partition IDs are application-controlled and typically alphanumeric. Matches Go canonical behavior.
Recommendation: Document the restriction or add validation.

25. **[LOW] Weak pseudo-random jitter for cache TTL**
Evidence: `asherah/src/cache.rs:159-168`.
Impact: Jitter is based on a monotonic counter with a fixed LCG constant, not actual randomness. Deterministic and predictable.
Note: Jitter purpose is thundering herd prevention, not security. Predictability doesn't matter.
Recommendation: Use actual random source if concerned about timing oracle attacks.

26. **[LOW] Cobhan buffer negative length error is misleading**
Evidence: `asherah-cobhan/src/lib.rs:237-241`.
Impact: Negative buffer lengths (Go temp-file protocol) return `ERR_BUFFER_TOO_LARGE` which is confusing. Callers expect a size error, not a protocol feature mismatch.
Recommendation: Add a distinct error code for unsupported temp-file buffers.

## Performance Opportunities

P1. **[PERF] Cobhan buffer always copies to Vec on read**
Evidence: `asherah-cobhan/src/lib.rs:246-247`.
Impact: Every encrypt/decrypt FFI call allocates and copies the input buffer into a new Vec, even when only a temporary reference is needed.
Recommendation: Use slice references where possible to avoid the copy.

P2. **[PERF] Cobhan single RwLock for all factory operations**
Evidence: `asherah-cobhan/src/lib.rs:181`.
Impact: All encrypt/decrypt operations acquire `FACTORY.read()`. Under high concurrency the read-lock overhead adds latency.
Note: RwLock read-side is cheap on modern hardware. Practical impact is minimal unless contention is extreme.
Recommendation: Consider lock-free session access for the common path.
