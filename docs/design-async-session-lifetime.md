# Design: Async Session Lifetime Safety

**Status:** Proposed  
**Date:** 2026-04-12  
**Scope:** `asherah-ffi`, `asherah-java`, `asherah-dotnet`, `asherah-ruby`

## Problem

The async encrypt/decrypt paths in the C FFI, Java JNI, .NET, and Ruby
bindings all store a raw native session pointer (cast to `usize`) inside a
tokio task. Nothing prevents the caller from freeing the session while async
work is still in flight. If that happens, the tokio worker dereferences
freed memory.

### Current flow (C FFI example)

```
Caller                          Rust FFI                    Tokio worker
  │                               │                            │
  ├─ encrypt_to_json_async ──────►│                            │
  │  (passes *mut AsherahSession) │                            │
  │                               ├─ AsyncContext { session: ptr as usize }
  │                               ├─ ASYNC_RT.spawn(task) ───►│
  │  returns 0 (success)  ◄───────┤                            │
  │                               │                            │
  ├─ asherah_session_free ───────►│                            │
  │  (drops Box<AsherahSession>)  │                            │
  │                               │             ┌──────────────┤
  │                               │             │ ctx.restore()
  │                               │             │ → &*(addr as *const AsherahSession)
  │                               │             │ USE-AFTER-FREE ← session already dropped
```

### Per-binding manifestation

| Binding | How pointer is stored | How freed | Race window |
|---------|----------------------|-----------|-------------|
| C FFI (`asherah-ffi/src/lib.rs:366`) | `AsyncContext.session: usize` | `asherah_session_free` drops `Box` | Between `spawn` and callback |
| Java JNI (`asherah-java/src/lib.rs:254-255`) | `session_addr: usize` captured by move | `freeSession` drops `Box` | Between `spawn` and `complete_java_future` |
| .NET (`AsherahSession.cs:115`) | `DangerousGetHandle()` → `IntPtr` | `Dispose()` → `SafeSessionHandle.ReleaseHandle()` | Between P/Invoke return and callback |
| Ruby (`session.rb:45`) | `@pointer` passed to FFI | `close()` → `asherah_session_free` | Between `queue.pop` waiting and `close` from another thread |

## Design Constraints

1. **No API surface change for callers.** The fix must be internal to the
   Rust FFI and binding wrappers. External consumers should not see new
   parameters or changed return types.

2. **No performance regression on the sync path.** The sync encrypt/decrypt
   functions must not pay for ref-counting overhead. Only the async path
   needs lifetime protection.

3. **`Session.close()` must remain meaningful.** Closing a session releases
   internal cryptographic state (cache entries, key material). It should
   still happen promptly, just not while async work is using the session.

4. **Minimize cross-language complexity.** Push as much of the solution
   into the Rust FFI layer as possible so each binding wrapper needs
   minimal changes.

## Proposed Solution: Arc-wrapped session in async paths

### Core change: `asherah-ffi/src/lib.rs`

Replace the raw pointer dance with `Arc<AsherahSession>`:

```rust
pub struct AsherahSession {
    inner: Session,
}

// New: shared handle returned by get_session, used by async paths
struct SharedSession {
    session: Arc<AsherahSession>,
}
```

**Factory returns `SharedSession`:**

```rust
pub unsafe extern "C" fn asherah_factory_get_session(
    factory: *mut AsherahFactory,
    partition_id: *const c_char,
) -> *mut SharedSession {
    // ...
    let session = AsherahSession { inner: f.inner.get_session(pid) };
    let shared = SharedSession { session: Arc::new(session) };
    Box::into_raw(Box::new(shared))
}
```

**Sync paths borrow from the Arc (zero overhead):**

```rust
pub unsafe extern "C" fn asherah_encrypt_to_json(
    session: *mut SharedSession,
    // ...
) -> c_int {
    let s = &(*session).session;  // &Arc<AsherahSession> → deref
    s.inner.encrypt(bytes) // ...
}
```

**Async paths clone the Arc into the task:**

```rust
struct AsyncContext {
    session: Arc<AsherahSession>,  // owned clone
    callback: usize,
    user_data: usize,
}

fn spawn_encrypt_async(ctx: AsyncContext, input: Vec<u8>) {
    ASYNC_RT.spawn(async move {
        // ctx.session is an owned Arc clone — session cannot be freed
        // while this task is alive
        match ctx.session.inner.encrypt_async(&input).await {
            // ...
        }
    });
}
```

**Free drops the caller's Arc clone:**

```rust
pub unsafe extern "C" fn asherah_session_free(ptr: *mut SharedSession) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
        // If async tasks still hold Arc clones, the underlying
        // AsherahSession lives until the last clone drops.
    }
}
```

### Updated flow

```
Caller                          Rust FFI                    Tokio worker
  │                               │                            │
  ├─ encrypt_to_json_async ──────►│                            │
  │                               ├─ Arc::clone(&shared.session)
  │                               ├─ AsyncContext { session: arc_clone, .. }
  │                               ├─ ASYNC_RT.spawn(task) ───►│
  │  returns 0 ◄──────────────────┤                            │
  │                               │                            │
  ├─ asherah_session_free ───────►│                            │
  │  (drops caller's Arc clone)   │  Arc strong_count: 1 → 0? │
  │  Arc strong_count still ≥ 1   │  No! Task holds a clone.  │
  │                               │             ┌──────────────┤
  │                               │             │ ctx.session.inner.encrypt_async()
  │                               │             │ ✓ session is alive (Arc holds it)
  │                               │             │ callback fires
  │                               │             │ task drops → Arc clone drops
  │                               │             │ now strong_count → 0 → session freed
```

### Java JNI changes (`asherah-java/src/lib.rs`)

The JNI layer manages its own `Box<Session>`. Apply the same pattern:

```rust
struct SharedJniSession {
    session: Arc<Session>,
}
```

- `getSession` returns `Box::into_raw(Box::new(SharedJniSession { .. }))` as `jlong`
- Sync `encrypt`/`decrypt` borrow from the Arc
- Async `encryptAsync`/`decryptAsync` clone the Arc into the spawned task
- `closeSession` calls `session.close()` on the Arc's contents
- `freeSession` drops the `Box<SharedJniSession>`

### .NET changes (`AsherahSession.cs`)

Two options, in order of preference:

**Option A (minimal, recommended):** The Rust-side Arc already protects
against use-after-free. The .NET wrapper just needs to avoid disposing
while async work may be in flight. Add a simple pending-operation counter:

```csharp
private int _pendingOps;

public unsafe Task<byte[]> EncryptBytesAsync(byte[] plaintext)
{
    EnsureNotDisposed();
    Interlocked.Increment(ref _pendingOps);
    // ... existing code ...
    // In the callback: Interlocked.Decrement(ref _pendingOps);
}

public void Dispose()
{
    if (_disposed) return;
    SpinWait.SpinUntil(() => Volatile.Read(ref _pendingOps) == 0);
    _handle.Dispose();
    _disposed = true;
}
```

With the Rust-side Arc, even if the .NET counter races, the worst case
is a delayed free, not a use-after-free.

**Option B (belt-and-suspenders):** Also wrap every `DangerousGetHandle()`
call in `DangerousAddRef`/`DangerousRelease`. This is strictly correct
per .NET conventions but adds verbosity for no safety gain given the
Rust-side Arc.

### Ruby changes (`session.rb`)

Same as .NET — the Rust-side Arc provides the safety net. Add in-flight
tracking under the existing `@close_mu` mutex:

```ruby
def initialize(pointer)
  raise Asherah::Error::GetSessionFailed, Native.last_error if pointer.null?
  @pointer = pointer
  @close_mu = Mutex.new
  @pending_ops = 0
end

def encrypt_bytes_async(data)
  @close_mu.synchronize { @pending_ops += 1 }
  begin
    # ... existing async code ...
  ensure
    @close_mu.synchronize { @pending_ops -= 1 }
  end
end

def close
  ptr = @close_mu.synchronize do
    return if @pointer.null?
    # Wait for in-flight async ops
    sleep 0.001 while @pending_ops > 0
    p = @pointer
    @pointer = FFI::Pointer::NULL
    p
  end
  Native.asherah_session_free(ptr)
end
```

## Implementation Plan

### Phase 1: Rust FFI layer (asherah-ffi)

1. Introduce `SharedSession` wrapping `Arc<AsherahSession>`.
2. Change `asherah_factory_get_session` to return `*mut SharedSession`.
3. Update sync functions to deref through the Arc (no behavior change).
4. Update `AsyncContext` to hold `Arc<AsherahSession>` instead of `usize`.
5. Update `asherah_session_free` to drop `Box<SharedSession>`.
6. Remove `unsafe impl Send for AsyncContext` (Arc is naturally Send).
7. Add a test that starts an async op and frees the session before
   callback — assert no crash (would catch regressions under Miri/ASAN).

### Phase 2: Java JNI (asherah-java)

1. Introduce `SharedJniSession` wrapping `Arc<Session>`.
2. Update `getSession`, `closeSession`, `freeSession`, sync
   `encrypt`/`decrypt`, async `encryptAsync`/`decryptAsync`.
3. No Java-side API changes needed.
4. Add a Java test: `encryptBytesAsync` → immediate `close()` → assert
   future completes (success or deterministic error, no crash).

### Phase 3: .NET wrapper

1. Add `_pendingOps` counter with `Interlocked` increment/decrement.
2. `Dispose()` waits for counter to reach zero before releasing handle.
3. Add a .NET test racing `Dispose` against async operations.

### Phase 4: Ruby wrapper

1. Add `@pending_ops` tracking under `@close_mu`.
2. `close()` waits for in-flight ops before freeing.
3. Add a Ruby test racing `close` against `encrypt_bytes_async`.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Arc overhead on sync path | Deref through `&Arc<T>` is a pointer indirection, not an atomic op. Benchmark to confirm no regression. |
| Session.close() delayed indefinitely | In practice, encrypt/decrypt complete in microseconds. If a caller deadlocks, the session leak is a symptom, not the cause. |
| Breaking C ABI | The pointer type changes from `*mut AsherahSession` to `*mut SharedSession`, but callers only see `void*`. No ABI break. |
| Cobhan paths | The `asherah-cobhan` crate has its own session management via Cobhan buffers. Verify it is not affected (it uses the sync API only). |

## Testing Strategy

1. **Unit test per phase:** Start async op, free session, assert safe completion.
2. **Miri:** Run `cargo miri test -p asherah-ffi` to validate no UB in the
   new Arc-based paths.
3. **ASAN:** Run `scripts/test.sh --sanitizers` to catch any memory errors.
4. **Existing test suites:** All binding tests must continue to pass
   (`scripts/test.sh --bindings`, `scripts/test.sh --interop`).
5. **Benchmarks:** Run `scripts/benchmark.sh --rust-only --memory` before
   and after to confirm no performance regression on the sync path.

## Non-goals

- Fixing the `factory_from_config_async` concurrency issue (Defect 2
  Phase 2) — that's a separate problem with a separate fix.
- Fixing the Java static facade lock (Defect 4) — that's blocked on this
  work but will be a follow-up PR.
- Adding async support to Go bindings — Go uses purego (no cgo) and
  doesn't call the async FFI functions.
