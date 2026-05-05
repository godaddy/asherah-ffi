# Asherah-FFI Review — 2026-05-05 Findings Tracker

Source: 3-pass convergence review against the GoDaddy Rust review skill (`rust-godaddy-review`), 10 angles. Non-convergent — each pass surfaced new blocking-tier defects in different subsystems.

Severity: **B** = Blocking, **S** = Suggestion. Status checkbox per item.

## Progress log

Branch: `fix/review-2026-05-05-priority`. One commit per defect group, in priority order:

| Item | Commit | Subject |
| --- | --- | --- |
| T1 | `29e45e9` | `fix(builders): reject empty STATIC_MASTER_KEY_HEX for KMS=static` |
| T3 | `5944736` | `chore(asherah): hide memguard/memcall from public API surface` |
| T11 + REGION_MAP | `cdba397` | `fix(builders): order AWS region map deterministically and validate input` |
| Async FFI plaintext zeroize | `6b70f02` | `fix(asherah-ffi): zeroize plaintext after async decrypt callback returns` |
| T9 | `276e375` | `fix(server): chmod the Unix socket to 0660 after bind` |
| T6 | `e23bde4` | `fix(metastore_dynamodb): match typed PutItemError variant for duplicate detection` |
| T7 | `4c2ac6b` | `fix(metastore_postgres): replace consistency_mode interpolation with typed enum` |
| T10 | `ea2ebd5` | `fix(pool_mysql): cleanly close pool, wake reaper, and reject new checkouts` |
| T4 | `4d8f01c` | `fix(kms,ffi,memguard): drop expect()/unreachable() on tokio runtime init` |

---

## Top fix-first set (blocking, highest leverage)

- [x] **T1 — Silent fallback to public static master key.** `asherah/src/builders.rs:737-742` and `:1067-1069`. Empty `STATIC_MASTER_KEY_HEX` substitutes `"thisIsAStaticMasterKeyForTesting"`. With `KMS=static` as default at line 1064, an unconfigured deployment encrypts everything under a publicly known key. Reject empty hex; require explicit opt-in. — *fixed in `29e45e9`; well-known key reachable only via the explicit `test-debug-static` alias; tests + samples + 6 binding test fixtures migrated.*
- [ ] **T2 — `Send` on `PoolSlot` is unsound.** `asherah/src/memguard.rs:456,671`. Slot owner on thread A can read another caller's plaintext after thread B's eviction; `exclude` only guards `cache_get`. Soundness bug. — *deferred (design work — needs slot-lifetime refcount or `unsafe impl !Send`).*
- [x] **T3 — Public memguard module.** `asherah/src/lib.rs:56-57`. `pub mod memcall; pub mod memguard;` lets external crates call `pool_release`, `wipe_bytes`, `Enclave::open` directly and corrupt the global SLAB. Make `pub(crate)` or split into a private internal crate. — *fixed in `5944736`; gated behind `#[doc(hidden)]` with comment explaining it's not part of the public API.*
- [x] **T4 — `expect()` on init paths violates the no-panic policy from PR #218.** `memguard.rs:653` (`SecureSlab::new().expect(...)`), `memguard.rs:928` (`Signals::new().expect(...)`), `asherah-ffi/src/lib.rs:447` (tokio runtime expect), `kms_aws.rs:110`, `kms_aws_envelope.rs:177` (per-call runtime). — *partial in `4d8f01c`: ASYNC_RT, both KMS `block_on_maybe`/`unreachable!()` paths, and signal-handler init now return `Result`/log+forward. SLAB `Lazy::new` is intentionally deferred (would require fallibility through every call site).*
- [ ] **T5 — Sync `encrypt`/`decrypt` blocks JS event loop / Python GIL / Ruby GVL.** `asherah-node/src/lib.rs:347-407` (libuv main thread), `asherah-py/src/lib.rs:121-145, 320-341` (no `py.detach`), `asherah-ruby/lib/asherah/native.rb:79-80` (no `blocking: true`). Direct violation of the CLAUDE.md "never lie to async callers" rule for the *sync* surface — these calls hit MySQL/Postgres while holding the dispatch thread.
- [x] **T6 — DynamoDB error matched on `Debug` text.** `asherah/src/metastore_dynamodb.rs:362-373`. `format!("{e:?}").contains("ConditionalCheckFailed")` is fragile and false-positive prone. Use `e.into_service_error().is_conditional_check_failed_exception()`. — *fixed in `e23bde4` using the typed `as_service_error().is_some_and(|svc| svc.is_conditional_check_failed_exception())` predicate.*
- [x] **T7 — Postgres `consistency_mode` interpolated into SQL.** `asherah/src/metastore_postgres.rs:259-263`. `connect_with` validator runs only when value is `Some`; future direct construction allows arbitrary SQL. — *fixed in `4c2ac6b`; replaced with typed `ReplicaConsistency` enum + static `as_set_statement` returning a `&'static str`. SQL-injection regression test included.*
- [ ] **T8 — Server: blocking init + abrupt shutdown on Tokio executor.** `asherah-server/src/main.rs:174-175` (sync factory build on async main), `service.rs:77` (sync `s.close()` on Tokio worker), `main.rs:226-237` (force-shutdown drops the server future, abandoning in-flight `encrypt_async`/`decrypt_async`).
- [x] **T9 — Unix socket created with permissive mode.** `asherah-server/src/main.rs:204`. Default permissions (umask-dependent, typically 0666). Any local UID can decrypt. `chmod 0660` after bind. — *fixed in `276e375`; configurable via `--socket-mode` / `ASHERAH_SOCKET_MODE` (default `0660`); octal parser tested for canonical/invalid/overflow inputs.*
- [x] **T10 — MySQL pool `open_count` underflow.** `asherah/src/pool_mysql.rs:416-424`. `close()` subtracts `idle.len()` then `Drop` decrements again on returning checked-out connections; `open_count` underflows `usize` to a huge value, blocks future creates forever. — *fixed in `ea2ebd5`. Three behavioral fixes: (1) `get_conn()` rejects when closed; (2) `Drop` discards conns instead of pushing to a closed pool's idle list; (3) reaper joined via condvar+JoinHandle so close() returns promptly even with a 60s reaper interval.*
- [x] **T11 — Region map non-deterministic preferred index.** `asherah/src/builders.rs:751-759`. `regions.iter().enumerate()` over a `HashMap` picks `pref_idx = 0` from random iteration when `preferred_region` is unset. Sort or require explicit value. — *fixed in `cdba397`; `order_region_map` sorts entries alphabetically, requires `PREFERRED_REGION` for multi-entry maps, rejects empty regions/ARNs/maps. 32-iteration ordering-stability test included.*

---

## Memguard / memcall

- [ ] **B — `memguard.rs:138-140, 134`** Pointer arithmetic on `total = 2*ps + inner_len` can overflow for `usize::MAX`-class inputs; `round_to_page_size` wraps to 0. Use `checked_add`/`checked_mul`.
- [ ] **B — `memguard.rs:172-200, 258-270`** Multiple `unsafe` blocks with no SAFETY comment justifying offset/length invariants.
- [ ] **B — `memguard.rs:954`** `pub static mut STREAM_CHUNK_SIZE: usize = 0;`. Replace with `AtomicUsize`.
- [ ] **B — `memguard.rs:275-276`** `Buffer::destroy` allocates inside the destroy path; alloc failure leaves buffer half-destroyed. Reorder.
- [ ] **B — `memguard.rs:707, 739`** `SLAB_CV.wait(&mut slab)` holds `MutexGuard` indefinitely; FFI caller leak → DoS.
- [ ] **B — `memguard.rs:341-349`** `Enclave::Drop` takes `SLAB.lock()`; reachable from a panic unwind, risks double-panic abort.
- [ ] **B — `memguard.rs:296`** AES-GCM nonce uses 4 zero bytes + counter; `rekey_coffer` doesn't reset counter, persisted ciphertext across rekey could collide. Document or randomize.
- [ ] **B — `memcall.rs:79-80`** `unsafe impl Send/Sync for MemBuf` with no SAFETY note.
- [ ] **B — `memcall.rs:115-121`** Wipe runs after a silently-ignored `protect`; segfaults if protect failed because page is `PROT_NONE`.
- [ ] **B — `memcall.rs:280-285`** `madvise` return value dropped (MADV_DONTDUMP failure invisible).
- [ ] **B — `memguard.rs:128-129`** `Buffer::new` accepts `usize::MAX` size; underflows `data_off`.
- [x] **B — `memguard.rs:927-933`** `Signals::new(&signals_vec).expect("signals")` panics inside spawned thread; signal handling silently lost. — *fixed in `4d8f01c`; logs error and forwards `Err(io::Error)` to the user-supplied handler.*
- [ ] **S — `memguard.rs:802-808`** `LockedBuffer::from_bytes` doesn't wipe `Vec` spare capacity.
- [ ] **S — `memguard.rs:836-838`** `LockedBuffer::bytes(&self) -> Vec<u8>` clones plaintext to unprotected, unwiped Vec. Rename or wrap in `Zeroizing`.
- [ ] **S — `memguard.rs:874-905`** `purge` joins errors into one String; loses structure.
- [ ] **S — `memguard.rs:907-919`** `safe_exit` calls `process::exit`; Drop handlers don't run, untracked `Buffer`s leak with plaintext.
- [ ] **S — `memcall.rs:123-136`** `Drop::drop` ignores `os_free` errors; munmap/VirtualFree failures silent.

## Core (session, cache, builders, types, policy)

- [ ] **B — `session.rs:596`** `Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone_for_return())` causes the cache to lose the entry on every contended call. Replace with direct deref-clone.
- [ ] **B — `cache.rs:175-180`** `is_expired` returns `true` when `ttl_ms == 0`; "no TTL" config thrashes on every access.
- [ ] **B — `cache.rs:296-302`** `Simple` policy bypasses eviction entirely; `max=N` silently unbounded with this policy.
- [ ] **B — `cache.rs:236-260`** `get_meta_if_fresh` returns revoked keys as fresh hits forever for non-`latest` lookups.
- [ ] **B — `cache.rs:455-475`** Mixed `Relaxed` reads + `AcqRel` CAS for `loaded_at_ms` allows freshness signal to be observed inverted across threads.
- [ ] **B — `session.rs:1029,1009,991`** Async SK loaders use `std::thread::spawn` per call — unbounded thread spawning. Use `tokio::task::spawn_blocking`.
- [ ] **B — `session.rs:331-395`** Legacy `decrypt` doesn't wipe `drk` when AEAD fails; async path uses `DrkGuard`, legacy doesn't.
- [ ] **B — `session.rs:602-610`** `PublicFactory::close` swallows `c.close()` errors via `drop(...)`.
- [ ] **B — `session.rs:16-27`, `config.rs:4-9`, `types.rs:24-40`** Public fields on `SessionFactory`/`Config`/`EnvelopeKeyRecord.id` let callers mutate invariants mid-session.
- [ ] **B — `session.rs:283-296`** Legacy `Session::encrypt` doesn't reload `load_latest` on race-loss; two encrypters racing first IK get misleading "store failed" error.
- [ ] **S — `cache.rs:183-197`** `random_jitter_ms` is sequential LCG; entries close in time get identical jitter, defeating thundering-herd protection.
- [ ] **S — `cache.rs:62-72`** `CacheCheck` reinvents Result; `Hit | StaleOther` arms merged identically in consumer.
- [ ] **S — `types.rs:374-388`** `json_escape_into` allocates via `format!` for control chars on hot path.
- [ ] **S — `types.rs:182-187`** `from_json_fast` advances `i += 4` for `null`/`true` without verifying the literal.
- [ ] **S — `types.rs:268-272`** `to_json_fast` writes `pm.id` raw without escape; if id ever contains a quote/backslash, JSON corrupts.
- [ ] **S — `aead.rs:78-92`** `fast_random_bytes` doesn't retry init after transient OsRng failure.
- [ ] **S — `aead.rs:11-13`** Comment claims 2^-32 collision after 2^32 messages — actual safe bound for AES-GCM is 2^32 messages per key total. With 90-day rotation and >540 enc/sec, this becomes non-negligible.
- [ ] **S — `session.rs:438-444`** `now_s` returns 0 if `SystemTime::now < UNIX_EPOCH`.
- [ ] **S — `session_cache.rs:83-84`** Non-atomic remove+insert race produces two distinct sessions for same id.
- [ ] **S — `policy.rs:36-49`** Default `simple` IK cache + 90-day TTL + revocation gap = IK can stay cached past revocation.
- [ ] **S — `partition.rs:31-40, 50-54`** SK id allocated via `format!` per encrypt; cache it like `cached_ik_id`.
- [ ] **S — `builders.rs:707-722`** Hand-rolled hex decode; static master-key plaintext Vec not wiped.
- [ ] **S — `session.rs:798`** Trait-object dispatch on key-loader closure; per-encrypt vtable lookup.
- [ ] **S — `session.rs:60`** `from_config` clones every field; take `&Config` and clone selectively.

## FFI / cobhan

- [x] **B — `asherah-ffi/src/lib.rs:543, 545-549`** Async decrypt callback path drops plaintext `Vec<u8>` un-zeroized after `cb(...)`. Sync path was fixed in PR #216; async wasn't. — *fixed in `6b70f02`; `pt.zeroize()` after the callback returns.*
- [ ] **B — `asherah-cobhan/src/lib.rs:355-363`** No test for `Setup → Shutdown → Setup` re-init or concurrent shutdown-during-encrypt.
- [ ] **B — `asherah-cobhan/src/lib.rs:391-393`** `SetEnv` calls `std::env::set_var` after threads spawned; on POSIX races with `getenv` (now `unsafe` on nightly).
- [ ] **B — `asherah-ffi/src/lib.rs:434-437`, `hooks.rs:118,389`** `transmute::<usize, fn>` not guaranteed by Rust reference; use `*const ()` round-trip or `AtomicPtr<()>`.
- [ ] **B — `asherah-cobhan/src/lib.rs:254-267` vs `:714-724`** Negative length returns inconsistent error codes (`ERR_BUFFER_TOO_SMALL` vs `ERR_UNSUPPORTED_TEMP_FILE`) across entry points.
- [ ] **B — `asherah-cobhan/src/lib.rs:434-436, 575-576, 700-701, 803-804, 871-872`** Poisoned-lock recovery silently uses corrupted state via `into_inner()`.
- [ ] **S — `asherah-ffi/src/lib.rs:524, 549`, `asherah-cobhan:599, 752`** `format!("{e:#}")` returns full anyhow chain to user callbacks; AWS SDK errors include ARNs/request IDs.
- [ ] **S — `hooks.rs:159-172`** `map_log_level` treats unknown values as `Trace`; binding off-by-one becomes verbose-logging footgun.
- [ ] **S — `hooks.rs:87-93`** `CallbackLogSink` reads `LOG_HOOK` under mutex on every record; metrics path uses `AtomicUsize` fast-path probe.
- [ ] **S — `asherah-cobhan/src/lib.rs:206-216, 642`** `cobhan_buffer_set_length` doesn't validate against capacity.
- [ ] **S — `asherah-cobhan/src/lib.rs:500-528`** `EstimateBuffer` panic-catches pure i64 arithmetic.
- [ ] **S — `asherah-cobhan` tests** No isolated subprocess test verifies canary `verify_canaries` actually triggers.

## Metastores

- [ ] **B — `metastore.rs:70-80`** `InMemoryMetastore::store` race on `latest` pointer; `upsert` is unconditional. Use `entry().and_modify(...)`.
- [ ] **B — `metastore_postgres.rs:242-252`** `checked_out` increment outside failure-decrement lock; panic between leaks state, eventually deadlocks pool.
- [ ] **B — `metastore_postgres.rs:281, 332`** `created as f64` for logically-integer epoch; precision/parity risk.
- [ ] **B — `metastore_postgres.rs:331-339`** `to_json_fast()` then `serde_json::from_str::<Value>` re-parses solely for postgres driver. Bind text + `$3::jsonb`.
- [ ] **B — `metastore_dynamodb.rs:56-60, 443-449`** `region_suffix_enabled=true` with no region produces silent `None`, diverging from Go.
- [ ] **B — `metastore_dynamodb.rs:395`** Base64 errors propagated verbatim include offending byte index.
- [x] **B — `pool_mysql.rs:262-278`** Reaper thread `JoinHandle` dropped via `.ok()`; `close()` cannot wait for reaper. — *fixed in `ea2ebd5`; reaper handle stored on `ManagedPool`, `close()` joins it after waking the reaper via a dedicated condvar.*
- [ ] **B — `metastore_postgres.rs:50-61`, `pool_mysql.rs:177,184,190`** `expect("PgPooledClient accessed after drop")` / `ManagedConn` panic-on-deref violates no-panic policy.
- [ ] **S — `metastore_sqlite.rs:23-29, 43, 94`** `created` stored as TEXT via `datetime(?,'unixepoch')`; differs from Go reference and other backends.
- [ ] **S — `metastore_mysql.rs:21-44`** Hand-rolled civil-from-days routine in encryption hot path; replace with `chrono`.
- [ ] **S — `metastore_postgres.rs:340-342`** Duplicate-id store path doesn't log; rotation collisions silent.
- [ ] **S — `metastore_dynamodb.rs:219-225, 282-287`** Inline `kr.as_m()` at load sites returns `Ok(None)` for malformed records, hiding schema corruption.
- [ ] **S — `metastore_region.rs:37-39`** `region_suffix(&self) -> Option<String>` clones per call. Return `Option<&str>`.
- [ ] **S — `store.rs:32-38`** `InMemoryStore` key collision on `{Created, Len}` silently overwrites.
- [ ] **S — `metastore_postgres.rs:239`** `std::thread::sleep` up to 320 ms on blocking pool worker; consider Condvar.
- [ ] **S — `metastore_dynamodb.rs:112`** Owns a `tokio::runtime::Runtime` even on async-only path.
- [ ] **S — All metastores** `log::debug!` only; no `tracing` spans for distributed traces.

## KMS adapters

- [x] **B — `kms_aws.rs:108-112`, `kms_aws_envelope.rs:174-180`** Fallback path constructs fresh `tokio::runtime::Runtime` per call; ms overhead and FD/thread exhaustion. — *fixed in `4d8f01c`; replaced with a process-wide `OnceLock`-backed fallback runtime; init failures surface as `anyhow::Error` instead of panic.*
- [ ] **B — `kms_aws.rs:122,148`, `kms_aws_envelope.rs:194-219, 283`** Plaintext data keys wrapped in `Blob::new(Vec)`/`as_ref().to_vec()` with no zeroize path.
- [ ] **B — `kms_aws_envelope.rs:240-313`** Multi-region decrypt loop has no integrity binding between envelope's `arn` and used `RegionalKek`. Pin to matching region.
- [ ] **B — `kms_secrets_manager.rs:18`** `master_key: Vec<u8>` plaintext, never wiped, `Clone` produces additional un-wiped copies.
- [ ] **B — `kms.rs:11`** `StaticKMS::master_key` same shape as above.
- [ ] **B — `kms_vault_transit.rs:26`** `token: String` cached for process life; no TTL, no renewal, no zeroize. Vault tokens have finite TTL.
- [ ] **B — `kms_vault_transit.rs:386-413, 446-474`** Never inspects `resp.status()` before `.json()`; 5xx with non-JSON body produces parse error masking real status.
- [ ] **B — `kms_vault_transit.rs:370-371,397-398,430-431,458-459`** `{e:#}` logs full reqwest chain; `error!` on decrypt failures.
- [ ] **B — `kms_secrets_manager.rs:118-126`** Hex decode hand-loop; no `0x` strip, whitespace-only outer trim, error-path Vec not wiped.
- [ ] **B — `kms_aws_envelope.rs:122,156`** `new_*_async` allocates Runtime even when sync path never used.
- [ ] **S — `aead.rs:141`** AEAD uses `Aad::empty()`; document intentional cross-language compatibility.
- [ ] **S — `kms_vault_transit.rs:383,443`** No validation of `vault:v` prefix on round-trip.
- [ ] **S — `kms_aws.rs:117,139`** `log::debug!` includes KMS key ARN (account number PII for some compliance frames).
- [ ] **S — `kms_multi.rs:62-73`** Blindly retries every backend on any error; `AccessDenied` triggers N regional Decrypt calls.
- [ ] **S — `traits.rs:11-12`** `KeyManagementService` uses `&()` as context placeholder; consider real `KmsContext`.
- [ ] **S — `kms_vault_transit.rs:92-94`** PEM body Vec not wiped; private key half should be `Zeroizing`.
- [ ] **S — `kms_aws_envelope.rs:241-243`** `serde_json` errors with `{e}` include offending input snippet.
- [ ] **S — `kms_builders.rs:71`** `MultiKms::new` builds 5 runtimes for 5 regions; share or use envelope.

## Server / logging / metrics

- [ ] **B — `asherah-server/src/main.rs:174-175`** Sync `factory_from_config` blocks Tokio main thread.
- [ ] **B — `asherah-server/src/service.rs:77`** Sync `s.close()` on Tokio worker; runs munlock under parking_lot locks.
- [ ] **B — `asherah-server/src/main.rs:226-237`** Drain timeout `select!` drops server future, abandoning in-flight `encrypt_async`/`decrypt_async`.
- [ ] **B — `asherah-server/src/main.rs:266`** `signal(SignalKind::terminate()).expect(...)`.
- [ ] **B — `asherah-server/src/main.rs:181-202, 244-256`** `std::fs::symlink_metadata`/`remove_file` on Tokio runtime; should use `tokio::fs`.
- [ ] **B — `asherah-server/src/service.rs:55,57-81`** Spawned session task detached with no JoinHandle; combined with #226-237 above, abrupt shutdown abandons cleanup.
- [ ] **B — `logging.rs:182`, `metrics.rs:210`** `.expect("spawn worker")` aborts cdylib-loaded process on EAGAIN.
- [ ] **B — `metrics.rs:48,54`** `if let Ok(mut guard) = SINK.write()` swallows lock poisoning permanently.
- [ ] **S — `asherah-server/src/service.rs:97`** No length/charset validation on client-supplied `partition_id`; flows into key IDs and SQL.
- [ ] **S — `asherah-server/src/service.rs:113,129`** `e.to_string()` returns full anyhow chain over the wire; cross-trust-boundary detail leak.
- [ ] **S — `asherah-server/src/main.rs:222`** `drop(shutdown_rx.changed().await)` discards `Result`; sender drop indistinguishable from signal.
- [ ] **S — `logging.rs:78-80`** `log::max_level = Trace` whenever any subscriber registers; defeats subscribers wanting `Warn`.
- [ ] **S — `logging.rs:48-56`** `ensure_logger` returns `Result` but cannot fail; misleading signature.
- [ ] **S — `logging.rs:159`, `metrics.rs:188`** Worker `JoinHandle` never joined in `Drop`; worker panics lost.
- [ ] **S — `metrics.rs:45, 67-72`** Inconsistent `std::sync::RwLock` (metrics) vs `parking_lot::RwLock` (logging); user closure runs holding the read lock.
- [ ] **S — `metrics.rs:75-97`** `Relaxed` ordering on `count` and `total_ns` allows reader to undercount average.
- [ ] **S — `asherah-server/src/main.rs:31, 39, 89`** `value_parser` with string array; use typed enum.
- [ ] **S — `asherah-server/src/lib.rs:19-34`** `parse_go_duration` rejects compound durations like `"1h30m"`; parity bug for interop sidecar.
- [ ] **S — `asherah-server/src/convert.rs:7, 20`** `proto_to_drr` populates `id: String::new()`/`revoked: None`; document this is deliberate parity with Go server.
- [ ] **S — `asherah-server/src/main.rs:208`** `verbose` mode emits per-request partition ID logs; tenant identifier exposure.
- [ ] **S — `api.rs:22-25`** `FactoryOption::SecretFactory` is a no-op; `#[doc(hidden)]` it or remove.

## Language bindings

### Python
- [ ] **B — `asherah-py/src/lib.rs:121-145, 320-341`** Sync `encrypt_bytes`/`decrypt_bytes` hold the GIL across DB I/O. Wrap in `py.detach(|| ...)`.
- [ ] **B — `asherah-py/src/lib.rs:135-144, :175, :329, :359`** Plaintext `bytes`/`pt` Vec dropped un-wiped after `PyBytes::new` copy. Add `Zeroize::zeroize` after callback.

### Ruby
- [ ] **B — `asherah-ruby/lib/asherah/native.rb:79-80`** `attach_function` lacks `blocking: true`; one encrypt blocks every Ruby thread.
- [ ] **B — `asherah-ruby/lib/asherah/session.rb:38-44, 49-55`** Thread-local `AsherahBuffer` reuse without `begin/ensure`; raise mid-call double-frees on next call.
- [ ] **S — `asherah-ruby/lib/asherah.rb:85-91, 117-123, 172-186`** `setup_async`/`shutdown_async`/`encrypt_async`/`decrypt_async` swallow Thread exceptions.

### Go
- [ ] **B — `asherah-go/asherah.go:193-264`** `globalMu` write lock on every cache hit just for `MoveToBack`; serializes whole library.
- [ ] **S — `asherah-go/ffi.go:25-40`** `lastErrorMessage` reads thread-local C string from arbitrary OS thread.
- [ ] **S — `asherah-go` plaintext** Returned plaintext `[]byte` lingers in Go heap unwiped after `asherah_buffer_free`.

### .NET
- [ ] **B — `asherah-dotnet/src/GoDaddy.Asherah.Encryption/AsherahSession.cs:239-253`** `Dispose()` SpinWait on `_pendingOps` with no deadline; can pin a thread until process exit.
- [ ] **S — `AsherahSession.cs:263-274, 307`** Managed `byte[]` plaintext from `Marshal.Copy` never wiped; consider `CryptographicOperations.ZeroMemory`.
- [ ] **S — `AsherahSession.cs:282-316`** `[UnmanagedCallersOnly]` callback can let `SetException` exception unwind into native code (UB in .NET 8).

### Java
- [ ] **S — `asherah-java/src/lib.rs:194-202`** `freeSession` has no double-free guard; relies on Java caller for single-free invariant. Mirror C# `SafeHandle` pattern with `AtomicLong` swap.
- [ ] **S — `asherah-java/src/lib.rs:330-374`** `complete_java_future` builds class/method lookups and strings on every async completion; cache jclass/methodID in `OnceLock<jclass>`.
- [ ] **S — Java JNI entries** No `catch_unwind` on the 16 `extern "system"` JNI entry points.

### Node
- [ ] **B — `asherah-node/src/lib.rs:347-407`** Sync `encrypt`/`decrypt` are plain `#[napi]`, run on libuv main thread; block Node event loop. Wrap in `napi::Task`.
- [ ] **S — `asherah-node/src/lib.rs:659, 684, 756, 786`** Two `transmute::<Function<'_>, Function<'static>>`; latent UAF if V8 isolate torn down before `clear_log_hook` fires.

### Cross-binding
- [ ] **S — All bindings** Language-side plaintext copy (Go `dst`, .NET `Marshal.Copy`, Java `byte_array_from_slice`, Ruby `read_bytes`, Py `PyBytes::new`, Node `Buffer::from`) never wiped after `asherah_buffer_free` zeroes the native side. False sense of containment. Document or expose `decrypt_into(*mut u8, capacity)`.
- [ ] **S — PyO3 / napi / JNI** `catch_unwind` discipline absent on language-binding entry points; `tokio::spawn` futures inside those bindings can panic across language boundary.

## Tests / fuzz

- [ ] **B — Memguard tests** No test exercises `Buffer::destroy` returning `Error::CanaryFailed` (the canary-corruption branch).
- [ ] **B — `fuzz/fuzz_targets/cobhan_buffer.rs:11-61`** Fuzz target reimplements parsing logic in safe Rust and tests *that*, not the unsafe FFI.
- [ ] **B — `asherah-cobhan/tests/integration_tests.rs:1404`** No null-pointer FFI tests; `Encrypt`/`Decrypt`/`EncryptToJson`/`DecryptFromJson` not exercised with `null` inputs.
- [ ] **B — `asherah/tests/cross_fixtures.rs:11`** Cross-language ciphertext fixtures gated behind unset `FIXTURES_DIR`; no checked-in canonical Go DRR roundtrip.
- [ ] **B — `asherah/tests/`** No test confirms plaintext zeroization on drop (sentinel + scan).
- [ ] **B — `asherah/tests/cache_concurrent.rs:39-116`** Eviction tests don't assert `cache.by_meta.len() <= max`; happy-path roundtrip only.
- [ ] **S — `asherah/tests/cache_ttl.rs:34`** `assert!(ik3 >= ik2)` is a no-op; monotonic clock cannot be less.
- [ ] **S — `asherah/tests/revocation.rs`** Timing-sensitive `sleep(1100ms)` × 4 tests; inject a logical clock.
- [ ] **S — `asherah-ffi/tests/hooks.rs:83-91`** `wait_for` silently passes on timeout.
- [ ] **S — `fuzz/fuzz_targets/data_row_record.rs`, `config_json.rs`** 17-line shells with no seed corpus.
- [ ] **S — `fuzz/fuzz_targets/encrypt_decrypt.rs:62-74`** Tampers JSON before `from_str`; mostly fuzzes serde.
- [ ] **S — Missing fuzz targets** Cobhan-real-FFI, Vault Transit response parsing, KMS multi-region selection, region-suffix parsing, JSON `to_json_fast`/`from_json_fast` parity vs serde, session policy.
- [ ] **S — `aead.rs` tests** No Wycheproof / NIST KAT vectors.
- [ ] **S — `asherah/tests/integration_containers.rs`** Concurrent variants use different partition IDs each — zero metastore contention. Add same-partition variant.
- [ ] **S — `asherah/tests/error_injection.rs:303`** Optimistic-store-collision recovery uses in-memory mock; per skill, persistence flows want real DB.
- [ ] **S — `asherah/tests/cache_tests.rs`** `let _ = cache.get_or_load_latest(...).unwrap()` discards return value; doesn't verify the *right* key.
- [ ] **S — `e2e/`** Single happy-path script per ecosystem; no rotation, real KMS, revocation, or async-callback e2e.

## CI / build / release

- [ ] **B — `.github/workflows/publish-server.yml`** No `concurrency:` group (CLAUDE.md hard rule).
- [ ] **B — `.github/workflows/release-cobhan.yml`** No `concurrency:` group.
- [ ] **B — `.github/workflows/publish-maven.yml`** Missing top-level `permissions: { contents: read }`.
- [ ] **B — `.github/workflows/publish-nuget.yml`** Missing top-level `permissions: { contents: read }`.
- [ ] **B — `publish-npm.yml:137-153` vs `ci.yml` dry-runs** Windows builds: publish omits `OPENSSL_STATIC=1`, dry-runs set it. CLAUDE.md says these MUST match exactly.
- [ ] **S — `publish-server.yml`** Dockerfile uses `rust:1.88-bookworm` while toolchain is 1.91.1.
- [ ] **S — `ci.yml:986-988`** pip install hardcodes `--break-system-packages`; use detection probe per CLAUDE.md.
- [ ] **S — `publish-npm.yml`** No Linux GNU or macOS dry-run mirror; only musl/Windows mirrored.
- [ ] **S — `ci.yml:50, 91, 118, ...`** ~30 jobs lack per-job `permissions:` block (top-level covers them but CLAUDE.md says every job must declare one).
- [ ] **S — `ci.yml:987`** `apt-get install libssl-dev` for cross-compile to aarch64; CLAUDE.md says vendor from source for cross-compile glibc.
- [ ] **S — `scripts/test.sh:184`** Unit tests omit `vault` and `secrets-manager` features; adapters can break unnoticed.
- [ ] **S — `codeql.yml`** Only analyzes Actions workflows; no `language: rust`.

## Internal / builders / samples / public surface

- [ ] **B — `builders.rs:737-742, 1067-1069`** Silent fallback to public test key. (Top issue #1.)
- [ ] **B — `builders.rs:1071-1074`** Empty/malformed `REGION_MAP` JSON accepted; later panics on `entries[0]`.
- [ ] **B — `lib.rs:56-57`** `pub mod memguard/memcall`. (Top issue #3.)
- [ ] **S — `lib.rs:17`** Crate-wide `#![allow(unsafe_code)]`; future unsafe additions invisible to lint.
- [ ] **S — `lib.rs:19-54`** Most modules `pub`; many implementation-detail (`session_cache`, `store`, `partition`) should be `pub(crate)` or `#[doc(hidden)]`.
- [ ] **S — `internal/crypto_key.rs:32`** `UnboundKey::new(&AES_256_GCM, &bytes).ok()` silently discards unreachable error.
- [ ] **S — `internal/crypto_key.rs:84`** `with_key_func` lacks panic guard; closure panic leaks buffer from pool.
- [ ] **S — `builders.rs:204, 974, 1158`** `SQLITE_PATH` from env passed without canonicalization or allowlist.
- [ ] **S — `builders.rs:991-1043`** `metastore_from_env` and `resolve_from_env` duplicate ~70 lines; can produce different metastores from same env.
- [ ] **S — All samples** None demonstrate plaintext zeroize after decrypt.
- [ ] **S — `samples/ruby/sample.rb:30-32`** Reaches into `Asherah::Native` directly; users will copy.
- [ ] **S — `samples/python/sample.py:22-31, 36-41`** Mixes config-dict and env-var APIs in same script.

---

## Recurring patterns

- [~] **Plaintext-on-heap leakage** — sync FFI was fixed in #216. Async FFI (`asherah-ffi/src/lib.rs:543`) closed in `6b70f02`. The 5 language-binding decrypt sites (Py/Node/Java/Go/.NET) still keep an unwiped managed-side copy after the native buffer is freed; tracked under T5 / cross-binding suggestions.
- [ ] **`catch_unwind` discipline** — present on every `extern "C"` in asherah-ffi/cobhan, **absent** on PyO3, napi-rs, and JNI binding entry points.
- [~] **Insecure defaults** — `KMS=static` empty key fixed in `29e45e9`; HashMap region-iteration ordering fixed in `cdba397`. Default `Simple` cache policy is still unbounded.
- [~] **`expect()` on init paths** — closed in `4d8f01c` for ASYNC_RT, both KMS `block_on_maybe`/`unreachable!()` paths, and the signal-handler thread. SLAB `Lazy::new` (memguard.rs:653) deliberately deferred — making the global SLAB fallible requires propagating `Result` through every call site.

---

## Recommended fix order

Items already addressed are crossed out; the remainder are still open.

1. ~~T1 — silent static-key fallback (single-line, closes real production-misconfig hole).~~ — `29e45e9`
2. ~~T3 — `pub mod memguard` (gate `#[doc(hidden)]` or split crate).~~ — `5944736`
3. T2 — `PoolSlot Send` soundness (design work; track separately).
4. T5 — sync GIL/GVL/event-loop blocking (per-binding, mechanical).
5. ~~Plaintext-leak variant in async FFI `asherah-ffi/src/lib.rs:543` (explicit `Zeroize::zeroize(&mut pt)` after `cb(...)`).~~ — `6b70f02`
6. T8 — server factory init + shutdown.
7. ~~T7 — Postgres SQL string interpolation.~~ — `4c2ac6b`
8. ~~T11 — region map non-deterministic ordering.~~ — `cdba397`
9. ~~T9 — Unix socket permissions.~~ — `276e375`
10. ~~T10 — MySQL pool underflow.~~ — `ea2ebd5`
11. ~~T6 — DynamoDB Debug-text matching.~~ — `e23bde4`
12. ~~T4 — three `expect()` paths violating PR #218 policy.~~ — `4d8f01c` (SLAB Lazy::new deferred)

After top items land, a clean fourth-pass review would be worthwhile — the convergence loop terminated non-clean here primarily because each angle owned different defect sets.
