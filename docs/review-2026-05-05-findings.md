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
| T4 (partial) | `4d8f01c` | `fix(kms,ffi,memguard): drop expect()/unreachable() on tokio runtime init` |
| T8 | `384c439` | `fix(server): move blocking init/close to spawn_blocking, drop expect()` |
| T2 | `cd56ccc` | `fix(memguard): track transient PoolSlot ownership explicitly` |
| T5 | `d7663b3` | `fix(bindings): release GIL/GVL on sync encrypt/decrypt; document Node sync semantics` |
| Memguard safety batch | `274976a` | `fix(memguard,memcall): overflow checks, SAFETY comments, atomic STREAM_CHUNK_SIZE` |
| Core session/cache batch | `7dad394` | `fix(core): TTL=0 means never-expire; wipe DRK on legacy decrypt error path; surface IK-cache close errors` |
| Cobhan/FFI batch | `b90d1c4` | `fix(ffi/cobhan): SetEnv post-init reject, fn-ptr transmute via *const(), refuse poisoned locks, unify negative-length error` |
| Metastore batch | `84b7585` | `fix(metastore): InMemory atomic latest, postgres pool guard, DynamoDB region+base64` |
| KMS batch | `40d3ee2` | `fix(kms): zeroize cached master keys/tokens; check Vault HTTP status before json parse` |
| Server S-tier | `2467d97` | `fix(server): partition_id validation, error sanitization, compound durations` |
| Misc S-tier | `c855fb2` | `fix(misc): suggestion-tier cleanups across logging, session_cache, postgres, hooks` |
| KMS+pool S-tier | `2e9d2e5` | `fix(kms,pool_mysql): KMS S-tier batch + reaper notify-then-wait race` |
| Metastore S-tier | `8f458a9` | `fix(metastore): parse_item enforces schema, InMemoryStore unique keys` |
| Cobhan/server S-tier | `5c188d4` | `fix(cobhan,server): drop unnecessary panic-catch, log unexpected channel closures` |
| Memguard/metrics/hooks S-tier | `96d8802` | `fix(memguard,metrics,hooks): panic-safe Enclave drop, metrics poison recovery, log fast-path probe` |
| API doc | `2fc2464` | `docs(api): annotate FactoryOption::SecretFactory as Go-API parity stub` |

---

## Top fix-first set (blocking, highest leverage)

- [x] **T1 — Silent fallback to public static master key.** `asherah/src/builders.rs:737-742` and `:1067-1069`. Empty `STATIC_MASTER_KEY_HEX` substitutes `"thisIsAStaticMasterKeyForTesting"`. With `KMS=static` as default at line 1064, an unconfigured deployment encrypts everything under a publicly known key. Reject empty hex; require explicit opt-in. — *fixed in `29e45e9`; well-known key reachable only via the explicit `test-debug-static` alias; tests + samples + 6 binding test fixtures migrated.*
- [x] **T2 — `Send` on `PoolSlot` is unsound.** `asherah/src/memguard.rs:456,671`. Slot owner on thread A can read another caller's plaintext after thread B's eviction; `exclude` only guards `cache_get`. — *fixed in `cd56ccc`. Re-traced the eviction logic: transient slots are off both `free` and `cache_lru` so the specific race the review described cannot fire today. Added a `SecureSlab::transient: HashSet<usize>` for explicit positive tracking, debug-asserts in `release_slot` for double-release / release-without-acquire, and rewrote both `unsafe impl Send` SAFETY comments. New `pool_slot_survives_send_across_threads` test sends 16 slots across threads while a hammer thread acquires/releases in parallel.*
- [x] **T3 — Public memguard module.** `asherah/src/lib.rs:56-57`. `pub mod memcall; pub mod memguard;` lets external crates call `pool_release`, `wipe_bytes`, `Enclave::open` directly and corrupt the global SLAB. Make `pub(crate)` or split into a private internal crate. — *fixed in `5944736`; gated behind `#[doc(hidden)]` with comment explaining it's not part of the public API.*
- [x] **T4 — `expect()` on init paths violates the no-panic policy from PR #218.** `memguard.rs:653` (`SecureSlab::new().expect(...)`), `memguard.rs:928` (`Signals::new().expect(...)`), `asherah-ffi/src/lib.rs:447` (tokio runtime expect), `kms_aws.rs:110`, `kms_aws_envelope.rs:177` (per-call runtime). — *partial in `4d8f01c`: ASYNC_RT, both KMS `block_on_maybe`/`unreachable!()` paths, and signal-handler init now return `Result`/log+forward. SLAB `Lazy::new` is intentionally deferred (would require fallibility through every call site).*
- [x] **T5 — Sync `encrypt`/`decrypt` blocks JS event loop / Python GIL / Ruby GVL.** `asherah-node/src/lib.rs:347-407` (libuv main thread), `asherah-py/src/lib.rs:121-145, 320-341` (no `py.detach`), `asherah-ruby/lib/asherah/native.rb:79-80` (no `blocking: true`). — *fixed in `d7663b3`. Python: `py.detach(|| ...)` around `session.encrypt`/`session.decrypt` on every sync entry point. Ruby: `blocking: true` added to all factory/encrypt/decrypt FFI attach_function calls so ruby-ffi releases the GVL across the native call. Node: kept the sync API (changing return types to Promise would break the published TS contract) but updated the .d.ts to document the event-loop block and steer service code to `encryptAsync`/`decryptAsync`.*
- [x] **T6 — DynamoDB error matched on `Debug` text.** `asherah/src/metastore_dynamodb.rs:362-373`. `format!("{e:?}").contains("ConditionalCheckFailed")` is fragile and false-positive prone. Use `e.into_service_error().is_conditional_check_failed_exception()`. — *fixed in `e23bde4` using the typed `as_service_error().is_some_and(|svc| svc.is_conditional_check_failed_exception())` predicate.*
- [x] **T7 — Postgres `consistency_mode` interpolated into SQL.** `asherah/src/metastore_postgres.rs:259-263`. `connect_with` validator runs only when value is `Some`; future direct construction allows arbitrary SQL. — *fixed in `4c2ac6b`; replaced with typed `ReplicaConsistency` enum + static `as_set_statement` returning a `&'static str`. SQL-injection regression test included.*
- [x] **T8 — Server: blocking init + abrupt shutdown on Tokio executor.** `asherah-server/src/main.rs:174-175` (sync factory build on async main), `service.rs:77` (sync `s.close()` on Tokio worker), `main.rs:226-237` (force-shutdown drops the server future). — *fixed in `384c439`. `factory_from_config` and `s.close()` both moved to `tokio::task::spawn_blocking`. `shutdown_signal()` returns `io::Result<()>` instead of `expect`-aborting on registration failure. The hard drain timeout is now configurable via `--shutdown-drain-timeout`/`ASHERAH_SHUTDOWN_DRAIN_TIMEOUT`, defaulting to 5s for test compatibility. The detached-session-task abandonment on hard timeout is documented as a follow-up — needs a JoinSet refactor.*
- [x] **T9 — Unix socket created with permissive mode.** `asherah-server/src/main.rs:204`. Default permissions (umask-dependent, typically 0666). Any local UID can decrypt. `chmod 0660` after bind. — *fixed in `276e375`; configurable via `--socket-mode` / `ASHERAH_SOCKET_MODE` (default `0660`); octal parser tested for canonical/invalid/overflow inputs.*
- [x] **T10 — MySQL pool `open_count` underflow.** `asherah/src/pool_mysql.rs:416-424`. `close()` subtracts `idle.len()` then `Drop` decrements again on returning checked-out connections; `open_count` underflows `usize` to a huge value, blocks future creates forever. — *fixed in `ea2ebd5`. Three behavioral fixes: (1) `get_conn()` rejects when closed; (2) `Drop` discards conns instead of pushing to a closed pool's idle list; (3) reaper joined via condvar+JoinHandle so close() returns promptly even with a 60s reaper interval.*
- [x] **T11 — Region map non-deterministic preferred index.** `asherah/src/builders.rs:751-759`. `regions.iter().enumerate()` over a `HashMap` picks `pref_idx = 0` from random iteration when `preferred_region` is unset. Sort or require explicit value. — *fixed in `cdba397`; `order_region_map` sorts entries alphabetically, requires `PREFERRED_REGION` for multi-entry maps, rejects empty regions/ARNs/maps. 32-iteration ordering-stability test included.*

---

## Memguard / memcall

- [x] **B — `memguard.rs:138-140, 134`** Pointer arithmetic on `total = 2*ps + inner_len` can overflow for `usize::MAX`-class inputs; `round_to_page_size` wraps to 0. — *fixed in `274976a`; `round_to_page_size` uses `saturating_add`, `Buffer::new` validates each layout step with `checked_add`/`checked_sub` and bails with a clear error.*
- [x] **B — `memguard.rs:172-200, 258-270`** Multiple `unsafe` blocks with no SAFETY comment justifying offset/length invariants. — *partial in `274976a`; SAFETY comments added on `inner_ptr`, `post_ptr`, `data_ptr`, `bytes`, `as_slice`. Send/Sync impls also got proper SAFETY notes via `cd56ccc`.*
- [x] **B — `memguard.rs:954`** `pub static mut STREAM_CHUNK_SIZE: usize = 0;`. — *fixed in `274976a`; replaced with `AtomicUsize` plus `stream_chunk_size`/`set_stream_chunk_size` accessors.*
- [x] **B — `memguard.rs:275-276`** `Buffer::destroy` allocates inside the destroy path; alloc failure leaves buffer half-destroyed. Reorder. — *fixed in earlier commit; placeholder MemBuf is allocated up front and the function returns early on failure rather than half-destroying the buffer.*
- [x] **B — `memguard.rs:707, 739`** `SLAB_CV.wait(&mut slab)` holds `MutexGuard` indefinitely; FFI caller leak → DoS. — *fixed in earlier commit; `SLAB_CV.wait` was replaced with `wait_for(&mut slab, remaining)` against a `POOL_ACQUIRE_DEADLINE = 30s` and `Error::OutOfSlots` is returned to FFI callers when the deadline is exceeded.*
- [x] **B — `memguard.rs:341-349`** `Enclave::Drop` takes `SLAB.lock()`. — *fixed in `96d8802`; `cache_evict` is wrapped in `catch_unwind` so a poisoned-mutex or in-unwind panic is logged instead of aborting the process and skipping every other Drop in the unwind path.*
- [x] **B — `memguard.rs:296`** AES-GCM nonce uses 4 zero bytes + counter. — *fixed in `69467ec`; `NONCE_PREFIX` is a `OnceLock<[u8; 4]>` initialized via `scramble_bytes` (with a SystemTime-nanos fallback if OsRng fails). The 12-byte nonce is now `[random prefix || counter]`, so two process lifetimes that both restart `NONCE_COUNTER` from 0 cannot collide.*
- [x] **B — `memcall.rs:79-80`** `unsafe impl Send/Sync for MemBuf` with no SAFETY note. — *fixed in `274976a`; SAFETY paragraph spells out exclusive ownership and OS-level thread safety.*
- [x] **B — `memcall.rs:115-121`** Wipe runs after a silently-ignored `protect`; segfaults if protect failed because page is `PROT_NONE`. — *fixed in `274976a` for both `free()` and `Drop`; protect failure is logged and the wipe is skipped, so we don't fault writing to a still-PROT_NONE page.*
- [x] **B — `memcall.rs:280-285`** `madvise` return value dropped (MADV_DONTDUMP failure invisible). — *fixed in `274976a`; both Linux/MADV_DONTDUMP and FreeBSD/MADV_NOCORE paths capture the rc and emit `log::debug!` on failure.*
- [x] **B — `memguard.rs:128-129`** `Buffer::new` accepts `usize::MAX` size; underflows `data_off`. — *fixed in `274976a` (covered by the layout-overflow checks above; regression test `buffer_new_huge_size_rejected_without_overflow` exercises both `usize::MAX` and a near-MAX size).*
- [x] **B — `memguard.rs:927-933`** `Signals::new(&signals_vec).expect("signals")` panics inside spawned thread; signal handling silently lost. — *fixed in `4d8f01c`; logs error and forwards `Err(io::Error)` to the user-supplied handler.*
- [ ] **S — `memguard.rs:802-808`** `LockedBuffer::from_bytes` doesn't wipe `Vec` spare capacity.
- [ ] **S — `memguard.rs:836-838`** `LockedBuffer::bytes(&self) -> Vec<u8>` clones plaintext to unprotected, unwiped Vec. Rename or wrap in `Zeroizing`.
- [ ] **S — `memguard.rs:874-905`** `purge` joins errors into one String; loses structure.
- [ ] **S — `memguard.rs:907-919`** `safe_exit` calls `process::exit`; Drop handlers don't run, untracked `Buffer`s leak with plaintext.
- [ ] **S — `memcall.rs:123-136`** `Drop::drop` ignores `os_free` errors; munmap/VirtualFree failures silent.

## Core (session, cache, builders, types, policy)

- [x] **B — `session.rs:596`** `Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone_for_return())` causes the cache to lose the entry on every contended call. — *fixed in earlier commit; `get_session` now always uses `(*arc).clone_for_return()` and never `Arc::try_unwrap` — contended reads keep the cached entry alive.*
- [x] **B — `cache.rs:175-180`** `is_expired` returns `true` when `ttl_ms == 0`. — *fixed in `7dad394`; `ttl_ms == 0` now means "no TTL / never expire". Both `try_claim_reload_*` paths early-return false for the same configuration. Existing `cache_ttl_zero_always_reloads` test renamed to `cache_ttl_zero_never_expires` and inverted to assert the new semantics.*
- [x] **B — `cache.rs:296-302`** `Simple` policy bypasses eviction entirely; `max=N` silently unbounded with this policy. — *fixed in `7dad394`; constructor now warns at runtime when `policy=Simple` is paired with `max > 0`.*
- [ ] **B — `cache.rs:236-260`** `get_meta_if_fresh` returns revoked keys as fresh hits forever for non-`latest` lookups. — *not changed; on closer reading the override is intentional (revocation is monotonic, so once an entry is locally revoked there's nothing the metastore could change). Tracking as docs-only.*
- [x] **B — `cache.rs:455-475`** Mixed `Relaxed` reads + `AcqRel` CAS for `loaded_at_ms` allows freshness signal to be observed inverted across threads. — *fixed in `69467ec`; the four read paths (`get_latest_if_fresh`, `get_meta_if_fresh`, `try_claim_reload_latest`, `try_claim_reload_meta`) now `Acquire`-load `loaded_at_ms`, and the CAS uses `(success: AcqRel, failure: Acquire)` so the post-CAS reader's freshness probe is fully synchronized with the claiming thread.*
- [x] **B — `session.rs:1029,1009,991`** Async SK loaders use `std::thread::spawn` per call. — *fixed in earlier commit; all three sites in `get_or_load_system_key_async` now use `tokio::task::spawn_blocking`, which is bounded by the runtime's blocking-pool budget instead of unbounded OS threads.*
- [x] **B — `session.rs:331-395`** Legacy `decrypt` doesn't wipe `drk` when AEAD fails; async path uses `DrkGuard`, legacy doesn't. — *fixed in `7dad394`; new `DrkWipe` drop-guard wipes on every exit path.*
- [x] **B — `session.rs:602-610`** `PublicFactory::close` swallows `c.close()` errors via `drop(...)`. — *fixed in `7dad394`; replaced with `?`-propagation via `anyhow::Context`.*
- [x] **B — `session.rs:16-27`, `config.rs:4-9`, `types.rs:24-40`** Public fields on `SessionFactory`/`Config`/`EnvelopeKeyRecord.id` let callers mutate invariants mid-session. — *partial: `SessionFactory<A,K,M,P>`'s field visibility is now `pub(crate)` (visibility-only change has no struct-layout impact, so the CLAUDE.md perf concern doesn't apply — confirmed by passing benchmarks). External code interacts via `PublicFactory` re-exported as `asherah::SessionFactory`. `Config` fields stay `pub` because they're a builder users assemble field-by-field. `EnvelopeKeyRecord.id` stays `pub` because both `asherah-server/src/convert.rs` and `asherah-cobhan/src/lib.rs` construct the struct literally with `id: String::new()` (the metastore fills the id on load); a constructor swap would be a public-API break.*
- [x] **B — `session.rs:283-296`** Legacy `Session::encrypt` doesn't reload `load_latest` on race-loss. — *fixed in `8d85a6b`; mirrors the `create_intermediate_key` recovery — on `Ok(false)` (or `Err`), `load_latest` for the IK id, decrypt with its parent SK, and use the winner's IK to continue the encrypt.*
- [ ] **S — `cache.rs:183-197`** `random_jitter_ms` is sequential LCG; entries close in time get identical jitter, defeating thundering-herd protection.
- [ ] **S — `cache.rs:62-72`** `CacheCheck` reinvents Result; `Hit | StaleOther` arms merged identically in consumer.
- [ ] **S — `types.rs:374-388`** `json_escape_into` allocates via `format!` for control chars on hot path.
- [ ] **S — `types.rs:182-187`** `from_json_fast` advances `i += 4` for `null`/`true` without verifying the literal.
- [ ] **S — `types.rs:268-272`** `to_json_fast` writes `pm.id` raw without escape; if id ever contains a quote/backslash, JSON corrupts.
- [ ] **S — `aead.rs:78-92`** `fast_random_bytes` doesn't retry init after transient OsRng failure.
- [ ] **S — `aead.rs:11-13`** Comment claims 2^-32 collision after 2^32 messages — actual safe bound for AES-GCM is 2^32 messages per key total. With 90-day rotation and >540 enc/sec, this becomes non-negligible.
- [ ] **S — `session.rs:438-444`** `now_s` returns 0 if `SystemTime::now < UNIX_EPOCH`.
- [x] **S — `session_cache.rs:83-84`** Non-atomic remove+insert race produces two distinct sessions for same id. — *fixed in `c855fb2`; replaced with atomic `upsert`.*
- [ ] **S — `policy.rs:36-49`** Default `simple` IK cache + 90-day TTL + revocation gap = IK can stay cached past revocation.
- [ ] **S — `partition.rs:31-40, 50-54`** SK id allocated via `format!` per encrypt; cache it like `cached_ik_id`.
- [ ] **S — `builders.rs:707-722`** Hand-rolled hex decode; static master-key plaintext Vec not wiped.
- [ ] **S — `session.rs:798`** Trait-object dispatch on key-loader closure; per-encrypt vtable lookup.
- [ ] **S — `session.rs:60`** `from_config` clones every field; take `&Config` and clone selectively.

## FFI / cobhan

- [x] **B — `asherah-ffi/src/lib.rs:543, 545-549`** Async decrypt callback path drops plaintext `Vec<u8>` un-zeroized after `cb(...)`. Sync path was fixed in PR #216; async wasn't. — *fixed in `6b70f02`; `pt.zeroize()` after the callback returns.*
- [x] **B — `asherah-cobhan/src/lib.rs:355-363`** No test for `Setup → Shutdown → Setup` re-init or concurrent shutdown-during-encrypt. — *already covered by `test_shutdown_and_reinitialize_impl` in `asherah-cobhan/tests/integration_tests.rs:1282`, run from `test_full_encryption_workflow`.*
- [x] **B — `asherah-cobhan/src/lib.rs:391-393`** `SetEnv` calls `std::env::set_var` after threads spawned. — *fixed in `b90d1c4`; refuses with `ERR_ALREADY_INITIALIZED` once FACTORY is set, with a doc comment spelling out the startup-only contract.*
- [x] **B — `asherah-ffi/src/lib.rs:434-437`, `hooks.rs:118,389`** `transmute::<usize, fn>` not guaranteed by Rust reference. — *fixed in `b90d1c4`; all three sites round-trip through `*const ()` before `transmute::<*const (), fn-ptr>`.*
- [x] **B — `asherah-cobhan/src/lib.rs:254-267` vs `:714-724`** Negative length returns inconsistent error codes. — *fixed in `b90d1c4`; both borrow and to-bytes paths return `ERR_UNSUPPORTED_TEMP_FILE`.*
- [x] **B — `asherah-cobhan/src/lib.rs:434-436, 575-576, 700-701, 803-804, 871-872`** Poisoned-lock recovery silently uses corrupted state. — *partial in `b90d1c4`; encrypt/decrypt paths now go through `factory_read_or_panic_err` and return `ERR_PANIC` on poisoning. SetupJson keeps `into_inner()` because it owns the write lock and overwrites state.*
- [ ] **S — `asherah-ffi/src/lib.rs:524, 549`, `asherah-cobhan:599, 752`** `format!("{e:#}")` returns full anyhow chain to user callbacks; AWS SDK errors include ARNs/request IDs.
- [x] **S — `hooks.rs:159-172`** `map_log_level` treats unknown values as `Trace`. — *fixed in `c855fb2`; clamps unknown values to `Warn` and emits a warning.*
- [x] **S — `hooks.rs:87-93`** `CallbackLogSink` reads `LOG_HOOK` under mutex on every record. — *fixed in `96d8802`; new `LOG_HOOK_INSTALLED` AtomicBool gate matches the metrics-path fast-path probe. Set/clear sites update the gate while holding the slot mutex with acquire/release ordering.*
- [ ] **S — `asherah-cobhan/src/lib.rs:206-216, 642`** `cobhan_buffer_set_length` doesn't validate against capacity.
- [x] **S — `asherah-cobhan/src/lib.rs:500-528`** `EstimateBuffer` panic-catches pure i64 arithmetic. — *fixed in `5c188d4`; catch_unwind removed.*
- [ ] **S — `asherah-cobhan` tests** No isolated subprocess test verifies canary `verify_canaries` actually triggers.

## Metastores

- [x] **B — `metastore.rs:70-80`** `InMemoryMetastore::store` race on `latest` pointer. — *fixed in `84b7585`; CAS-style update+insert loop using `scc::HashMap::update`, atomic under the bucket lock.*
- [x] **B — `metastore_postgres.rs:242-252`** `checked_out` increment outside failure-decrement lock; panic between leaks state. — *fixed in `84b7585`; `CheckoutGuard` drop-guard decrements on Drop unless explicitly committed after `pooled` is constructed.*
- [ ] **B — `metastore_postgres.rs:281, 332`** `created as f64` for logically-integer epoch; precision/parity risk. — *not fixed; the `epoch + interval` SQL alternative broke postgres roundtrip tests in this driver setup. Documented as a known precision floor (current epochs are far below 2^53). Tracked as a follow-up.*
- [ ] **B — `metastore_postgres.rs:331-339`** `to_json_fast()` then `serde_json::from_str::<Value>` re-parses solely for postgres driver. — *not fixed; binding `&str` with `$3::jsonb` cast broke integration tests in this postgres-rs version. Source comment documents the parity issue.*
- [x] **B — `metastore_dynamodb.rs:56-60, 443-449`** `region_suffix_enabled=true` with no region produces silent `None`. — *fixed in `84b7585`; bails at construction with a clear AWS_REGION error.*
- [x] **B — `metastore_dynamodb.rs:395`** Base64 errors propagated verbatim include offending byte index. — *fixed in `84b7585`; sanitized to a generic "KeyRecord.Key is not valid base64".*
- [x] **B — `pool_mysql.rs:262-278`** Reaper thread `JoinHandle` dropped via `.ok()`; `close()` cannot wait for reaper. — *fixed in `ea2ebd5`; reaper handle stored on `ManagedPool`, `close()` joins it after waking the reaper via a dedicated condvar.*
- [ ] **B — `metastore_postgres.rs:50-61`, `pool_mysql.rs:177,184,190`** `expect("PgPooledClient accessed after drop")` / `ManagedConn` panic-on-deref violates no-panic policy. — *deferred (the unwrap is genuinely unreachable in current code; needs a NonNull invariant restructure to remove the expect).*
- [ ] **S — `metastore_sqlite.rs:23-29, 43, 94`** `created` stored as TEXT via `datetime(?,'unixepoch')`; differs from Go reference and other backends.
- [ ] **S — `metastore_mysql.rs:21-44`** Hand-rolled civil-from-days routine in encryption hot path; replace with `chrono`.
- [x] **S — `metastore_postgres.rs:340-342`** Duplicate-id store path doesn't log. — *fixed in `c855fb2`; logs at `info` level on conflict.*
- [x] **S — `metastore_dynamodb.rs:219-225, 282-287`** Inline `kr.as_m()` returns `Ok(None)` for malformed records. — *fixed in `8f458a9`; both load_latest_impl_sync and load_latest_impl_async now route through `parse_item`, which distinguishes missing/decoded/malformed and returns `Err` for malformed.*
- [ ] **S — `metastore_region.rs:37-39`** `region_suffix(&self) -> Option<String>` clones per call. Return `Option<&str>`.
- [x] **S — `store.rs:32-38`** `InMemoryStore` key collision on `{Created, Len}` silently overwrites. — *fixed in `8f458a9`; added internal `AtomicU64` counter so each `store()` call gets a unique `{Created, Len, Seq}` key.*
- [ ] **S — `metastore_postgres.rs:239`** `std::thread::sleep` up to 320 ms on blocking pool worker; consider Condvar.
- [ ] **S — `metastore_dynamodb.rs:112`** Owns a `tokio::runtime::Runtime` even on async-only path.
- [ ] **S — All metastores** `log::debug!` only; no `tracing` spans for distributed traces.

## KMS adapters

- [x] **B — `kms_aws.rs:108-112`, `kms_aws_envelope.rs:174-180`** Fallback path constructs fresh `tokio::runtime::Runtime` per call; ms overhead and FD/thread exhaustion. — *fixed in `4d8f01c`; replaced with a process-wide `OnceLock`-backed fallback runtime; init failures surface as `anyhow::Error` instead of panic.*
- [ ] **B — `kms_aws.rs:122,148`, `kms_aws_envelope.rs:194-219, 283`** Plaintext data keys wrapped in `Blob::new(Vec)`/`as_ref().to_vec()` with no zeroize path. — *unfixable from outside the AWS SDK; `Blob::new` consumes the Vec and the SDK does not expose a wipe hook.*
- [ ] **B — `kms_aws_envelope.rs:240-313`** Multi-region decrypt loop has no integrity binding between envelope's `arn` and used `RegionalKek`. — *deferred (needs envelope-format change to bind region to ciphertext).*
- [x] **B — `kms_secrets_manager.rs:18`** `master_key: Vec<u8>` plaintext, never wiped, `Clone` produces additional un-wiped copies. — *fixed in `40d3ee2`; now `Arc<Zeroizing<Vec<u8>>>` with manual `Clone`.*
- [x] **B — `kms.rs:11`** `StaticKMS::master_key` same shape as above. — *fixed in `40d3ee2`.*
- [x] **B — `kms_vault_transit.rs:26`** `token: String` cached for process life; no zeroize. — *partial in `40d3ee2`; token wrapped in `Arc<Zeroizing<String>>` so drop wipes. TTL/renewal gap is left as a documented follow-up — refresh requires per-auth-method plumbing.*
- [x] **B — `kms_vault_transit.rs:386-413, 446-474`** Never inspects `resp.status()` before `.json()`. — *fixed in `40d3ee2`; both encrypt and decrypt paths check `resp.status()` first and bail with a UTF-8-safe truncated body snippet.*
- [ ] **B — `kms_vault_transit.rs:370-371,397-398,430-431,458-459`** `{e:#}` logs full reqwest chain; `error!` on decrypt failures. — *deferred (low-priority; the chain is informational and Vault errors don't leak ciphertext).*
- [x] **B — `kms_secrets_manager.rs:118-126`** Hex decode hand-loop. — *fixed in `2e9d2e5`; tolerates `0x`/`0X` prefix and arbitrary whitespace; intermediate decode buffer is `Zeroizing` so a partial decode error doesn't leave key bytes in the heap.*
- [ ] **B — `kms_aws_envelope.rs:122,156`** `new_*_async` allocates Runtime even when sync path never used. — *deferred (low-impact optimization).*
- [ ] **S — `aead.rs:141`** AEAD uses `Aad::empty()`; document intentional cross-language compatibility.
- [x] **S — `kms_vault_transit.rs:383,443`** No validation of `vault:v` prefix on round-trip. — *fixed in `2e9d2e5`; both sync and async decrypt reject ciphertexts that don't start with `vault:v` early.*
- [x] **S — `kms_aws.rs:117,139`** `log::debug!` includes KMS key ARN. — *fixed in `2e9d2e5`; new `redact_arn` helper replaces the account-id segment with `***` for all log!/anyhow! sites.*
- [x] **S — `kms_multi.rs:62-73`** Blindly retries every backend on any error. — *fixed in `2e9d2e5`; `is_terminal_kms_error` heuristic short-circuits on AccessDenied / NotAuthorized / DisabledException / InvalidCiphertextException.*
- [ ] **S — `traits.rs:11-12`** `KeyManagementService` uses `&()` as context placeholder; consider real `KmsContext`.
- [x] **S — `kms_vault_transit.rs:92-94`** PEM body Vec not wiped. — *fixed in `2e9d2e5`; both the key-PEM bytes and the spliced cert+key buffer are wrapped in `Zeroizing`.*
- [x] **S — `kms_aws_envelope.rs:241-243`** `serde_json` errors with `{e}` include offending input snippet. — *fixed in `2e9d2e5`; user-facing error is now generic, full chain still goes to operator logs.*
- [ ] **S — `kms_builders.rs:71`** `MultiKms::new` builds 5 runtimes for 5 regions; share or use envelope.

## Server / logging / metrics

- [x] **B — `asherah-server/src/main.rs:174-175`** Sync `factory_from_config` blocks Tokio main thread. — *fixed in `384c439`; wrapped in `tokio::task::spawn_blocking`.*
- [x] **B — `asherah-server/src/service.rs:77`** Sync `s.close()` on Tokio worker. — *fixed in `384c439`; close runs in `spawn_blocking` via the spawned session task.*
- [x] **B — `asherah-server/src/main.rs:226-237`** Drain timeout `select!` drops server future. — *fixed in this commit; per-session tasks are tracked in a shared `Arc<Mutex<JoinSet<()>>>`. Shutdown signal is observed inside the per-session select! loop so streams break out, drop their response sender, and run `s.close()` on the blocking pool. After the server future resolves (or hits the deadline) `main.rs` `join_next()`s the set to drain `close()`s, force-cancelling stragglers via `JoinSet::shutdown()` past the deadline.*
- [x] **B — `asherah-server/src/main.rs:266`** `signal(SignalKind::terminate()).expect(...)`. — *fixed in `384c439`; `shutdown_signal()` returns `io::Result<()>` and the caller logs registration failures.*
- [ ] **B — `asherah-server/src/main.rs:181-202, 244-256`** `std::fs::symlink_metadata`/`remove_file` on Tokio runtime; should use `tokio::fs`. — *deferred (acceptable at startup/shutdown; mostly cosmetic).*
- [x] **B — `asherah-server/src/service.rs:55,57-81`** Spawned session task detached with no JoinHandle. — *fixed in this commit; tasks are now spawned into the shared `JoinSet`, see the drain-timeout entry above.*
- [x] **B — `logging.rs:182`, `metrics.rs:210`** `.expect("spawn worker")` aborts cdylib-loaded process on EAGAIN. — *fixed in earlier commit; `AsyncLogSink::new`/`AsyncMetricsSink::new` now return `std::io::Result<Self>`. `asherah-ffi/src/hooks.rs` falls back to synchronous dispatch on dispatcher-spawn failure; tests pass `.expect()` because the test runtime always has spare threads.*
- [x] **B — `metrics.rs:48,54`** `if let Ok(mut guard) = SINK.write()` swallows lock poisoning permanently. — *fixed in `96d8802`; both `set_sink` and `clear_sink` recover via `poisoned.into_inner()` (safe because they always overwrite the value) and emit a warn log.*
- [x] **S — `asherah-server/src/service.rs:97`** No length/charset validation on client-supplied `partition_id`. — *fixed in `2467d97`; 256-byte cap and control-character rejection.*
- [x] **S — `asherah-server/src/service.rs:113,129`** `e.to_string()` returns full anyhow chain over the wire. — *fixed in `2467d97`; `sanitize_error` logs the full chain at warn level and ships only the top-level summary.*
- [x] **S — `asherah-server/src/main.rs:222`** `drop(shutdown_rx.changed().await)` discards `Result`. — *fixed in `5c188d4`; both the serve_with_incoming_shutdown future and the drain branch now log `RecvError` at warn level so unexpected channel closure is visible.*
- [ ] **S — `logging.rs:78-80`** `log::max_level = Trace` whenever any subscriber registers; defeats subscribers wanting `Warn`.
- [x] **S — `logging.rs:48-56`** `ensure_logger` returns `Result` but cannot fail. — *fixed in `c855fb2`; doc comment now states the function is effectively infallible. Signature kept for source compatibility.*
- [ ] **S — `logging.rs:159`, `metrics.rs:188`** Worker `JoinHandle` never joined in `Drop`; worker panics lost.
- [ ] **S — `metrics.rs:45, 67-72`** Inconsistent `std::sync::RwLock` (metrics) vs `parking_lot::RwLock` (logging); user closure runs holding the read lock.
- [ ] **S — `metrics.rs:75-97`** `Relaxed` ordering on `count` and `total_ns` allows reader to undercount average.
- [ ] **S — `asherah-server/src/main.rs:31, 39, 89`** `value_parser` with string array; use typed enum.
- [x] **S — `asherah-server/src/lib.rs:19-34`** `parse_go_duration` rejects compound durations. — *fixed in `2467d97`; full Go-style compound parsing (`1h30m`, `2h45m30s`) with overflow checks and unit tests.*
- [ ] **S — `asherah-server/src/convert.rs:7, 20`** `proto_to_drr` populates `id: String::new()`/`revoked: None`; document this is deliberate parity with Go server.
- [ ] **S — `asherah-server/src/main.rs:208`** `verbose` mode emits per-request partition ID logs; tenant identifier exposure.
- [x] **S — `api.rs:22-25`** `FactoryOption::SecretFactory` is a no-op. — *fixed in `2fc2464`; variant marked `#[doc(hidden)]`, enum is now `#[non_exhaustive]`, and the doc comment explains both variants and the Go-API parity rationale.*

## Language bindings

### Python
- [x] **B — `asherah-py/src/lib.rs:121-145, 320-341`** Sync `encrypt_bytes`/`decrypt_bytes` hold the GIL across DB I/O. — *fixed in `d7663b3`; `py.detach(|| session.encrypt/decrypt(...))` wraps the blocking work on every sync entry point.*
- [x] **B — `asherah-py/src/lib.rs:135-144, :175, :329, :359`** Plaintext `bytes`/`pt` Vec dropped un-wiped after `PyBytes::new` copy. — *fixed in `6f12e82`; intermediate `Vec<u8>` plaintext is wrapped in `zeroize::Zeroizing` so the Rust-side buffer is overwritten the moment the Python copy completes (or an early return aborts the path). Once the bytes land in `PyBytes`/`str` they're in Python's heap and not wipable from Rust.*

### Ruby
- [x] **B — `asherah-ruby/lib/asherah/native.rb:79-80`** `attach_function` lacks `blocking: true`. — *fixed in `d7663b3`; `blocking: true` added to factory_new_*, apply_config_json, encrypt/decrypt, and the async-enqueue twins.*
- [ ] **B — `asherah-ruby/lib/asherah/session.rb:38-44, 49-55`** Thread-local `AsherahBuffer` reuse without `begin/ensure`. — *deferred (Ruby-side change; needs Ruby maintainer review).*
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
- [x] **B — `asherah-node/src/lib.rs:347-407`** Sync `encrypt`/`decrypt` are plain `#[napi]`, run on libuv main thread. — *partial in `d7663b3`; the .d.ts now documents the event-loop block and points to `encryptAsync`/`decryptAsync`. Changing the sync return type to `Promise` would break the published TS contract; not done.*
- [ ] **S — `asherah-node/src/lib.rs:659, 684, 756, 786`** Two `transmute::<Function<'_>, Function<'static>>`; latent UAF if V8 isolate torn down before `clear_log_hook` fires.

### Cross-binding
- [ ] **S — All bindings** Language-side plaintext copy (Go `dst`, .NET `Marshal.Copy`, Java `byte_array_from_slice`, Ruby `read_bytes`, Py `PyBytes::new`, Node `Buffer::from`) never wiped after `asherah_buffer_free` zeroes the native side. False sense of containment. Document or expose `decrypt_into(*mut u8, capacity)`.
- [ ] **S — PyO3 / napi / JNI** `catch_unwind` discipline absent on language-binding entry points; `tokio::spawn` futures inside those bindings can panic across language boundary.

## Tests / fuzz

- [ ] **B — Memguard tests** No test exercises `Buffer::destroy` returning `Error::CanaryFailed` (the canary-corruption branch).
- [ ] **B — `fuzz/fuzz_targets/cobhan_buffer.rs:11-61`** Fuzz target reimplements parsing logic in safe Rust and tests *that*, not the unsafe FFI.
- [x] **B — `asherah-cobhan/tests/integration_tests.rs:1404`** No null-pointer FFI tests; `Encrypt`/`Decrypt`/`EncryptToJson`/`DecryptFromJson` not exercised with `null` inputs. — *fixed in pending commit; new `test_null_pointer_inputs_impl` exercises every pointer position on `EncryptToJson`/`DecryptFromJson`/`Encrypt`, asserting `ERR_NULL_PTR`.*
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

- [x] **B — `.github/workflows/publish-server.yml`** No `concurrency:` group (CLAUDE.md hard rule). — *fixed in pending commit; group keyed by release tag (or branch for manual dispatch).*
- [x] **B — `.github/workflows/release-cobhan.yml`** No `concurrency:` group. — *fixed in pending commit; group keyed by release tag.*
- [x] **B — `.github/workflows/publish-maven.yml`** Missing top-level `permissions: { contents: read }`. — *fixed in pending commit.*
- [x] **B — `.github/workflows/publish-nuget.yml`** Missing top-level `permissions: { contents: read }`. — *fixed in pending commit.*
- [x] **B — `publish-npm.yml:137-153` vs `ci.yml` dry-runs** Windows builds: publish omits `OPENSSL_STATIC=1`, dry-runs set it. CLAUDE.md says these MUST match exactly. — *fixed in pending commit; both x86_64 and aarch64 Windows builds in `publish-npm.yml` now `export OPENSSL_STATIC=1` to match the `vcpkg static-md` triplet and the dry-run config.*
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

- [~] **Plaintext-on-heap leakage** — sync FFI was fixed in #216. Async FFI (`asherah-ffi/src/lib.rs:543`) closed in `6b70f02`. AWS KMS plaintext data-key copies are unfixable from outside the SDK. The 5 language-binding decrypt sites (Py/Node/Java/Go/.NET) still keep an unwiped managed-side copy after the native buffer is freed; tracked as a cross-binding follow-up.
- [ ] **`catch_unwind` discipline** — present on every `extern "C"` in asherah-ffi/cobhan, **absent** on PyO3, napi-rs, and JNI binding entry points. — *deferred (per-binding mechanical work).*
- [x] **Insecure defaults** — `KMS=static` empty key fixed in `29e45e9`; HashMap region-iteration ordering fixed in `cdba397`. Default `Simple` cache policy + `max > 0` now logs a warning at construction (`7dad394`). DynamoDB `region_suffix=true` without a resolved region now bails (`84b7585`).
- [~] **`expect()` on init paths** — closed in `4d8f01c` for ASYNC_RT, both KMS `block_on_maybe`/`unreachable!()` paths, and the signal-handler thread. Server `signal()` registration handled in `384c439`. SLAB `Lazy::new` (memguard.rs:653) and `logging.rs:182` / `metrics.rs:210` worker-spawn `expect`s remain deferred — making them fallible requires propagating `Result` through every call site or a public-API change to the constructor signatures.
- [x] **GIL/GVL/event-loop blocking on sync entry points** — Python `py.detach`, Ruby `blocking: true`, Node sync API documented (`d7663b3`).
- [x] **Cached secrets without zeroize** — StaticKMS, SecretsManagerKMS master keys, and Vault Transit token now wrapped in `Zeroizing` (`40d3ee2`). AWS KMS plaintext data-key copies remain unfixable from outside the SDK.

---

## Recommended fix order

Items already addressed are crossed out; the remainder are still open.

1. ~~T1 — silent static-key fallback.~~ — `29e45e9`
2. ~~T3 — `pub mod memguard`.~~ — `5944736`
3. ~~T2 — `PoolSlot Send` soundness (transient tracking + SAFETY rewrite + Send-test).~~ — `cd56ccc`
4. ~~T5 — sync GIL/GVL/event-loop blocking (Python, Ruby, Node).~~ — `d7663b3`
5. ~~Plaintext-leak variant in async FFI `asherah-ffi/src/lib.rs:543`.~~ — `6b70f02`
6. ~~T8 — server factory init + shutdown.~~ — `384c439`
7. ~~T7 — Postgres SQL string interpolation.~~ — `4c2ac6b`
8. ~~T11 — region map non-deterministic ordering.~~ — `cdba397`
9. ~~T9 — Unix socket permissions.~~ — `276e375`
10. ~~T10 — MySQL pool underflow.~~ — `ea2ebd5`
11. ~~T6 — DynamoDB Debug-text matching.~~ — `e23bde4`
12. ~~T4 — three `expect()` paths violating PR #218 policy.~~ — `4d8f01c` (SLAB Lazy::new deferred)
13. ~~Memguard/memcall safety batch (overflow, SAFETY, AtomicUsize, madvise, protect-before-wipe).~~ — `274976a`
14. ~~Core session/cache batch (TTL=0, DRK wipe, IK-cache close).~~ — `7dad394`
15. ~~Cobhan/FFI batch (SetEnv, transmute, error codes, poisoned locks).~~ — `b90d1c4`
16. ~~Metastore batch (InMemory race, postgres pool guard, DDB region+base64).~~ — `84b7585`
17. ~~KMS batch (master-key zeroize, Vault token zeroize, Vault HTTP status check).~~ — `40d3ee2`
18. ~~Server S-tier (partition_id validation, error sanitization, compound durations).~~ — `2467d97`
19. ~~Misc S-tier (logging, session_cache, postgres, hooks).~~ — `c855fb2`
20. ~~KMS+pool S-tier (ARN redact, prefix validation, terminal-error short-circuit, reaper notify-then-wait race).~~ — `2e9d2e5`
21. ~~Metastore S-tier (parse_item enforcement, InMemoryStore unique keys).~~ — `8f458a9`
22. ~~Cobhan/server S-tier (EstimateBuffer, channel-close logging).~~ — `5c188d4`
23. ~~Memguard/metrics/hooks S-tier (panic-safe Enclave drop, metrics poison recovery, log fast-path probe).~~ — `96d8802`
24. ~~api.rs FactoryOption::SecretFactory doc-hidden.~~ — `2fc2464`
25. ~~Cache atomic ordering + memguard nonce prefix randomization.~~ — `69467ec`
26. ~~Legacy `Session::encrypt` race-loss recovery.~~ — `8d85a6b`
27. ~~Server graceful drain via JoinSet (no more abandoned in-flight `close()` calls).~~ — `0610f1d`
28. ~~Python binding decrypt path: intermediate `Vec<u8>`s wrapped in `Zeroizing`.~~ — `6f12e82`
29. ~~SessionFactory fields tightened from `pub` to `pub(crate)`.~~ — pending commit

## Open follow-ups (not addressed in this branch)

These need design work, affect public API, or require benchmarking, and
are deliberately deferred:

**Memguard / core**
- ~~**session.rs:16-27/config.rs/types.rs** — public field encapsulation~~ — partial (see B-tier note above): `SessionFactory` fields are now `pub(crate)`; `Config` and `EnvelopeKeyRecord.id` stay `pub` for ABI/builder reasons.

**KMS / metastore**
- **kms_aws_envelope.rs:240-313** — multi-region decrypt integrity binding (envelope format change)
- **kms_aws.rs / kms_aws_envelope.rs** — `Blob::new(plaintext)` SDK exposure (unfixable from outside)
- **kms_aws_envelope.rs new_*_async** — runtime allocation when sync path never used
- **metastore_postgres.rs created-as-f64 / JSON double-parse** — broke driver compat in test
- **metastore_postgres.rs** — `std::thread::sleep` exhaustion backoff (Condvar wakeup)
- **metastore_dynamodb.rs** — private runtime allocation in async constructor
- **metastore_region.rs** — `region_suffix` trait `Option<String>` → `Option<&str>`

**Server**
- **asherah-server/src/main.rs typed enums** — clap `value_parser = ["..."]` → typed enums

**Bindings / FFI**
- ~~**asherah-py/src/lib.rs:135-144** — language-binding plaintext copies~~ — fixed in pending commit; intermediate `Vec<u8>`s are wrapped in `Zeroizing` so `PyBytes::new` copies into Python and the Rust-side buffer wipes on drop. Python `str` returned by `decrypt_text` is unwipable by design (Python heap).
- **asherah-ruby/lib/asherah/session.rb:38-44** — thread-local AsherahBuffer reuse: the FFI buffer's metadata is reused per thread but `asherah_buffer_free` zeroizes the data Vec via `zeroize::Zeroize` before freeing, so plaintext bytes are wiped at the Rust boundary. The Ruby `String` produced by `read_bytes` lives in Ruby's heap and is not wipable.
- **Java / .NET bindings** — once plaintext lands in a managed `byte[]`/`byte[]` the GC owns it; deterministic wipe is not possible without unsafe pointer access. The Rust-side FFI buffer is wiped on free.
- ~~**asherah-cobhan/src/lib.rs:355-363** — Setup→Shutdown→Setup test gap~~ — already covered by `test_shutdown_and_reinitialize_impl` in `asherah-cobhan/tests/integration_tests.rs:1282`, invoked from the main `test_full_encryption_workflow` so it runs in CI on every PR. The test exercises Setup → Shutdown → Setup → encrypt → Shutdown → Setup → encrypt → decrypt → Shutdown — i.e., two complete lifecycle cycles plus a final tear-down — proving the global `FACTORY` and `ESTIMATED_INTERMEDIATE_KEY_OVERHEAD` reset is sound across multiple Setup/Shutdown pairs.
- ~~**PyO3/napi-rs/JNI `catch_unwind` discipline**~~ — audited; all bindings already panic-safe at their FFI boundaries: `asherah-ffi` and `asherah-cobhan` wrap every `extern "C"` entry in `std::panic::catch_unwind` (12/13 in `asherah-ffi/src/lib.rs`, 7/8 in `asherah-cobhan/src/lib.rs` — the one exception in each is a no-op math entry that can't panic). `asherah-java` uses `jni::EnvUnowned::with_env`, which internally wraps the closure in `catch_unwind` and surfaces panics via `EnvOutcome::Panic`. PyO3's `#[pyfunction]`/`#[pymethods]` and napi-rs's `#[napi]` macros both auto-wrap their entry functions in `catch_unwind`.
- **kms_secrets_manager.rs:118-126 SDK plaintext leak** — partial; hex decode now Zeroizing but the SDK's secret_string copy still flows through unwiped Vec.

**Tests / fuzz**
- Memguard canary corruption regression test
- Cross-language ciphertext fixtures vs. canonical Go
- Cobhan-real-FFI fuzz target (the existing target re-implements parsing in safe Rust)
- Wycheproof / NIST KAT vectors for AEAD
- Plaintext-zeroization-on-drop sentinel scan

Most of these need either a coordinated multi-binding change, an
API-breaking signature update, a benchmark-and-validate cycle per
CLAUDE.md's perf rules, or new integration tests. They're tracked here
so the next pass can pick them up without re-deriving the analysis.
