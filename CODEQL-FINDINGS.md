# Security & Quality Findings

All open findings from GitHub security tooling as of 2026-03-25. Includes
CodeQL code scanning, Dependabot vulnerability alerts, and Copilot AI findings.
Some may not be appropriate to fix due to interop compatibility requirements
with the canonical GoDaddy Asherah SDK.

No secret scanning alerts. No security advisories.

---

## Dependabot Vulnerability Alerts — 7 open

### CRITICAL

1. **Alert #44** — `google.golang.org/grpc` in `benchmarks/grpc-bench/go.mod`
   - **gRPC-Go authorization bypass via missing leading slash in :path**
   - Vulnerable: < 1.79.3
   - Fix: update grpc dependency

### HIGH

2. **Alert #34** — `aws-lc-sys` in `Cargo.lock`
   - **AWS-LC X.509 Name Constraints Bypass via Wildcard/Unicode CN**
   - Vulnerable: >= 0.32.0, < 0.39.0
   - Fix: `cargo update -p aws-lc-sys`

3. **Alert #37** — `aws-lc-sys` in `Cargo.lock`
   - **CRL Distribution Point Scope Check Logic Error in AWS-LC**
   - Vulnerable: >= 0.15.0, < 0.39.0
   - Fix: `cargo update -p aws-lc-sys`

4. **Alert #45** — `aws-lc-sys` in `fuzz/Cargo.lock`
   - Same as #34 but in fuzz lockfile
   - Fix: `cd fuzz && cargo update -p aws-lc-sys`

5. **Alert #46** — `aws-lc-sys` in `fuzz/Cargo.lock`
   - Same as #37 but in fuzz lockfile
   - Fix: `cd fuzz && cargo update -p aws-lc-sys`

### MEDIUM

6. **Alert #40** — `rustls-webpki` in `Cargo.lock`
   - **webpki: CRLs not considered authoritative by Distribution Point due to faulty matching logic**
   - Vulnerable: >= 0.101.0, < 0.103.10
   - Fix: `cargo update -p rustls-webpki`

7. **Alert #47** — `rustls-webpki` in `fuzz/Cargo.lock`
   - Same as #40 but in fuzz lockfile
   - Fix: `cd fuzz && cargo update -p rustls-webpki`

**Notes:** Alerts #34, #37, #40 can likely all be fixed with a single `cargo update`. The fuzz lockfile needs a separate update. The gRPC alert (#44) is in a benchmark project only — not production code — but should still be updated.

---

## ACCESS OF INVALID POINTER (Rust) — 2 findings — SEVERITY: ERROR

> Dereferencing a pointer that may be invalid.

### asherah-node/src/lib.rs

1. **Alert #34, Line 321** — Access of invalid pointer
2. **Alert #35, Line 380** — Access of invalid pointer

**Notes:** These are severity ERROR — the highest priority findings. Need to inspect the actual code to understand if these are real unsafe pointer bugs or false positives from CodeQL's Rust analysis.

## Disabled TLS certificate check (Rust) — 3 findings — SEVERITY: WARNING

> TLS certificate verification is disabled, allowing man-in-the-middle attacks.

### asherah/src/metastore_postgres.rs

1. **Alert #36, Line 107** — Disabled TLS certificate check
2. **Alert #37, Line 106** — Disabled TLS certificate check
3. **Alert #38, Line 115** — Disabled TLS certificate check

**Notes:** This is the Postgres metastore TLS configuration. May be intentional for dev/test environments or when using custom CAs. Should at minimum be behind a config flag, not unconditional.

## Missing workflow permissions (Actions) — 6 findings — SEVERITY: WARNING

> Workflow does not contain permissions.

1. **Alert #11** — `release-cobhan.yml` line 23 (build job)
2. **Alert #13** — `test-runner.yml` line 8
3. **Alert #14** — `test-runner.yml` line 13
4. **Alert #20** — `release-cobhan.yml` line 302 (show-urls job)
5. **Alert #46** — `benchmark-setup.yml` line 13
6. **Alert #50** — `release-cobhan.yml` line 217 (package job)

**Notes:** Add `permissions: contents: read` to these jobs/workflows. Same issue we've fixed elsewhere.

---

## Standard CodeQL Findings (from web UI)

## Useless parameter (Java) — 7 findings

> Parameters that are not used add unnecessary complexity to an interface.

All in the canonical compatibility API layer (`asherah-java/java/src/main/java/com/godaddy/asherah/appencryption/persistence/`).

### Metastore.java

1. **Line 15** — `Metastore<V>` interface: `load(String keyId, Instant created)` — parameters flagged as unused
2. **Line 17** — `loadLatest(String keyId)` — parameter flagged as unused
3. **Line 19** — `store(String keyId, Instant created, V value)` — parameters flagged as unused (appears 3 times in findings, likely for each parameter)

### Persistence.java

6. **Line 25** — `generateKey(final T value)` — `value` parameter flagged as unused. Already has `@SuppressWarnings("unused")` with comment: "value available for subclass overrides to generate content-based keys"

**Notes:** These are interface/abstract methods in the canonical compatibility layer. The parameters define the contract — implementations are expected to use them. This is a false positive for interface method signatures.

## Path.Combine may silently drop earlier arguments (C#) — 4 findings

> `Path.Combine` may silently drop its earlier arguments if its later arguments are absolute paths.

### RoundTripTests.cs

1. **Line 26** — `Path.Combine(root, "target", "debug")` — `root` could be dropped if `"target"` were absolute
2. **Line 403** — `Path.Combine(dir.FullName, "Cargo.toml")` — `dir.FullName` could be dropped if `"Cargo.toml"` were absolute

### NativeLibraryLoader.cs

3. **Line 75** — `Path.Combine(root, GetPlatformLibraryName())` — `root` could be dropped if platform lib name were absolute

### benchmarks/dotnet-bench/Program.cs

4. **Line 65** — `Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", nativePath)` — earlier args could be dropped if `nativePath` is absolute

**Notes:** These are all using string literals or controlled values as later arguments, so the "absolute path silently drops" behavior can't actually occur. Likely false positives, but could add `Path.GetFullPath()` guards if desired.

## Missing Override annotation (Java) — 3 findings

> A method that overrides a method in a superclass but does not have an `@Override` annotation cannot take advantage of compiler checks, and makes code less readable.

### SessionFactoryCompatTest.java

All 3 findings are in the same anonymous `Metastore<JSONObject>` implementation at lines 189-191:

1. **Line 189** — `load(String k, Instant c)` missing `@Override`
2. **Line 190** — `loadLatest(String k)` missing `@Override`
3. **Line 191** — `store(String k, Instant c, JSONObject v)` missing `@Override`

**Notes:** Straightforward fix — add `@Override` to all three methods in the anonymous class.

## Unused variable, import, function or class (JavaScript) — 3 findings

> Unused variables, imports, functions or classes may be a symptom of a bug and should be examined carefully.

### asherah/cucumber/js/gen.js

1. **Line 9** — `const fs = require('fs')` — `fs` is imported but never used
2. **Line 36** — `function hexToBytes(hex)` — function defined but never called

### interop/interop.js

3. **Line 53** — `function toHex(buf)` — function defined but never called

**Notes:** Easy fixes — remove unused imports and dead functions.

## Generic catch clause (C#) — 2 findings

> Catching all exceptions with a generic catch clause may be overly broad, which can make errors harder to diagnose.

### Asherah.cs

1. **Line 75** — Bare `catch` (no exception type) swallowing errors during `session.Dispose()` in shutdown. Comment says `// ignore`.

### NativeLibraryLoader.cs

2. **Line 44** — `catch (Exception ex)` wrapping `NativeLibrary.Load()` — catches all exceptions and rethrows as `AsherahException`.

**Notes:** The Asherah.cs one is intentional — dispose during shutdown shouldn't throw. Could narrow to `catch (Exception)` for clarity. The NativeLibraryLoader.cs one is wrapping a platform call where the exception type isn't predictable (could be DllNotFoundException, BadImageFormatException, etc.) — catching broad and re-wrapping is reasonable here.

## Missed 'readonly' opportunity (C#) — 2 findings

> A private field where all assignments occur as part of the declaration or in a constructor in the same class can be `readonly`.

### AsherahFactory.cs

1. **Line 8** — `private SafeFactoryHandle _handle` — only assigned in constructor, should be `readonly`

### AsherahSession.cs

2. **Line 9** — `private SafeSessionHandle _handle` — only assigned in constructor, should be `readonly`

**Notes:** Straightforward fix — add `readonly` to both fields.

## Missed 'using' opportunity (C#) — 2 findings

> C# provides a `using` statement as a better alternative to manual resource disposal in a `finally` block.

### RoundTripTests.cs

1. **Line 134** — `IAsherahFactory factory = Asherah.FactoryFromEnv()` in try/finally instead of `using`
2. **Line 137** — `IAsherahSession session = factory.GetSession(...)` in nested try/finally instead of `using`

**Notes:** Straightforward fix — replace try/finally with `using` statements.

## Missed opportunity to use Where (C#) — 1 finding

> The intent of a foreach loop that implicitly filters its target sequence can often be better expressed using LINQ's `Where` method.

### benchmarks/dotnet-bench/Program.cs

1. **Line 62** — `foreach` over candidate paths with `if (Directory.Exists(candidate))` filter + `break` could be expressed as LINQ `.Where(...).FirstOrDefault()`.

**Notes:** This is a benchmark setup helper with 2 candidates and a break. LINQ would obscure the intent. Low priority / skip.

## Unused import (Python) — 1 finding

> Import is not required as it is not used.

### interop/tests/test_py_node_rust.py

1. **Line 8** — `import sys` — imported but never used

**Notes:** Easy fix — remove the import.

## Copilot AI Findings — 14 findings in 5 files

These are from Copilot code scanning (AI-powered), not standard CodeQL rules.

### SessionFactoryCompatTests.cs — 2 findings

1. **Static constructor sets environment variable** — `static SessionFactoryCompatTests()` sets `STATIC_MASTER_KEY_HEX` as a side effect. Copilot suggests using per-test setup/teardown for test isolation and parallel safety. Suggests `SetStaticMasterKeyHexForTest()` / `RestoreStaticMasterKeyHex()` pattern with try/finally.

2. **Hardcoded static master key** — `"thisIsAStaticMasterKeyForTesting"` used across multiple tests. Copilot suggests extracting to `private const string TestStaticMasterKey` and notes it should never be used in production.

**Notes:** Both are test-only code. The static constructor side effect is a valid concern for parallel test execution. The hardcoded key is intentional for testing — it's the same key the canonical GoDaddy SDK uses in its tests.

### asherah-ruby/test/round_trip_test.rb — 2 findings

1. **Missing large payload upper bound test** — Tests cover 1MB but nothing for 10MB+ or error handling at extreme sizes. Copilot suggests adding a 10MB test and/or documenting max supported payload size.

2. **Concurrent test doesn't test shared partition** — Each thread uses a different partition ID (`concurrent-0`, `concurrent-1`, etc.), so it doesn't actually test concurrent access to the same session/partition. Copilot suggests adding a test where multiple threads share the same `partition_id`.

**Notes:** Both are reasonable test coverage suggestions. The concurrent same-partition test would be valuable for verifying thread-safety of session caching.

### benchmarks/ruby-bench/bench_ffi.rb — 3 findings

1. **Duplicated MySQL URL validation** — The `mysql_url` fetching and validation logic is copy-pasted across hot, warm, and cold modes. Copilot suggests extracting into a `configure_mysql_for_mode!` helper.

2. **Potential race condition on `enc_idx`/`dec_idx`** — Counter variables initialized in `SIZES.each` loop and incremented inside `Benchmark.ips` blocks. If the benchmark framework runs iterations concurrently, non-atomic read-modify-write could race. Copilot suggests using `Enumerator#cycle` with `.next` instead.

3. **Same `enc_idx`/`dec_idx` race condition (duplicate)** — Second finding for the same issue, specifically calling out lines 87-88. Suggests using block-local variables (`enc_idx_local`) scoped inside the `x.report` block.

**Notes:** The MySQL dedup is a valid maintainability fix. The race condition is theoretical — Ruby's GIL prevents true parallel execution in MRI, and `benchmark-ips` runs iterations sequentially. But the `.cycle.next` pattern is cleaner regardless.

### scripts/maturin-before-script-linux.sh — 2 findings

1. **Architecture fallback assumes aarch64** — `if [ "$MUSL_ARCH" = "x86_64" ]; then ARCH=x86_64; else ARCH=aarch64; fi` silently treats any non-x86_64 architecture (armv7, i686, riscv64) as aarch64. Copilot suggests using a `case` statement with explicit error for unsupported architectures.

2. **Sources script without existence check** — `source "${GITHUB_WORKSPACE:-$(pwd)}/scripts/download-musl-openssl.sh"` will fail with an unclear error if the file is missing. Copilot suggests checking `-f` before sourcing and providing a clear error message.

**Notes:** Both are reasonable defensive improvements. We only target x86_64 and aarch64 so the fallback is currently safe, but an explicit case statement is more correct. The existence check is good practice for sourced scripts.

### scripts/test.sh — 5 findings

1. **Missing `-e` flag in `set -uo pipefail`** — Without `-e`, the script continues executing when commands fail, which could mask errors. Copilot suggests `set -euo pipefail`.

2. **`summary` called inside `run_test` on failure causes early exit** — Calling `summary` after a fail (which exits when FAIL > 0) prevents subsequent tests from running, defeating the purpose of collecting multiple results. Copilot suggests removing `summary` from `run_test` and only calling it at the end.

3. **`tail -1` suppresses build errors** — `cargo build ... 2>&1 | tail -1` hides compilation errors and warnings. Copilot suggests removing the pipe or logging full output to a file.

4. **`PLATFORM` variable scoping** — `PLATFORM` is set but not exported. `do_sanitizers` uses it to construct the asan target triple. If called in a subshell, `PLATFORM` could be undefined, producing an invalid target like `-unknown-linux-gnu`. Copilot suggests passing it as a function parameter.

5. **Fuzz tests in `--all` mode undocumented** — `--all` includes fuzz tests with a 30-second default timeout, which may surprise users expecting a quick verification suite. Copilot suggests documenting this in the help text.

**Notes:** Finding 1 is wrong for a test runner — `set -e` would abort on the first test failure instead of collecting results. The script intentionally uses `set -uo pipefail` without `-e` because `run_test` handles failures itself. Finding 2 is a real issue if the intent is to run all tests before reporting. Finding 3 is valid — we should show full output on failure. Finding 4 is valid — passing as a parameter is safer. Finding 5 is a documentation nit.
