# PHP Binding Exploration

This note evaluates a PHP binding that lets PHP applications call Asherah
directly instead of running the gRPC sidecar. The recommended first
implementation is a Composer package backed by PHP's built-in FFI extension and
the existing `asherah-ffi` `cdylib`.

## Recommendation

Build `asherah-php` as a userland PHP package over `asherah-ffi`.

Do not start with a Zend extension. A Zend extension would avoid PHP FFI
deployment friction and may eventually be useful for very high-volume PHP-FPM
installations, but it would add C extension maintenance, PHP ABI/version
matrix testing, and more release machinery. The existing C ABI is already
designed for bindings, and PHP FFI can consume it with a thin wrapper.

The first release should be synchronous-first:

- `Asherah::setup(array|Config $config): void`
- `Asherah::shutdown(): void`
- `Asherah::encrypt(string $partitionId, string $payload): string`
- `Asherah::decrypt(string $partitionId, string $dataRowRecord): string`
- `Asherah::encryptString(...)` and `decryptString(...)` aliases
- `SessionFactory` and `Session` objects for explicit lifecycle control
- optional `Config` value object mirroring the Ruby and Go config keys

Defer native async callbacks, log hooks, and metrics hooks until the base
binding is proven. PHP supports callbacks through FFI, but PHP's own manual
warns they are not supported on every libffi platform, are inefficient, and
leak resources by the end of a request. Asherah's native async and hook APIs
invoke callbacks from Rust worker threads, which is a poor fit for typical PHP
request lifecycles and should not be the first surface area exposed.

## ABI Surface

The PHP binding can use the same C ABI consumed by Ruby, Go, .NET, and Java:

```c
typedef struct AsherahBuffer {
    uint8_t *data;
    size_t len;
    size_t capacity;
} AsherahBuffer;

const char *asherah_last_error_message(void);
void *asherah_factory_new_with_config(const char *config_json);
void *asherah_factory_new_from_env(void);
void asherah_factory_free(void *factory);
void *asherah_factory_get_session(void *factory, const char *partition_id);
void asherah_session_free(void *session);
int asherah_encrypt_to_json(void *session, const uint8_t *data, size_t len, AsherahBuffer *out);
int asherah_decrypt_from_json(void *session, const uint8_t *json, size_t len, AsherahBuffer *out);
void asherah_buffer_free(AsherahBuffer *buf);
```

The wrapper must always copy output bytes into a PHP string and then call
`asherah_buffer_free` in a `finally` block. The native buffer may contain
plaintext on decrypt and is zeroized by `asherah_buffer_free`.

The wrapper must read `asherah_last_error_message()` immediately after a failed
native call. The native last error is thread-local. PHP normally runs one
request on one OS thread in common SAPIs, but the wrapper should still avoid
any extra FFI calls between the failing call and the error read.

## Package Layout

Suggested package:

```text
asherah-php/
  composer.json
  src/
    Asherah.php
    Config.php
    Error.php
    Native.php
    Session.php
    SessionFactory.php
  native/
    linux-x64/libasherah_ffi.so
    linux-arm64/libasherah_ffi.so
    linux-musl-x64/libasherah_ffi.so
    linux-musl-arm64/libasherah_ffi.so
    darwin-x64/libasherah_ffi.dylib
    darwin-arm64/libasherah_ffi.dylib
    win-x64/asherah_ffi.dll
    win-arm64/asherah_ffi.dll
  tests/
```

`Native.php` should resolve the library in this order:

1. `ASHERAH_PHP_NATIVE`, either a file path or directory.
2. bundled platform-specific native library under `native/`.
3. development workspace `target/{release,debug}`.
4. system loader fallback by library name.

This mirrors the Ruby loader and keeps local development, CI, and packaged
installs predictable.

## PHP FFI Loading Modes

Support two modes:

- Development/CLI: call `FFI::cdef($cdef, $libraryPath)` dynamically. This
  requires `ffi.enable=true`.
- Production PHP-FPM: support `ffi.enable=preload` by shipping a preload file
  that initializes an `ASHERAH` FFI scope. Runtime code should first try
  `FFI::scope('ASHERAH')` and then fall back to `FFI::cdef`.

This matters because PHP's default `ffi.enable` is commonly `preload`, and
production systems often disable dynamic FFI creation during request handling.
The package should fail with an explicit diagnostic that names `ffi.enable`,
`opcache.preload`, and `ASHERAH_PHP_NATIVE` when FFI cannot be initialized.

## Public API Shape

Keep the surface close to Ruby and Go rather than exposing the C ABI:

```php
use GoDaddy\Asherah\Asherah;

Asherah::setup([
    'ServiceName' => 'my-service',
    'ProductID' => 'my-product',
    'Metastore' => 'memory',
    'KMS' => 'static',
]);

$ciphertext = Asherah::encryptString('tenant-123', 'secret');
$plaintext = Asherah::decryptString('tenant-123', $ciphertext);

Asherah::shutdown();
```

Also expose direct lifecycle control:

```php
$factory = SessionFactory::fromConfig($config);
$session = $factory->getSession('tenant-123');

try {
    $ciphertext = $session->encryptBytes($payload);
    $plaintext = $session->decryptBytes($ciphertext);
} finally {
    $session->close();
    $factory->close();
}
```

## Lifecycle And PHP-FPM

The static API should hold one native factory per PHP process, not per request,
when applications call `setup()` at framework boot. Session caching can be
implemented in PHP with a bounded LRU, using the existing `SessionCacheMaxSize`
config key as the bound. This matches the other bindings and avoids unbounded
native session handles in long-lived workers.

`shutdown()` must free all cached sessions before freeing the factory. Object
destructors can provide best-effort cleanup, but public `close()` and
`shutdown()` methods should be the documented contract because destructor timing
in PHP-FPM and fatal-error paths is not a good resource-management boundary.

For request-scoped usage, framework docs should recommend initializing at
worker/process boot where possible and only closing during worker shutdown.
Creating a factory per request may repeatedly initialize AWS SDK clients and
DB pools, which is likely worse than the sidecar for latency.

## Memory And Security Notes

PHP strings are immutable byte buffers from the application perspective and
cannot be reliably zeroized after use. The binding can ensure native buffers are
freed and wiped, but returned plaintext will live in PHP-managed memory until
the engine releases or reuses it. This limitation must be documented plainly.

The binding should preserve the existing input contract:

- `null` partition IDs, plaintext, and ciphertext are programmer errors.
- empty partition IDs are rejected.
- empty plaintext is valid and must still be encrypted.
- empty ciphertext is not valid DataRowRecord JSON and should fail.

Do not log plaintext, ciphertext, encrypted keys, raw config JSON, KMS ARNs, or
AWS SDK error chains from PHP. Surface the sanitized native top-level error
message.

## Multi-Region KMS And DynamoDB

The PHP binding should treat multi-region behavior as a pass-through contract
to the Rust core and should not reinterpret these fields:

- `RegionMap`
- `PreferredRegion`
- `KmsKeyId`
- `DynamoDBRegion`
- `DynamoDBSigningRegion`
- `DynamoDBTableName`
- `EnableRegionSuffix`
- `ReplicaReadConsistency`
- `AwsProfileName`

The config object should preserve PascalCase JSON names exactly and should not
sort, rewrite, infer, or drop region map entries. PHP associative arrays preserve
insertion order, but the Rust core now owns deterministic AWS region map
handling, so PHP should only serialize the user's map to JSON.

Tests should include config serialization cases for:

- two-region KMS `RegionMap` plus `PreferredRegion`;
- preferred region not first in input order;
- DynamoDB regional table suffix enabled;
- explicit `DynamoDBSigningRegion` differing from `DynamoDBRegion`;
- `AwsProfileName` included only when set.

End-to-end AWS tests should be opt-in and environment gated, matching the
other language bindings. Local unit tests should use memory metastore and
static KMS so they can run in normal CI.

## Tests

Minimum test suite:

- FFI loader resolution with `ASHERAH_PHP_NATIVE`.
- config normalization and JSON shape.
- static API setup/encrypt/decrypt/shutdown round trip.
- explicit `SessionFactory` and `Session` round trip.
- null/empty input contract.
- session cache bound and eviction closes evicted sessions.
- close/shutdown idempotence.
- native error propagation on bad config and invalid JSON.
- binary payload round trip, including embedded NUL bytes.
- preload-mode smoke test in a PHP CLI container with `ffi.enable=preload`.

Integration tests:

- `memory` + static KMS for all PRs.
- SQLite if PHP test containers can stage the native lib consistently.
- MySQL/Postgres/DynamoDB opt-in through environment variables.
- AWS KMS/DynamoDB multi-region tests opt-in and shared with the other
  language binding patterns.

## Release Work

Composer packaging is simpler than RubyGems/NuGet/npm for pure PHP code, but
native library distribution still has to line up with `release-cobhan.yml`.

Recommended release model:

1. Publish `godaddy/asherah` as the Composer package for PHP source,
   autoloading, tests, docs, and native-loader code.
2. Stage PHP-supported native libraries from the same `release-cobhan.yml`
   build outputs used by the other FFI bindings. Do not create an independent
   Rust build path for PHP.
3. Ship a `scripts/install_native.php` helper that downloads exactly one native
   library for the current platform from the matching Asherah release, verifies
   size/checksum metadata, and writes it under `native/<platform>/`.
4. Expose Composer script aliases such as `download-native` and
   `verify-native`, but document that Composer does not automatically run
   scripts from dependency packages during a consuming application's install.
   Consumers must either run the helper explicitly, add a root `post-install`
   / `post-update` hook, or use a prebuilt internal distribution artifact that
   already contains `native/<platform>/`.
5. Add CI dry-run jobs that install the Composer package from a staged artifact,
   run the native download/verify path, and execute PHP tests on Linux glibc
   and musl at minimum.

So yes, release download scripting needs to be solved before a real PHP release
unless we deliberately choose a fat Composer artifact containing every native
binary. A fat artifact gives the easiest install, but it bloats every deploy and
does not fit well with Composer installs from a monorepo source checkout. The
download helper matches `gd-auth-lib`'s practical approach while keeping
Asherah's native binaries tied to the existing release assets.

Windows support is feasible because PHP FFI can load DLLs, but it should be
validated explicitly before claiming support.

## Open Risks

- Production PHP-FPM deployments often restrict FFI. Preload support must be
  first-class, not an afterthought.
- Native callbacks from Rust worker threads are not a good initial fit for PHP.
  Avoid exposing async, log hooks, and metrics hooks until there is a tested
  callback strategy per SAPI.
- PHP plaintext copies cannot be deterministically wiped.
- Long-lived workers need bounded session caching and explicit shutdown hooks.
- Composer users expect simple installs; native library failures must produce
  precise, actionable diagnostics.

## Prototype Scope

This branch includes a small `asherah-php/` package with sync-only FFI calls,
Composer metadata, native artifact installation, PHP-FPM preload support,
PHPStan, PHP-CS-Fixer, PHPUnit, and Debian/Alpine PHP test containers. The
prototype validates pointer handling, buffer cleanup, binary strings, explicit
factory/session lifecycle, static API lifecycle, empty plaintext encryption,
native error propagation, native artifact checksum verification, and preload
scope loading without committing to callbacks or a Zend extension.

From `gd-auth-lib`, this branch adopts the useful operational pieces:

- Composer-native package metadata, autoloading, dev tools, and script entry
  points.
- Containerized PHP images that explicitly build and enable `ext-ffi`.
- Native library override through an environment variable for local and CI
  tests.
- A first-class native installer script that maps the current PHP platform to
  the existing `release-cobhan.yml` artifact names and verifies `SHA256SUMS`.
- PHPUnit tests that exercise the real Rust shared library through PHP FFI.

This branch intentionally skips the pieces that do not fit Asherah's current
C ABI:

- Dynamic-only `FFI::cdef()` loading. Asherah should support preload scope
  first, then fall back to dynamic loading for developer/test environments.
- Caller-owned Cobhan buffer output from PHP. The Asherah FFI already has a
  native-owned `AsherahBuffer` contract with an explicit free function, which is
  the safer boundary for variable-size ciphertext/plaintext results.
- Automatic dependency install hooks. Composer does not execute dependency
  package scripts during a consuming application's install, so applications
  must opt into a root hook or run the native installer explicitly.

The smoke and test paths currently run in Docker because the local Homebrew PHP
bottles on this machine hang during dynamic-loader startup. The tested path is:

```bash
docker build -t asherah-php-ffi-test \
  -f asherah-php/.Dockerfile.debian asherah-php

docker run --rm -v "$PWD":/work -w /work \
  -e CARGO_TARGET_DIR=/work/target-linux \
  rust:1.91-bookworm cargo build -p asherah-ffi

docker run --rm -v "$PWD":/work -w /work/asherah-php \
  asherah-php-ffi-test composer install --prefer-dist --no-progress

docker run --rm -v "$PWD":/work -w /work/asherah-php \
  -e ASHERAH_PHP_NATIVE=/work/target-linux/debug \
  asherah-php-ffi-test vendor/bin/phpunit --testdox --no-coverage

docker run --rm -v "$PWD":/work -w /work/asherah-php \
  -e ASHERAH_PHP_NATIVE=/work/target-linux/debug \
  asherah-php-ffi-test php -d ffi.enable=preload -d opcache.enable_cli=1 \
  -d opcache.preload=/work/asherah-php/preload.php \
  -r 'require "vendor/autoload.php"; GoDaddy\Asherah\Native::ffi();'
```
