# ExecPlan: Production PHP Language Binding

## Goal

Bring `asherah-php` from an exploration Composer package to a production-worthy,
merge-worthy PHP language binding with support and parity comparable to the
existing Node.js, Python, Java, .NET, Ruby, and Go bindings.

The finished binding should let PHP applications use Asherah directly through
the existing Rust C FFI library without requiring the gRPC sidecar. It should
feel natural to PHP developers, provide strong IDE/static-analysis support
where PHP allows it, support PHP-FPM preload deployments, and participate in
CI, release, packaging, interop, and documented operational workflows.

## Current State

The `explore-php` branch currently contains:

- A Composer package under `asherah-php/`.
- Sync FFI wrappers over `asherah-ffi`.
- Static API and explicit `SessionFactory` / `Session` API.
- Native-owned `AsherahBuffer` handling with explicit native free.
- Native artifact installer and verifier.
- PHP-FPM preload entrypoint.
- Debian and Alpine PHP test images.
- PHPUnit, PHPStan, PHP-CS-Fixer, syntax checks, smoke tests, and preload-mode
  smoke coverage.
- An exploration design note in `docs/explore-php-binding.md`.

The branch is still exploratory because release integration, CI integration,
typed config ergonomics, multi-region coverage, session-cache parity,
interoperability coverage, and production docs are incomplete.

## Progress Log

- 2026-05-06: Added the initial Composer/FFI exploration package, native
  installer, preload entrypoint, Docker PHP test images, PHPUnit/PHPStan/
  PHP-CS-Fixer configuration, smoke tests, and draft PR.
- 2026-05-06: Rebasing after the large mainline PR left this branch as PHP-only
  on top of `origin/main`.
- 2026-05-06: Began production hardening from this ExecPlan:
  - added typed config value objects (`AsherahConfig`, `MetastoreConfig`,
    `KmsConfig`);
  - added JSON-shape tests for memory/static, multi-region KMS, and
    DynamoDB region/signing-region fields;
  - added typed config support to `Asherah::setup()` and
    `SessionFactory::fromConfig()`;
  - hardened the native installer with `--install-dir`, checksum mismatch, and
    force-replace coverage;
  - added `samples/php/simple.php`;
  - added PHP to `scripts/test.sh --bindings --binding=php`;
  - added PHP to the x86_64 binding-test CI matrix.
- 2026-05-06: Continued source-only production work:
  - added specific exception subclasses for native library, native operation,
    and lifecycle failures;
  - added `Session::encryptString()` and `Session::decryptString()` aliases;
  - added close-after-use and not-initialized lifecycle tests;
  - added source-only Composer archive exclusions for `vendor`, `native`, and
    `composer.lock`;
  - added PHP source-package publish dry-run in CI;
  - added consumer install smoke test for source-only path repository usage;
  - added PHP interop probe scripts for future cross-language interop wiring.
- 2026-05-06: Hardened static session cache parity:
  - added tests for cache disabled mode, same-partition reuse, bounded LRU
    eviction, and shutdown draining cached native sessions;
  - added pre-FFI validation for required `KMS`, `EnableSessionCaching`, and
    `SessionCacheMaxSize`;
  - changed configuration validation failures to use `ConfigurationException`
    while preserving `InvalidArgumentException` catch compatibility.
- 2026-05-06: Added opt-in AWS FFI integration tests for multi-region KMS and
  DynamoDB region/signing-region round trips. These skip by default and run when
  the documented `ASHERAH_PHP_AWS_*` environment variables and AWS credentials
  are present.
- 2026-05-06: Added a PHP base64 interop CLI and wired PHP into the primary
  Python/Node/Rust/Ruby interop test as an optional participant when local PHP
  and Composer are available.
- 2026-05-06: Extended the PHP source-package dry-run with Alpine/musl x64
  runtime coverage by building the musl FFI library through `cargo zigbuild`
  and running the consumer install smoke in the Alpine PHP image.
- 2026-05-06: Expanded package documentation for native staging with GitHub
  tokens, explicit factory/session lifecycle, static session-cache lifecycle,
  source-only publishing, PHP plaintext caveats, and troubleshooting.
- 2026-05-06: Re-audited the ExecPlan line by line and closed the remaining
  implementation gaps:
  - added Composer authors metadata;
  - added PHP 8.1, 8.2, 8.3, and 8.4 binding-test CI coverage for the claimed
    supported PHP versions;
  - expanded native installer tests for unsupported platforms, missing checksum
    entries, verify success, verify failure modes, and `--no-checksum`;
  - added subprocess tests for missing FFI, missing native overrides, and
    preload native-resolution diagnostics;
  - expanded typed-config phpdoc array shapes, JSON shape tests, unknown-option
    preservation tests, single-region KMS map coverage, RDBMS replica
    consistency coverage, static KMS coverage, SQLite coverage, and additional
    option type validation;
  - added samples for explicit factory/session usage, PHP-FPM preload config,
    and Docker native download staging;
  - added a PHP source-package publish workflow that validates a source-only
    Composer archive and attaches it to GitHub releases;
  - added a manual `PHP AWS Integration` workflow that requires a two-region
    KMS map and DynamoDB table inputs for release validation against real AWS;
  - fixed PHP 8.1 compatibility in the interop CLI and preload smoke command.
- 2026-05-06: Additional audit found and closed two production-readiness gaps:
  - centralized PHP config validation so both `Asherah::setup()` and
    `SessionFactory::fromConfig()` reject malformed array configs before
    crossing the FFI boundary, including invalid required strings,
    region-sensitive strings, booleans, integer options, and `RegionMap`
    entries;
  - fixed the PHP binding test runner and source archive builder to remove
    generated `composer.lock` files before dependency resolution, preventing a
    previous PHP 8.4 run from poisoning PHP 8.1 validation in the same
    worktree.
- 2026-05-06: Additional test-depth sweep closed an AWS release-gate gap and
  added package lifecycle assertions:
  - passed AWS/KMS/DynamoDB environment variables through Dockerized PHP
    PHPUnit runs so the manual AWS workflow exercises the same tests that local
    CI uses;
  - added required-integration mode so the manual AWS workflow fails instead of
    silently skipping when multi-region KMS or DynamoDB inputs are missing;
  - added PHPUnit coverage that proves required AWS mode fails instead of
    skipping and that Composer metadata preserves the source-only package
    lifecycle, explicit native staging commands, archive exclusions, runtime
    requirements, and author metadata.
- 2026-05-06: Additional convergence sweep closed installer and typed-config
  edge cases:
  - disabled automatic PHP HTTP redirects in the native installer and now
    re-evaluates token eligibility on each redirect target;
  - added coverage that GitHub release redirect asset hosts do not receive the
    installer token;
  - made typed KMS region maps reject non-string key ARN values with
    `ConfigurationException`;
  - made the FFI-unavailable negative test skip only when the local PHP binary
    still exposes FFI under `php -n`.
- 2026-05-06: Additional convergence sweep closed filesystem and standalone
  smoke-test edges:
  - checked native installer temporary-file writes, checksum sidecar writes, and
    executable-bit changes instead of assuming they succeeded;
  - added copy/unlink fallback when final native-library `rename()` cannot cross
    filesystems;
  - fixed the no-vendor smoke-test fallback to load all required source classes;
  - added no-vendor smoke coverage to the PHP binding test runner.
- 2026-05-06: Follow-up convergence sweep closed a package lifecycle gap:
  - changed `scripts/build-php-source-archive.sh` to build from a temporary
    package copy instead of writing `vendor/` and `composer.lock` into the
    checkout;
  - isolated the archive build's Composer cache under the temporary workspace so
    it cannot interfere with the checkout's dependency install;
  - preserved Composer package versioning for source archives by exporting the
    current tag or branch as `COMPOSER_ROOT_VERSION` before building from the
    temporary copy;
  - added binding-test, CI dry-run, and publish guards that fail if source
    archive construction mutates `asherah-php/`.
- 2026-05-06: Follow-up convergence sweep closed a native artifact download
  scalability gap:
  - changed `NativeLibraryInstaller` to stream release assets into the temporary
    download file instead of materializing the whole native library in a PHP
    string;
  - added a subprocess regression test that installs a 12 MB native fixture
    under a 16 MB PHP memory limit.

No known implementation gaps remain in this ExecPlan. Composer publication is
source-only, the workflow supports GitHub Release source archive publication,
and manual non-dry-run publication requires an explicit release tag. Direct
Packagist notification is intentionally not wired from this monorepo because
Packagist reads `composer.json` from a repository root; use a subtree split or
internal Composer repository if Packagist-style indexing is required. Native
binaries remain external release artifacts staged by `scripts/install_native.php`
or an equivalent image-build artifact step.

## Non-Goals

Do not build these for the first production merge:

- Zend extension.
- Async PHP FFI callbacks.
- Native log or metrics callbacks into PHP.
- Cobhan-style caller-owned PHP output buffers.
- Attempts to reliably zeroize PHP strings after plaintext is copied into PHP
  memory.
- Bundling native binaries in Composer packages, including fat all-platform
  packages or Git LFS-backed Composer installs.
- A Composer plugin for native installation.

These may be revisited after the sync binding is stable and shipped.

## Milestone 1: Stabilize Package Shape

Implementation steps:

1. Confirm the final Composer package name and namespace.
   - Proposed package: `godaddy/asherah`.
   - Proposed namespace: `GoDaddy\Asherah`.
2. Decide whether `asherah-php/composer.lock` is committed.
   - For a library package, keep it uncommitted unless release policy requires
     fully pinned dev tools.
3. Add package metadata required for publication.
   - authors
   - support URLs
   - keywords
   - homepage/source URLs
   - explicit PHP platform support
4. Confirm minimum PHP version.
   - Current prototype uses `php >=8.1`.
   - Run CI on every supported minor version that is claimed.
5. Keep `vendor/`, caches, downloaded native libraries, and lockfiles out of
   source. Native binaries are release artifacts and image-build/deploy inputs,
   not Composer package contents.

Validation:

- `composer validate --strict`
- Package can be installed as a path repository from a clean consumer project.
- Autoloading works from a consumer project without relying on repository-root
  paths.

Acceptance criteria:

- Package metadata is complete enough for source-only GitHub Release or
  internal Composer/artifact repository publication, or for a future subtree
  split if Packagist indexing is required.
- A clean consumer project can `composer require` the package from a local path
  and instantiate `GoDaddy\Asherah\Asherah`.

## Milestone 2: Native Artifact Installation And Verification

Implementation steps:

1. Harden `scripts/install_native.php` and `NativeLibraryInstaller`.
2. Keep platform mapping tied to the existing `release-cobhan.yml` artifact
   names:
   - `linux-x64` -> `libasherah-x64.so`
   - `linux-arm64` -> `libasherah-arm64.so`
   - `linux-musl-x64` -> `libasherah-x64-musl.so`
   - `linux-musl-arm64` -> `libasherah-arm64-musl.so`
   - `darwin-x64` -> `libasherah-x64.dylib`
   - `darwin-arm64` -> `libasherah-arm64.dylib`
   - `win-x64` -> `libasherah-x64.dll`
   - `win-arm64` -> `libasherah-arm64.dll`
3. Add installer options needed by CI and Docker users:
   - `--version=<tag>`
   - `--platform=<platform>`
   - `--release-base-url=<url>`
   - `--install-dir=<dir>`
   - `--force`
   - `--verify`
   - `--no-checksum`
   - `--quiet`
   - `--verbose`
4. Verify downloaded assets against `SHA256SUMS` by default.
5. Fail closed on missing, empty, too-small, unreadable, non-executable, or
   checksum-mismatched native libraries.
6. Document that Composer dependency scripts do not run automatically for
   consuming applications, and do not depend on them for production installs.
7. Document explicit image-build/deploy staging as the primary native
   installation path. Root Composer hooks can be shown as optional, but not as
   the preferred model.
8. Support `GITHUB_TOKEN` / `GH_TOKEN` for private or rate-limited release
   downloads.

Tests:

- Supported platform maps to expected release asset and installed filename.
- Unsupported platform fails with a clear error.
- Offline fixture release downloads the correct artifact.
- Checksum mismatch fails.
- Missing `SHA256SUMS` entry fails.
- `--verify` succeeds for a staged valid native library.
- `--verify` fails for missing, empty, too-small, unreadable, and non-executable
  libraries.
- `--force` replaces an existing staged library.
- `--install-dir` stages outside the package tree.
- Custom release base URL is honored.

Acceptance criteria:

- A clean container can install the source-only Composer package, explicitly
  stage one native release artifact during image build, and load that library
  through the PHP binding.

## Milestone 3: PHP-FPM Preload Support

Implementation steps:

1. Keep runtime loading order:
   - first `FFI::scope('ASHERAH')`
   - then dynamic `FFI::cdef()` fallback for CLI/development
2. Keep `preload.php` as a first-class package entrypoint.
3. Ensure preload uses the same library resolution rules as runtime loading.
4. Document PHP-FPM configuration:
   - `ffi.enable=preload`
   - `opcache.preload=/path/to/vendor/godaddy/asherah/preload.php`
   - `ASHERAH_PHP_NATIVE` for custom native library paths
5. Add a preload smoke test in CI.

Tests:

- CLI dynamic loading works with `ffi.enable=1`.
- Preload loading works with `ffi.enable=preload` and `opcache.enable_cli=1`.
- Runtime fails with an actionable diagnostic when FFI is unavailable.
- Runtime fails with an actionable diagnostic when preload cannot locate the
  native library.

Acceptance criteria:

- PHP-FPM-style preload mode is tested and documented before merge.

## Milestone 4: Typed PHP Configuration API

Implementation steps:

1. Add immutable config/value-object types that serialize to the exact PascalCase
   JSON names expected by the Rust core.
2. Provide a PHP-native builder API:
   - `AsherahConfig`
   - `MetastoreConfig::memory()`
   - `MetastoreConfig::dynamoDb(...)`
   - `MetastoreConfig::rdbms(...)`
   - `KmsConfig::aws(...)`
   - `KmsConfig::static(...)`
   - `KmsConfig::testDebugStatic()`
3. Preserve array input for simple adoption, but prefer typed config in docs.
4. Add phpdoc array shapes where arrays remain public.
5. Add strong validation before crossing the FFI boundary:
   - required service name
   - required product ID
   - required metastore
   - required KMS
   - empty partition rejection
   - option type validation
6. Avoid rewriting, sorting, inferring, or dropping user-supplied region fields
   in PHP. Multi-region semantics stay in Rust.

Tests:

- JSON shape tests for every typed config variant.
- Array config and typed config produce equivalent JSON.
- Missing required fields fail before FFI.
- Invalid field types fail before FFI.
- Unknown fields are either preserved or rejected according to the final API
  decision, with tests documenting the behavior.

Acceptance criteria:

- PHP developers can configure common memory/static, RDBMS/static, AWS KMS, and
  DynamoDB scenarios without hand-crafting PascalCase arrays.
- Static-analysis tools see meaningful types and docblocks.

## Milestone 5: Multi-Region KMS And DynamoDB Coverage

Implementation steps:

1. Add typed config support for:
   - `RegionMap`
   - `PreferredRegion`
   - `KmsKeyId`
   - `DynamoDBRegion`
   - `DynamoDBSigningRegion`
   - `DynamoDBTableName`
   - `EnableRegionSuffix`
   - `ReplicaReadConsistency`
   - `AwsProfileName`
2. Add local tests proving PHP preserves these fields exactly.
3. Add opt-in integration tests for real AWS KMS multi-region scenarios.
4. Add opt-in integration tests for DynamoDB region suffix and signing-region
   scenarios.
5. Match the repository's existing environment-gated AWS test style so normal
   CI does not require AWS credentials.

Tests:

- Two-region KMS `RegionMap` plus `PreferredRegion`.
- Preferred region not first in input order.
- Single-region KMS map without accidental PHP-side rewrite.
- DynamoDB regional table suffix enabled.
- Explicit `DynamoDBSigningRegion` differing from `DynamoDBRegion`.
- `AwsProfileName` included only when set.
- Opt-in end-to-end encrypt/decrypt with multi-region KMS.
- Opt-in DynamoDB metastore round trip with regional suffix/signing-region.

Acceptance criteria:

- PHP has at least the same config serialization confidence as the other
  bindings for multi-region KMS and DynamoDB.
- The PHP layer is demonstrably a pass-through for region-sensitive behavior.

## Milestone 6: Session Cache Parity

Implementation steps:

1. Implement PHP session caching for the static API.
2. Use `SessionCacheMaxSize` as the cache bound.
3. Implement deterministic eviction, likely LRU.
4. Close native sessions on eviction.
5. Ensure `Asherah::shutdown()` closes all cached sessions before freeing the
   native factory.
6. Make `close()` / `shutdown()` idempotent.
7. Document lifecycle guidance for PHP-FPM and long-lived workers.
8. Avoid unbounded native session handle growth.

Tests:

- Static API reuses sessions when caching is enabled.
- Static API creates/closes per-call sessions when caching is disabled.
- Cache bound is enforced.
- Eviction closes evicted native sessions.
- Shutdown closes all cached sessions and the factory.
- Double shutdown is safe.
- Explicit `SessionFactory` / `Session` lifecycle remains independent of static
  cache behavior.

Acceptance criteria:

- Long-lived PHP workers do not leak native sessions under normal static API
  use.
- Static API behavior is aligned with other language bindings.

## Milestone 7: Public API And Error Semantics

Implementation steps:

1. Keep the public API PHP-native and avoid exposing the C ABI.
2. Provide:
   - `Asherah::setup(...)`
   - `Asherah::shutdown()`
   - `Asherah::encrypt(...)`
   - `Asherah::decrypt(...)`
   - `Asherah::encryptBytes(...)`
   - `Asherah::decryptBytes(...)`
   - `Asherah::encryptString(...)`
   - `Asherah::decryptString(...)`
   - `SessionFactory::fromConfig(...)`
   - `Session::encryptBytes(...)`
   - `Session::decryptBytes(...)`
3. Define stable exception types:
   - configuration errors
   - native loading errors
   - native operation errors
   - lifecycle errors
4. Preserve binary string behavior, including embedded NUL bytes.
5. Keep native error message reads immediately after failed native calls.
6. Do not log plaintext, ciphertext, encrypted keys, raw config JSON, KMS ARNs,
   or AWS SDK error chains from PHP.

Tests:

- Binary payload round trip with embedded NUL bytes.
- Empty plaintext encrypts and round trips.
- Empty ciphertext fails as invalid DRR JSON.
- Empty partition ID fails.
- Invalid config returns a stable PHP exception.
- Invalid DRR JSON returns a stable PHP exception with native error context.
- Operations after close fail predictably.

Acceptance criteria:

- The public API is stable enough to document and support.
- Error behavior is predictable for application developers and tests.

## Milestone 8: Interoperability And Samples

Implementation steps:

1. Add `samples/php`.
2. Add PHP to repository interop tests where practical.
3. Add PHP-generated DataRowRecord round trips with at least one other binding.
4. Add a consumer-app smoke test that installs `godaddy/asherah` through
   Composer and runs a basic encrypt/decrypt path.
5. Add examples for:
   - memory + test-debug-static
   - static API
   - explicit factory/session API
   - PHP-FPM preload setup
   - native download in Docker

Tests:

- PHP encrypt -> Rust decrypt.
- Rust encrypt -> PHP decrypt.
- PHP encrypt -> at least one other high-level binding decrypts.
- Consumer Composer install smoke.

Acceptance criteria:

- PHP participates in cross-language compatibility checks instead of being
  validated only in isolation.

## Milestone 9: CI Integration

Implementation steps:

1. Add PHP checks to CI:
   - Docker image build
   - Composer validate
   - PHP syntax
   - PHPStan
   - PHP-CS-Fixer dry run
   - PHPUnit
   - smoke test
   - preload-mode smoke test
2. Run glibc Linux and musl Linux at minimum.
3. Wire PHP into `scripts/test.sh --bindings`.
4. Add optional AWS/DynamoDB/KMS integration jobs gated by environment and
   credentials.
5. Keep dry-run jobs aligned with release/publish workflows once PHP publishing
   exists.

Validation:

- `scripts/test.sh --bindings` runs PHP checks when PHP tooling is available.
- CI job fails when native library cannot be loaded.
- CI job fails when preload mode is broken.
- CI job fails when the native installer cannot install from a staged release
  fixture.

Acceptance criteria:

- The PHP binding is continuously validated on every PR with the same seriousness
  as the other bindings.

## Milestone 10: Release And Publish Flow

Implementation steps:

1. Add a PHP source-package publish workflow.
2. Decide publishing target:
   - GitHub Release source archive
   - internal Composer/artifact repository
   - Packagist only through a subtree split or separate package repository
3. Ensure release versioning maps cleanly to Asherah release tags.
4. Add publish dry-run jobs that exactly mirror publish behavior.
5. Ensure native staging helper can fetch assets from the same release produced
   by `release-cobhan.yml`.
6. Add documentation for internal/private GitHub token usage if release assets
   require authentication.
7. Do not publish native binaries through Composer. If an internal prebuilt
   distribution is needed, publish it as an image/artifact outside Composer.

Acceptance criteria:

- A tagged release can publish PHP source without native binaries.
- A clean consumer can install the published source package and explicitly stage
  the matching native artifact during image build/deploy.
- Dry-run CI catches the same classes of failure as the publish workflow.

## Milestone 11: Documentation

Implementation steps:

1. Expand `asherah-php/README.md`.
2. Add repository-level PHP binding docs if consistent with other bindings.
3. Document:
   - installation
   - native download
   - Composer root hook caveat
   - PHP-FPM preload
   - Docker builds
   - configuration builders
   - static API lifecycle
   - explicit factory/session lifecycle
   - multi-region KMS
   - multi-region DynamoDB
   - AWS profile behavior
   - security caveat for PHP plaintext strings
   - troubleshooting
4. Add API examples for all common deployment patterns.

Acceptance criteria:

- A PHP-FPM service can install, preload, configure, encrypt, and decrypt by
  following docs without source-code spelunking.

## Milestone 12: Platform Support Decision

Implementation steps:

1. Validate and advertise only platforms that are tested.
2. Minimum merge-worthy support:
   - Linux glibc x64
   - Linux musl x64
3. Strongly preferred before production release:
   - Linux glibc arm64
   - Linux musl arm64
   - macOS arm64/x64 for development
4. Windows:
   - PHP FFI can load DLLs, but do not advertise Windows support until tested
     with real PHP on Windows.

Acceptance criteria:

- README supported-platform table matches CI/release reality.

## Final Merge Criteria

The PHP binding is merge-worthy when all of the following are true:

- CI validates PHP on every PR.
- Native staging helper is tested, documented, and tied to existing release
  assets.
- PHP-FPM preload mode is tested.
- Typed config API exists and covers common metastore/KMS setups.
- Multi-region KMS and DynamoDB config preservation is covered by tests.
- Session cache behavior has parity with other bindings.
- Public API and exception behavior are stable.
- Interop coverage proves PHP can exchange DataRowRecords with other bindings.
- Release/publish dry-run exists or there is an explicitly accepted follow-up
  tracked before merging.
- Documentation is complete enough for real PHP-FPM deployment.

## Suggested Implementation Order

1. Package metadata and consumer install smoke.
2. Installer hardening and offline fixture tests.
3. Preload smoke in CI.
4. Typed config API and JSON shape tests.
5. Multi-region KMS/DynamoDB config tests.
6. Session cache parity.
7. Public API/error polish.
8. Interop and samples.
9. CI wiring.
10. Release/publish dry-run.
11. Documentation final pass.

This order keeps the release and deployment foundations visible early while
preserving the highest-risk Asherah scenarios, especially multi-region KMS and
DynamoDB, as explicit implementation gates rather than late documentation work.
