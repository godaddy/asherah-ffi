# Asherah PHP

PHP FFI bindings for Asherah envelope encryption.

## Requirements

- PHP 8.1 or newer
- `ext-ffi`
- `ext-json`
- An Asherah native FFI library for the current platform

## Installation

Install the PHP package from Packagist:

```bash
composer require godaddy/asherah
```

The Composer package is source-only and does not bundle native binaries. After
installing via Composer, download the platform-specific native FFI library:

```bash
php vendor/godaddy/asherah/asherah-php/scripts/install_native.php
```

The installer automatically detects the latest release version from the Composer
package and downloads the matching native library for your platform. For
production builds or when the package version doesn't match the release tag,
specify the version explicitly:

```bash
php vendor/godaddy/asherah/asherah-php/scripts/install_native.php --version=v0.6.98
```

### Alternative: VCS Installation

For development or pre-release testing, install directly from the Git repository:

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/godaddy/asherah-ffi"
    }
  ],
  "require": {
    "godaddy/asherah": "dev-main"
  }
}
```

VCS installs still require the native library staging step and may clone the
full monorepo. Packagist installs are preferred for production use.

### Container Deployment

Recommended Dockerfile pattern for production:

```dockerfile
# Install PHP source from Packagist
RUN composer install --no-dev --optimize-autoloader

# Download platform-specific native library
RUN php vendor/godaddy/asherah/asherah-php/scripts/install_native.php

# Optional: Set explicit path to native library
ENV ASHERAH_PHP_NATIVE=/app/vendor/godaddy/asherah/asherah-php/native/linux-x64
```

The native installer downloads one platform artifact from the GitHub release,
verifies it against `SHA256SUMS`, and stages it under
`vendor/godaddy/asherah/asherah-php/native/<platform>/`. You can also skip the
installer and copy the native artifact from your artifact pipeline.

### Optional: Composer Hook for Local Development

For local development, you can automate native library downloads with Composer
hooks in your application's root `composer.json`:

```json
{
  "scripts": {
    "post-install-cmd": [
      "@php vendor/godaddy/asherah/asherah-php/scripts/install_native.php"
    ],
    "post-update-cmd": [
      "@php vendor/godaddy/asherah/asherah-php/scripts/install_native.php"
    ]
  }
}
```

For production container builds, explicit native staging in the Dockerfile is
preferred over Composer hooks.

### Configuration Options

**Environment Variables:**
- `ASHERAH_PHP_NATIVE_VERSION` — Override the release version (default: auto-detected from package version)
- `ASHERAH_PHP_NATIVE` — Use an existing native library file or directory instead of downloading
- `GITHUB_TOKEN` or `GH_TOKEN` — Authenticate for private repositories or rate-limit avoidance (only sent to `github.com` hosts)

**Installer Script Options:**
- `--version=<tag>` — Specify the release tag (e.g., `v0.6.98`)
- `--install-dir=<dir>` — Stage native libraries outside the Composer package tree
- `--verify` — Verify existing installation without downloading
- `--release-base-url=<url>` — Use a custom release artifact host

## Supported Platforms

The source package can run anywhere PHP FFI can load the matching Asherah native
library. CI validates Linux glibc x64 and Linux musl x64 source-package
installation and runtime loading. The PHP binding test suite runs on PHP 8.1,
8.2, 8.3, and 8.4. Do not claim Windows support until DLL loading is tested in
CI or a release dry-run.

## Opt-In AWS Tests

Normal CI does not require AWS credentials. To exercise PHP against real
multi-region KMS, set `ASHERAH_PHP_AWS_KMS_REGION_MAP` to a JSON object mapping
regions to key ARNs, and optionally set
`ASHERAH_PHP_AWS_KMS_PREFERRED_REGION`.

To exercise DynamoDB metastore region handling, set
`ASHERAH_PHP_AWS_DYNAMODB_TABLE` and `ASHERAH_PHP_AWS_DYNAMODB_REGION`.
Optional fields are `ASHERAH_PHP_AWS_DYNAMODB_SIGNING_REGION`,
`ASHERAH_PHP_AWS_DYNAMODB_ENDPOINT`, and
`ASHERAH_PHP_AWS_DYNAMODB_ENABLE_REGION_SUFFIX=1`.

`AwsProfileName` is omitted from generated config unless it is explicitly set
with a non-empty value. When present, PHP passes it through unchanged to the
Rust core; PHP does not infer a profile from the process environment.

For release validation, run the `PHP AWS Integration` workflow manually with a
two-region KMS map and DynamoDB table/signing-region inputs. The workflow uses
the repository AWS credential secrets and fails if the KMS map has fewer than
two regions, so multi-region behavior cannot be accidentally validated with a
single-region setup.

## Usage

Prefer the typed config API for application code:

```php
use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;

Asherah::setup(
    AsherahConfig::memoryTestDebugStatic('my-service', 'my-product')
        ->withSessionCache(true, 100)
);

$ciphertext = Asherah::encryptString('tenant-123', 'secret');
$plaintext = Asherah::decryptString('tenant-123', $ciphertext);

Asherah::shutdown();
```

Multi-region KMS and DynamoDB options are preserved exactly as PascalCase JSON
fields and passed through to the Rust core:

```php
use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\KmsConfig;
use GoDaddy\Asherah\MetastoreConfig;

$config = (new AsherahConfig(
    'my-service',
    'my-product',
    MetastoreConfig::dynamoDb(
        tableName: 'EncryptionKey',
        region: 'us-west-2',
        signingRegion: 'us-east-1',
        enableRegionSuffix: true
    ),
    KmsConfig::aws(
        regionMap: [
            'us-west-2' => 'arn:aws:kms:us-west-2:111122223333:key/west',
            'us-east-1' => 'arn:aws:kms:us-east-1:111122223333:key/east',
        ],
        preferredRegion: 'us-east-1'
    )
))->withAwsProfileName('prod-profile');
```

Array configs are still accepted for compatibility, but typed configs provide
better IDE completion and static-analysis coverage.

For explicit lifecycle control, use a factory and session directly:

```php
use GoDaddy\Asherah\SessionFactory;

$factory = SessionFactory::fromConfig($config);
$session = $factory->getSession('tenant-123');

try {
    $ciphertext = $session->encryptString('secret');
    $plaintext = $session->decryptString($ciphertext);
} finally {
    $session->close();
    $factory->close();
}
```

The static API caches native sessions by partition when session caching is
enabled, bounded by `SessionCacheMaxSize` with LRU eviction. Call
`Asherah::shutdown()` from long-lived workers before process shutdown or worker
recycle so cached native handles are closed deterministically. Set
`withSessionCache(false)` for short-lived scripts or tests that should create
and close a session per call.

## PHP-FPM Preload

Production PHP-FPM deployments often use `ffi.enable=preload`, which disables
dynamic FFI creation during requests. Configure `opcache.preload` to point at
this package's `preload.php`:

```ini
ffi.enable=preload
opcache.preload=/path/to/vendor/godaddy/asherah/asherah-php/preload.php
```

Runtime code first uses `FFI::scope('ASHERAH')` from preload mode and falls
back to dynamic `FFI::cdef()` for CLI and development environments.

See `samples/php/preload-fpm.ini` for the minimum PHP-FPM settings.

## Samples

- `samples/php/simple.php` uses the static API with memory metastore and
  test-debug-static KMS.
- `samples/php/factory.php` uses explicit `SessionFactory` and `Session`
  lifecycle management.
- `samples/php/preload-fpm.ini` shows PHP-FPM preload settings.
- `samples/php/Dockerfile.native-download` shows source install plus native
  artifact download during image build.

## Publishing Model

The PHP package is published to Packagist as a source-only distribution. The
Composer package does not bundle native binaries — native FFI libraries remain
separate GitHub release artifacts that are downloaded on-demand via
`scripts/install_native.php`.

This design:
- Keeps Packagist installs small (~172KB)
- Avoids platform-specific fat packages
- Eliminates Git LFS dependencies
- Allows applications to download only the native library for their platform

The repository root `composer.json` exposes `godaddy/asherah` for Packagist
indexing without moving files out of the monorepo. `.gitattributes` keeps
Composer dist archives source-only by exporting the root package metadata and
the `asherah-php` runtime files while excluding Rust crates, other language
bindings, tests, and native binaries.

Packagist automatically syncs with GitHub releases via webhook. When a new
release tag is pushed, Packagist indexes the source archive and consumers can
install it immediately via `composer require godaddy/asherah`.

## Security Notes

Asherah still protects keys and native buffers in Rust, but PHP strings are
ordinary managed memory. Treat plaintext and decrypted payload strings as
sensitive application data, keep their lifetime short, and do not log config
JSON, KMS ARNs, encrypted keys, ciphertexts, or plaintexts from application
error handlers.

## Troubleshooting

- `PHP FFI extension is not enabled`: install/enable `ext-ffi`. For PHP-FPM
  preload deployments, use `ffi.enable=preload`; for CLI development, use
  `ffi.enable=1`.
- `ASHERAH_PHP_NATIVE does not point to a readable native library`: set
  `ASHERAH_PHP_NATIVE` to either the native library file or a directory
  containing `libasherah_ffi.so`, `libasherah_ffi.dylib`, or `asherah_ffi.dll`.
- `failed to initialize Asherah FFI`: verify the native library matches the
  operating system and C runtime. A glibc `.so` will not load in an Alpine/musl
  image.
- Native download checksum failures usually mean the release tag and source
  package version do not match. Pass `--version=<tag>` explicitly.

## Development

```bash
composer install
composer test
composer phpstan
composer cs-check
```
