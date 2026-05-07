# Asherah PHP

PHP FFI bindings for Asherah envelope encryption.

## Requirements

- PHP 8.1 or newer
- `ext-ffi`
- `ext-json`
- An Asherah native FFI library for the current platform

## Native Library Staging

The Composer package is source-only. It does not bundle native binaries and it
does not rely on Git LFS or Composer dependency scripts to make native libraries
appear during install.

Install the PHP source with Composer, then stage the one native library your
image or host needs from an Asherah release:

```bash
composer require godaddy/asherah
php vendor/godaddy/asherah/scripts/install_native.php --version=v0.6.64
```

The native installer downloads one platform artifact from the GitHub release,
verifies it against `SHA256SUMS`, and stages it under `native/<platform>/`.
You can also skip the helper and copy the native artifact into your image from
your normal artifact pipeline.

Recommended container pattern:

```dockerfile
RUN composer install --no-dev --optimize-autoloader
RUN php vendor/godaddy/asherah/scripts/install_native.php --version=v0.6.64
ENV ASHERAH_PHP_NATIVE=/app/vendor/godaddy/asherah/native/linux-x64
```

Composer does not run scripts from dependency packages during a consuming
application's install, and that is intentional here. Applications that still
want a root Composer hook can add one, but image-build staging is the preferred
production path:

```json
{
  "scripts": {
    "post-install-cmd": [
      "@php vendor/godaddy/asherah/scripts/install_native.php"
    ],
    "post-update-cmd": [
      "@php vendor/godaddy/asherah/scripts/install_native.php"
    ]
  }
}
```

Set `ASHERAH_PHP_NATIVE_VERSION` when the package version does not directly
match the Asherah release tag, or pass `--version=<tag>` to the script. Set
`ASHERAH_PHP_NATIVE` to a file or directory to use an existing local native
library instead of the default `native/` staging directory.

Use `--install-dir=<dir>` when building container images that stage native
libraries outside the Composer package tree.

For private repositories or rate-limited release downloads, set `GITHUB_TOKEN`
or `GH_TOKEN` in the image build environment. The helper sends the token only to
the configured GitHub release host.

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
opcache.preload=/path/to/vendor/godaddy/asherah/preload.php
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

The PHP package is source-only. Publish it through Packagist, GitHub Packages,
or an internal Composer repository as PHP source, not as a fat package with
native binaries. Native libraries remain release artifacts produced by the
existing native release workflow and are staged into application images with
`scripts/install_native.php` or an equivalent artifact-copy step.

This keeps Composer installs small and avoids Git LFS behavior that Composer
does not handle reliably for large native assets.

`.github/workflows/publish-php.yml` validates the Composer source archive,
attaches the source archive to a GitHub release, and can notify Packagist when
`PACKAGIST_USERNAME` and `PACKAGIST_API_TOKEN` repository secrets are present.
Native libraries remain the existing release assets consumed by
`scripts/install_native.php`.

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
