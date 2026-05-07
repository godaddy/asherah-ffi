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

## Supported Platforms

The source package can run anywhere PHP FFI can load the matching Asherah native
library. CI currently validates Linux glibc x64. Linux musl x64 is the next
required production target. Do not claim Windows support until DLL loading is
tested in CI or a release dry-run.

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

## Development

```bash
composer install
composer test
composer phpstan
composer cs-check
```
