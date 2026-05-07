# Asherah PHP

PHP FFI bindings for Asherah envelope encryption.

## Requirements

- PHP 8.1 or newer
- `ext-ffi`
- `ext-json`
- An Asherah native FFI library for the current platform

## Native Library Install

Install the PHP package with Composer, then download the matching native
library from an Asherah release:

```bash
composer require godaddy/asherah
composer run download-native -- --version=v0.6.64
```

The native installer downloads one platform artifact from the GitHub release,
verifies it against `SHA256SUMS`, and stages it under `native/<platform>/`.

Composer does not run scripts from dependency packages during the consuming
application's install. Applications that want automatic native installation
must add a root Composer hook:

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
library instead of the packaged `native/` directory.

Use `--install-dir=<dir>` when building container images that stage native
libraries outside the Composer package tree.

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
