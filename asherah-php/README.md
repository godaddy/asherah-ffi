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
