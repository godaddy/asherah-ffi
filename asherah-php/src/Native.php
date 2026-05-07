<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use FFI;
use FFI\CData;

final class Native
{
    private const CDEF = <<<'CDEF'
typedef unsigned char uint8_t;

typedef struct AsherahBuffer {
    uint8_t *data;
    size_t len;
    size_t capacity;
} AsherahBuffer;

const char *asherah_last_error_message(void);
void *asherah_factory_new_from_env(void);
void *asherah_factory_new_with_config(const char *config_json);
void asherah_factory_free(void *factory);
void *asherah_factory_get_session(void *factory, const char *partition_id);
void asherah_session_free(void *session);
int asherah_encrypt_to_json(void *session, const uint8_t *data, size_t len, AsherahBuffer *out);
int asherah_decrypt_from_json(void *session, const uint8_t *json, size_t len, AsherahBuffer *out);
void asherah_buffer_free(AsherahBuffer *buf);
CDEF;

    private static ?FFI $ffi = null;

    public static function ffi(): FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }

        if (!extension_loaded('ffi') || !class_exists(FFI::class)) {
            throw new NativeLibraryException('PHP FFI extension is not enabled');
        }

        try {
            self::$ffi = FFI::scope('ASHERAH');
            return self::$ffi;
        } catch (\Throwable) {
            // Fall through to dynamic loading for CLI/development usage.
        }

        $library = self::resolveLibraryPath();
        try {
            self::$ffi = FFI::cdef(self::CDEF, $library);
        } catch (\Throwable $e) {
            throw new NativeLibraryException(
                'failed to initialize Asherah FFI; check ffi.enable, opcache preload, and ASHERAH_PHP_NATIVE: '
                . $e->getMessage(),
                previous: $e
            );
        }

        return self::$ffi;
    }

    public static function lastError(): string
    {
        $ptr = self::ffi()->asherah_last_error_message();
        if (is_string($ptr)) {
            return $ptr === '' ? 'unknown error' : $ptr;
        }
        if ($ptr === null || FFI::isNull($ptr)) {
            return 'unknown error';
        }

        return FFI::string($ptr);
    }

    public static function cdef(): string
    {
        return self::CDEF;
    }

    public static function bytes(string $data): CData
    {
        $len = strlen($data);
        if ($len === 0) {
            return self::ffi()->cast('uint8_t *', 0);
        }

        $buf = self::ffi()->new("uint8_t[$len]", false);
        FFI::memcpy($buf, $data, $len);
        return $buf;
    }

    public static function newOutputBuffer(): CData
    {
        $buffer = self::ffi()->new('AsherahBuffer');
        $buffer->data = null;
        $buffer->len = 0;
        $buffer->capacity = 0;
        return $buffer;
    }

    public static function readAndFree(CData $buffer): string
    {
        try {
            if ($buffer->len === 0 || $buffer->data === null || FFI::isNull($buffer->data)) {
                return '';
            }

            return FFI::string($buffer->data, $buffer->len);
        } finally {
            self::ffi()->asherah_buffer_free(FFI::addr($buffer));
        }
    }

    public static function freeOutputBuffer(CData $buffer): void
    {
        self::ffi()->asherah_buffer_free(FFI::addr($buffer));
    }

    public static function resolveLibraryPath(): string
    {
        $names = match (PHP_OS_FAMILY) {
            'Darwin' => ['libasherah_ffi.dylib'],
            'Windows' => ['asherah_ffi.dll'],
            default => ['libasherah_ffi.so'],
        };

        $override = trim((string) getenv('ASHERAH_PHP_NATIVE'));
        if ($override !== '') {
            return self::resolveOverride($override, $names);
        }

        $root = dirname(__DIR__);
        $platform = self::platformId();
        foreach ($names as $name) {
            $candidates = [
                $root . "/native/$platform/$name",
                dirname($root) . "/target/release/$name",
                dirname($root) . "/target/debug/$name",
                dirname($root, 2) . "/target/release/$name",
                dirname($root, 2) . "/target/debug/$name",
            ];

            foreach ($candidates as $candidate) {
                if (self::isUsableLibraryFile($candidate)) {
                    return $candidate;
                }
            }
        }

        // Let the dynamic loader search system paths last.
        return $names[0];
    }

    /**
     * @param list<string> $names
     */
    private static function resolveOverride(string $override, array $names): string
    {
        $candidates = [];
        if (is_dir($override)) {
            foreach ($names as $name) {
                $candidates[] = $override . DIRECTORY_SEPARATOR . $name;
            }
        } else {
            $candidates[] = $override;
        }

        foreach ($candidates as $candidate) {
            if (self::isUsableLibraryFile($candidate)) {
                return $candidate;
            }
        }

        throw new NativeLibraryException(
            'ASHERAH_PHP_NATIVE does not point to a readable native library; searched: '
            . implode(', ', $candidates)
        );
    }

    private static function isUsableLibraryFile(string $path): bool
    {
        return file_exists($path)
            && is_file($path)
            && filesize($path) !== 0
            && is_readable($path)
            && (PHP_OS_FAMILY === 'Windows' || is_executable($path));
    }

    private static function platformId(): string
    {
        $arch = strtolower(php_uname('m'));
        $arch = match ($arch) {
            'x86_64', 'amd64' => 'x64',
            'aarch64', 'arm64' => 'arm64',
            default => $arch,
        };

        return match (PHP_OS_FAMILY) {
            'Darwin' => "darwin-$arch",
            'Windows' => "win-$arch",
            default => self::isMusl() ? "linux-musl-$arch" : "linux-$arch",
        };
    }

    private static function isMusl(): bool
    {
        if (file_exists('/etc/alpine-release')) {
            return true;
        }

        $ldd = trim((string) @shell_exec('ldd --version 2>&1'));
        return stripos($ldd, 'musl') !== false;
    }
}
