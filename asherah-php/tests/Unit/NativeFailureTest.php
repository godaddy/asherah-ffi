<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class NativeFailureTest extends TestCase
{
    public function testRuntimeFailsClearlyWhenFfiExtensionIsUnavailable(): void
    {
        $result = $this->runPhp([
            '-n',
            '-d',
            'display_errors=1',
            '-r',
            'require "vendor/autoload.php"; GoDaddy\Asherah\Native::ffi();',
        ]);

        self::assertNotSame(0, $result['exitCode']);
        self::assertStringContainsString('PHP FFI extension is not enabled', $result['output']);
    }

    public function testRuntimeFailsClearlyWhenNativeOverrideCannotBeResolved(): void
    {
        $result = $this->runPhp([
            '-d',
            'ffi.enable=1',
            '-d',
            'display_errors=1',
            '-r',
            'require "vendor/autoload.php"; GoDaddy\Asherah\Native::ffi();',
        ], [
            'ASHERAH_PHP_NATIVE' => sys_get_temp_dir() . '/asherah-missing-native-' . bin2hex(random_bytes(4)),
        ]);

        self::assertNotSame(0, $result['exitCode']);
        self::assertStringContainsString('ASHERAH_PHP_NATIVE does not point to a readable native library', $result['output']);
    }

    public function testPreloadFailsClearlyWhenNativeLibraryCannotBeResolved(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            self::markTestSkipped('PHP CLI preload can fail before package preload code when PHPUnit runs as root');
        }

        $result = $this->runPhp([
            '-d',
            'ffi.enable=preload',
            '-d',
            'opcache.enable_cli=1',
            '-d',
            'opcache.preload=' . dirname(__DIR__, 2) . '/preload.php',
            '-d',
            'display_errors=1',
            '-r',
            'require "vendor/autoload.php"; GoDaddy\Asherah\Native::ffi();',
        ], [
            'ASHERAH_PHP_NATIVE' => sys_get_temp_dir() . '/asherah-missing-preload-native-' . bin2hex(random_bytes(4)),
        ]);

        self::assertNotSame(0, $result['exitCode']);
        self::assertStringContainsString('ASHERAH_PHP_NATIVE does not point to a readable native library', $result['output']);
    }

    /**
     * @param list<string> $args
     * @param array<string, string> $env
     * @return array{exitCode: int, output: string}
     */
    private function runPhp(array $args, array $env = []): array
    {
        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open(
            array_merge([PHP_BINARY], $args),
            $descriptorSpec,
            $pipes,
            dirname(__DIR__, 2),
            array_replace($_ENV, $env)
        );

        if (!is_resource($process)) {
            self::fail('Failed to start PHP subprocess');
        }

        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [
            'exitCode' => $exitCode,
            'output' => $output,
        ];
    }
}
