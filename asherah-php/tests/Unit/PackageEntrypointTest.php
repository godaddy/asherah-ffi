<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class PackageEntrypointTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/asherah_php_entrypoint_' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0o755, true);
    }

    protected function tearDown(): void
    {
        $this->removeTree($this->tmpDir);
    }

    public function testInstallNativeScriptFindsConsumerRootAutoload(): void
    {
        $consumer = $this->createConsumerPackageLayout();

        $result = $this->runPhp([
            $consumer . '/vendor/godaddy/asherah/scripts/install_native.php',
            '--help',
        ], cwd: $consumer);

        self::assertSame(0, $result['exitCode'], $result['output']);
        self::assertStringContainsString('Usage: php scripts/install_native.php [options]', $result['output']);
    }

    public function testPreloadFindsConsumerRootAutoloadBeforeResolvingNativeLibrary(): void
    {
        $consumer = $this->createConsumerPackageLayout();

        $result = $this->runPhp([
            '-d',
            'ffi.enable=1',
            '-r',
            'try { require "vendor/godaddy/asherah/preload.php"; } catch (Throwable $e) { echo $e->getMessage(); exit(0); } exit(1);',
        ], [
            'ASHERAH_PHP_NATIVE' => $consumer . '/missing-native',
        ], $consumer);

        self::assertSame(0, $result['exitCode'], $result['output']);
        self::assertStringContainsString('ASHERAH_PHP_NATIVE does not point to a readable native library', $result['output']);
        self::assertStringNotContainsString('autoload', strtolower($result['output']));
    }

    private function createConsumerPackageLayout(): string
    {
        $consumer = $this->tmpDir . '/consumer';
        $package = $consumer . '/vendor/godaddy/asherah';
        mkdir($package, 0o755, true);
        $this->copyTree(dirname(__DIR__, 2), $package);
        $this->removeTree($package . '/vendor');
        @unlink($package . '/composer.lock');

        $vendor = $consumer . '/vendor';
        $autoload = <<<'PHP'
<?php
spl_autoload_register(static function (string $class): void {
    $prefix = 'GoDaddy\\Asherah\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/godaddy/asherah/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
PHP;
        file_put_contents($vendor . '/autoload.php', $autoload);

        return $consumer;
    }

    /**
     * @param list<string> $args
     * @param array<string, string> $env
     * @return array{exitCode: int, output: string}
     */
    private function runPhp(array $args, array $env = [], ?string $cwd = null): array
    {
        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open(
            array_merge([PHP_BINARY], $args),
            $descriptorSpec,
            $pipes,
            $cwd ?? dirname(__DIR__, 2),
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

    private function copyTree(string $source, string $destination): void
    {
        if (!is_dir($destination) && !mkdir($destination, 0o755, true) && !is_dir($destination)) {
            self::fail("Failed to create directory: {$destination}");
        }

        $entries = scandir($source);
        if ($entries === false) {
            self::fail("Failed to read directory: {$source}");
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $from = $source . DIRECTORY_SEPARATOR . $entry;
            $to = $destination . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($from)) {
                $this->copyTree($from, $to);
            } else {
                copy($from, $to);
            }
        }
    }

    private function removeTree(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $entries = scandir($path);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $child = $path . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($child)) {
                $this->removeTree($child);
            } else {
                unlink($child);
            }
        }

        rmdir($path);
    }
}
