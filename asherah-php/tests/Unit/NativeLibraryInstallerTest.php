<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use GoDaddy\Asherah\NativeLibraryException;
use GoDaddy\Asherah\NativeLibraryInstaller;
use PHPUnit\Framework\TestCase;

final class NativeLibraryInstallerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $base = sys_get_temp_dir() . '/asherah_php_installer_' . bin2hex(random_bytes(6));
        mkdir($base, 0o755, true);
        $this->tmpDir = $base;
    }

    protected function tearDown(): void
    {
        $this->removeTree($this->tmpDir);
    }

    public function testArtifactMappingForLinuxX64(): void
    {
        $artifact = NativeLibraryInstaller::artifactForPlatform('linux-x64');

        self::assertSame('libasherah-x64.so', $artifact['asset']);
        self::assertSame('libasherah_ffi.so', $artifact['library']);
    }

    public function testUnsupportedPlatformFailsWithClearError(): void
    {
        $this->expectException(NativeLibraryException::class);
        $this->expectExceptionMessage('Unsupported native platform: solaris-sparc');

        NativeLibraryInstaller::artifactForPlatform('solaris-sparc');
    }

    public function testEmptyVersionOptionFails(): void
    {
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--version=', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testEmptyReleaseBaseUrlOptionFails(): void
    {
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--version=v1.2.3', '--release-base-url=', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testGitHubTokenIsNotSentToArbitraryReleaseHosts(): void
    {
        $restore = $this->setEnv(['GITHUB_TOKEN' => 'secret-token']);
        try {
            $headers = $this->headersForUrl('https://example.invalid/releases/v1/libasherah-x64.so');

            self::assertStringContainsString('User-Agent: asherah-php-native-installer', $headers);
            self::assertStringNotContainsString('Authorization:', $headers);
        } finally {
            $restore();
        }
    }

    public function testGitHubTokenIsSentToGitHubReleaseHosts(): void
    {
        $restore = $this->setEnv(['GITHUB_TOKEN' => 'secret-token']);
        try {
            $headers = $this->headersForUrl('https://github.com/godaddy/asherah-ffi/releases/download/v1/libasherah-x64.so');

            self::assertStringContainsString('Authorization: Bearer secret-token', $headers);
        } finally {
            $restore();
        }
    }

    public function testGitHubTokenIsNotSentToRedirectAssetHosts(): void
    {
        $restore = $this->setEnv(['GITHUB_TOKEN' => 'secret-token']);
        try {
            $headers = $this->headersForUrl('https://objects.githubusercontent.com/github-production-release-asset/foo');

            self::assertStringNotContainsString('Authorization:', $headers);
        } finally {
            $restore();
        }
    }

    public function testAutomaticRedirectsAreDisabledSoRedirectHostsAreReevaluated(): void
    {
        $options = $this->contextOptionsForUrl('https://github.com/godaddy/asherah-ffi/releases/download/v1/libasherah-x64.so');

        self::assertSame(0, $options['http']['follow_location']);
        self::assertSame(0, $options['http']['max_redirects']);
    }

    public function testDownloadsAndVerifiesCurrentPlatformArtifact(): void
    {
        $tag = 'v9.9.9-test';
        $payload = str_repeat('a', 1024 * 1024 + 1);
        $releaseRoot = $this->createReleaseFixture($tag, $payload);

        $installRoot = $this->tmpDir . '/package';
        $installer = new NativeLibraryInstaller($installRoot);

        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--quiet',
        ]);
        ob_end_clean();

        $installed = $installRoot . '/native/linux-x64/libasherah_ffi.so';
        self::assertSame(0, $code);
        self::assertFileExists($installed);
        self::assertSame(hash('sha256', $payload), hash_file('sha256', $installed));
        self::assertFileExists($installed . '.sha256');
        self::assertSame(hash('sha256', $payload) . "  libasherah_ffi.so\n", file_get_contents($installed . '.sha256'));
    }

    public function testLargeNativeArtifactDownloadsUnderConstrainedMemoryLimit(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('Subprocess command quoting for this memory-limit guard is Unix-specific');
        }

        $script = $this->tmpDir . '/large_download.php';
        $autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';
        $package = $this->tmpDir . '/package';
        $releaseRoot = $this->tmpDir . '/release';
        $autoloadLiteral = var_export($autoload, true);
        $packageLiteral = var_export($package, true);
        $releaseRootLiteral = var_export($releaseRoot, true);
        $code = <<<PHP
<?php
declare(strict_types=1);

require {$autoloadLiteral};

use GoDaddy\Asherah\NativeLibraryInstaller;

\$tag = 'v9.9.9-test';
\$releaseRoot = {$releaseRootLiteral};
\$assetDir = \$releaseRoot . '/' . \$tag;
mkdir(\$assetDir, 0755, true);
\$asset = \$assetDir . '/libasherah-x64.so';
\$out = fopen(\$asset, 'wb');
\$hash = hash_init('sha256');
\$chunk = str_repeat('z', 1024 * 1024);
for (\$i = 0; \$i < 12; \$i++) {
    fwrite(\$out, \$chunk);
    hash_update(\$hash, \$chunk);
}
fclose(\$out);
chmod(\$asset, 0755);
\$digest = hash_final(\$hash);
file_put_contents(\$assetDir . '/SHA256SUMS', \$digest . "  libasherah-x64.so\n");
\$installer = new NativeLibraryInstaller({$packageLiteral});
exit(\$installer->run([
    '--platform=linux-x64',
    '--version=' . \$tag,
    '--release-base-url=file://' . \$releaseRoot,
    '--quiet',
]));
PHP;
        file_put_contents($script, $code);

        $output = [];
        exec(escapeshellarg(PHP_BINARY) . ' -d memory_limit=16M ' . escapeshellarg($script), $output, $exitCode);

        $installed = $package . '/native/linux-x64/libasherah_ffi.so';
        self::assertSame(0, $exitCode, implode("\n", $output));
        self::assertFileExists($installed);
        self::assertSame(12 * 1024 * 1024, filesize($installed));
    }

    public function testInstallDirStagesOutsidePackageNativeDirectory(): void
    {
        $tag = 'v9.9.9-test';
        $payload = str_repeat('b', 1024 * 1024 + 1);
        $releaseRoot = $this->createReleaseFixture($tag, $payload);
        $installDir = $this->tmpDir . '/external-native';
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--install-dir=' . $installDir,
            '--quiet',
        ]);
        ob_end_clean();

        self::assertSame(0, $code);
        self::assertFileExists($installDir . '/linux-x64/libasherah_ffi.so');
        self::assertFileDoesNotExist($this->tmpDir . '/package/native/linux-x64/libasherah_ffi.so');
    }

    public function testChecksumMismatchFails(): void
    {
        $tag = 'v9.9.9-test';
        $releaseRoot = $this->createReleaseFixture($tag, str_repeat('c', 1024 * 1024 + 1), '00');
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--quiet',
        ]);
        ob_end_clean();

        self::assertSame(1, $code);
        self::assertFileDoesNotExist($this->tmpDir . '/package/native/linux-x64/libasherah_ffi.so');
    }

    public function testMissingChecksumEntryFails(): void
    {
        $tag = 'v9.9.9-test';
        $releaseRoot = $this->createReleaseFixture($tag, str_repeat('m', 1024 * 1024 + 1), null, 'other-asset.so');
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--quiet',
        ]);
        ob_end_clean();

        self::assertSame(1, $code);
        self::assertFileDoesNotExist($this->tmpDir . '/package/native/linux-x64/libasherah_ffi.so');
    }

    public function testForceReplacesExistingNativeLibrary(): void
    {
        $tag = 'v9.9.9-test';
        $oldPayload = str_repeat('d', 1024 * 1024 + 1);
        $newPayload = str_repeat('e', 1024 * 1024 + 1);
        $releaseRoot = $this->createReleaseFixture($tag, $newPayload);
        $installRoot = $this->tmpDir . '/package';
        $installed = $installRoot . '/native/linux-x64/libasherah_ffi.so';
        mkdir(dirname($installed), 0o755, true);
        file_put_contents($installed, $oldPayload);
        chmod($installed, 0o755);

        $installer = new NativeLibraryInstaller($installRoot);
        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--force',
            '--quiet',
        ]);
        ob_end_clean();

        self::assertSame(0, $code);
        self::assertSame(hash('sha256', $newPayload), hash_file('sha256', $installed));
    }

    public function testVerifyFailsWhenNativeLibraryIsMissing(): void
    {
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testVerifySucceedsForStagedValidNativeLibrary(): void
    {
        $installed = $this->stageInstalledLibrary(str_repeat('v', 1024 * 1024 + 1));
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(0, $code);
        self::assertFileExists($installed);
    }

    public function testVerifyFailsWhenNativeLibraryIsEmpty(): void
    {
        $this->stageInstalledLibrary('');
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testVerifyFailsWhenNativeLibraryIsTooSmall(): void
    {
        $this->stageInstalledLibrary(str_repeat('s', 1024));
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testVerifyFailsWhenNativeLibraryIsUnreadable(): void
    {
        $installed = $this->stageInstalledLibrary(str_repeat('u', 1024 * 1024 + 1));
        chmod($installed, 0o000);
        if (is_readable($installed)) {
            self::markTestSkipped('Current user can still read chmod 000 files');
        }

        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');
        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testVerifyFailsWhenNativeLibraryIsNotExecutable(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('Windows native library executability is not represented by chmod');
        }

        $installed = $this->stageInstalledLibrary(str_repeat('x', 1024 * 1024 + 1));
        chmod($installed, 0o644);
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run(['--platform=linux-x64', '--verify', '--quiet']);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testNoChecksumAllowsFixtureWithoutSha256Sums(): void
    {
        $tag = 'v9.9.9-test';
        $payload = str_repeat('n', 1024 * 1024 + 1);
        $releaseRoot = $this->createReleaseFixture($tag, $payload, writeChecksums: false);
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');

        ob_start();
        $code = $installer->run([
            '--platform=linux-x64',
            '--version=' . $tag,
            '--release-base-url=file://' . $releaseRoot,
            '--no-checksum',
            '--quiet',
        ]);
        ob_end_clean();

        self::assertSame(0, $code);
        self::assertFileExists($this->tmpDir . '/package/native/linux-x64/libasherah_ffi.so');
    }

    private function createReleaseFixture(
        string $tag,
        string $payload,
        ?string $checksum = null,
        string $checksumAsset = 'libasherah-x64.so',
        bool $writeChecksums = true
    ): string {
        $releaseRoot = $this->tmpDir . '/release_' . bin2hex(random_bytes(4));
        $assetDir = $releaseRoot . '/' . $tag;
        mkdir($assetDir, 0o755, true);

        $asset = $assetDir . '/libasherah-x64.so';
        file_put_contents($asset, $payload);
        chmod($asset, 0o755);
        if ($writeChecksums) {
            file_put_contents(
                $assetDir . '/SHA256SUMS',
                ($checksum ?? hash('sha256', $payload)) . "  {$checksumAsset}\n"
            );
        }

        return $releaseRoot;
    }

    private function stageInstalledLibrary(string $payload): string
    {
        $installed = $this->tmpDir . '/package/native/linux-x64/libasherah_ffi.so';
        mkdir(dirname($installed), 0o755, true);
        file_put_contents($installed, $payload);
        chmod($installed, 0o755);
        return $installed;
    }

    private function headersForUrl(string $url): string
    {
        $options = $this->contextOptionsForUrl($url);
        self::assertIsString($options['http']['header']);
        return $options['http']['header'];
    }

    /**
     * @return array{http: array<string, mixed>}
     */
    private function contextOptionsForUrl(string $url): array
    {
        $installer = new NativeLibraryInstaller($this->tmpDir . '/package');
        $method = new \ReflectionMethod(NativeLibraryInstaller::class, 'streamContext');
        $context = $method->invoke($installer, $url);
        self::assertIsResource($context);

        $options = stream_context_get_options($context);
        self::assertIsArray($options['http']);
        return $options;
    }

    /**
     * @param array<string, ?string> $updates
     * @return callable(): void
     */
    private function setEnv(array $updates): callable
    {
        $previous = [];
        foreach ($updates as $name => $value) {
            $old = getenv($name);
            $previous[$name] = $old === false ? null : $old;
            putenv($value === null ? $name : "{$name}={$value}");
        }

        return static function () use ($previous): void {
            foreach ($previous as $name => $value) {
                putenv($value === null ? $name : "{$name}={$value}");
            }
        };
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
