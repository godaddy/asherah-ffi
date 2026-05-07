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
