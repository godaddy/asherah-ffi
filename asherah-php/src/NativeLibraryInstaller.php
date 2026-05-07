<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use Composer\InstalledVersions;

final class NativeLibraryInstaller
{
    private const DEFAULT_RELEASE_BASE_URL = 'https://github.com/godaddy/asherah-ffi/releases/download';
    private const MIN_LIBRARY_SIZE = 1024 * 1024;
    private const TIMEOUT_SECONDS = 300;

    /**
     * @var array<string, array{asset: string, library: string}>
     */
    private const ARTIFACTS = [
        'linux-x64' => ['asset' => 'libasherah-x64.so', 'library' => 'libasherah_ffi.so'],
        'linux-arm64' => ['asset' => 'libasherah-arm64.so', 'library' => 'libasherah_ffi.so'],
        'linux-musl-x64' => ['asset' => 'libasherah-x64-musl.so', 'library' => 'libasherah_ffi.so'],
        'linux-musl-arm64' => ['asset' => 'libasherah-arm64-musl.so', 'library' => 'libasherah_ffi.so'],
        'darwin-x64' => ['asset' => 'libasherah-x64.dylib', 'library' => 'libasherah_ffi.dylib'],
        'darwin-arm64' => ['asset' => 'libasherah-arm64.dylib', 'library' => 'libasherah_ffi.dylib'],
        'win-x64' => ['asset' => 'libasherah-x64.dll', 'library' => 'asherah_ffi.dll'],
        'win-arm64' => ['asset' => 'libasherah-arm64.dll', 'library' => 'asherah_ffi.dll'],
    ];

    private string $baseDir;
    private ?string $installDir = null;
    private bool $quiet = false;
    private bool $verbose = false;

    public function __construct(?string $baseDir = null)
    {
        $this->baseDir = $baseDir ?? dirname(__DIR__);
    }

    /**
     * @param list<string> $args
     */
    public function run(array $args): int
    {
        $options = $this->parseArgs($args);
        $this->quiet = $options['quiet'];
        $this->verbose = $options['verbose'];

        try {
            $platform = $options['platform'] ?? self::detectPlatform();
            if ($options['help']) {
                $this->printHelp();
                return 0;
            }
            $this->installDir = $options['installDir'];

            $artifact = self::artifactForPlatform($platform);
            $destination = $this->libraryPath($platform, $artifact['library']);

            if ($options['verify']) {
                $this->verifyInstalledLibrary($destination);
                $this->log("Native library verified: {$destination}");
                return 0;
            }

            if (!$options['force'] && is_file($destination)) {
                $this->verifyInstalledLibrary($destination);
                $this->log("Native library already installed: {$destination}");
                return 0;
            }

            $version = $options['version'] ?? $this->detectVersion();
            $baseUrl = $options['releaseBaseUrl'];
            $releaseUrl = $this->releaseUrl($baseUrl, $version);
            $assetUrl = $releaseUrl . '/' . rawurlencode($artifact['asset']);
            $checksumsUrl = $releaseUrl . '/SHA256SUMS';

            $this->log("Downloading {$artifact['asset']} for {$platform} from {$version}");
            if ($this->verbose) {
                $this->log("Asset URL: {$assetUrl}");
            }
            $checksum = $options['checksum']
                ? $this->downloadExpectedChecksum($checksumsUrl, $artifact['asset'])
                : null;

            $tmp = $this->downloadToTempFile($assetUrl);
            try {
                $this->verifyDownloadedLibrary($tmp, $checksum);
                $this->installFile($tmp, $destination);
                $this->verifyInstalledLibrary($destination);
                if ($checksum !== null) {
                    file_put_contents($destination . '.sha256', $checksum . "  {$artifact['library']}\n");
                }
            } finally {
                if (is_file($tmp)) {
                    unlink($tmp);
                }
            }

            $this->log("Native library installed: {$destination}");
            return 0;
        } catch (\Throwable $e) {
            $this->error('Native library installation failed: ' . $e->getMessage());
            $this->error('Set ASHERAH_PHP_NATIVE to an existing library for local builds, or rerun with '
                . 'ASHERAH_PHP_NATIVE_VERSION=<release-tag>.');
            return 1;
        }
    }

    public static function detectPlatform(): string
    {
        $arch = strtolower(php_uname('m'));
        $arch = match ($arch) {
            'x86_64', 'amd64' => 'x64',
            'aarch64', 'arm64' => 'arm64',
            default => $arch,
        };

        return match (PHP_OS_FAMILY) {
            'Darwin' => "darwin-{$arch}",
            'Windows' => "win-{$arch}",
            default => self::isMusl() ? "linux-musl-{$arch}" : "linux-{$arch}",
        };
    }

    /**
     * @return array{asset: string, library: string}
     */
    public static function artifactForPlatform(string $platform): array
    {
        return self::ARTIFACTS[$platform]
            ?? throw new NativeLibraryException("Unsupported native platform: {$platform}");
    }

    public function libraryPath(string $platform, string $libraryName): string
    {
        $root = $this->installDir ?? $this->baseDir . '/native';
        return rtrim($root, DIRECTORY_SEPARATOR) . "/{$platform}/{$libraryName}";
    }

    /**
     * @param list<string> $args
     *
     * @return array{
     *   checksum: bool,
     *   force: bool,
     *   help: bool,
     *   installDir: ?string,
     *   platform: ?string,
     *   quiet: bool,
     *   releaseBaseUrl: string,
     *   verbose: bool,
     *   verify: bool,
     *   version: ?string
     * }
     */
    private function parseArgs(array $args): array
    {
        $options = [
            'checksum' => true,
            'force' => false,
            'help' => false,
            'installDir' => null,
            'platform' => null,
            'quiet' => false,
            'releaseBaseUrl' => rtrim((string) (getenv('ASHERAH_PHP_RELEASE_BASE_URL') ?: self::DEFAULT_RELEASE_BASE_URL), '/'),
            'verbose' => false,
            'verify' => false,
            'version' => $this->envString('ASHERAH_PHP_NATIVE_VERSION'),
        ];

        foreach ($args as $arg) {
            if ($arg === '--force') {
                $options['force'] = true;
            } elseif ($arg === '--help' || $arg === '-h') {
                $options['help'] = true;
            } elseif ($arg === '--no-checksum') {
                $options['checksum'] = false;
            } elseif ($arg === '--quiet' || $arg === '-q') {
                $options['quiet'] = true;
            } elseif ($arg === '--verbose' || $arg === '-v') {
                $options['verbose'] = true;
            } elseif ($arg === '--verify') {
                $options['verify'] = true;
            } elseif (str_starts_with($arg, '--install-dir=')) {
                $installDir = substr($arg, strlen('--install-dir='));
                if ($installDir === '') {
                    throw new NativeLibraryException('--install-dir must not be empty');
                }
                $options['installDir'] = $installDir;
            } elseif (str_starts_with($arg, '--platform=')) {
                $options['platform'] = substr($arg, strlen('--platform='));
            } elseif (str_starts_with($arg, '--release-base-url=')) {
                $options['releaseBaseUrl'] = rtrim(substr($arg, strlen('--release-base-url=')), '/');
            } elseif (str_starts_with($arg, '--version=')) {
                $options['version'] = substr($arg, strlen('--version='));
            } else {
                throw new NativeLibraryException("Unknown option: {$arg}");
            }
        }

        return $options;
    }

    private function detectVersion(): string
    {
        if (class_exists(InstalledVersions::class)) {
            $version = InstalledVersions::getPrettyVersion('godaddy/asherah');
            if (is_string($version) && $version !== '') {
                return $version;
            }
        }

        $composerJson = $this->baseDir . '/composer.json';
        if (is_file($composerJson)) {
            $data = json_decode((string) file_get_contents($composerJson), true);
            if (is_array($data) && isset($data['version']) && is_string($data['version']) && $data['version'] !== '') {
                return $data['version'];
            }
        }

        throw new NativeLibraryException(
            'Unable to determine release tag; pass --version=<tag> or set ASHERAH_PHP_NATIVE_VERSION'
        );
    }

    private function releaseUrl(string $baseUrl, string $version): string
    {
        return rtrim($baseUrl, '/') . '/' . rawurlencode($version);
    }

    private function downloadExpectedChecksum(string $url, string $asset): string
    {
        $contents = $this->downloadString($url);
        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            $parts = preg_split('/\s+/', $line);
            if ($parts !== false && count($parts) >= 2 && $parts[1] === $asset) {
                return strtolower($parts[0]);
            }
        }

        throw new NativeLibraryException("SHA256SUMS does not contain checksum for {$asset}");
    }

    private function downloadString(string $url): string
    {
        $contents = @file_get_contents($url, false, $this->streamContext());
        if ($contents === false || $contents === '') {
            throw new NativeLibraryException("Failed to download {$url}");
        }

        return $contents;
    }

    private function downloadToTempFile(string $url): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'asherah_php_native_');
        if ($tmp === false) {
            throw new NativeLibraryException('Failed to create temporary download file');
        }

        $data = @file_get_contents($url, false, $this->streamContext());
        if ($data === false) {
            unlink($tmp);
            throw new NativeLibraryException("Failed to download {$url}");
        }

        file_put_contents($tmp, $data);
        return $tmp;
    }

    private function verifyDownloadedLibrary(string $path, ?string $expectedSha256): void
    {
        if (!is_file($path)) {
            throw new NativeLibraryException("Downloaded native library does not exist: {$path}");
        }

        $size = filesize($path);
        if ($size === false || $size < self::MIN_LIBRARY_SIZE) {
            throw new NativeLibraryException("Downloaded native library is missing or too small: {$path}");
        }

        if (!is_readable($path)) {
            throw new NativeLibraryException("Downloaded native library is not readable: {$path}");
        }

        if ($expectedSha256 !== null) {
            $actual = strtolower((string) hash_file('sha256', $path));
            if (!hash_equals($expectedSha256, $actual)) {
                throw new NativeLibraryException("Checksum mismatch: expected {$expectedSha256}, got {$actual}");
            }
        }
    }

    private function verifyInstalledLibrary(string $path): void
    {
        if (!is_file($path)) {
            throw new NativeLibraryException("Native library does not exist: {$path}");
        }

        $size = filesize($path);
        if ($size === false || $size < self::MIN_LIBRARY_SIZE) {
            throw new NativeLibraryException("Native library is missing or too small: {$path}");
        }

        if (!is_readable($path)) {
            throw new NativeLibraryException("Native library is not readable: {$path}");
        }

        if (PHP_OS_FAMILY !== 'Windows' && !is_executable($path)) {
            throw new NativeLibraryException("Native library is not executable: {$path}");
        }
    }

    private function installFile(string $tmp, string $destination): void
    {
        $dir = dirname($destination);
        if (!is_dir($dir) && !mkdir($dir, 0o755, true) && !is_dir($dir)) {
            throw new NativeLibraryException("Failed to create native directory: {$dir}");
        }

        if (!rename($tmp, $destination)) {
            throw new NativeLibraryException("Failed to move native library to {$destination}");
        }

        if (PHP_OS_FAMILY !== 'Windows') {
            chmod($destination, 0o755);
        }
    }

    /**
     * @return resource
     */
    private function streamContext()
    {
        $headers = ['User-Agent: asherah-php-native-installer'];
        $token = $this->envString('GITHUB_TOKEN') ?? $this->envString('GH_TOKEN');
        if ($token !== null) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        return stream_context_create([
            'http' => [
                'follow_location' => 1,
                'header' => implode("\r\n", $headers),
                'timeout' => self::TIMEOUT_SECONDS,
            ],
        ]);
    }

    private static function isMusl(): bool
    {
        if (file_exists('/etc/alpine-release')) {
            return true;
        }

        $ldd = trim((string) @shell_exec('ldd --version 2>&1'));
        return stripos($ldd, 'musl') !== false;
    }

    private function envString(string $name): ?string
    {
        $value = getenv($name);
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        return trim($value);
    }

    private function printHelp(): void
    {
        echo <<<'HELP'
Usage: php scripts/install_native.php [options]

Options:
  --version=<tag>            Asherah release tag to download.
  --platform=<platform>      Override detected platform.
  --release-base-url=<url>   Override GitHub release download base URL.
  --install-dir=<dir>        Stage native libraries under this directory.
  --force                   Redownload even when a native library exists.
  --verify                  Verify the installed native library only.
  --no-checksum             Skip SHA256SUMS verification.
  --quiet, -q               Suppress output.
  --verbose, -v             Print additional download details.
  --help, -h                Show this help.

Environment:
  ASHERAH_PHP_NATIVE_VERSION     Default release tag.
  ASHERAH_PHP_RELEASE_BASE_URL   Default release download base URL.
  GITHUB_TOKEN or GH_TOKEN       Optional token for private or rate-limited releases.

HELP;
    }

    private function log(string $message): void
    {
        if ($this->quiet) {
            return;
        }

        echo "[asherah-php] {$message}\n";
    }

    private function error(string $message): void
    {
        if ($this->quiet) {
            return;
        }

        fwrite(STDERR, "[asherah-php] {$message}\n");
    }
}
