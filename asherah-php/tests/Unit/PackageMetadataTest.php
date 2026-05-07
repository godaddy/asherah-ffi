<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class PackageMetadataTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $composer;

    protected function setUp(): void
    {
        $json = file_get_contents(dirname(__DIR__, 2) . '/composer.json');
        self::assertIsString($json);

        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        $this->composer = $decoded;
    }

    public function testComposerPackageIdentityAndAuthorMetadata(): void
    {
        self::assertSame('godaddy/asherah', $this->composer['name']);
        self::assertSame('src/', $this->composer['autoload']['psr-4']['GoDaddy\\Asherah\\']);
        self::assertSame([['name' => 'Jay Gowdy']], $this->composer['authors']);
    }

    public function testSourceArchiveExcludesGeneratedAndNativeArtifacts(): void
    {
        $expected = [
            '/.php-cs-fixer.cache',
            '/.phpunit.cache',
            '/composer.lock',
            '/native',
            '/vendor',
        ];
        $actual = $this->composer['archive']['exclude'];
        sort($expected);
        sort($actual);

        self::assertSame($expected, $actual);
    }

    public function testNativeLifecycleScriptsRemainExplicitRootCommands(): void
    {
        self::assertSame('php scripts/install_native.php', $this->composer['scripts']['download-native']);
        self::assertSame('php scripts/install_native.php --verify', $this->composer['scripts']['verify-native']);
        self::assertArrayNotHasKey('post-install-cmd', $this->composer['scripts']);
        self::assertArrayNotHasKey('post-update-cmd', $this->composer['scripts']);
    }

    public function testRuntimeRequirementsStaySourceOnlyAndFfiExplicit(): void
    {
        self::assertSame('>=8.1', $this->composer['require']['php']);
        self::assertSame('*', $this->composer['require']['ext-ffi']);
        self::assertSame('*', $this->composer['require']['ext-json']);
        self::assertArrayNotHasKey('bin', $this->composer);
    }
}
