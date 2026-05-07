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

    public function testRootComposerPackageIndexesMonorepoForPackagist(): void
    {
        $json = file_get_contents(dirname(__DIR__, 3) . '/composer.json');
        self::assertIsString($json);

        $rootComposer = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($rootComposer);

        self::assertSame('godaddy/asherah', $rootComposer['name']);
        self::assertSame('asherah-php/src/', $rootComposer['autoload']['psr-4']['GoDaddy\\Asherah\\']);
        self::assertSame([['name' => 'Jay Gowdy']], $rootComposer['authors']);
        self::assertSame('php asherah-php/scripts/install_native.php', $rootComposer['scripts']['download-native']);
        self::assertSame('php asherah-php/scripts/install_native.php --verify', $rootComposer['scripts']['verify-native']);
        self::assertArrayNotHasKey('post-install-cmd', $rootComposer['scripts']);
        self::assertArrayNotHasKey('post-update-cmd', $rootComposer['scripts']);
    }

    public function testRootComposerArchiveExcludesMonorepoOnlySources(): void
    {
        $json = file_get_contents(dirname(__DIR__, 3) . '/composer.json');
        self::assertIsString($json);

        $rootComposer = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($rootComposer);

        $exclude = $rootComposer['archive']['exclude'];
        self::assertContains('/asherah', $exclude);
        self::assertContains('/asherah-node', $exclude);
        self::assertContains('/asherah-py', $exclude);
        self::assertContains('/interop-grpc', $exclude);
        self::assertContains('/target-*', $exclude);
        self::assertContains('/asherah-php/tests', $exclude);
        self::assertContains('/asherah-php/native', $exclude);
        self::assertNotContains('/asherah-php/src', $exclude);
        self::assertNotContains('/asherah-php/scripts', $exclude);
        self::assertNotContains('/asherah-php/preload.php', $exclude);
    }

    public function testGitAttributesPruneComposerDistArchives(): void
    {
        $contents = file_get_contents(dirname(__DIR__, 3) . '/.gitattributes');
        self::assertIsString($contents);

        foreach ([
            '/asherah/** export-ignore',
            '/asherah-node/** export-ignore',
            '/asherah-py/** export-ignore',
            '/interop-grpc/** export-ignore',
            '/scripts/** export-ignore',
            '/target-*/** export-ignore',
            '/asherah-php/tests/** export-ignore',
            '/asherah-php/native/** export-ignore',
        ] as $rule) {
            self::assertStringContainsString($rule, $contents);
        }

        self::assertStringNotContainsString('/asherah-php/src/** export-ignore', $contents);
        self::assertStringNotContainsString('/asherah-php/scripts/** export-ignore', $contents);
        self::assertStringNotContainsString('/asherah-php/preload.php export-ignore', $contents);
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
