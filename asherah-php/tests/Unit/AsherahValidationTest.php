<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\SessionFactory;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class AsherahValidationTest extends TestCase
{
    public function testSetupRequiresServiceName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ServiceName is required');

        Asherah::setup([
            'ProductID' => 'product',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
        ]);
    }

    public function testSetupRequiresProductId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ProductID is required');

        Asherah::setup([
            'ServiceName' => 'service',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
        ]);
    }

    public function testSetupRequiresMetastore(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Metastore is required');

        Asherah::setup([
            'ServiceName' => 'service',
            'ProductID' => 'product',
            'KMS' => 'test-debug-static',
        ]);
    }

    public function testSetupRequiresKms(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('KMS is required');

        Asherah::setup([
            'ServiceName' => 'service',
            'ProductID' => 'product',
            'Metastore' => 'memory',
        ]);
    }

    public function testSetupRejectsNonBooleanSessionCacheFlag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('EnableSessionCaching must be boolean');

        Asherah::setup($this->config(['EnableSessionCaching' => 'false']));
    }

    public function testSetupRejectsNonStringRequiredFieldsBeforeFfi(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ServiceName is required');

        Asherah::setup($this->config(['ServiceName' => ['not-a-string']]));
    }

    public function testSetupRejectsInvalidOptionalStringFieldsBeforeFfi(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('DynamoDBRegion must be a non-empty string');

        Asherah::setup($this->config([
            'Metastore' => 'dynamodb',
            'DynamoDBRegion' => false,
        ]));
    }

    public function testSetupRejectsInvalidEnableRegionSuffixBeforeFfi(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('EnableRegionSuffix must be boolean');

        Asherah::setup($this->config(['EnableRegionSuffix' => 'true']));
    }

    public function testSetupRejectsInvalidArrayRegionMapBeforeFfi(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('RegionMap entry for us-west-2 must be a non-empty string');

        Asherah::setup($this->config([
            'KMS' => 'aws',
            'RegionMap' => ['us-west-2' => ''],
        ]));
    }

    public function testSessionFactoryRejectsInvalidArrayConfigBeforeFfi(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('KMS is required');

        SessionFactory::fromConfig($this->config(['KMS' => false]));
    }

    public function testSetupRejectsInvalidSessionCacheMaxSize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SessionCacheMaxSize must be an integer >= 1');

        Asherah::setup($this->config(['SessionCacheMaxSize' => 0]));
    }

    public function testSetupRejectsInvalidSessionCacheDuration(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('SessionCacheDuration must be an integer >= 0');

        Asherah::setup($this->config(['SessionCacheDuration' => '60']));
    }

    public function testSetupRejectsInvalidExpireAfter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ExpireAfter must be an integer >= 1');

        Asherah::setup($this->config(['ExpireAfter' => 0]));
    }

    public function testSetupRejectsInvalidCheckInterval(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CheckInterval must be an integer >= 1');

        Asherah::setup($this->config(['CheckInterval' => false]));
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_replace([
            'ServiceName' => 'service',
            'ProductID' => 'product',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
        ], $overrides);
    }
}
