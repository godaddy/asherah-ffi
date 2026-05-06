<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use GoDaddy\Asherah\Asherah;
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
}
