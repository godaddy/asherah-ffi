<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\LifecycleException;
use PHPUnit\Framework\TestCase;

final class LifecycleTest extends TestCase
{
    protected function tearDown(): void
    {
        Asherah::shutdown();
    }

    public function testEncryptBeforeSetupFailsWithLifecycleException(): void
    {
        $this->expectException(LifecycleException::class);
        $this->expectExceptionMessage('not initialized');

        Asherah::encryptString('tenant', 'payload');
    }

    public function testShutdownIsIdempotent(): void
    {
        Asherah::shutdown();
        Asherah::shutdown();

        self::assertTrue(true);
    }
}
