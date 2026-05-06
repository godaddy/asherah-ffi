<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\FFI;

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahException;
use GoDaddy\Asherah\SessionFactory;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class NativeRoundTripTest extends TestCase
{
    protected function tearDown(): void
    {
        Asherah::shutdown();
    }

    public function testStaticApiRoundTripsBinaryPayload(): void
    {
        Asherah::setup($this->config());

        $payload = "secret\0payload\xff";
        $ciphertext = Asherah::encryptString('tenant-1', $payload);

        self::assertNotSame($payload, $ciphertext);
        self::assertStringContainsString('"Key"', $ciphertext);
        self::assertSame($payload, Asherah::decryptString('tenant-1', $ciphertext));
    }

    public function testEmptyPlaintextIsEncryptedAndRoundTrips(): void
    {
        Asherah::setup($this->config());

        $ciphertext = Asherah::encryptString('tenant-1', '');

        self::assertNotSame('', $ciphertext);
        self::assertSame('', Asherah::decryptString('tenant-1', $ciphertext));
    }

    public function testStaticApiWithoutSessionCachingClosesPerCallSessions(): void
    {
        Asherah::setup($this->config(['EnableSessionCaching' => false]));

        $ciphertext = Asherah::encryptString('tenant-no-cache', 'payload');

        self::assertSame('payload', Asherah::decryptString('tenant-no-cache', $ciphertext));
    }

    public function testExplicitFactoryAndSessionRoundTrip(): void
    {
        $factory = SessionFactory::fromConfig($this->config());
        try {
            $session = $factory->getSession('tenant-2');
            try {
                $ciphertext = $session->encryptBytes('factory-payload');

                self::assertSame('factory-payload', $session->decryptBytes($ciphertext));
            } finally {
                $session->close();
            }
        } finally {
            $factory->close();
        }
    }

    public function testEmptyPartitionIsRejected(): void
    {
        Asherah::setup($this->config());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('partition_id cannot be empty');

        Asherah::encryptString('', 'payload');
    }

    public function testInvalidDataRowRecordJsonReturnsNativeError(): void
    {
        $factory = SessionFactory::fromConfig($this->config());
        try {
            $session = $factory->getSession('tenant-3');
            try {
                $this->expectException(AsherahException::class);
                $this->expectExceptionMessage('invalid JSON');

                $session->decryptBytes('');
            } finally {
                $session->close();
            }
        } finally {
            $factory->close();
        }
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_replace([
            'ServiceName' => 'php-test-service',
            'ProductID' => 'php-test-product',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
            'SessionCacheMaxSize' => 2,
        ], $overrides);
    }
}
