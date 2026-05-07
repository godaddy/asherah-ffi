<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\FFI;

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\AsherahException;
use GoDaddy\Asherah\LifecycleException;
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
        self::assertSame([], $this->cachedPartitions());
    }

    public function testStaticApiReusesCachedSessionForPartition(): void
    {
        Asherah::setup($this->config(['SessionCacheMaxSize' => 2]));

        $ciphertext = Asherah::encryptString('tenant-cache', 'payload');
        self::assertSame(['tenant-cache'], $this->cachedPartitions());

        self::assertSame('payload', Asherah::decryptString('tenant-cache', $ciphertext));
        self::assertSame(['tenant-cache'], $this->cachedPartitions());
    }

    public function testSessionCacheEvictsLeastRecentlyUsedPartition(): void
    {
        Asherah::setup($this->config(['SessionCacheMaxSize' => 2]));

        Asherah::encryptString('tenant-a', 'a');
        Asherah::encryptString('tenant-b', 'b');
        Asherah::encryptString('tenant-a', 'a2');
        Asherah::encryptString('tenant-c', 'c');

        self::assertSame(['tenant-a', 'tenant-c'], $this->cachedPartitions());
    }

    public function testShutdownDrainsCachedSessions(): void
    {
        Asherah::setup($this->config(['SessionCacheMaxSize' => 2]));

        Asherah::encryptString('tenant-a', 'a');
        Asherah::encryptString('tenant-b', 'b');
        self::assertSame(['tenant-a', 'tenant-b'], $this->cachedPartitions());

        Asherah::shutdown();

        self::assertSame([], $this->cachedPartitions());
    }

    public function testDoubleSetupFailsWithLifecycleException(): void
    {
        Asherah::setup($this->config());

        $this->expectException(LifecycleException::class);
        $this->expectExceptionMessage('already initialized');

        Asherah::setup($this->config());
    }

    public function testExplicitFactoryAndSessionRoundTrip(): void
    {
        $factory = SessionFactory::fromConfig($this->config());
        try {
            $session = $factory->getSession('tenant-2');
            try {
                $ciphertext = $session->encryptBytes('factory-payload');

                self::assertSame('factory-payload', $session->decryptString($ciphertext));
            } finally {
                $session->close();
            }
        } finally {
            $factory->close();
        }
    }

    public function testTypedConfigRoundTrip(): void
    {
        Asherah::setup(
            AsherahConfig::memoryTestDebugStatic('php-test-service', 'php-test-product')
                ->withSessionCache(true, 2)
        );

        $ciphertext = Asherah::encryptBytes('tenant-typed', 'typed-payload');

        self::assertSame('typed-payload', Asherah::decryptBytes('tenant-typed', $ciphertext));
    }

    public function testClosedSessionRejectsOperations(): void
    {
        $factory = SessionFactory::fromConfig($this->config());
        try {
            $session = $factory->getSession('tenant-closed');
            $session->close();

            $this->expectException(LifecycleException::class);
            $this->expectExceptionMessage('session is closed');

            $session->encryptString('payload');
        } finally {
            $factory->close();
        }
    }

    public function testClosedFactoryRejectsGetSession(): void
    {
        $factory = SessionFactory::fromConfig($this->config());
        $factory->close();

        $this->expectException(LifecycleException::class);
        $this->expectExceptionMessage('factory is closed');

        $factory->getSession('tenant-after-close');
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

    /**
     * @return list<string>
     */
    private function cachedPartitions(): array
    {
        $reader = \Closure::bind(static fn (): array => array_keys(Asherah::$sessions), null, Asherah::class);

        return $reader();
    }
}
