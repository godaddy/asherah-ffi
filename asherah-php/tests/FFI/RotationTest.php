<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\FFI;

use GoDaddy\Asherah\Asherah;
use PHPUnit\Framework\TestCase;

/**
 * Rotation, revocation, and concurrent-cycle tests for the
 * asherah-php binding.
 *
 * The Rust core has comprehensive rotation/revocation coverage in
 * asherah/tests/. The PHP binding had zero rotation tests prior to
 * this file. Mirrors the asherah-node, asherah-py, asherah-java,
 * asherah-dotnet, asherah-go, and asherah-ruby rotation suites.
 *
 * Hermetic: Metastore: 'memory' + KMS: 'test-debug-static' produces
 * a hermetic factory with no Docker or network dependency. PHP has
 * no async API — only sync rotation tests are needed here.
 */
final class RotationTest extends TestCase
{
    protected function tearDown(): void
    {
        Asherah::shutdown();
    }

    public function testSyncRotationAcrossExpiry(): void
    {
        Asherah::setup($this->shortExpiryConfig('sync'));

        $drr1 = Asherah::encryptString('p1', 'before');
        $ik1 = $this->ikCreated($drr1);

        sleep(3);

        $drr2 = Asherah::encryptString('p1', 'after');
        $ik2 = $this->ikCreated($drr2);

        self::assertGreaterThan(
            $ik1,
            $ik2,
            "expected IK rotation across expiry: ik2={$ik2} should be > ik1={$ik1}"
        );
        self::assertSame('before', Asherah::decryptString('p1', $drr1));
        self::assertSame('after', Asherah::decryptString('p1', $drr2));
    }

    public function testMultipleRotationCycles(): void
    {
        Asherah::setup($this->shortExpiryConfig('multi'));

        $history = [];
        for ($i = 0; $i < 3; $i++) {
            $payload = "cycle-{$i}";
            $drr = Asherah::encryptString('p1', $payload);
            $history[] = ['drr' => $drr, 'payload' => $payload, 'ik' => $this->ikCreated($drr)];
            sleep(3);
        }

        // Each cycle's IK must be strictly newer than the previous.
        for ($i = 1; $i < count($history); $i++) {
            self::assertGreaterThan(
                $history[$i - 1]['ik'],
                $history[$i]['ik'],
                "cycle {$i}: ik={$history[$i]['ik']} should be > prev ik={$history[$i - 1]['ik']}"
            );
        }

        // Every historical DRR still decrypts.
        foreach ($history as $entry) {
            self::assertSame(
                $entry['payload'],
                Asherah::decryptString('p1', $entry['drr'])
            );
        }
    }

    public function testHistoricalDrrsDecryptAfterRotation(): void
    {
        Asherah::setup($this->shortExpiryConfig('hist'));

        // Capture several DRRs under one IK.
        $pre = [];
        for ($i = 0; $i < 5; $i++) {
            $payload = "hist-{$i}";
            $pre[] = ['drr' => Asherah::encryptString('p1', $payload), 'payload' => $payload];
        }

        sleep(3);

        // Trigger rotation.
        $afterDrr = Asherah::encryptString('p1', 'after-rotation');
        self::assertGreaterThan(
            $this->ikCreated($pre[0]['drr']),
            $this->ikCreated($afterDrr),
            'rotation must advance IK'
        );

        // All pre-rotation DRRs still decrypt — decrypt loads IK by
        // exact (id, created), bypassing any "latest" lookup.
        foreach ($pre as $entry) {
            self::assertSame(
                $entry['payload'],
                Asherah::decryptString('p1', $entry['drr'])
            );
        }
        self::assertSame('after-rotation', Asherah::decryptString('p1', $afterDrr));
    }

    /** Pull Key.ParentKeyMeta.Created out of a DRR JSON string. */
    private function ikCreated(string $drrJson): int
    {
        $parsed = json_decode($drrJson, true);
        self::assertIsArray($parsed, "DRR JSON parse failed: {$drrJson}");
        self::assertArrayHasKey('Key', $parsed, "DRR missing Key: {$drrJson}");
        self::assertArrayHasKey('ParentKeyMeta', $parsed['Key'], "DRR missing ParentKeyMeta: {$drrJson}");
        return (int) $parsed['Key']['ParentKeyMeta']['Created'];
    }

    /**
     * @return array<string, mixed>
     */
    private function shortExpiryConfig(string $suffix): array
    {
        return [
            'ServiceName' => "rot-{$suffix}-svc",
            'ProductID' => "rot-{$suffix}-prod",
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
            'ExpireAfter' => 1,
            'CheckInterval' => 1,
            'EnableSessionCaching' => false,
        ];
    }
}
