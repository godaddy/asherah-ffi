<?php

declare(strict_types=1);

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require __DIR__ . '/../vendor/autoload.php';
} else {
    require __DIR__ . '/../src/AsherahException.php';
    require __DIR__ . '/../src/ConfigurationException.php';
    require __DIR__ . '/../src/LifecycleException.php';
    require __DIR__ . '/../src/NativeLibraryException.php';
    require __DIR__ . '/../src/NativeOperationException.php';
    require __DIR__ . '/../src/ConfigValidator.php';
    require __DIR__ . '/../src/Native.php';
    require __DIR__ . '/../src/Session.php';
    require __DIR__ . '/../src/SessionFactory.php';
    require __DIR__ . '/../src/Asherah.php';
}

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahException;
use GoDaddy\Asherah\SessionFactory;

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$config = [
    'ServiceName' => 'php-smoke-service',
    'ProductID' => 'php-smoke-product',
    'Metastore' => 'memory',
    'KMS' => 'test-debug-static',
    'SessionCacheMaxSize' => 2,
];

Asherah::setup($config);
try {
    $payload = "secret\0payload";
    $ciphertext = Asherah::encryptString('tenant-1', $payload);
    assertTrue($ciphertext !== $payload, 'ciphertext should not equal plaintext');
    assertTrue(str_contains($ciphertext, '"Key"'), 'ciphertext should be DataRowRecord JSON');
    $plaintext = Asherah::decryptString('tenant-1', $ciphertext);
    assertTrue($plaintext === $payload, 'static API round trip failed');

    $emptyCiphertext = Asherah::encryptString('tenant-1', '');
    assertTrue(Asherah::decryptString('tenant-1', $emptyCiphertext) === '', 'empty payload round trip failed');

    try {
        Asherah::encryptString('', 'payload');
        throw new RuntimeException('empty partition should have failed');
    } catch (InvalidArgumentException) {
    }
} finally {
    Asherah::shutdown();
}

$factory = SessionFactory::fromConfig($config);
try {
    $session = $factory->getSession('tenant-2');
    try {
        $ciphertext = $session->encryptBytes('factory-payload');
        assertTrue($session->decryptBytes($ciphertext) === 'factory-payload', 'factory/session round trip failed');

        try {
            $session->decryptBytes('');
            throw new RuntimeException('empty DRR JSON should have failed');
        } catch (AsherahException $e) {
            assertTrue(str_contains($e->getMessage(), 'invalid JSON'), 'expected invalid JSON error');
        }
    } finally {
        $session->close();
    }
} finally {
    $factory->close();
}

echo "asherah-php smoke OK\n";
