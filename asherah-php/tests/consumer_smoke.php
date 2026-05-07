<?php

declare(strict_types=1);

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;

$autoloadCandidates = [
    getcwd() . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
];

foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        break;
    }
}

if (!class_exists(Asherah::class)) {
    fwrite(STDERR, "consumer autoload failed\n");
    exit(1);
}

Asherah::setup(AsherahConfig::memoryTestDebugStatic('consumer-service', 'consumer-product'));

try {
    $ciphertext = Asherah::encryptString('consumer-tenant', 'consumer-payload');
    $plaintext = Asherah::decryptString('consumer-tenant', $ciphertext);
    if ($plaintext !== 'consumer-payload') {
        fwrite(STDERR, "consumer round trip mismatch\n");
        exit(1);
    }
} finally {
    Asherah::shutdown();
}

echo "asherah-php consumer smoke OK\n";
