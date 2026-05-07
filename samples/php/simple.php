<?php

declare(strict_types=1);

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;

require_once dirname(__DIR__, 2) . '/asherah-php/vendor/autoload.php';

Asherah::setup(
    AsherahConfig::memoryTestDebugStatic('sample-service', 'sample-product')
        ->withSessionCache(true, 100)
);

try {
    $partitionId = 'tenant-123';
    $plaintext = 'hello from php';

    $dataRowRecord = Asherah::encryptString($partitionId, $plaintext);
    $roundTrip = Asherah::decryptString($partitionId, $dataRowRecord);

    if ($roundTrip !== $plaintext) {
        throw new RuntimeException('round trip failed');
    }

    echo "asherah php sample OK\n";
} finally {
    Asherah::shutdown();
}
