<?php

declare(strict_types=1);

use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\SessionFactory;

require_once dirname(__DIR__, 2) . '/asherah-php/vendor/autoload.php';

$factory = SessionFactory::fromConfig(
    AsherahConfig::memoryTestDebugStatic('sample-service', 'sample-product')
        ->withSessionCache(false)
);
$session = $factory->getSession('tenant-123');

try {
    $plaintext = "binary\0payload";
    $dataRowRecord = $session->encrypt($plaintext);
    $roundTrip = $session->decrypt($dataRowRecord);

    if ($roundTrip !== $plaintext) {
        throw new RuntimeException('round trip failed');
    }

    echo "asherah php factory sample OK\n";
    if ($dataRowRecord->hasKey()) {
        echo "Key created: " . $dataRowRecord->getKeyCreated() . "\n";
    }
} finally {
    $session->close();
    $factory->close();
}
