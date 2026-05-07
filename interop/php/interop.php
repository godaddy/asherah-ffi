<?php

declare(strict_types=1);

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\KmsConfig;
use GoDaddy\Asherah\MetastoreConfig;

require_once dirname(__DIR__, 2) . '/asherah-php/vendor/autoload.php';

if ($argc !== 4) {
    fwrite(STDERR, "usage: php interop/php/interop.php <encrypt|decrypt> <partition-id> <base64>\n");
    exit(2);
}

$metastore = getenv('Metastore') ?: 'memory';
$connectionString = getenv('CONNECTION_STRING') ?: getenv('SQLITE_PATH') ?: '';
$kms = getenv('KMS') ?: 'test-debug-static';
$staticMasterKeyHex = getenv('STATIC_MASTER_KEY_HEX') ?: '';

$metastoreConfig = match ($metastore) {
    'sqlite' => MetastoreConfig::sqlite($connectionString),
    'memory' => MetastoreConfig::memory(),
    default => throw new InvalidArgumentException("unsupported PHP interop metastore: {$metastore}"),
};
$kmsConfig = match ($kms) {
    'static' => KmsConfig::static($staticMasterKeyHex),
    'test-debug-static' => $staticMasterKeyHex !== ''
        ? KmsConfig::static($staticMasterKeyHex)
        : KmsConfig::testDebugStatic(),
    default => throw new InvalidArgumentException("unsupported PHP interop KMS: {$kms}"),
};

$config = new AsherahConfig(
    getenv('SERVICE_NAME') ?: 'service',
    getenv('PRODUCT_ID') ?: 'product',
    $metastoreConfig,
    $kmsConfig
);
Asherah::setup($config->withSessionCache(false));

try {
    $payload = base64_decode($argv[3], true);
    if ($payload === false) {
        throw new InvalidArgumentException('payload must be base64');
    }

    if ($argv[1] === 'encrypt') {
        echo base64_encode(Asherah::encryptBytes($argv[2], $payload));
    } elseif ($argv[1] === 'decrypt') {
        echo base64_encode(Asherah::decryptBytes($argv[2], $payload));
    } else {
        fwrite(STDERR, "usage: php interop/php/interop.php <encrypt|decrypt> <partition-id> <base64>\n");
        exit(2);
    }
} finally {
    Asherah::shutdown();
}
