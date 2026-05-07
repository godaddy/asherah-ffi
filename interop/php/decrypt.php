<?php

declare(strict_types=1);

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\KmsConfig;
use GoDaddy\Asherah\MetastoreConfig;

require_once dirname(__DIR__, 2) . '/asherah-php/vendor/autoload.php';

if ($argc !== 3) {
    fwrite(STDERR, "usage: php interop/php/decrypt.php <partition-id> <data-row-record-json>\n");
    exit(2);
}

$sqlitePath = getenv('ASHERAH_PHP_INTEROP_SQLITE') ?: sys_get_temp_dir() . '/asherah_php_interop.db';
Asherah::setup(new AsherahConfig(
    'interop-service',
    'interop-product',
    MetastoreConfig::sqlite($sqlitePath),
    KmsConfig::testDebugStatic()
));

try {
    echo Asherah::decryptString($argv[1], $argv[2]);
} finally {
    Asherah::shutdown();
}
