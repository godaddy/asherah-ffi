<?php

declare(strict_types=1);

use GoDaddy\Asherah\Native;

$autoloadCandidates = [
    __DIR__ . '/vendor/autoload.php',
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 2) . '/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
];

foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        break;
    }
}

if (!class_exists(Native::class)) {
    throw new RuntimeException('Unable to locate Composer autoload.php for asherah-php preload');
}

$library = Native::resolveLibraryPath();
$header = getenv('ASHERAH_PHP_PRELOAD_HEADER');
$removeHeader = false;
if (!is_string($header) || trim($header) === '') {
    $header = tempnam(sys_get_temp_dir(), 'asherah_ffi_');
    if ($header === false) {
        throw new RuntimeException('Failed to create Asherah FFI preload header');
    }
    $removeHeader = true;
}

$ffiLib = addcslashes($library, "\\\"");
$contents = <<<CDEF
#define FFI_SCOPE "ASHERAH"
#define FFI_LIB "{$ffiLib}"

CDEF
    . Native::cdef()
    . "\n";

if (@file_put_contents($header, $contents) === false) {
    if ($removeHeader) {
        @unlink($header);
    }
    throw new RuntimeException("Failed to write Asherah FFI preload header: {$header}");
}

try {
    FFI::load($header);
} finally {
    if ($removeHeader) {
        @unlink($header);
    }
}
