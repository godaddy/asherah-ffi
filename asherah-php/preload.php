<?php

declare(strict_types=1);

use GoDaddy\Asherah\Native;

require_once __DIR__ . '/vendor/autoload.php';

$library = Native::resolveLibraryPath();
$header = getenv('ASHERAH_PHP_PRELOAD_HEADER');
if (!is_string($header) || trim($header) === '') {
    $header = sys_get_temp_dir() . '/asherah_ffi_' . hash('sha256', $library) . '.h';
}

$ffiLib = addcslashes($library, "\\\"");
$contents = <<<CDEF
#define FFI_SCOPE "ASHERAH"
#define FFI_LIB "{$ffiLib}"

CDEF
    . Native::cdef()
    . "\n";

if (@file_put_contents($header, $contents) === false) {
    throw new RuntimeException("Failed to write Asherah FFI preload header: {$header}");
}

FFI::load($header);
