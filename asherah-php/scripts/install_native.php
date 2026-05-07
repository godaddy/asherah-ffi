#!/usr/bin/env php
<?php

declare(strict_types=1);

use GoDaddy\Asherah\NativeLibraryInstaller;

$autoloadCandidates = [
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
];

foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        exit((new NativeLibraryInstaller())->run(array_slice($argv, 1)));
    }
}

fwrite(STDERR, "Unable to locate Composer autoload.php for asherah-php\n");
exit(1);
